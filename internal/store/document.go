package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Document is deliberately driver-neutral. The production adapter can map it
// to a MongoDB driver's bson.M without leaking that dependency into
// domain code or local tests.
type Document map[string]any

type UpdateResult struct {
	Matched  int64
	Modified int64
	Upserted int64
}
type DeleteResult struct{ Deleted int64 }

// IndexKey is one ordered component of an index or sort specification.
// Order is 1 for ascending and -1 for descending. A slice keeps compound
// index/sort keys ordered, which a Document (map) cannot.
type IndexKey struct {
	Field string
	Order int
}

type IndexSpec struct {
	Keys               []IndexKey
	Unique             bool
	ExpireAfterSeconds *int32
}

type FindOptions struct {
	Sort  []IndexKey
	Limit int64
}

// FindOneAndUpdateOptions mirrors the Node driver's findOneAndUpdate options.
// With ReturnAfter=false the pre-update document is returned, so an upsert
// that inserts reports ErrNotFound exactly like the Mongo driver.
type FindOneAndUpdateOptions struct {
	Upsert      bool
	ReturnAfter bool
}

// DocumentCollection is the exact Mongo-compatible surface DocumentRepository
// needs. An SDK adapter must normalize driver no-document/duplicate-key errors
// to ErrNotFound/ErrConflict.
type DocumentCollection interface {
	CreateIndex(context.Context, Document) error
	CreateIndexSpec(context.Context, IndexSpec) error
	InsertOne(context.Context, any) error
	FindOne(context.Context, Document, any) error
	FindMany(context.Context, Document, any) error
	FindManyOptions(context.Context, Document, FindOptions, any) error
	// FindOneAndUpdate decodes the selected document into dst (nil discards
	// it) and returns ErrNotFound when no document is returned.
	FindOneAndUpdate(context.Context, Document, Document, FindOneAndUpdateOptions, any) error
	UpdateOne(context.Context, Document, Document, bool) (UpdateResult, error)
	UpdateMany(context.Context, Document, Document) (UpdateResult, error)
	DeleteOne(context.Context, Document) (DeleteResult, error)
	DeleteMany(context.Context, Document) (DeleteResult, error)
}

type DocumentDatabase interface {
	Collection(string) DocumentCollection
}
type DatabaseProvider interface {
	Database(context.Context) (DocumentDatabase, error)
}

type StaticDatabaseProvider struct{ DB DocumentDatabase }

func (p StaticDatabaseProvider) Database(context.Context) (DocumentDatabase, error) {
	if p.DB == nil {
		return nil, ErrUnavailable
	}
	return p.DB, nil
}

type DatabaseDialer func(context.Context) (DocumentDatabase, io.Closer, error)

// RetryingDatabaseProvider preserves the legacy distinction between an
// intentionally unconfigured store and a configured store in a temporary
// outage. A failed dial is retried after RetryDelay; it never switches to an
// empty in-memory authority.
type RetryingDatabaseProvider struct {
	Dial       DatabaseDialer
	RetryDelay time.Duration

	mu         sync.Mutex
	db         DocumentDatabase
	closer     io.Closer
	retryAfter time.Time
	closed     bool
}

func (p *RetryingDatabaseProvider) Database(ctx context.Context) (DocumentDatabase, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.Dial == nil {
		return nil, ErrUnavailable
	}
	if p.db != nil {
		return p.db, nil
	}
	if time.Now().Before(p.retryAfter) {
		return nil, ErrUnavailable
	}
	db, closer, err := p.Dial(ctx)
	if err != nil {
		delay := p.RetryDelay
		if delay <= 0 {
			delay = 30 * time.Second
		}
		p.retryAfter = time.Now().Add(delay)
		return nil, normalizeDBError(err)
	}
	p.db, p.closer = db, closer
	return db, nil
}

func (p *RetryingDatabaseProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.closer == nil {
		return nil
	}
	err := p.closer.Close()
	p.closer = nil
	p.db = nil
	return err
}

// Collection names owned by DocumentRepository.
const (
	collectionMachines                  = "machines"
	collectionUsers                     = "users"
	collectionTeams                     = "teams"
	collectionDevices                   = "devices"
	collectionDeviceGrants              = "device_grants"
	collectionDesktopSessionRevocations = "desktop_session_revocations"
	collectionDesktopAuthCodeUses       = "desktop_auth_code_uses"
	collectionProxyTicketUses           = "proxy_ticket_uses"
)

// DocumentRepository implements the existing Mongo schema and update operators.
// Connection discovery/retry belongs in DatabaseProvider so the same repository
// can be wired to the internal mongo-go-driver or a fake in tests. Local
// development uses the very same implementation on NewMemoryDatabaseProvider.
//
// The repository also owns the pod-local positive authority caches (machine
// lookups and desktop session families); share one instance per process so
// same-pod invalidations reach every reader.
type DocumentRepository struct {
	provider DatabaseProvider
	// now is the repository clock (tests override it).
	now func() time.Time

	machineCache *positiveCache[MachineDoc]
	familyCache  *positiveCache[DesktopFamilyStatus]
	// authority read counters (tests assert read coalescing).
	machineReads atomic.Int64
	familyReads  atomic.Int64
}

func NewDocumentRepository(provider DatabaseProvider) *DocumentRepository {
	return &DocumentRepository{
		provider:     provider,
		now:          time.Now,
		machineCache: newPositiveCache[MachineDoc](),
		familyCache:  newPositiveCache[DesktopFamilyStatus](),
	}
}

func (s *DocumentRepository) nowMS() int64 { return s.now().UnixMilli() }

func (s *DocumentRepository) collection(ctx context.Context, name string) (DocumentCollection, error) {
	if s == nil || s.provider == nil {
		return nil, ErrUnavailable
	}
	db, err := s.provider.Database(ctx)
	if err != nil {
		return nil, normalizeDBError(err)
	}
	if db == nil || db.Collection(name) == nil {
		return nil, ErrUnavailable
	}
	return db.Collection(name), nil
}

// EnsureIndexes is idempotent. Production startup first establishes and pings
// the provider, then invokes this best-effort to preserve the legacy behavior
// where missing create-index permission does not prevent serving traffic.
//
// Only the collections owned by this file family are covered here (machines,
// devices, device grants and the desktop/proxy one-time-use fences). TTL
// indexes are best-effort physical cleanup; the authoritative expiry is always
// the millisecond expiresAt checked in queries.
func (s *DocumentRepository) EnsureIndexes(ctx context.Context) error {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	for _, keys := range []Document{{"unionId": 1}, {"memberships.teamId": 1}, {"coManagers.unionId": 1}} {
		if err := c.CreateIndex(ctx, keys); err != nil {
			return normalizeDBError(err)
		}
	}
	devices, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return err
	}
	if err := devices.CreateIndex(ctx, Document{"unionId": 1}); err != nil {
		return normalizeDBError(err)
	}
	zero := int32(0)
	for _, name := range []string{collectionDeviceGrants, collectionDesktopSessionRevocations, collectionDesktopAuthCodeUses, collectionProxyTicketUses} {
		ttl, err := s.collection(ctx, name)
		if err != nil {
			return err
		}
		if err := ttl.CreateIndexSpec(ctx, IndexSpec{Keys: []IndexKey{{Field: "expireAt", Order: 1}}, ExpireAfterSeconds: &zero}); err != nil {
			return normalizeDBError(err)
		}
	}
	return nil
}

func (s *DocumentRepository) UpsertUserProfile(ctx context.Context, p UserProfile) error {
	c, err := s.collection(ctx, collectionUsers)
	if err != nil {
		return err
	}
	set := Document{"name": p.Name, "updatedAt": bsonNumber(p.UpdatedAt)}
	if p.Avatar != "" {
		set["avatar"] = p.Avatar
	}
	_, err = c.UpdateOne(ctx, Document{"_id": p.ID}, Document{"$set": set}, true)
	return normalizeDBError(err)
}
func (s *DocumentRepository) GetUserProfiles(ctx context.Context, ids []string) (map[string]UserProfile, error) {
	out := make(map[string]UserProfile, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	c, err := s.collection(ctx, collectionUsers)
	if err != nil {
		return nil, err
	}
	var docs []UserProfile
	if err := c.FindMany(ctx, Document{"_id": Document{"$in": ids}}, &docs); err != nil {
		return nil, normalizeDBError(err)
	}
	for _, d := range docs {
		out[d.ID] = d
	}
	return out, nil
}

// PersistRegister stores a tunnel register's online metadata. It never
// creates a document and never changes owner or status: the filter pins
// {_id, unionId, status != RETIRED}, so a stale token's register cannot
// resurrect a tombstone or rewrite ownership. ErrNotFound means nothing
// matched (unbound, foreign or retired machine).
func (s *DocumentRepository) PersistRegister(ctx context.Context, m RegisterMachine) error {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	set := Document{"name": m.Name, "botmuxVersion": m.BotmuxVersion, "dashboardPort": m.DashboardPort,
		"memberships": m.Memberships, "bots": m.Bots, "lastSeen": bsonNumber(m.LastSeen)}
	r, err := c.UpdateOne(ctx, Document{"_id": m.MachineID, "unionId": m.UnionID, "status": notRetired()}, Document{"$set": set}, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	return nil
}

// PersistHeartbeat refreshes lastSeen (the cross-pod liveness signal) and the
// optional version/memberships/bots. Like PersistRegister, RETIRED tombstones
// accept no updates; ErrNotFound means nothing matched.
func (s *DocumentRepository) PersistHeartbeat(ctx context.Context, machineID string, u HeartbeatUpdate) error {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	set := Document{"lastSeen": bsonNumber(u.LastSeen)}
	if u.BotmuxVersion != nil && *u.BotmuxVersion != "" {
		set["botmuxVersion"] = *u.BotmuxVersion
	}
	if u.Memberships != nil {
		set["memberships"] = *u.Memberships
	}
	if u.Bots != nil {
		set["bots"] = *u.Bots
	}
	r, err := c.UpdateOne(ctx, Document{"_id": machineID, "status": notRetired()}, Document{"$set": set}, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMachinesForUser lists the owner's machines (online or not, excluding
// RETIRED tombstones).
func (s *DocumentRepository) ListMachinesForUser(ctx context.Context, unionID string) ([]MachineDoc, error) {
	return s.findMachines(ctx, Document{"unionId": unionID, "status": notRetired()})
}

// ListMachinesForTeam lists machines whose daemon-reported memberships include
// teamID (excluding tombstones). Those memberships are forgeable legacy data;
// authorization must use ListMachinesForUsers over teams.members instead.
func (s *DocumentRepository) ListMachinesForTeam(ctx context.Context, teamID string) ([]MachineDoc, error) {
	return s.findMachines(ctx, Document{"memberships.teamId": teamID, "status": notRetired()})
}
func (s *DocumentRepository) findMachines(ctx context.Context, filter Document) ([]MachineDoc, error) {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return nil, err
	}
	out := []MachineDoc{}
	if err := c.FindMany(ctx, filter, &out); err != nil {
		return nil, normalizeDBError(err)
	}
	return out, nil
}

// GetMachine reads one machine document straight from the authority (no
// cache). RETIRED tombstones are returned as-is; callers decide.
func (s *DocumentRepository) GetMachine(ctx context.Context, id string) (MachineDoc, error) {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return MachineDoc{}, err
	}
	var out MachineDoc
	if err := c.FindOne(ctx, Document{"_id": id}, &out); err != nil {
		return MachineDoc{}, normalizeDBError(err)
	}
	return out, nil
}
func (s *DocumentRepository) RenameMachine(ctx context.Context, id, name string) error {
	name = truncateRunes(name, 64)
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": id}, Document{"$set": Document{"displayName": name}}, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *DocumentRepository) RemoveMachineFromTeamBots(ctx context.Context, machineID string) error {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return err
	}
	_, err = c.UpdateMany(ctx, Document{"bots.machineId": machineID}, Document{"$pull": Document{"bots": Document{"machineId": machineID}}})
	return normalizeDBError(err)
}

func (s *DocumentRepository) CreateTeam(ctx context.Context, t TeamDoc) error {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return err
	}
	// The legacy Node driver stores Date.now() values as BSON doubles. Keep the
	// existing physical schema stable during mixed-version rollout instead of
	// silently changing timestamps to BSON int64.
	// Optional arrays are omitted rather than written as BSON null: a null
	// field would make later $addToSet/$push updates fail.
	members := t.Members
	if members == nil {
		members = []string{}
	}
	document := Document{
		"_id": t.ID, "name": t.Name, "members": members,
		"createdBy": t.CreatedBy, "createdAt": bsonNumber(t.CreatedAt),
	}
	if len(t.Bots) > 0 {
		document["bots"] = t.Bots
	}
	if len(t.GroupChatIDs) > 0 {
		document["groupChatIds"] = t.GroupChatIDs
	}
	if len(t.PendingInvites) > 0 {
		document["pendingInvites"] = pendingInviteDocuments(t.PendingInvites)
	}
	if len(t.Admins) > 0 {
		document["admins"] = t.Admins
	}
	if t.HallChatID != "" {
		document["hallChatId"] = t.HallChatID
	}
	return normalizeDBError(c.InsertOne(ctx, document))
}
func (s *DocumentRepository) AddTeamMember(ctx context.Context, teamID, unionID string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$addToSet": Document{"members": unionID}})
}

// RemoveTeamMember removes unionID from members and from admins (someone who
// left the team must not keep admin rights).
func (s *DocumentRepository) RemoveTeamMember(ctx context.Context, teamID, unionID string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"members": unionID, "admins": unionID}})
}
func (s *DocumentRepository) UpdateTeamBots(ctx context.Context, teamID string, add, remove []TeamBotRef) error {
	if _, err := s.GetTeam(ctx, teamID); err != nil {
		return err
	}
	if len(add) > 0 {
		clean := make([]TeamBotRef, len(add))
		for i, b := range add {
			clean[i] = TeamBotRef{MachineID: b.MachineID, AppID: b.AppID}
		}
		if err := s.updateTeamRequired(ctx, teamID, Document{"$addToSet": Document{"bots": Document{"$each": clean}}}); err != nil {
			return err
		}
	}
	for _, b := range remove {
		if err := s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"bots": Document{"machineId": b.MachineID, "appId": b.AppID}}}); err != nil {
			return err
		}
	}
	return nil
}
func (s *DocumentRepository) AddTeamGroupChat(ctx context.Context, teamID, chatID string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$addToSet": Document{"groupChatIds": chatID}})
}
func (s *DocumentRepository) CompareAndSetTeamHallChat(ctx context.Context, teamID, expected, replacement string) (bool, error) {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return false, err
	}
	// A nil value intentionally matches both a missing field and BSON null.
	var expectedValue any = expected
	if expected == "" {
		expectedValue = nil
	}
	r, err := c.UpdateOne(ctx, Document{"_id": teamID, "hallChatId": expectedValue}, Document{"$set": Document{"hallChatId": replacement}}, false)
	if err != nil {
		return false, normalizeDBError(err)
	}
	return r.Matched > 0, nil
}
func (s *DocumentRepository) GetTeams(ctx context.Context, ids []string) (map[string]TeamDoc, error) {
	out := make(map[string]TeamDoc, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return nil, err
	}
	docs := []TeamDoc{}
	if err := c.FindMany(ctx, Document{"_id": Document{"$in": ids}}, &docs); err != nil {
		return nil, normalizeDBError(err)
	}
	for _, d := range docs {
		out[d.ID] = d
	}
	return out, nil
}
func (s *DocumentRepository) ListTeamsForUser(ctx context.Context, unionID string) ([]TeamDoc, error) {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return nil, err
	}
	out := []TeamDoc{}
	if err := c.FindMany(ctx, Document{"members": unionID}, &out); err != nil {
		return nil, normalizeDBError(err)
	}
	return out, nil
}
func (s *DocumentRepository) GetTeam(ctx context.Context, id string) (TeamDoc, error) {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return TeamDoc{}, err
	}
	var out TeamDoc
	if err := c.FindOne(ctx, Document{"_id": id}, &out); err != nil {
		return TeamDoc{}, normalizeDBError(err)
	}
	return out, nil
}
func (s *DocumentRepository) AddPendingInvite(ctx context.Context, teamID string, in PendingInvite) error {
	if err := s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"pendingInvites": Document{"unionId": in.UnionID}}}); err != nil {
		return err
	}
	return s.updateTeamRequired(ctx, teamID, Document{"$push": Document{"pendingInvites": pendingInviteDocument(in)}})
}
func (s *DocumentRepository) RemovePendingInvite(ctx context.Context, teamID, unionID string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"pendingInvites": Document{"unionId": unionID}}})
}
func (s *DocumentRepository) PrunePendingInvites(ctx context.Context, teamID string, cutoffMS int64, members []string) error {
	if err := s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"pendingInvites": Document{"invitedAt": Document{"$lt": bsonNumber(cutoffMS)}}}}); err != nil {
		return err
	}
	if len(members) > 0 {
		return s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"pendingInvites": Document{"unionId": Document{"$in": members}}}})
	}
	return nil
}

func bsonNumber(value int64) float64 { return float64(value) }

// notRetired is the {$ne: 'RETIRED'} condition; it also matches legacy
// documents without a status field.
func notRetired() Document { return Document{"$ne": MachineStatusRetired} }

func pendingInviteDocument(invite PendingInvite) Document {
	document := Document{
		"unionId": invite.UnionID, "name": invite.Name, "invitedBy": invite.InvitedBy,
		"invitedAt": bsonNumber(invite.InvitedAt),
	}
	if invite.OpenID != "" {
		document["openId"] = invite.OpenID
	}
	return document
}

func pendingInviteDocuments(invites []PendingInvite) []Document {
	out := make([]Document, 0, len(invites))
	for _, invite := range invites {
		out = append(out, pendingInviteDocument(invite))
	}
	return out
}
func (s *DocumentRepository) RenameTeam(ctx context.Context, teamID, name string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$set": Document{"name": name}})
}
func (s *DocumentRepository) DeleteTeam(ctx context.Context, teamID string) error {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return err
	}
	r, err := c.DeleteOne(ctx, Document{"_id": teamID})
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Deleted == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *DocumentRepository) RemoveUserBotsFromTeam(ctx context.Context, teamID string, machineIDs []string) error {
	if len(machineIDs) == 0 {
		return nil
	}
	return s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"bots": Document{"machineId": Document{"$in": machineIDs}}}})
}
func (s *DocumentRepository) updateTeamRequired(ctx context.Context, teamID string, update Document) error {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": teamID}, update, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	return nil
}

func normalizeDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

var (
	_ Repository               = (*DocumentRepository)(nil)
	_ DeviceRepository         = (*DocumentRepository)(nil)
	_ DesktopSessionRepository = (*DocumentRepository)(nil)
)
