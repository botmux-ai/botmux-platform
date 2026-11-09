package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/credential"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// CredentialStore is the credential vault repository (src/store/credentials.ts).
// Three collections, all fail-closed like IssueStore:
//   - credentials: one per person per platform, _id = unionId::platform. Only
//     the envelope-encrypted refresh credential plus non-secret metadata; the
//     KEK never lives here. version is a CAS counter so two pods refreshing at
//     once cannot overwrite each other's freshly rotated refresh token.
//   - credential_grants: one audit row per issuance, TTL 90 days.
//   - credential_pending: device-login snapshots so begin and complete may
//     land on different pods, TTL 1 hour.
type CredentialStore struct {
	provider DatabaseProvider
	now      func() time.Time
}

func NewCredentialStore(provider DatabaseProvider) *CredentialStore {
	return NewCredentialStoreWithClock(provider, time.Now)
}

func NewCredentialStoreWithClock(provider DatabaseProvider, now func() time.Time) *CredentialStore {
	if now == nil {
		now = time.Now
	}
	return &CredentialStore{provider: provider, now: now}
}

type CredentialPlatform string

// CredentialPlatformLarkCLI is the built-in platform; the others are the
// device logins an edition links in (credential.DeviceLogin).
const CredentialPlatformLarkCLI CredentialPlatform = "lark-cli"

var credentialPlatformSyntax = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// IsCredentialPlatform reports whether value can name a platform. Which
// platforms are served is the HTTP layer's call.
func IsCredentialPlatform(value string) bool {
	return credentialPlatformSyntax.MatchString(value)
}

type CredentialKind string

const CredentialKindLarkOAuth CredentialKind = "lark-oauth"

type CredentialStatus string

const (
	CredentialActive         CredentialStatus = "active"
	CredentialReauthRequired CredentialStatus = "reauth_required"
)

type CredentialGrantOutcome string

const (
	CredentialGranted CredentialGrantOutcome = "granted"
	CredentialRefused CredentialGrantOutcome = "refused"
)

const (
	credentialsCollection       = "credentials"
	credentialGrantsCollection  = "credential_grants"
	credentialPendingCollection = "credential_pending"

	credentialGrantTTLMS   int64 = 90 * 24 * 3600 * 1000
	credentialPendingTTLMS int64 = 60 * 60 * 1000

	defaultCredentialGrantLimit = 50
)

// CredentialID is credentialId(unionId, platform).
func CredentialID(unionID string, platform CredentialPlatform) string {
	return unionID + "::" + string(platform)
}

// ConsentTeams is the TS union 'all' | string[]: All means every team the
// person belongs to, including teams joined later; otherwise only machines of
// Teams may receive the credential.
type ConsentTeams struct {
	All   bool
	Teams []string
}

func ConsentAll() ConsentTeams { return ConsentTeams{All: true} }

func ConsentToTeams(teams []string) ConsentTeams {
	return ConsentTeams{Teams: append([]string{}, teams...)}
}

func (c ConsentTeams) bsonValue() any {
	if c.All {
		return "all"
	}
	if c.Teams == nil {
		return []string{}
	}
	return c.Teams
}

func (c ConsentTeams) MarshalBSONValue() (bsontype.Type, []byte, error) {
	return bson.MarshalValue(c.bsonValue())
}

func (c *ConsentTeams) UnmarshalBSONValue(t bsontype.Type, data []byte) error {
	raw := bson.RawValue{Type: t, Value: data}
	switch t {
	case bsontype.String:
		if raw.StringValue() != "all" {
			return fmt.Errorf("store: consentTeams string must be \"all\"")
		}
		*c = ConsentAll()
		return nil
	case bsontype.Array:
		var teams []string
		if err := raw.Unmarshal(&teams); err != nil {
			return err
		}
		*c = ConsentToTeams(teams)
		return nil
	default:
		return fmt.Errorf("store: consentTeams must be \"all\" or an array, got %s", t)
	}
}

func (c ConsentTeams) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(c.bsonValue()); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

// UnmarshalJSON accepts exactly "all" or an array of strings.
func (c *ConsentTeams) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		if text != "all" {
			return fmt.Errorf("store: consentTeams string must be \"all\"")
		}
		*c = ConsentAll()
		return nil
	}
	var teams []string
	if err := json.Unmarshal(data, &teams); err != nil || teams == nil {
		return fmt.Errorf("store: consentTeams must be \"all\" or an array of strings")
	}
	*c = ConsentToTeams(teams)
	return nil
}

// CredentialMeta is non-secret metadata: issuing app, scope, display account.
type CredentialMeta struct {
	AppID   string `json:"appId,omitempty" bson:"appId,omitempty"`
	Scope   string `json:"scope,omitempty" bson:"scope,omitempty"`
	Account string `json:"account,omitempty" bson:"account,omitempty"`
}

// CredentialDoc mirrors the credentials collection. Timestamps are Unix ms.
type CredentialDoc struct {
	ID       string             `json:"_id" bson:"_id"`
	UnionID  string             `json:"unionId" bson:"unionId"`
	Platform CredentialPlatform `json:"platform" bson:"platform"`
	Kind     CredentialKind     `json:"kind" bson:"kind"`
	Sealed   credential.Sealed  `json:"sealed" bson:"sealed"`
	// Version is the CAS counter, +1 on every sealed write.
	Version      int64            `json:"version" bson:"version,truncate"`
	Meta         CredentialMeta   `json:"meta" bson:"meta"`
	ConsentTeams ConsentTeams     `json:"consentTeams" bson:"consentTeams"`
	Status       CredentialStatus `json:"status" bson:"status"`
	StatusReason string           `json:"statusReason,omitempty" bson:"statusReason,omitempty"`
	CreatedAt    int64            `json:"createdAt" bson:"createdAt,truncate"`
	UpdatedAt    int64            `json:"updatedAt" bson:"updatedAt,truncate"`
	// RefreshExpiresAt is the refresh credential's own expiry when known, used
	// to prompt re-authorization.
	RefreshExpiresAt  int64  `json:"refreshExpiresAt,omitempty" bson:"refreshExpiresAt,omitempty,truncate"`
	LastUsedAt        int64  `json:"lastUsedAt,omitempty" bson:"lastUsedAt,omitempty,truncate"`
	LastUsedMachineID string `json:"lastUsedMachineId,omitempty" bson:"lastUsedMachineId,omitempty"`
}

// CredentialGrantDoc mirrors credential_grants in the TS insert order.
type CredentialGrantDoc struct {
	ID           string                 `json:"_id" bson:"_id"`
	UnionID      string                 `json:"unionId" bson:"unionId"`
	Platform     CredentialPlatform     `json:"platform" bson:"platform"`
	MachineID    string                 `json:"machineId" bson:"machineId"`
	MachineName  string                 `json:"machineName,omitempty" bson:"machineName,omitempty"`
	OwnerUnionID string                 `json:"ownerUnionId" bson:"ownerUnionId"`
	AppID        string                 `json:"appId" bson:"appId"`
	SessionID    string                 `json:"sessionId" bson:"sessionId"`
	TurnID       string                 `json:"turnId,omitempty" bson:"turnId,omitempty"`
	Outcome      CredentialGrantOutcome `json:"outcome" bson:"outcome"`
	Reason       string                 `json:"reason,omitempty" bson:"reason,omitempty"`
	At           int64                  `json:"at" bson:"at,truncate"`
	// ExpireAt is a BSON Date for the TTL index (physical cleanup only).
	ExpireAt time.Time `json:"expireAt" bson:"expireAt"`
}

// CredentialPendingDoc mirrors credential_pending. Sealed holds the
// provider's begin payload (its login challenge).
type CredentialPendingDoc struct {
	ID        string             `json:"_id" bson:"_id"`
	UnionID   string             `json:"unionId" bson:"unionId"`
	Platform  CredentialPlatform `json:"platform" bson:"platform"`
	Sealed    credential.Sealed  `json:"sealed" bson:"sealed"`
	AuthURL   string             `json:"authUrl" bson:"authUrl"`
	CreatedAt int64              `json:"createdAt" bson:"createdAt,truncate"`
	ExpireAt  time.Time          `json:"expireAt" bson:"expireAt"`
}

// credentialGrantRecord / credentialPendingRecord are the insert literals
// with Node's BSON numeric types.
type credentialGrantRecord struct {
	ID           string                 `bson:"_id"`
	UnionID      string                 `bson:"unionId"`
	Platform     CredentialPlatform     `bson:"platform"`
	MachineID    string                 `bson:"machineId"`
	MachineName  string                 `bson:"machineName,omitempty"`
	OwnerUnionID string                 `bson:"ownerUnionId"`
	AppID        string                 `bson:"appId"`
	SessionID    string                 `bson:"sessionId"`
	TurnID       string                 `bson:"turnId,omitempty"`
	Outcome      CredentialGrantOutcome `bson:"outcome"`
	Reason       string                 `bson:"reason,omitempty"`
	At           float64                `bson:"at"`
	ExpireAt     time.Time              `bson:"expireAt"`
}

type credentialPendingRecord struct {
	ID        string             `bson:"_id"`
	UnionID   string             `bson:"unionId"`
	Platform  CredentialPlatform `bson:"platform"`
	Sealed    credential.Sealed  `bson:"sealed"`
	AuthURL   string             `bson:"authUrl"`
	CreatedAt float64            `bson:"createdAt"`
	ExpireAt  time.Time          `bson:"expireAt"`
}

func (s *CredentialStore) nowMS() int64 { return s.now().UnixMilli() }

// PersistenceAvailable is false in memory mode (see
// UnavailableDatabaseProvider), where the TS vault has no storage at all.
func (s *CredentialStore) PersistenceAvailable() bool {
	return s != nil && s.provider != nil && !isMemoryProvider(s.provider)
}

func (s *CredentialStore) collection(ctx context.Context, name string) (DocumentCollection, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	return providerCollection(ctx, s.provider, name)
}

// EnsureIndexes creates the vault indexes from the TS ensureIndexes block:
// per-person listing, audit by person (newest first) and first-use lookup by
// machine, plus the TTL cleanup indexes.
func (s *CredentialStore) EnsureIndexes(ctx context.Context) error {
	zero := int32(0)
	specs := []struct {
		collection string
		spec       IndexSpec
	}{
		{credentialsCollection, IndexSpec{Keys: []IndexKey{{Field: "unionId", Order: 1}}}},
		{credentialGrantsCollection, IndexSpec{Keys: []IndexKey{{Field: "unionId", Order: 1}, {Field: "at", Order: -1}}}},
		{credentialGrantsCollection, IndexSpec{Keys: []IndexKey{{Field: "unionId", Order: 1}, {Field: "machineId", Order: 1}, {Field: "outcome", Order: 1}}}},
		{credentialGrantsCollection, IndexSpec{Keys: []IndexKey{{Field: "expireAt", Order: 1}}, ExpireAfterSeconds: &zero}},
		{credentialPendingCollection, IndexSpec{Keys: []IndexKey{{Field: "expireAt", Order: 1}}, ExpireAfterSeconds: &zero}},
	}
	for _, item := range specs {
		c, err := s.collection(ctx, item.collection)
		if err != nil {
			return err
		}
		if err := c.CreateIndexSpec(ctx, item.spec); err != nil {
			return failClosed(err)
		}
	}
	return nil
}

// decodeCredential applies TS isCredentialDoc to the raw document before
// decoding, so a malformed record is ErrInvalid (callers answer "re-authorize")
// rather than a decode failure that would look like an outage.
func decodeCredential(raw bson.Raw) (CredentialDoc, error) {
	if !validCredentialRaw(raw) {
		return CredentialDoc{}, ErrInvalid
	}
	var doc CredentialDoc
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return CredentialDoc{}, ErrInvalid
	}
	return doc, nil
}

func validCredentialRaw(raw bson.Raw) bool {
	isString := func(key string) bool {
		_, ok := raw.Lookup(key).StringValueOK()
		return ok
	}
	if !isString("_id") || !isString("unionId") {
		return false
	}
	if platform, ok := raw.Lookup("platform").StringValueOK(); !ok || !IsCredentialPlatform(platform) {
		return false
	}
	sealed, ok := raw.Lookup("sealed").DocumentOK()
	if !ok || !validSealedRaw(sealed) {
		return false
	}
	if !isBSONNumber(raw.Lookup("version")) {
		return false
	}
	consent := raw.Lookup("consentTeams")
	if text, ok := consent.StringValueOK(); !(ok && text == "all") && consent.Type != bsontype.Array {
		return false
	}
	status, ok := raw.Lookup("status").StringValueOK()
	return ok && (status == string(CredentialActive) || status == string(CredentialReauthRequired))
}

// validSealedRaw is TS isSealedCredential.
func validSealedRaw(raw bson.Raw) bool {
	if !bsonNumberEquals(raw.Lookup("v"), credential.Version) {
		return false
	}
	if alg, ok := raw.Lookup("alg").StringValueOK(); !ok || alg != credential.Algorithm {
		return false
	}
	for _, key := range []string{"kekId", "wrappedDek", "data"} {
		if _, ok := raw.Lookup(key).StringValueOK(); !ok {
			return false
		}
	}
	return true
}

func isBSONNumber(value bson.RawValue) bool {
	switch value.Type {
	case bsontype.Double, bsontype.Int32, bsontype.Int64:
		return true
	default:
		return false
	}
}

func bsonNumberEquals(value bson.RawValue, want float64) bool {
	switch value.Type {
	case bsontype.Double:
		return value.Double() == want
	case bsontype.Int32:
		return float64(value.Int32()) == want
	case bsontype.Int64:
		return float64(value.Int64()) == want
	default:
		return false
	}
}

// ---- credentials ----

// Get returns ErrNotFound when absent and ErrInvalid when the stored record
// fails shape validation.
func (s *CredentialStore) Get(ctx context.Context, unionID string, platform CredentialPlatform) (CredentialDoc, error) {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return CredentialDoc{}, err
	}
	var raw bson.Raw
	if err := c.FindOne(ctx, Document{"_id": CredentialID(unionID, platform)}, &raw); err != nil {
		if errors.Is(err, ErrNotFound) {
			return CredentialDoc{}, ErrNotFound
		}
		return CredentialDoc{}, failClosed(err)
	}
	return decodeCredential(raw)
}

// ListForUser returns the person's well-formed credentials; malformed records
// are skipped as in TS.
func (s *CredentialStore) ListForUser(ctx context.Context, unionID string) ([]CredentialDoc, error) {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return nil, err
	}
	var raws []bson.Raw
	if err := c.FindMany(ctx, Document{"unionId": unionID}, &raws); err != nil {
		return nil, failClosed(err)
	}
	out := make([]CredentialDoc, 0, len(raws))
	for _, raw := range raws {
		if doc, err := decodeCredential(raw); err == nil {
			out = append(out, doc)
		}
	}
	return out, nil
}

// UpsertCredentialInput mirrors upsertCredential's input. RefreshExpiresAt 0
// means unknown. DefaultConsent applies only when the record is created (nil
// = all teams).
type UpsertCredentialInput struct {
	UnionID          string
	Platform         CredentialPlatform
	Kind             CredentialKind
	Sealed           credential.Sealed
	Meta             CredentialMeta
	RefreshExpiresAt int64
	DefaultConsent   *ConsentTeams
}

// Upsert stores a fresh authorization: an existing record has its sealed
// credential replaced (version+1, reauth flag cleared) while consentTeams and
// createdAt are preserved. A new authorization invalidates the old refresh
// credential anyway, so this is deliberately not a CAS.
func (s *CredentialStore) Upsert(ctx context.Context, in UpsertCredentialInput) (CredentialDoc, error) {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return CredentialDoc{}, err
	}
	now := float64(s.nowMS())
	id := CredentialID(in.UnionID, in.Platform)
	set := Document{
		"unionId": in.UnionID, "platform": in.Platform, "kind": in.Kind,
		"sealed": in.Sealed, "meta": in.Meta, "status": CredentialActive, "updatedAt": now,
	}
	if in.RefreshExpiresAt != 0 {
		set["refreshExpiresAt"] = float64(in.RefreshExpiresAt)
	}
	consent := ConsentAll()
	if in.DefaultConsent != nil {
		consent = *in.DefaultConsent
	}
	update := Document{
		"$set":         set,
		"$unset":       Document{"statusReason": ""},
		"$inc":         Document{"version": int32(1)},
		"$setOnInsert": Document{"createdAt": now, "consentTeams": consent},
	}
	var raw bson.Raw
	err = c.FindOneAndUpdate(ctx, Document{"_id": id}, update, FindOneAndUpdateOptions{Upsert: true, ReturnAfter: true}, &raw)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return CredentialDoc{}, failClosed(err)
	}
	if err == nil {
		if doc, err := decodeCredential(raw); err == nil {
			return doc, nil
		}
	}
	// Older drivers may not return the upserted document: read it once more.
	raw = nil
	if err := c.FindOne(ctx, Document{"_id": id}, &raw); err == nil {
		if doc, err := decodeCredential(raw); err == nil {
			return doc, nil
		}
	} else if !errors.Is(err, ErrNotFound) {
		return CredentialDoc{}, failClosed(err)
	}
	return CredentialDoc{}, ErrUnavailable
}

// CredentialSealedPatch is updateCredentialSealed's patch: RefreshExpiresAt 0
// and a nil Meta leave the stored values alone.
type CredentialSealedPatch struct {
	RefreshExpiresAt int64
	Meta             *CredentialMeta
}

// UpdateSealed writes a refreshed credential only while the record is still
// at expectedVersion. ErrConflict means another pod refreshed first: the
// caller must drop its own new token (already invalidated by that refresh)
// and re-read.
func (s *CredentialStore) UpdateSealed(ctx context.Context, id string, expectedVersion int64, sealed credential.Sealed, patch CredentialSealedPatch) error {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return err
	}
	set := Document{"sealed": sealed, "updatedAt": float64(s.nowMS()), "status": CredentialActive}
	if patch.RefreshExpiresAt != 0 {
		set["refreshExpiresAt"] = float64(patch.RefreshExpiresAt)
	}
	if patch.Meta != nil {
		set["meta"] = *patch.Meta
	}
	update := Document{"$set": set, "$unset": Document{"statusReason": ""}, "$inc": Document{"version": int32(1)}}
	r, err := c.UpdateOne(ctx, Document{"_id": id, "version": expectedVersion}, update, false)
	if err != nil {
		return failClosed(err)
	}
	if r.Matched == 0 {
		return ErrConflict
	}
	return nil
}

// SetConsent replaces the consent scope; ErrNotFound when the person has no
// credential for platform.
func (s *CredentialStore) SetConsent(ctx context.Context, unionID string, platform CredentialPlatform, consent ConsentTeams) error {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx,
		Document{"_id": CredentialID(unionID, platform), "unionId": unionID},
		Document{"$set": Document{"consentTeams": consent, "updatedAt": float64(s.nowMS())}}, false)
	if err != nil {
		return failClosed(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkReauthRequired flags a credential whose refresh was rejected. With a
// non-nil expectedVersion it only applies while the version is unchanged, so a
// stale failure cannot void another pod's fresh refresh. Best-effort: a missed
// mark only costs one more refresh attempt.
func (s *CredentialStore) MarkReauthRequired(ctx context.Context, id, reason string, expectedVersion *int64) {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return
	}
	filter := Document{"_id": id}
	if expectedVersion != nil {
		filter["version"] = *expectedVersion
	}
	update := Document{"$set": Document{"status": CredentialReauthRequired, "statusReason": reason, "updatedAt": float64(s.nowMS())}}
	if _, err := c.UpdateOne(ctx, filter, update, false); err != nil {
		slog.Warn("credentials mark reauth failed", "id", id, "error", err)
	}
}

// TouchUse records the latest use (best-effort; credential_grants is the
// audit of record).
func (s *CredentialStore) TouchUse(ctx context.Context, id, machineID string) {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return
	}
	_, _ = c.UpdateOne(ctx, Document{"_id": id}, Document{"$set": Document{"lastUsedAt": float64(s.nowMS()), "lastUsedMachineId": machineID}}, false)
}

// Delete removes the person's credential; ErrNotFound when nothing matched.
func (s *CredentialStore) Delete(ctx context.Context, unionID string, platform CredentialPlatform) error {
	c, err := s.collection(ctx, credentialsCollection)
	if err != nil {
		return err
	}
	r, err := c.DeleteOne(ctx, Document{"_id": CredentialID(unionID, platform), "unionId": unionID})
	if err != nil {
		return failClosed(err)
	}
	if r.Deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- grants (audit) ----

// CredentialGrantInput is appendCredentialGrant's event; empty MachineName,
// TurnID and Reason are omitted.
type CredentialGrantInput struct {
	UnionID      string
	Platform     CredentialPlatform
	MachineID    string
	MachineName  string
	OwnerUnionID string
	AppID        string
	SessionID    string
	TurnID       string
	Outcome      CredentialGrantOutcome
	Reason       string
}

// AppendGrant writes one audit row (best-effort).
func (s *CredentialStore) AppendGrant(ctx context.Context, in CredentialGrantInput) {
	c, err := s.collection(ctx, credentialGrantsCollection)
	if err != nil {
		return
	}
	at := s.nowMS()
	record := credentialGrantRecord{
		ID: randomDocumentID("cg"), UnionID: in.UnionID, Platform: in.Platform, MachineID: in.MachineID,
		MachineName: in.MachineName, OwnerUnionID: in.OwnerUnionID, AppID: in.AppID, SessionID: in.SessionID,
		TurnID: in.TurnID, Outcome: in.Outcome, Reason: in.Reason,
		At: float64(at), ExpireAt: time.UnixMilli(at + credentialGrantTTLMS).UTC(),
	}
	if err := c.InsertOne(ctx, record); err != nil {
		slog.Warn("credential_grants append failed (best-effort)", "error", err)
	}
}

// ListGrantsForUser returns the newest grants first. limit <= 0 uses the TS
// default of 50.
func (s *CredentialStore) ListGrantsForUser(ctx context.Context, unionID string, limit int) ([]CredentialGrantDoc, error) {
	c, err := s.collection(ctx, credentialGrantsCollection)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultCredentialGrantLimit
	}
	var docs []CredentialGrantDoc
	opts := FindOptions{Sort: []IndexKey{{Field: "at", Order: -1}}, Limit: int64(limit)}
	if err := c.FindManyOptions(ctx, Document{"unionId": unionID}, opts, &docs); err != nil {
		return nil, failClosed(err)
	}
	if docs == nil {
		docs = []CredentialGrantDoc{}
	}
	return docs, nil
}

// HasGrantedOnMachine reports whether the person's credential was ever
// granted on machineID (drives the first-use notification).
func (s *CredentialStore) HasGrantedOnMachine(ctx context.Context, unionID, machineID string) (bool, error) {
	c, err := s.collection(ctx, credentialGrantsCollection)
	if err != nil {
		return false, err
	}
	var raw bson.Raw
	err = c.FindOne(ctx, Document{"unionId": unionID, "machineId": machineID, "outcome": CredentialGranted}, &raw)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, failClosed(err)
	}
	return true, nil
}

// ---- pending device logins ----

// PutPending stores a device-login snapshot. One person keeps at most one
// pending login, whatever its platform: older ones are removed first so the
// page never shows several competing links.
func (s *CredentialStore) PutPending(ctx context.Context, unionID string, platform CredentialPlatform, sealed credential.Sealed, authURL string) (CredentialPendingDoc, error) {
	c, err := s.collection(ctx, credentialPendingCollection)
	if err != nil {
		return CredentialPendingDoc{}, err
	}
	now := s.nowMS()
	record := credentialPendingRecord{
		ID: randomDocumentID("cp"), UnionID: unionID, Platform: platform,
		Sealed: sealed, AuthURL: authURL, CreatedAt: float64(now),
		ExpireAt: time.UnixMilli(now + credentialPendingTTLMS).UTC(),
	}
	if _, err := c.DeleteMany(ctx, Document{"unionId": unionID}); err != nil {
		return CredentialPendingDoc{}, failClosed(err)
	}
	if err := c.InsertOne(ctx, record); err != nil {
		return CredentialPendingDoc{}, failClosed(err)
	}
	return CredentialPendingDoc{
		ID: record.ID, UnionID: unionID, Platform: platform, Sealed: sealed,
		AuthURL: authURL, CreatedAt: now, ExpireAt: record.ExpireAt,
	}, nil
}

// GetPending returns the person's pending login by id; ErrNotFound when
// absent, owned by someone else, or past its logical expiry (the TTL index
// is only best-effort cleanup).
func (s *CredentialStore) GetPending(ctx context.Context, unionID, id string) (CredentialPendingDoc, error) {
	return s.findPending(ctx, Document{"_id": id, "unionId": unionID})
}

// GetPendingForUser returns the person's in-flight device login so a page
// reload can keep polling; ErrNotFound when none is live.
func (s *CredentialStore) GetPendingForUser(ctx context.Context, unionID string) (CredentialPendingDoc, error) {
	return s.findPending(ctx, Document{"unionId": unionID})
}

func (s *CredentialStore) findPending(ctx context.Context, filter Document) (CredentialPendingDoc, error) {
	c, err := s.collection(ctx, credentialPendingCollection)
	if err != nil {
		return CredentialPendingDoc{}, err
	}
	var doc CredentialPendingDoc
	if err := c.FindOne(ctx, filter, &doc); err != nil {
		if errors.Is(err, ErrNotFound) {
			return CredentialPendingDoc{}, ErrNotFound
		}
		return CredentialPendingDoc{}, failClosed(err)
	}
	if doc.CreatedAt+credentialPendingTTLMS < s.nowMS() {
		return CredentialPendingDoc{}, ErrNotFound
	}
	return doc, nil
}

// DeletePending removes a pending login (best-effort).
func (s *CredentialStore) DeletePending(ctx context.Context, id string) {
	c, err := s.collection(ctx, credentialPendingCollection)
	if err != nil {
		return
	}
	_, _ = c.DeleteOne(ctx, Document{"_id": id})
}
