package store

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type recordingDB struct{ collection *recordingCollection }

func (d *recordingDB) Collection(string) DocumentCollection { return d.collection }

type recordedUpdate struct {
	filter, update Document
	upsert         bool
}
type recordingCollection struct {
	indexes      []Document
	indexSpecs   []IndexSpec
	inserts      []any
	updates      []recordedUpdate
	updateResult UpdateResult
	deleteResult DeleteResult
}

func (c *recordingCollection) CreateIndex(_ context.Context, d Document) error {
	c.indexes = append(c.indexes, d)
	return nil
}
func (c *recordingCollection) InsertOne(_ context.Context, value any) error {
	c.inserts = append(c.inserts, value)
	return nil
}
func (*recordingCollection) FindOne(context.Context, Document, any) error  { return ErrNotFound }
func (*recordingCollection) FindMany(context.Context, Document, any) error { return nil }
func (c *recordingCollection) UpdateOne(_ context.Context, f, u Document, upsert bool) (UpdateResult, error) {
	c.updates = append(c.updates, recordedUpdate{f, u, upsert})
	return c.updateResult, nil
}
func (*recordingCollection) UpdateMany(context.Context, Document, Document) (UpdateResult, error) {
	return UpdateResult{}, nil
}
func (c *recordingCollection) CreateIndexSpec(_ context.Context, spec IndexSpec) error {
	c.indexSpecs = append(c.indexSpecs, spec)
	return nil
}
func (*recordingCollection) FindManyOptions(context.Context, Document, FindOptions, any) error {
	return nil
}
func (*recordingCollection) FindOneAndUpdate(context.Context, Document, Document, FindOneAndUpdateOptions, any) error {
	return ErrNotFound
}
func (*recordingCollection) DeleteMany(context.Context, Document) (DeleteResult, error) {
	return DeleteResult{}, nil
}
func (c *recordingCollection) DeleteOne(context.Context, Document) (DeleteResult, error) {
	return c.deleteResult, nil
}

func TestDocumentIndexesAndHallCASShape(t *testing.T) {
	t.Parallel()
	c := &recordingCollection{updateResult: UpdateResult{Matched: 1}}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: &recordingDB{collection: c}})
	if err := s.EnsureIndexes(context.Background()); err != nil {
		t.Fatal(err)
	}
	// machines: unionId, memberships.teamId, coManagers.unionId; devices: unionId.
	if len(c.indexes) != 4 || c.indexes[0]["unionId"] != 1 || c.indexes[1]["memberships.teamId"] != 1 ||
		c.indexes[2]["coManagers.unionId"] != 1 || c.indexes[3]["unionId"] != 1 {
		t.Fatalf("indexes=%#v", c.indexes)
	}
	// device_grants, desktop_session_revocations, desktop_auth_code_uses,
	// proxy_ticket_uses: TTL on expireAt with expireAfterSeconds 0.
	if len(c.indexSpecs) != 4 {
		t.Fatalf("index specs=%#v", c.indexSpecs)
	}
	for _, spec := range c.indexSpecs {
		if len(spec.Keys) != 1 || spec.Keys[0] != (IndexKey{Field: "expireAt", Order: 1}) || spec.ExpireAfterSeconds == nil || *spec.ExpireAfterSeconds != 0 || spec.Unique {
			t.Fatalf("TTL spec=%#v", spec)
		}
	}
	ok, err := s.CompareAndSetTeamHallChat(context.Background(), "team", "", "chat")
	if err != nil || !ok {
		t.Fatalf("CAS=%v %v", ok, err)
	}
	u := c.updates[len(c.updates)-1]
	if value, exists := u.filter["hallChatId"]; !exists || value != nil {
		t.Fatalf("missing/null contract lost: %#v", u.filter)
	}
}

func TestDocumentRegisterDoesNotPersistConnectionSecrets(t *testing.T) {
	t.Parallel()
	c := &recordingCollection{updateResult: UpdateResult{Matched: 1}}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: &recordingDB{collection: c}})
	err := s.PersistRegister(context.Background(), RegisterMachine{MachineID: "m", UnionID: "u", DashboardPort: 7891, LastSeen: 1})
	if err != nil {
		t.Fatal(err)
	}
	set := c.updates[0].update["$set"].(Document)
	if _, ok := set["dashboardToken"]; ok {
		t.Fatal("dashboard token must stay in memory")
	}
	if _, ok := set["directHosts"]; ok {
		t.Fatal("direct hosts must stay in memory")
	}
	if _, ok := set["lastSeen"].(float64); !ok {
		t.Fatalf("lastSeen BSON type = %T, want legacy double", set["lastSeen"])
	}
	// Register never creates documents and never rewrites ownership/status.
	u := c.updates[0]
	if u.upsert || u.filter["_id"] != "m" || u.filter["unionId"] != "u" {
		t.Fatalf("register filter=%#v upsert=%v", u.filter, u.upsert)
	}
	if status, _ := u.filter["status"].(Document); status["$ne"] != MachineStatusRetired {
		t.Fatalf("register must exclude tombstones: %#v", u.filter)
	}
	for _, field := range []string{"unionId", "ownerName", "status", "boundAt"} {
		if _, ok := set[field]; ok {
			t.Fatalf("register must not write %s: %#v", field, set)
		}
	}
	if _, ok := u.update["$setOnInsert"]; ok {
		t.Fatalf("register must not upsert: %#v", u.update)
	}
}

func TestDocumentTimestampWritesPreserveLegacyBSONDoubleShape(t *testing.T) {
	t.Parallel()
	c := &recordingCollection{updateResult: UpdateResult{Matched: 1}}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: &recordingDB{collection: c}})
	ctx := context.Background()

	s.now = func() time.Time { return time.UnixMilli(1_700_000_000_123) }

	if result, err := s.BindMachineCAS(ctx, "m", "u", "owner"); err != nil || result != BindCreated {
		t.Fatalf("bind = %v %v", result, err)
	}
	machine, ok := c.inserts[0].(machineInsertDocument)
	if !ok || machine.BoundAt != 1_700_000_000_123 || machine.Status != MachineStatusActive {
		t.Fatalf("machine insert = %#v", c.inserts[0])
	}
	c.inserts = nil

	team := TeamDoc{ID: "team", Name: "Team", Members: []string{"u"}, CreatedBy: "u", CreatedAt: 1_700_000_000_456,
		PendingInvites: []PendingInvite{{UnionID: "invitee", InvitedAt: 1_700_000_000_789}}}
	if err := s.CreateTeam(ctx, team); err != nil {
		t.Fatal(err)
	}
	document, ok := c.inserts[0].(Document)
	if !ok {
		t.Fatalf("team insert type = %T", c.inserts[0])
	}
	if _, ok := document["createdAt"].(float64); !ok {
		t.Fatalf("createdAt BSON type = %T, want double", document["createdAt"])
	}
	pending := document["pendingInvites"].([]Document)
	if _, ok := pending[0]["invitedAt"].(float64); !ok {
		t.Fatalf("invitedAt BSON type = %T, want double", pending[0]["invitedAt"])
	}
}

func TestDocumentRequiredMachineMutationsReportNotFound(t *testing.T) {
	t.Parallel()
	c := &recordingCollection{}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: &recordingDB{collection: c}})
	if err := s.PersistHeartbeat(context.Background(), "missing", HeartbeatUpdate{LastSeen: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("heartbeat error = %v", err)
	}
	if err := s.PersistRegister(context.Background(), RegisterMachine{MachineID: "missing", UnionID: "u"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("register error = %v", err)
	}
	// Retire succeeds even when nothing matched (idempotent unbind).
	if err := s.RetireMachine(context.Background(), "missing"); err != nil {
		t.Fatalf("retire error = %v", err)
	}
}

type closeRecorder struct{ closed bool }

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestRetryingDatabaseProviderBacksOffAndCloses(t *testing.T) {
	t.Parallel()
	wantDB := &recordingDB{collection: &recordingCollection{}}
	closer := &closeRecorder{}
	calls := 0
	p := &RetryingDatabaseProvider{
		RetryDelay: time.Hour,
		Dial: func(context.Context) (DocumentDatabase, io.Closer, error) {
			calls++
			if calls == 1 {
				return nil, nil, errors.New("temporary outage")
			}
			return wantDB, closer, nil
		},
	}
	if _, err := p.Database(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first dial error = %v", err)
	}
	if _, err := p.Database(context.Background()); !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatalf("backoff error/calls = %v/%d", err, calls)
	}
	p.retryAfter = time.Time{}
	got, err := p.Database(context.Background())
	if err != nil || got != wantDB || calls != 2 {
		t.Fatalf("retry = (%v, %v), calls=%d", got, err, calls)
	}
	if err := p.Close(); err != nil || !closer.closed {
		t.Fatalf("close = %v, closed=%v", err, closer.closed)
	}
	if _, err := p.Database(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("database after close = %v", err)
	}
}
