package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/credential"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// testDevicePlatform stands for a device-login platform an edition links in.
const (
	testDevicePlatform CredentialPlatform = "device-cli"
	testDeviceKind     CredentialKind     = "device-archive"
)

// Ports test/store-credentials.test.ts onto MemoryDatabase (the Go
// counterpart of test/fake-credentials-db.ts).

type credentialFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *MemoryDatabase
	store *CredentialStore
	now   time.Time
	kek   []byte
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	f := &credentialFixture{t: t, ctx: context.Background(), db: NewMemoryDatabase(), now: time.UnixMilli(1_760_000_000_000), kek: kek}
	f.store = NewCredentialStoreWithClock(StaticDatabaseProvider{DB: f.db}, func() time.Time { return f.now })
	if err := f.store.EnsureIndexes(f.ctx); err != nil {
		t.Fatalf("ensure indexes: %v", err)
	}
	return f
}

func (f *credentialFixture) sealed(unionID string, platform CredentialPlatform, text string) credential.Sealed {
	f.t.Helper()
	sealed, err := credential.Seal(f.kek, []byte(text), credential.AAD(unionID, string(platform)))
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

func (f *credentialFixture) upsert(unionID string, platform CredentialPlatform, text string, consent *ConsentTeams) CredentialDoc {
	f.t.Helper()
	kind := CredentialKindLarkOAuth
	if platform == testDevicePlatform {
		kind = testDeviceKind
	}
	doc, err := f.store.Upsert(f.ctx, UpsertCredentialInput{UnionID: unionID, Platform: platform, Kind: kind, Sealed: f.sealed(unionID, platform, text), DefaultConsent: consent})
	if err != nil {
		f.t.Fatalf("upsert: %v", err)
	}
	return doc
}

func (f *credentialFixture) raw(collection, id string) map[string]any {
	f.t.Helper()
	for _, doc := range f.db.MemoryCollection(collection).Documents() {
		if doc["_id"] == id {
			return doc
		}
	}
	f.t.Fatalf("%s/%s not found", collection, id)
	return nil
}

func TestCredentialStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]*CredentialStore{
		"nil store":        nil,
		"empty provider":   NewCredentialStore(StaticDatabaseProvider{}),
		"failing provider": NewCredentialStore(failingDatabaseProvider{}),
		"memory mode":      NewCredentialStore(UnavailableDatabaseProvider{}),
	} {
		t.Run(name, func(t *testing.T) {
			ops := map[string]error{}
			_, ops["get"] = s.Get(ctx, "on_a", CredentialPlatformLarkCLI)
			_, ops["list"] = s.ListForUser(ctx, "on_a")
			_, ops["upsert"] = s.Upsert(ctx, UpsertCredentialInput{UnionID: "on_a", Platform: CredentialPlatformLarkCLI})
			ops["update"] = s.UpdateSealed(ctx, "on_a::lark-cli", 1, credential.Sealed{}, CredentialSealedPatch{})
			ops["consent"] = s.SetConsent(ctx, "on_a", CredentialPlatformLarkCLI, ConsentAll())
			ops["delete"] = s.Delete(ctx, "on_a", CredentialPlatformLarkCLI)
			_, ops["grants"] = s.ListGrantsForUser(ctx, "on_a", 10)
			_, ops["granted"] = s.HasGrantedOnMachine(ctx, "on_a", "m1")
			_, ops["put pending"] = s.PutPending(ctx, "on_a", testDevicePlatform, credential.Sealed{}, "https://sso")
			_, ops["get pending"] = s.GetPending(ctx, "on_a", "cp_1")
			_, ops["pending for user"] = s.GetPendingForUser(ctx, "on_a")
			ops["indexes"] = s.EnsureIndexes(ctx)
			for op, err := range ops {
				if StoreReason(err) != "unavailable" {
					t.Errorf("%s: err = %v, want unavailable", op, err)
				}
			}
			// Best-effort writes must not panic without a database.
			s.MarkReauthRequired(ctx, "on_a::lark-cli", "x", nil)
			s.TouchUse(ctx, "on_a::lark-cli", "m1")
			s.AppendGrant(ctx, CredentialGrantInput{UnionID: "on_a"})
			s.DeletePending(ctx, "cp_1")
		})
	}
}

func TestCredentialUpsertPreservesConsentAndCreatedAt(t *testing.T) {
	f := newCredentialFixture(t)
	t1 := ConsentToTeams([]string{"t1"})
	a, err := f.store.Upsert(f.ctx, UpsertCredentialInput{
		UnionID: "on_a", Platform: CredentialPlatformLarkCLI, Kind: CredentialKindLarkOAuth,
		Sealed: f.sealed("on_a", CredentialPlatformLarkCLI, "v1"), Meta: CredentialMeta{Account: "A"}, DefaultConsent: &t1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != 1 || a.Status != CredentialActive || a.ConsentTeams.All || strings.Join(a.ConsentTeams.Teams, ",") != "t1" {
		t.Fatalf("created credential: %+v", a)
	}
	got, err := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI)
	if err != nil || got.ID != "on_a::lark-cli" || got.Meta.Account != "A" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	f.store.MarkReauthRequired(f.ctx, "on_a::lark-cli", "expired", nil)
	marked, _ := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI)
	if marked.Status != CredentialReauthRequired || marked.StatusReason != "expired" {
		t.Fatalf("marked credential: %+v", marked)
	}

	f.now = f.now.Add(time.Hour)
	all := ConsentAll()
	b, err := f.store.Upsert(f.ctx, UpsertCredentialInput{
		UnionID: "on_a", Platform: CredentialPlatformLarkCLI, Kind: CredentialKindLarkOAuth,
		Sealed: f.sealed("on_a", CredentialPlatformLarkCLI, "v2"), Meta: CredentialMeta{Account: "A2"}, DefaultConsent: &all,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 2 || b.ConsentTeams.All || strings.Join(b.ConsentTeams.Teams, ",") != "t1" {
		t.Fatalf("re-authorization must keep consent: %+v", b)
	}
	if b.CreatedAt != a.CreatedAt || b.UpdatedAt != f.now.UnixMilli() {
		t.Fatalf("timestamps: created %d->%d updated %d", a.CreatedAt, b.CreatedAt, b.UpdatedAt)
	}
	if b.Status != CredentialActive || b.StatusReason != "" {
		t.Fatalf("re-authorization must clear the reauth flag: %+v", b)
	}
	if _, ok := f.raw(credentialsCollection, b.ID)["statusReason"]; ok {
		t.Fatal("statusReason must be unset")
	}
	plain, ok := credential.Open([][]byte{f.kek}, b.Sealed, credential.AAD(b.UnionID, string(b.Platform)))
	if !ok || string(plain) != "v2" {
		t.Fatalf("stored envelope must open: %q, %v", plain, ok)
	}
}

func TestCredentialDefaultConsentIsAll(t *testing.T) {
	f := newCredentialFixture(t)
	doc := f.upsert("on_a", testDevicePlatform, "x", nil)
	if !doc.ConsentTeams.All {
		t.Fatalf("default consent = %+v", doc.ConsentTeams)
	}
	if got := f.raw(credentialsCollection, doc.ID)["consentTeams"]; got != "all" {
		t.Fatalf("stored consentTeams = %#v", got)
	}
}

func TestCredentialCASWriteback(t *testing.T) {
	f := newCredentialFixture(t)
	a := f.upsert("on_a", testDevicePlatform, "v1", nil)
	if err := f.store.UpdateSealed(f.ctx, a.ID, 1, f.sealed("on_a", testDevicePlatform, "v2"), CredentialSealedPatch{RefreshExpiresAt: 123}); err != nil {
		t.Fatalf("CAS write: %v", err)
	}
	err := f.store.UpdateSealed(f.ctx, a.ID, 1, f.sealed("on_a", testDevicePlatform, "v3"), CredentialSealedPatch{})
	if !errors.Is(err, ErrConflict) || StoreReason(err) != "conflict" {
		t.Fatalf("stale CAS err = %v", err)
	}
	got, _ := f.store.Get(f.ctx, "on_a", testDevicePlatform)
	if got.Version != 2 || got.RefreshExpiresAt != 123 {
		t.Fatalf("after CAS: %+v", got)
	}
	plain, ok := credential.Open([][]byte{f.kek}, got.Sealed, credential.AAD("on_a", "device-cli"))
	if !ok || string(plain) != "v2" {
		t.Fatalf("CAS loser must not overwrite: %q", plain)
	}
	meta := CredentialMeta{AppID: "cli_x", Scope: "offline_access"}
	f.store.MarkReauthRequired(f.ctx, a.ID, "refresh rejected", nil)
	if err := f.store.UpdateSealed(f.ctx, a.ID, 2, got.Sealed, CredentialSealedPatch{Meta: &meta}); err != nil {
		t.Fatal(err)
	}
	got, _ = f.store.Get(f.ctx, "on_a", testDevicePlatform)
	if got.Meta != meta || got.Status != CredentialActive || got.StatusReason != "" || got.RefreshExpiresAt != 123 {
		t.Fatalf("refresh write-back must reactivate and keep unpatched fields: %+v", got)
	}
}

func TestCredentialMarkReauthHonoursExpectedVersion(t *testing.T) {
	f := newCredentialFixture(t)
	doc := f.upsert("on_a", CredentialPlatformLarkCLI, "v1", nil)
	stale := doc.Version - 1
	f.store.MarkReauthRequired(f.ctx, doc.ID, "old failure", &stale)
	if got, _ := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI); got.Status != CredentialActive {
		t.Fatalf("a stale failure must not void a newer refresh: %+v", got)
	}
	current := doc.Version
	f.store.MarkReauthRequired(f.ctx, doc.ID, "rejected", &current)
	if got, _ := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI); got.Status != CredentialReauthRequired || got.StatusReason != "rejected" {
		t.Fatalf("matching version must mark: %+v", got)
	}
}

func TestCredentialConsentDeleteListIsolation(t *testing.T) {
	f := newCredentialFixture(t)
	f.upsert("on_a", CredentialPlatformLarkCLI, "x", nil)
	f.upsert("on_b", CredentialPlatformLarkCLI, "y", nil)
	if err := f.store.SetConsent(f.ctx, "on_a", CredentialPlatformLarkCLI, ConsentToTeams([]string{"t9"})); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetConsent(f.ctx, "on_c", CredentialPlatformLarkCLI, ConsentAll()); StoreReason(err) != "not_found" {
		t.Fatalf("consent on missing credential = %v", err)
	}
	mine, err := f.store.ListForUser(f.ctx, "on_a")
	if err != nil || len(mine) != 1 || strings.Join(mine[0].ConsentTeams.Teams, ",") != "t9" {
		t.Fatalf("list = %+v, %v", mine, err)
	}
	if err := f.store.Delete(f.ctx, "on_a", CredentialPlatformLarkCLI); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Delete(f.ctx, "on_a", CredentialPlatformLarkCLI); StoreReason(err) != "not_found" {
		t.Fatalf("second delete = %v", err)
	}
	if _, err := f.store.Get(f.ctx, "on_b", CredentialPlatformLarkCLI); err != nil {
		t.Fatalf("deleting A must not affect B: %v", err)
	}
	if _, err := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI); StoreReason(err) != "not_found" {
		t.Fatalf("deleted credential get = %v", err)
	}
	empty, err := f.store.ListForUser(f.ctx, "on_a")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v", empty, err)
	}
}

func TestCredentialShapeValidation(t *testing.T) {
	f := newCredentialFixture(t)
	good := f.upsert("on_a", CredentialPlatformLarkCLI, "x", nil)
	c := f.db.Collection(credentialsCollection)
	sealed := Document{"v": int32(1), "alg": "A256GCM", "kekId": "k", "wrappedDek": "w", "data": "d"}
	base := func() Document {
		return Document{"unionId": "on_a", "platform": "device-cli", "kind": "device-archive", "sealed": sealed,
			"version": 1.0, "meta": Document{}, "consentTeams": []string{"t1"}, "status": "active", "createdAt": 1.0, "updatedAt": 1.0}
	}
	cases := map[string]func(Document){
		"malformed platform": func(d Document) { d["platform"] = "Not A Platform" },
		"sealed version 2": func(d Document) {
			d["sealed"] = Document{"v": 2, "alg": "A256GCM", "kekId": "k", "wrappedDek": "w", "data": "d"}
		},
		"sealed missing data": func(d Document) { d["sealed"] = Document{"v": 1, "alg": "A256GCM", "kekId": "k", "wrappedDek": "w"} },
		"string version":      func(d Document) { d["version"] = "1" },
		"consent string":      func(d Document) { d["consentTeams"] = "some" },
		"unknown status":      func(d Document) { d["status"] = "revoked" },
		"consent not strings": func(d Document) { d["consentTeams"] = []int{1} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.DeleteMany(f.ctx, Document{"_id": "on_a::device-cli"}); err != nil {
				t.Fatal(err)
			}
			doc := base()
			doc["_id"] = "on_a::device-cli"
			mutate(doc)
			if err := c.InsertOne(f.ctx, doc); err != nil {
				t.Fatal(err)
			}
			_, err := f.store.Get(f.ctx, "on_a", testDevicePlatform)
			if StoreReason(err) != "invalid" {
				t.Fatalf("get malformed = %v, want invalid", err)
			}
			list, err := f.store.ListForUser(f.ctx, "on_a")
			if err != nil || len(list) != 1 || list[0].ID != good.ID {
				t.Fatalf("list must skip malformed records: %+v, %v", list, err)
			}
		})
	}
	// A Node-written double v=1 and int64 version are still well-formed.
	if _, err := c.DeleteMany(f.ctx, Document{"_id": "on_a::device-cli"}); err != nil {
		t.Fatal(err)
	}
	doc := base()
	doc["_id"] = "on_a::device-cli"
	doc["sealed"] = Document{"v": 1.0, "alg": "A256GCM", "kekId": "k", "wrappedDek": "w", "data": "d"}
	doc["version"] = int64(7)
	if err := c.InsertOne(f.ctx, doc); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.Get(f.ctx, "on_a", testDevicePlatform)
	if err != nil || got.Version != 7 || got.Sealed.V != 1 {
		t.Fatalf("lenient numeric decode = %+v, %v", got, err)
	}
}

func TestCredentialGrantsAudit(t *testing.T) {
	f := newCredentialFixture(t)
	base := CredentialGrantInput{UnionID: "on_a", Platform: CredentialPlatformLarkCLI, OwnerUnionID: "on_owner", AppID: "cli_x", SessionID: "s1"}
	refused := base
	refused.MachineID, refused.Outcome, refused.Reason = "m1", CredentialRefused, "credential_not_found"
	f.store.AppendGrant(f.ctx, refused)
	f.now = f.now.Add(2 * time.Millisecond)
	granted := base
	granted.MachineID, granted.Outcome, granted.MachineName = "m1", CredentialGranted, "workstation"
	f.store.AppendGrant(f.ctx, granted)

	if ok, err := f.store.HasGrantedOnMachine(f.ctx, "on_a", "m1"); err != nil || !ok {
		t.Fatalf("granted on m1 = %v, %v", ok, err)
	}
	if ok, err := f.store.HasGrantedOnMachine(f.ctx, "on_a", "m2"); err != nil || ok {
		t.Fatalf("granted on m2 = %v, %v", ok, err)
	}
	list, err := f.store.ListGrantsForUser(f.ctx, "on_a", 10)
	if err != nil || len(list) != 2 || list[0].Outcome != CredentialGranted || list[0].MachineName != "workstation" || list[1].Reason != "credential_not_found" {
		t.Fatalf("grants = %+v, %v", list, err)
	}
	if limited, _ := f.store.ListGrantsForUser(f.ctx, "on_a", 1); len(limited) != 1 || limited[0].Outcome != CredentialGranted {
		t.Fatalf("limit = %+v", limited)
	}
	if other, err := f.store.ListGrantsForUser(f.ctx, "on_b", 10); err != nil || other == nil || len(other) != 0 {
		t.Fatalf("other user's grants = %#v, %v", other, err)
	}
	g := list[0]
	if !strings.HasPrefix(g.ID, "cg_") || g.At != f.now.UnixMilli() || !g.ExpireAt.Equal(time.UnixMilli(g.At+credentialGrantTTLMS)) {
		t.Fatalf("grant record: %+v", g)
	}
	raw := f.raw(credentialGrantsCollection, g.ID)
	if goBSONType(raw["at"]) != "double" || goBSONType(raw["expireAt"]) != "date" {
		t.Fatalf("grant BSON types: at=%T expireAt=%T", raw["at"], raw["expireAt"])
	}
	if _, ok := raw["turnId"]; ok {
		t.Fatal("empty turnId must be omitted")
	}
}

func TestCredentialPending(t *testing.T) {
	f := newCredentialFixture(t)
	p1, err := f.store.PutPending(f.ctx, "on_a", testDevicePlatform, f.sealed("on_a", testDevicePlatform, "c1"), "https://sso/1")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := f.store.PutPending(f.ctx, "on_a", testDevicePlatform, f.sealed("on_a", testDevicePlatform, "c2"), "https://sso/2")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(f.db.MemoryCollection(credentialPendingCollection).Documents()); n != 1 {
		t.Fatalf("one pending login per person, got %d", n)
	}
	if _, err := f.store.GetPending(f.ctx, "on_a", p1.ID); StoreReason(err) != "not_found" {
		t.Fatalf("replaced pending = %v", err)
	}
	got, err := f.store.GetPending(f.ctx, "on_a", p2.ID)
	if err != nil || got.AuthURL != "https://sso/2" || got.Platform != testDevicePlatform {
		t.Fatalf("get pending = %+v, %v", got, err)
	}
	if _, err := f.store.GetPending(f.ctx, "on_b", p2.ID); StoreReason(err) != "not_found" {
		t.Fatalf("another person's pending = %v", err)
	}
	mine, err := f.store.GetPendingForUser(f.ctx, "on_a")
	if err != nil || mine.ID != p2.ID {
		t.Fatalf("pending for user = %+v, %v", mine, err)
	}
	raw := f.raw(credentialPendingCollection, p2.ID)
	if goBSONType(raw["createdAt"]) != "double" || goBSONType(raw["expireAt"]) != "date" {
		t.Fatalf("pending BSON types: %#v", raw)
	}
	if expire := raw["expireAt"].(primitive.DateTime); int64(expire) != p2.CreatedAt+credentialPendingTTLMS {
		t.Fatalf("pending expireAt = %d", expire)
	}

	// Logical expiry wins over the best-effort TTL index.
	f.now = f.now.Add(time.Hour)
	if _, err := f.store.GetPending(f.ctx, "on_a", p2.ID); err != nil {
		t.Fatalf("pending at exactly the TTL is still live: %v", err)
	}
	f.now = f.now.Add(time.Millisecond)
	if _, err := f.store.GetPending(f.ctx, "on_a", p2.ID); StoreReason(err) != "not_found" {
		t.Fatalf("expired pending = %v", err)
	}
	if _, err := f.store.GetPendingForUser(f.ctx, "on_a"); StoreReason(err) != "not_found" {
		t.Fatalf("expired pending for user = %v", err)
	}
	f.store.DeletePending(f.ctx, p2.ID)
	if n := len(f.db.MemoryCollection(credentialPendingCollection).Documents()); n != 0 {
		t.Fatalf("delete pending left %d", n)
	}
}

func TestCredentialTouchUse(t *testing.T) {
	f := newCredentialFixture(t)
	doc := f.upsert("on_a", CredentialPlatformLarkCLI, "x", nil)
	f.now = f.now.Add(time.Minute)
	f.store.TouchUse(f.ctx, doc.ID, "m7")
	got, _ := f.store.Get(f.ctx, "on_a", CredentialPlatformLarkCLI)
	if got.LastUsedAt != f.now.UnixMilli() || got.LastUsedMachineID != "m7" || got.Version != doc.Version {
		t.Fatalf("touch = %+v", got)
	}
}

func TestCredentialWritesUseNodeBSONTypes(t *testing.T) {
	f := newCredentialFixture(t)
	doc, err := f.store.Upsert(f.ctx, UpsertCredentialInput{
		UnionID: "on_a", Platform: CredentialPlatformLarkCLI, Kind: CredentialKindLarkOAuth,
		Sealed: f.sealed("on_a", CredentialPlatformLarkCLI, "x"), Meta: CredentialMeta{AppID: "cli_x"}, RefreshExpiresAt: 1_800_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := f.raw(credentialsCollection, doc.ID)
	for field, want := range map[string]string{
		"version": "int32", "createdAt": "double", "updatedAt": "double", "refreshExpiresAt": "double",
		"consentTeams": "string", "sealed": "document", "meta": "document",
	} {
		if got := goBSONType(raw[field]); got != want {
			t.Errorf("credential.%s stored as %s, want %s", field, got, want)
		}
	}
	if goBSONType(raw["sealed"].(map[string]any)["v"]) != "int32" {
		t.Errorf("sealed.v must be int32 like the Node literal 1")
	}
	if meta := raw["meta"].(map[string]any); len(meta) != 1 || meta["appId"] != "cli_x" {
		t.Errorf("meta = %#v", meta)
	}
	if err := f.store.SetConsent(f.ctx, "on_a", CredentialPlatformLarkCLI, ConsentToTeams(nil)); err != nil {
		t.Fatal(err)
	}
	if consent, ok := f.raw(credentialsCollection, doc.ID)["consentTeams"].([]any); !ok || len(consent) != 0 {
		t.Fatalf("empty consent must be stored as [], got %#v", f.raw(credentialsCollection, doc.ID)["consentTeams"])
	}
}

func TestConsentTeamsJSON(t *testing.T) {
	if got := marshalNoEscape(t, ConsentAll()); got != `"all"` {
		t.Fatalf("all = %s", got)
	}
	if got := marshalNoEscape(t, ConsentToTeams(nil)); got != `[]` {
		t.Fatalf("empty = %s", got)
	}
	if got := marshalNoEscape(t, ConsentToTeams([]string{"t<1>"})); got != `["t<1>"]` {
		t.Fatalf("teams = %s", got)
	}
	var c ConsentTeams
	if err := json.Unmarshal([]byte(`"all"`), &c); err != nil || !c.All {
		t.Fatalf("decode all = %+v, %v", c, err)
	}
	if err := json.Unmarshal([]byte(`["a","b"]`), &c); err != nil || c.All || strings.Join(c.Teams, ",") != "a,b" {
		t.Fatalf("decode teams = %+v, %v", c, err)
	}
	for _, bad := range []string{`"some"`, `null`, `[1]`, `{}`} {
		if err := json.Unmarshal([]byte(bad), &c); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

func TestCredentialPersistenceAvailable(t *testing.T) {
	if NewCredentialStore(UnavailableDatabaseProvider{}).PersistenceAvailable() || NewCredentialStore(NewMemoryDatabaseProvider()).PersistenceAvailable() {
		t.Fatal("memory mode has no vault storage")
	}
	if !NewCredentialStore(&RetryingDatabaseProvider{}).PersistenceAvailable() {
		t.Fatal("a MongoDB provider is persistent even while unavailable")
	}
}

func TestCredentialHelpers(t *testing.T) {
	if CredentialID("on_a", testDevicePlatform) != "on_a::device-cli" {
		t.Fatal("credential id format")
	}
	for value, want := range map[string]bool{"lark-cli": true, "device-cli": true, "": false, "Lark": false, "a::b": false, "-x": false, strings.Repeat("a", 33): false} {
		if IsCredentialPlatform(value) != want {
			t.Errorf("IsCredentialPlatform(%q) = %v", value, !want)
		}
	}
}
