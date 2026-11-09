package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Ports test/server-machine-credentials.test.ts: POST
// /v1/machine/credential-grant, the daemon asking for the turn sender's
// short-lived credential. Machines and teams use the memory repository, the
// vault a MemoryDatabase CredentialStore; mint and notify are injected.

type grantNotification struct {
	unionID string
	info    feishu.CredentialFirstUseMessage
}

type grantTestEnv struct {
	*credentialTestEnv
	mu            sync.Mutex
	mintResult    credential.MintResult
	mintCalls     int
	onMint        func(call int) credential.MintResult
	notifications []grantNotification
	notified      chan struct{}
}

func newGrantTestEnv(t *testing.T) *grantTestEnv {
	t.Helper()
	base := newCredentialTestEnv(t)
	env := &grantTestEnv{credentialTestEnv: base, notified: make(chan struct{}, 16)}
	env.mintResult = credential.MintResult{
		OK:        true,
		Variables: credential.Variables{{Name: "LARKSUITE_CLI_APP_ID", Value: "cli_platform"}, {Name: "LARKSUITE_CLI_USER_ACCESS_TOKEN", Value: "u-at"}},
		ExpiresAt: time.Now().UnixMilli() + 3_600_000,
	}
	ctx := context.Background()
	// t1 = {alice (owner of the machine), bob}; carol shares no team.
	if err := base.repo.CreateTeam(ctx, store.TeamDoc{ID: "g1", Name: "Team", CreatedBy: "u-alice", Members: []string{"u-alice", "u-bob"}}); err != nil {
		t.Fatal(err)
	}
	if err := seedMachine(base.repo, store.RegisterMachine{
		MachineID: "m-alice", UnionID: "u-alice", OwnerName: "Alice", Name: "alice-box", LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	base.apex.Credentials.Mint = func(context.Context, store.CredentialDoc) credential.MintResult {
		env.mu.Lock()
		env.mintCalls++
		call, onMint, result := env.mintCalls, env.onMint, env.mintResult
		env.mu.Unlock()
		if onMint != nil {
			return onMint(call)
		}
		return result
	}
	base.apex.Credentials.Notify = func(_ context.Context, unionID string, info feishu.CredentialFirstUseMessage) error {
		env.mu.Lock()
		env.notifications = append(env.notifications, grantNotification{unionID, info})
		env.mu.Unlock()
		env.notified <- struct{}{}
		return nil
	}
	return env
}

func (e *grantTestEnv) token() string {
	return auth.MintMachineTokenAt(e.apex.Config, auth.MachineIdentity{UnionID: "u-alice", OwnerName: "Alice", MachineID: "m-alice"}, time.Now())
}

func (e *grantTestEnv) grant(body string, token string, method string) *httptest.ResponseRecorder {
	e.t.Helper()
	if method == "" {
		method = http.MethodPost
	}
	request := httptest.NewRequest(method, "http://localhost/v1/machine/credential-grant", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	e.apex.ServeHTTP(recorder, request)
	return recorder
}

func grantBody(unionID, tool string) string {
	return `{"unionId":"` + unionID + `","tool":"` + tool + `","appId":"cli_bot","sessionId":"sess-1","turnId":"om_1"}`
}

func (e *grantTestEnv) authorize(unionID string, platform store.CredentialPlatform, consent *store.ConsentTeams) store.CredentialDoc {
	e.t.Helper()
	kind := store.CredentialKindLarkOAuth
	if platform == testDevicePlatform {
		kind = "device-archive"
	}
	doc, err := e.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: unionID, Platform: platform, Kind: kind, Sealed: e.sealed(unionID, platform, "r"), DefaultConsent: consent,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return doc
}

func (e *grantTestEnv) sealed(unionID string, platform store.CredentialPlatform, refreshToken string) credential.Sealed {
	e.t.Helper()
	sealed, err := credential.SealPayload(e.keys, unionID, string(platform), map[string]string{"refreshToken": refreshToken})
	if err != nil {
		e.t.Fatal(err)
	}
	return sealed
}

func (e *grantTestEnv) grants(unionID string) []bson.M {
	var out []bson.M
	for _, doc := range e.rawDocs("credential_grants") {
		if doc["unionId"] == unionID {
			out = append(out, doc)
		}
	}
	return out
}

func (e *grantTestEnv) waitNotification() {
	e.t.Helper()
	select {
	case <-e.notified:
	case <-time.After(5 * time.Second):
		e.t.Fatal("first-use notification never sent")
	}
}

func (e *grantTestEnv) notificationCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.notifications)
}

func TestCredentialGrantAuthAndMethod(t *testing.T) {
	env := newGrantTestEnv(t)
	assertJSONError(t, env.grant(grantBody("u-bob", "lark-cli"), "", ""), http.StatusUnauthorized, "invalid_machine_token")
	assertCredentialResponse(t, env.grant("", env.token(), http.MethodGet), http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)
	// The method is checked before the token.
	assertCredentialResponse(t, env.grant("", "", http.MethodGet), http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)
}

func TestCredentialGrantVaultDisabled(t *testing.T) {
	env := newGrantTestEnv(t)
	env.apex.Config.CredentialKEK = nil
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusServiceUnavailable, `{"error":"credential_vault_disabled"}`)
}

func TestCredentialGrantBodyValidation(t *testing.T) {
	env := newGrantTestEnv(t)
	for _, body := range []string{
		`{"unionId":"../x","tool":"lark-cli","appId":"cli_bot","sessionId":"s"}`,
		`{"unionId":"u-bob","tool":"git","appId":"cli_bot","sessionId":"s"}`,
		`{"unionId":"u-bob","tool":"lark-cli","appId":"cli bot","sessionId":"s"}`,
		`{"unionId":"u-bob","tool":"lark-cli","appId":"cli_bot"}`,
		`{"unionId":"u-bob","tool":"lark-cli","appId":"cli_bot","sessionId":"s","turnId":null}`,
		`{"unionId":"u-bob","tool":"lark-cli","appId":"cli_bot","sessionId":"s","turnId":""}`,
		`[]`, `not json`, ``,
	} {
		assertCredentialResponse(t, env.grant(body, env.token(), ""), http.StatusBadRequest, `{"error":"invalid"}`)
	}
	mismatch := `{"unionId":"u-bob","tool":"lark-cli","appId":"cli_bot","sessionId":"s","machineId":"m-other"}`
	assertCredentialResponse(t, env.grant(mismatch, env.token(), ""), http.StatusForbidden, `{"error":"machine_mismatch"}`)
	nullMachine := `{"unionId":"u-bob","tool":"lark-cli","appId":"cli_bot","sessionId":"s","machineId":null}`
	assertCredentialResponse(t, env.grant(nullMachine, env.token(), ""), http.StatusForbidden, `{"error":"machine_mismatch"}`)
	if env.mintCalls != 0 || len(env.rawDocs("credential_grants")) != 0 {
		t.Fatal("invalid requests must neither mint nor audit")
	}
}

func TestCredentialGrantNotTeammateIsAudited(t *testing.T) {
	env := newGrantTestEnv(t)
	env.authorize("u-carol", store.CredentialPlatformLarkCLI, nil)
	assertCredentialResponse(t, env.grant(grantBody("u-carol", "lark-cli"), env.token(), ""), http.StatusForbidden, `{"error":"not_teammate"}`)
	if env.mintCalls != 0 {
		t.Fatal("must not mint")
	}
	audit := env.grants("u-carol")
	if len(audit) != 1 || audit[0]["outcome"] != "refused" || audit[0]["reason"] != "not_teammate" {
		t.Fatalf("audit = %v", audit)
	}
	if _, hasName := audit[0]["machineName"]; hasName {
		t.Fatalf("a refusal carries no machineName: %v", audit[0])
	}
}

func TestCredentialGrantNotFoundAndReauth(t *testing.T) {
	env := newGrantTestEnv(t)
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusNotFound,
		`{"error":"credential_not_found","authorizeUrl":"http://localhost/credentials"}`)
	if audit := env.grants("u-bob"); len(audit) != 1 || audit[0]["reason"] != "credential_not_found" {
		t.Fatalf("audit = %v", audit)
	}

	doc := env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	env.apex.CredentialStore.MarkReauthRequired(context.Background(), doc.ID, "refresh token expired", nil)
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusConflict,
		`{"error":"credential_reauth_required","authorizeUrl":"http://localhost/credentials","detail":"refresh token expired"}`)
	if env.mintCalls != 0 {
		t.Fatal("must not mint a credential marked for re-authorization")
	}
}

func TestCredentialGrantConsentScope(t *testing.T) {
	env := newGrantTestEnv(t)
	other := store.ConsentToTeams([]string{"t-other"})
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, &other)
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusForbidden,
		`{"error":"consent_missing","authorizeUrl":"http://localhost/credentials"}`)
	if err := env.apex.CredentialStore.SetConsent(context.Background(), "u-bob", store.CredentialPlatformLarkCLI, store.ConsentToTeams([]string{"g1"})); err != nil {
		t.Fatal(err)
	}
	if r := env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""); r.Code != http.StatusOK {
		t.Fatalf("consented grant = %d %s", r.Code, r.Body.String())
	}
}

func TestCredentialGrantSuccessAuditsAndNotifiesOnce(t *testing.T) {
	env := newGrantTestEnv(t)
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	first := env.grant(grantBody("u-bob", "lark-cli"), env.token(), "")
	want, _ := json.Marshal(env.mintResult.ExpiresAt)
	assertCredentialResponse(t, first, http.StatusOK,
		`{"ok":true,"tool":"lark-cli","unionId":"u-bob","variables":{"LARKSUITE_CLI_APP_ID":"cli_platform","LARKSUITE_CLI_USER_ACCESS_TOKEN":"u-at"},"expiresAt":`+string(want)+`}`)
	if strings.Contains(first.Body.String(), "refreshToken") {
		t.Fatal("the refresh credential never leaves the platform")
	}
	audit := env.grants("u-bob")
	if len(audit) != 1 || audit[0]["outcome"] != "granted" || audit[0]["machineName"] != "alice-box" ||
		audit[0]["ownerUnionId"] != "u-alice" || audit[0]["appId"] != "cli_bot" || audit[0]["turnId"] != "om_1" || audit[0]["sessionId"] != "sess-1" {
		t.Fatalf("audit = %v", audit)
	}
	if _, isDouble := audit[0]["at"].(float64); !isDouble {
		t.Fatalf("audit at BSON type = %T", audit[0]["at"])
	}
	env.waitNotification()
	env.mu.Lock()
	n := env.notifications[0]
	env.mu.Unlock()
	if n.unionID != "u-bob" || n.info != (feishu.CredentialFirstUseMessage{
		Platform: "lark-cli", MachineName: "alice-box", MachineID: "m-alice", OwnerName: "Alice", AppID: "cli_bot", ManageURL: "http://localhost/credentials",
	}) {
		t.Fatalf("notification = %+v", n)
	}

	// The same machine again: no second notification; last use recorded.
	if r := env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""); r.Code != http.StatusOK {
		t.Fatalf("second grant = %d %s", r.Code, r.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	if env.notificationCount() != 1 {
		t.Fatalf("notifications = %d", env.notificationCount())
	}
	doc, err := env.stored("u-bob", store.CredentialPlatformLarkCLI)
	if err != nil || doc.LastUsedMachineID != "m-alice" || doc.LastUsedAt == 0 {
		t.Fatalf("last use = %+v (%v)", doc, err)
	}
	// The audit list endpoint reads it back, newest first.
	list := env.do("/api/credentials/grants?limit=1", credentialRequest{cookie: credentialStr(env.cookie("u-bob", 0))})
	var grants struct {
		Grants []json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &grants); err != nil || len(grants.Grants) != 1 {
		t.Fatalf("grants = %s", list.Body.String())
	}
	if !strings.HasPrefix(string(grants.Grants[0]), `{"at":`) ||
		!strings.HasSuffix(string(grants.Grants[0]), `,"platform":"lark-cli","machineId":"m-alice","machineName":"alice-box","ownerUnionId":"u-alice","appId":"cli_bot","outcome":"granted"}`) {
		t.Fatalf("grant entry = %s", grants.Grants[0])
	}
}

func TestCredentialGrantSelfSkipsTeamsConsentAndNotify(t *testing.T) {
	env := newGrantTestEnv(t)
	none := store.ConsentToTeams(nil)
	env.authorize("u-alice", testDevicePlatform, &none)
	env.mintResult = credential.MintResult{OK: true, Variables: credential.Variables{{Name: "DEVICE_CLI_TOKEN", Value: "cloud"}}, ExpiresAt: time.Now().UnixMilli() + 1000}
	r := env.grant(grantBody("u-alice", "device-cli"), env.token(), "")
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"variables":{"DEVICE_CLI_TOKEN":"cloud"}`) {
		t.Fatalf("self grant = %d %s", r.Code, r.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	if env.notificationCount() != 0 {
		t.Fatal("self use never notifies")
	}
}

func TestCredentialGrantProviderFailures(t *testing.T) {
	env := newGrantTestEnv(t)
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	env.mintResult = credential.MintResult{Reason: credential.MintReauthRequired, Detail: "invalid_grant"}
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusConflict,
		`{"error":"credential_reauth_required","authorizeUrl":"http://localhost/credentials","detail":"invalid_grant"}`)
	marked, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI)
	if marked.Status != store.CredentialReauthRequired || marked.StatusReason != "invalid_grant" {
		t.Fatalf("marked = %+v", marked)
	}

	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil) // re-authorizing clears the flag
	env.mintResult = credential.MintResult{Reason: credential.MintUnavailable, Detail: "feishu 502"}
	assertCredentialResponse(t, env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""), http.StatusBadGateway,
		`{"error":"provider_unavailable","detail":"feishu 502"}`)
	still, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI)
	if still.Status != store.CredentialActive {
		t.Fatal("a transient failure must not mark reauth")
	}
	audit := env.grants("u-bob")
	if last := audit[len(audit)-1]; last["reason"] != "provider_unavailable: feishu 502" {
		t.Fatalf("audit = %v", last)
	}
}

func TestCredentialGrantConcurrentRefreshRetriesWithNewRecord(t *testing.T) {
	env := newGrantTestEnv(t)
	before := env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	fresh := credential.MintResult{OK: true, Variables: credential.Variables{{Name: "LARKSUITE_CLI_APP_ID", Value: "cli_platform"}, {Name: "LARKSUITE_CLI_USER_ACCESS_TOKEN", Value: "fresh"}}, ExpiresAt: time.Now().UnixMilli() + 3_600_000}
	env.onMint = func(call int) credential.MintResult {
		if call == 1 {
			// Another pod refreshed first and wrote back: version+1, our refresh
			// token was rotated away.
			if err := env.apex.CredentialStore.UpdateSealed(context.Background(), before.ID, before.Version, env.sealed("u-bob", "lark-cli", "r2"), store.CredentialSealedPatch{}); err != nil {
				t.Error(err)
			}
			return credential.MintResult{Reason: credential.MintReauthRequired, Detail: "feishu refresh rejected: invalid_grant"}
		}
		return fresh
	}
	r := env.grant(grantBody("u-bob", "lark-cli"), env.token(), "")
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"LARKSUITE_CLI_USER_ACCESS_TOKEN":"fresh"`) || env.mintCalls != 2 {
		t.Fatalf("grant = %d %s (mints=%d)", r.Code, r.Body.String(), env.mintCalls)
	}
	after, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI)
	if after.Status != store.CredentialActive {
		t.Fatal("another pod's refresh must not void the credential")
	}
}

func TestCredentialGrantReauthMarkIsVersionConditional(t *testing.T) {
	env := newGrantTestEnv(t)
	ctx := context.Background()
	before := env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	if err := env.apex.CredentialStore.UpdateSealed(ctx, before.ID, before.Version, env.sealed("u-bob", "lark-cli", "r2"), store.CredentialSealedPatch{}); err != nil {
		t.Fatal(err)
	}
	stale := before.Version
	env.apex.CredentialStore.MarkReauthRequired(ctx, before.ID, "stale result", &stale)
	if kept, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI); kept.Status != store.CredentialActive {
		t.Fatal("a stale result must not mark reauth")
	}
	current := before.Version + 1
	env.apex.CredentialStore.MarkReauthRequired(ctx, before.ID, "current result", &current)
	if marked, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI); marked.Status != store.CredentialReauthRequired {
		t.Fatal("the current version must be marked")
	}

	// Through the handler: a retry that is still rejected marks the version it
	// actually used.
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	env.mintResult = credential.MintResult{Reason: credential.MintReauthRequired, Detail: "dead"}
	if r := env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""); r.Code != http.StatusConflict || env.mintCalls != 1 {
		t.Fatalf("grant = %d (mints=%d)", r.Code, env.mintCalls)
	}
}

func TestCredentialGrantWritesBackRefreshWithCAS(t *testing.T) {
	env := newGrantTestEnv(t)
	before := env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	updated := env.sealed("u-bob", "lark-cli", "r2")
	env.mintResult = credential.MintResult{
		OK: true, Variables: credential.Variables{{Name: "LARKSUITE_CLI_APP_ID", Value: "a"}, {Name: "LARKSUITE_CLI_USER_ACCESS_TOKEN", Value: "t"}},
		ExpiresAt: time.Now().UnixMilli() + 1000, UpdatedSealed: &updated, RefreshExpiresAt: 999,
	}
	if r := env.grant(grantBody("u-bob", "lark-cli"), env.token(), ""); r.Code != http.StatusOK {
		t.Fatalf("grant = %d %s", r.Code, r.Body.String())
	}
	after, _ := env.stored("u-bob", store.CredentialPlatformLarkCLI)
	if after.Version != before.Version+1 || after.RefreshExpiresAt != 999 {
		t.Fatalf("after = %+v", after)
	}
	if got, _ := json.Marshal(after.Sealed); string(got) != func() string { raw, _ := json.Marshal(updated); return string(raw) }() {
		t.Fatalf("sealed = %s", got)
	}
	raw := env.rawDocs("credentials")[0]
	if _, isInt32 := raw["version"].(int32); !isInt32 {
		t.Fatalf("version BSON type = %T", raw["version"])
	}
}

func TestCredentialGrantRateLimit(t *testing.T) {
	env := newGrantTestEnv(t)
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	token := env.token()
	var last *httptest.ResponseRecorder
	for i := 0; i < 121; i++ {
		last = env.grant(grantBody("u-bob", "lark-cli"), token, "")
	}
	if last.Code != http.StatusTooManyRequests || !strings.HasPrefix(last.Body.String(), `{"error":"rate_limited","retryAfterMs":`) {
		t.Fatalf("121st grant = %d %s", last.Code, last.Body.String())
	}
}

func TestCredentialGrantLimiterWindow(t *testing.T) {
	limiter := NewCredentialGrantLimiter()
	for i := 0; i < credentialGrantMax; i++ {
		if _, limited := limiter.take("m", 1_000); limited {
			t.Fatalf("grant %d limited", i)
		}
	}
	if retry, limited := limiter.take("m", 31_000); !limited || retry != 30_000 {
		t.Fatalf("over limit: retry=%d limited=%v", retry, limited)
	}
	if _, limited := limiter.take("other", 31_000); limited {
		t.Fatal("limits are per machine")
	}
	if _, limited := limiter.take("m", 61_000); limited {
		t.Fatal("a new window starts after a minute")
	}
}

func TestCredentialGrantStoreFailures(t *testing.T) {
	env := newGrantTestEnv(t)
	env.apex.CredentialStore = store.NewCredentialStore(store.UnavailableDatabaseProvider{})
	// Memory mode: no audit is possible, the grant fails closed.
	assertCredentialResponse(t, env.grant(grantBody("u-alice", "lark-cli"), env.token(), ""), http.StatusServiceUnavailable,
		`{"error":"store_unavailable","authorizeUrl":"http://localhost/credentials"}`)
}
