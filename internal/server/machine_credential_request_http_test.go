package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// POST /v1/machine/credential-request: the daemon asking the platform to get
// the turn sender authorized. Machines and teams use the memory repository, the
// vault a MemoryDatabase; the card DM is injected.

type requestNotification struct {
	unionID string
	info    feishu.CredentialRequestMessage
}

type requestTestEnv struct {
	*grantTestEnv
	nowMS         int64
	dmMu          sync.Mutex
	notifications []requestNotification
	notifyErr     error
}

func newRequestTestEnv(t *testing.T) *requestTestEnv {
	t.Helper()
	env := &requestTestEnv{grantTestEnv: newGrantTestEnv(t), nowMS: time.Now().UnixMilli()}
	clock := func() time.Time { return time.UnixMilli(env.nowMS) }
	env.apex.CredentialStore = store.NewCredentialStoreWithClock(env.vault, clock)
	env.apex.Credentials.Now = clock
	env.apex.Credentials.RequestLimiter = NewCredentialRequestLimiter()
	env.apex.Credentials.NotifyRequest = func(_ context.Context, unionID string, info feishu.CredentialRequestMessage) error {
		env.dmMu.Lock()
		defer env.dmMu.Unlock()
		if env.notifyErr != nil {
			return env.notifyErr
		}
		env.notifications = append(env.notifications, requestNotification{unionID, info})
		return nil
	}
	return env
}

func (e *requestTestEnv) dms() []requestNotification {
	e.dmMu.Lock()
	defer e.dmMu.Unlock()
	return append([]requestNotification(nil), e.notifications...)
}

func (e *requestTestEnv) request(body, token, method string) *httptest.ResponseRecorder {
	e.t.Helper()
	if method == "" {
		method = http.MethodPost
	}
	r := httptest.NewRequest(method, "http://localhost/v1/machine/credential-request", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	e.apex.ServeHTTP(recorder, r)
	return recorder
}

func requestBody(unionID string, tools ...string) string {
	list, _ := json.Marshal(tools)
	return `{"unionId":"` + unionID + `","appId":"cli_bot","tools":` + string(list) + `,"sessionId":"sess-1","turnId":"om_1","unattended":true}`
}

type requestAnswer struct {
	OK         bool   `json:"ok"`
	Status     string `json:"status"`
	RequestID  string `json:"requestId"`
	ExpiresAt  int64  `json:"expiresAt"`
	Deduped    bool   `json:"deduped"`
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	RetryAfter int64  `json:"retryAfterMs"`
}

func answerOf(t *testing.T, r *httptest.ResponseRecorder, status int) requestAnswer {
	t.Helper()
	if r.Code != status {
		t.Fatalf("status = %d %s, want %d", r.Code, r.Body.String(), status)
	}
	if r.Code == http.StatusNotFound {
		t.Fatalf("the request endpoint must never answer 404: %s", r.Body.String())
	}
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", r.Header().Get("Cache-Control"))
	}
	var answer requestAnswer
	if err := json.Unmarshal(r.Body.Bytes(), &answer); err != nil {
		t.Fatalf("body %q: %v", r.Body.String(), err)
	}
	return answer
}

func TestCredentialRequestAuthVaultAndNotifierErrors(t *testing.T) {
	env := newRequestTestEnv(t)
	body := requestBody("u-carol", "lark-cli")
	assertJSONError(t, env.request(body, "", ""), http.StatusUnauthorized, "invalid_machine_token")
	assertCredentialResponse(t, env.request("", env.token(), http.MethodGet), http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)

	env.apex.Credentials.NotifyRequest = nil
	assertCredentialResponse(t, env.request(body, env.token(), ""), http.StatusServiceUnavailable, `{"error":"notify_unavailable"}`)

	env.apex.Config.CredentialKEK = nil
	assertCredentialResponse(t, env.request(body, env.token(), ""), http.StatusServiceUnavailable, `{"error":"credential_vault_disabled"}`)
}

func TestCredentialRequestBodyValidation(t *testing.T) {
	env := newRequestTestEnv(t)
	for _, body := range []string{
		`{"unionId":"../x","appId":"cli_bot","tools":["lark-cli"],"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli bot","tools":["lark-cli"],"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":"lark-cli","sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":null,"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":[],"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":["git",3],"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":["git"],"sessionId":"s"}`,
		`{"unionId":"u-carol","appId":"cli_bot","tools":["lark-cli"],"scopes":["not a scope"],"sessionId":"s"}`,
		`[]`, `not json`, ``,
	} {
		answerOf(t, env.request(body, env.token(), ""), http.StatusBadRequest)
	}
	mismatch := strings.TrimSuffix(requestBody("u-carol", "lark-cli"), "}") + `,"machineId":"m-other"}`
	if a := answerOf(t, env.request(mismatch, env.token(), ""), http.StatusForbidden); a.Error != "machine_mismatch" {
		t.Fatalf("answer = %+v", a)
	}
	if len(env.dms()) != 0 || len(env.rawDocs("credential_requests")) != 0 {
		t.Fatal("an invalid request must neither store nor send anything")
	}
}

func TestCredentialRequestReadySendsNothing(t *testing.T) {
	env := newRequestTestEnv(t)
	env.authorize("u-alice", store.CredentialPlatformLarkCLI, nil)
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil) // team consent all, shares g1
	for _, unionID := range []string{"u-alice", "u-bob"} {
		a := answerOf(t, env.request(requestBody(unionID, "lark-cli"), env.token(), ""), http.StatusOK)
		if !a.OK || a.Status != "ready" || a.RequestID != "" {
			t.Fatalf("%s answer = %+v", unionID, a)
		}
	}
	if len(env.dms()) != 0 || len(env.rawDocs("credential_requests")) != 0 {
		t.Fatal("nothing missing: no card, no record")
	}
	// A machine allowance covers a stranger too.
	env.authorize("u-carol", store.CredentialPlatformLarkCLI, nil)
	env.allowMachine("u-carol", "u-alice", "lark-cli")
	if a := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), env.token(), ""), http.StatusOK); a.Status != "ready" {
		t.Fatalf("allowed machine answer = %+v", a)
	}
}

func TestCredentialRequestSentCardNamesAuthoritativeOwnerAndRegistryBot(t *testing.T) {
	env := newRequestTestEnv(t)
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	registry.Upsert(&tunnel.MachineConn{MachineID: "m-alice", UnionID: "u-alice", Bots: []tunnel.BotInfo{{AppID: "cli_bot", Name: "Live Bot"}}})
	env.apex.Registry = registry
	// The token's owner name is a claim of the daemon's enrollment; the card
	// uses the stored machine.
	token := env.token()

	a := answerOf(t, env.request(requestBody("u-carol", "lark-cli", "device-cli", "git"), token, ""), http.StatusOK)
	if !a.OK || a.Status != "sent" || !strings.HasPrefix(a.RequestID, "cr_") || a.Deduped ||
		a.ExpiresAt != env.nowMS+24*3600*1000 {
		t.Fatalf("answer = %+v", a)
	}
	dms := env.dms()
	if len(dms) != 1 || dms[0].unionID != "u-carol" {
		t.Fatalf("dms = %+v", dms)
	}
	if info := dms[0].info; info.BotName != "Live Bot" || info.OwnerName != "Alice" || info.MachineName != "alice-box" ||
		strings.Join(info.Services, ",") != "飞书,Device" || info.AuthorizeURL != "http://localhost/credentials?request="+a.RequestID {
		t.Fatalf("card = %+v", info)
	}
	records := env.rawDocs("credential_requests")
	if len(records) != 1 || records[0]["_id"] != a.RequestID || records[0]["notifiedAt"] == nil ||
		records[0]["ownerUnionId"] != "u-alice" {
		t.Fatalf("records = %v", records)
	}
	if _, isDate := records[0]["expireAt"]; !isDate {
		t.Fatalf("record has no TTL date: %v", records[0])
	}

	// Without a live connection the stored machine's bot name is used. Names
	// lose control characters and angle brackets and are cut at 64 units; a bot
	// the machine does not list has no name.
	env.apex.Registry = nil
	long := strings.Repeat("n", 100)
	if err := seedMachine(env.repo, store.RegisterMachine{
		MachineID: "m-alice", UnionID: "u-alice", OwnerName: "Alice", Name: "box\n<b>" + long, LastSeen: time.Now().UnixMilli(),
		Bots: []store.BotInfo{{AppID: "cli_bot", Name: "a\n<b>" + long}},
	}); err != nil {
		t.Fatal(err)
	}
	env.nowMS += 11 * 60_000
	env.apex.Credentials.RequestLimiter = NewCredentialRequestLimiter()
	answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	info := env.dms()[1].info
	if info.BotName != "ab"+strings.Repeat("n", 62) || info.MachineName != "boxb"+strings.Repeat("n", 60) {
		t.Fatalf("stored names = %q, %q", info.BotName, info.MachineName)
	}
	env.nowMS += 11 * 60_000
	answerOf(t, env.request(strings.Replace(requestBody("u-carol", "lark-cli"), "cli_bot", "cli_other", 1), token, ""), http.StatusOK)
	if got := env.dms()[2].info.BotName; got != "" {
		t.Fatalf("unknown bot name = %q", got)
	}
}

func TestCredentialRequestStates(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()
	ask := func(body string) requestAnswer {
		t.Helper()
		env.nowMS += 11 * 60_000 // past the dedupe window
		return answerOf(t, env.request(body, token, ""), http.StatusOK)
	}

	stateOf := func(unionID string, tools ...string) string {
		a := ask(requestBody(unionID, tools...))
		if a.Status != "sent" {
			return a.Status
		}
		for _, record := range env.rawDocs("credential_requests") {
			if record["_id"] == a.RequestID {
				return strings.Join(bsonStrings(record["missing"]), ",")
			}
		}
		return "?"
	}

	// No credential.
	if got := stateOf("u-carol", "lark-cli"); got != "lark-cli:authorize" {
		t.Fatalf("state = %s", got)
	}
	// A credential marked for re-authorization.
	doc := env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	env.apex.CredentialStore.MarkReauthRequired(context.Background(), doc.ID, "dead", nil)
	if got := stateOf("u-bob", "lark-cli"); got != "lark-cli:reauthorize" {
		t.Fatalf("state = %s", got)
	}
	// A usable credential on a machine the person has not allowed.
	env.authorize("u-carol", store.CredentialPlatformLarkCLI, nil)
	if got := stateOf("u-carol", "lark-cli"); got != "lark-cli:allow" {
		t.Fatalf("state = %s", got)
	}
	// Narrowed team consent also needs the machine allowed.
	other := store.ConsentToTeams([]string{"t-other"})
	if err := env.apex.CredentialStore.SetConsent(context.Background(), "u-bob", store.CredentialPlatformLarkCLI, other); err != nil {
		t.Fatal(err)
	}
	env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
	if got := stateOf("u-bob", "lark-cli"); got != "lark-cli:allow" {
		t.Fatalf("state = %s", got)
	}
	// Missing scopes on a usable credential.
	scoped, err := env.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: store.CredentialPlatformLarkCLI, Kind: store.CredentialKindLarkOAuth,
		Sealed: env.sealed("u-alice", store.CredentialPlatformLarkCLI, "r"), Meta: store.CredentialMeta{Scope: "offline_access docx:document:readonly"},
	})
	if err != nil || scoped.Status != store.CredentialActive {
		t.Fatal(err)
	}
	withScopes := func(scopes string) string {
		return strings.TrimSuffix(requestBody("u-alice", "lark-cli"), "}") + `,"scopes":` + scopes + `}`
	}
	a := ask(withScopes(`["docx:document:readonly"]`))
	if a.Status != "ready" {
		t.Fatalf("scopes already granted = %+v", a)
	}
	a = ask(withScopes(`["docx:document:readonly","base:record:read"]`))
	if a.Status != "sent" {
		t.Fatalf("missing scope = %+v", a)
	}
	// A device login with no credential, together with a ready lark-cli.
	if got := stateOf("u-alice", "lark-cli", "device-cli"); got != "device-cli:authorize" {
		t.Fatalf("state = %s", got)
	}
	// The card names only what is missing.
	last := env.dms()[len(env.dms())-1].info
	if strings.Join(last.Services, ",") != "Device" {
		t.Fatalf("services = %v", last.Services)
	}
}

// bsonStrings reads an array of strings out of a raw record.
func bsonStrings(value any) []string {
	raw, _ := json.Marshal(value)
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestCredentialRequestDedupeMergesAndChangedMissingSetSendsAgain(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()

	first := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	env.nowMS += 60_000
	again := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	if again.Status != "sent" || !again.Deduped || again.RequestID != first.RequestID || again.ExpiresAt != first.ExpiresAt {
		t.Fatalf("again = %+v, first = %+v", again, first)
	}
	if len(env.dms()) != 1 || len(env.rawDocs("credential_requests")) != 1 {
		t.Fatal("a repeated request must not message or store again")
	}

	// Same missing set with new scopes: the existing request grows.
	scoped := strings.TrimSuffix(requestBody("u-carol", "lark-cli"), "}") + `,"scopes":["base:record:read"]}`
	merged := answerOf(t, env.request(scoped, token, ""), http.StatusOK)
	if !merged.Deduped || merged.RequestID != first.RequestID || len(env.dms()) != 1 {
		t.Fatalf("merged = %+v", merged)
	}
	if scopes := bsonStrings(env.rawDocs("credential_requests")[0]["scopes"]); strings.Join(scopes, ",") != "base:record:read" {
		t.Fatalf("scopes = %v", scopes)
	}

	// A larger missing set is a new request and a new card.
	wider := answerOf(t, env.request(requestBody("u-carol", "lark-cli", "device-cli"), token, ""), http.StatusOK)
	if wider.Deduped || wider.RequestID == first.RequestID || len(env.dms()) != 2 {
		t.Fatalf("wider = %+v dms=%d", wider, len(env.dms()))
	}
	// A different person is a different request.
	answerOf(t, env.request(requestBody("u-dave", "lark-cli"), token, ""), http.StatusOK)
	if len(env.dms()) != 3 {
		t.Fatalf("dms = %d", len(env.dms()))
	}
	// Outside the ten minute window the same request sends again.
	env.nowMS += 11 * 60_000
	later := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	if later.Deduped || later.RequestID == first.RequestID || len(env.dms()) != 4 {
		t.Fatalf("later = %+v", later)
	}
}

func TestCredentialRequestUndeliverableKeepsRecordAndIsRetried(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()
	env.notifyErr = &feishu.APIError{Code: 230013, Msg: "Bot has NO availability to this user."}
	a := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	if !a.OK || a.Status != "undeliverable" || a.RequestID == "" || a.Detail == "" || a.ExpiresAt != 0 {
		t.Fatalf("answer = %+v", a)
	}
	records := env.rawDocs("credential_requests")
	if len(records) != 1 || records[0]["_id"] != a.RequestID {
		t.Fatalf("record not kept: %v", records)
	}
	if _, notified := records[0]["notifiedAt"]; notified {
		t.Fatal("an undelivered card is not notified")
	}
	// The next ask retries the DM on the same request.
	env.notifyErr = nil
	retry := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), token, ""), http.StatusOK)
	if retry.Status != "sent" || retry.RequestID != a.RequestID || len(env.dms()) != 1 || len(env.rawDocs("credential_requests")) != 1 {
		t.Fatalf("retry = %+v", retry)
	}
	// And a plain failure (not a Feishu answer) is reported with the error text.
	env.nowMS += 11 * 60_000
	env.notifyErr = errors.New("dial tcp: timeout")
	failed := answerOf(t, env.request(requestBody("u-dave", "lark-cli"), token, ""), http.StatusOK)
	if failed.Status != "undeliverable" || failed.Detail != "Error: dial tcp: timeout" {
		t.Fatalf("failed = %+v", failed)
	}
}

func TestCredentialRequestCaps(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()
	// 6 per day for one person and machine: distinct missing sets avoid the
	// dedupe, spaced past it.
	for i := 0; i < 6; i++ {
		env.nowMS += 11 * 60_000
		scope := `["s:r` + string(rune('a'+i)) + `"]`
		env.authorize("u-carol", store.CredentialPlatformLarkCLI, nil)
		env.allowMachine("u-carol", "u-alice", "lark-cli")
		body := strings.TrimSuffix(requestBody("u-carol", "lark-cli"), "}") + `,"scopes":` + scope + `}`
		if a := answerOf(t, env.request(body, token, ""), http.StatusOK); a.Status != "sent" {
			t.Fatalf("request %d = %+v", i, a)
		}
	}
	env.nowMS += 11 * 60_000
	capped := answerOf(t, env.request(strings.TrimSuffix(requestBody("u-carol", "lark-cli"), "}")+`,"scopes":["s:rz"]}`, token, ""), http.StatusTooManyRequests)
	if capped.Error != "request_cap" || capped.RetryAfter <= 0 || capped.RetryAfter > 24*3600*1000 {
		t.Fatalf("capped = %+v", capped)
	}
	if len(env.dms()) != 6 || len(env.rawDocs("credential_requests")) != 6 {
		t.Fatal("a capped request sends and stores nothing")
	}
	// The cap is per person and machine: another person is served.
	if a := answerOf(t, env.request(requestBody("u-dave", "lark-cli"), token, ""), http.StatusOK); a.Status != "sent" {
		t.Fatalf("other person = %+v", a)
	}
	// A day later the window has moved on.
	env.nowMS += 24 * 3600 * 1000
	if a := answerOf(t, env.request(strings.TrimSuffix(requestBody("u-carol", "lark-cli"), "}")+`,"scopes":["s:rz"]}`, token, ""), http.StatusOK); a.Status != "sent" {
		t.Fatalf("next day = %+v", a)
	}
}

func TestCredentialRequestPersonDayCapAcrossMachines(t *testing.T) {
	env := newRequestTestEnv(t)
	ctx := context.Background()
	// 20 requests of one person on other machines today.
	for i := 0; i < 20; i++ {
		if _, err := env.apex.CredentialStore.CreateRequest(ctx, store.CredentialRequestDoc{
			UnionID: "u-carol", MachineID: "m-other-" + string(rune('a'+i)), Missing: []string{"lark-cli:authorize"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	capped := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), env.token(), ""), http.StatusTooManyRequests)
	if capped.Error != "request_cap" || capped.RetryAfter <= 0 {
		t.Fatalf("capped = %+v", capped)
	}
	if len(env.dms()) != 0 {
		t.Fatal("capped: no card")
	}
}

func TestCredentialRequestPerMachineRateLimit(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()
	env.authorize("u-alice", store.CredentialPlatformLarkCLI, nil)
	var last *httptest.ResponseRecorder
	for i := 0; i < credentialRequestMax+1; i++ {
		last = env.request(requestBody("u-alice", "lark-cli"), token, "")
	}
	limited := answerOf(t, last, http.StatusTooManyRequests)
	if limited.Error != "rate_limited" || limited.RetryAfter <= 0 || limited.RetryAfter > credentialRequestWindowMS {
		t.Fatalf("limited = %+v", limited)
	}
	limiter := NewCredentialRequestLimiter()
	for i := 0; i < credentialRequestMax; i++ {
		if _, limited := limiter.take("m", 1_000); limited {
			t.Fatalf("request %d limited", i)
		}
	}
	if retry, limited := limiter.take("m", 301_000); !limited || retry != 300_000 {
		t.Fatalf("over limit: retry=%d limited=%v", retry, limited)
	}
	if _, limited := limiter.take("m", 601_000); limited {
		t.Fatal("a new window starts after ten minutes")
	}
}

func TestCredentialRequestStoreUnavailableSendsNothing(t *testing.T) {
	for _, collection := range []string{"credentials", "credential_machine_consents"} {
		env := newRequestTestEnv(t)
		env.apex.CredentialStore = store.NewCredentialStore(failingCollectionProvider{DatabaseProvider: env.vault, collection: collection})
		a := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), env.token(), ""), http.StatusServiceUnavailable)
		if a.Error != "store_unavailable" || len(env.dms()) != 0 {
			t.Fatalf("%s: answer = %+v dms=%d", collection, a, len(env.dms()))
		}
	}
	env := newRequestTestEnv(t)
	env.apex.CredentialStore = store.NewCredentialStore(store.UnavailableDatabaseProvider{})
	if a := answerOf(t, env.request(requestBody("u-carol", "lark-cli"), env.token(), ""), http.StatusServiceUnavailable); a.Error != "store_unavailable" || len(env.dms()) != 0 {
		t.Fatalf("answer = %+v", a)
	}
}

func TestCardTextDropsFormatCharactersAndSplitSurrogates(t *testing.T) {
	if got := cardText("a​b‮c d e"); got != "abcde" {
		t.Fatalf("got %q", got)
	}
	got := cardText(strings.Repeat("n", 63) + "😀")
	if got != strings.Repeat("n", 63) {
		t.Fatalf("got %q", got)
	}
}

func TestCredentialRequestNeverAnswers404(t *testing.T) {
	env := newRequestTestEnv(t)
	token := env.token()
	env.authorize("u-alice", store.CredentialPlatformLarkCLI, nil)
	for _, body := range []string{
		requestBody("u-alice", "lark-cli"),
		requestBody("u-carol", "lark-cli"),
		requestBody("u-carol", "device-cli"),
		requestBody("u-nobody", "lark-cli", "unknown-tool"),
		`{}`,
	} {
		if r := env.request(body, token, ""); r.Code == http.StatusNotFound {
			t.Fatalf("%s answered 404", body)
		}
	}
}
