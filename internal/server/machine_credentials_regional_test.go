package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Regional logins of a device-login platform (one login per site, one
// partition-scoped token per login), through the real grant handler, the
// real vault dispatch and the real credentials page routes.
//
// The compatibility contract with daemons: a regional variable reaches only a
// daemon that named the regions in its request. A daemon from before regions
// rejects a whole grant carrying a variable outside its allow-list, so sending
// one unasked would cost that person every grant.

const regionalTestPrimary = string(testDevicePlatform)

var regionalTestLogins = []credential.RegionalLogin{
	{Region: "r1", Site: "s1", Platform: credential.RegionalPlatform(regionalTestPrimary, "s1"), Title: "Region one"},
	{Region: "r2", Site: "s2", Platform: credential.RegionalPlatform(regionalTestPrimary, "s2"), Title: "Region two"},
	{Region: "r3", Site: "s3", Platform: credential.RegionalPlatform(regionalTestPrimary, "s3"), Title: "Region three"},
}

// fakeRegionalDeviceLogin is fakeDeviceLogin with regional logins.
type fakeRegionalDeviceLogin struct {
	*fakeDeviceLogin
	regionMu sync.Mutex
	begun    []string
}

func (f *fakeRegionalDeviceLogin) Regions() []credential.RegionalLogin {
	return append([]credential.RegionalLogin(nil), regionalTestLogins...)
}

func (f *fakeRegionalDeviceLogin) BeginRegion(_ context.Context, region string) credential.DeviceLoginBegin {
	f.regionMu.Lock()
	defer f.regionMu.Unlock()
	f.begun = append(f.begun, region)
	return credential.DeviceLoginBegin{OK: true, AuthURL: "https://sso.test/v?" + region, Payload: map[string]string{"challenge": "ct", "region": region}}
}

type regionalGrantEnv struct {
	*grantTestEnv
	regional *fakeRegionalDeviceLogin
	mu       sync.Mutex
	// minted lists the record platforms the provider was asked to mint.
	minted []string
	// mint answers per record platform; unset ones answer with a token.
	mint map[string]credential.MintResult
}

func newRegionalGrantEnv(t *testing.T) *regionalGrantEnv {
	t.Helper()
	env := &regionalGrantEnv{grantTestEnv: newGrantTestEnv(t), mint: map[string]credential.MintResult{}}
	env.regional = &fakeRegionalDeviceLogin{fakeDeviceLogin: env.device}
	env.apex.Credentials.Providers.DeviceLogins = []credential.DeviceLogin{env.regional}
	env.apex.Credentials.Providers.Keys = credential.StaticKeySource(env.keys)
	env.apex.Credentials.Mint = nil
	env.device.set(func(f *fakeDeviceLogin) {
		f.mint = func(rec credential.Record) credential.MintResult {
			env.mu.Lock()
			defer env.mu.Unlock()
			env.minted = append(env.minted, rec.Platform)
			if scripted, ok := env.mint[rec.Platform]; ok {
				return scripted
			}
			return regionalTestToken(rec.Platform, time.Hour)
		}
	})
	return env
}

// regionalTestToken is what the fake provider mints for a record: the primary
// one's variable, or one named after the region.
func regionalTestToken(platform string, life time.Duration) credential.MintResult {
	name := "DEVICE_CLI_TOKEN"
	for _, login := range regionalTestLogins {
		if login.Platform == platform {
			name = "DEVICE_CLI_TOKEN_" + strings.ToUpper(login.Region)
		}
	}
	return credential.MintResult{OK: true, Variables: credential.Variables{{Name: name, Value: "tok-" + platform}}, ExpiresAt: time.Now().Add(life).UnixMilli()}
}

func (e *regionalGrantEnv) mintedPlatforms() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]string(nil), e.minted...)
	sort.Strings(out)
	return out
}

func (e *regionalGrantEnv) authorizeRegions(unionID string, regions ...string) {
	e.t.Helper()
	e.authorize(unionID, testDevicePlatform, nil)
	for _, region := range regions {
		e.authorize(unionID, store.CredentialPlatform(credential.RegionalPlatform(regionalTestPrimary, "s"+strings.TrimPrefix(region, "r"))), nil)
	}
}

// grantWith posts a grant for bob with extra JSON members appended to the body.
func (e *regionalGrantEnv) grantWith(extra string) (int, map[string]json.RawMessage, string) {
	e.t.Helper()
	body := strings.TrimSuffix(grantBody("u-bob", regionalTestPrimary), "}") + extra + "}"
	r := e.grant(body, e.token(), "")
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(r.Body.Bytes(), &fields)
	return r.Code, fields, r.Body.String()
}

func grantVariables(t *testing.T, fields map[string]json.RawMessage) map[string]string {
	t.Helper()
	var variables map[string]string
	if err := json.Unmarshal(fields["variables"], &variables); err != nil {
		t.Fatalf("variables: %v", err)
	}
	return variables
}

func grantExpiresAt(t *testing.T, fields map[string]json.RawMessage) int64 {
	t.Helper()
	var expiresAt int64
	if err := json.Unmarshal(fields["expiresAt"], &expiresAt); err != nil {
		t.Fatalf("expiresAt: %v", err)
	}
	return expiresAt
}

func TestRegionalGrantReachesOnlyADaemonThatAsked(t *testing.T) {
	// An older daemon sends no regions and accepts only the variables it knows
	// (the botmux grant client's per-tool allow-list): exactly the old answer.
	t.Run("older daemon", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1", "r2")
		code, fields, raw := env.grantWith("")
		if code != http.StatusOK {
			t.Fatalf("grant = %d %s", code, raw)
		}
		if _, present := fields["cloudJwtRegions"]; present {
			t.Fatalf("an unasked grant answered regions: %s", raw)
		}
		olderAllowList := map[string]bool{"DEVICE_CLI_TOKEN": true}
		for name := range grantVariables(t, fields) {
			if !olderAllowList[name] {
				t.Fatalf("an older daemon would reject this grant for %s: %s", name, raw)
			}
		}
		if got := env.mintedPlatforms(); strings.Join(got, ",") != regionalTestPrimary {
			t.Fatalf("minted %v for an unasked grant", got)
		}
	})

	t.Run("daemon that names regions", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1", "r2")
		// r2's token expires first: the grant lasts only as long as it.
		env.mint[regionalTestLogins[1].Platform] = regionalTestToken(regionalTestLogins[1].Platform, 20*time.Minute)
		code, fields, raw := env.grantWith(`,"cloudJwtRegions":["r3","r1","r2","unknown"]`)
		if code != http.StatusOK {
			t.Fatalf("grant = %d %s", code, raw)
		}
		variables := grantVariables(t, fields)
		want := map[string]string{
			"DEVICE_CLI_TOKEN":    "tok-" + regionalTestPrimary,
			"DEVICE_CLI_TOKEN_R1": "tok-" + regionalTestLogins[0].Platform,
			"DEVICE_CLI_TOKEN_R2": "tok-" + regionalTestLogins[1].Platform,
		}
		if len(variables) != len(want) {
			t.Fatalf("variables = %v", variables)
		}
		for k, v := range want {
			if variables[k] != v {
				t.Fatalf("variables = %v, want %v", variables, want)
			}
		}
		// Tried: the regions it knows, in its own order; r3 was tried (bob has
		// no login there) and "unknown" was not.
		if string(fields["cloudJwtRegions"]) != `["r1","r2","r3"]` {
			t.Fatalf("cloudJwtRegions = %s", fields["cloudJwtRegions"])
		}
		if expiresAt := grantExpiresAt(t, fields); expiresAt > time.Now().Add(21*time.Minute).UnixMilli() {
			t.Fatalf("expiresAt %d outlives the regional token", expiresAt)
		}
		if got := env.mintedPlatforms(); strings.Join(got, ",") != strings.Join([]string{regionalTestPrimary, regionalTestLogins[0].Platform, regionalTestLogins[1].Platform}, ",") {
			t.Fatalf("minted %v", got)
		}
	})

	t.Run("an unreadable regions member is read as not asked", func(t *testing.T) {
		for _, extra := range []string{`,"cloudJwtRegions":{"r1":true}`, `,"cloudJwtRegions":["r1",7]`, `,"cloudJwtRegions":"r1"`, `,"cloudJwtRegions":null`, `,"cloudJwtRegions":[null]`} {
			env := newRegionalGrantEnv(t)
			env.authorizeRegions("u-bob", "r1")
			code, fields, raw := env.grantWith(extra)
			if code != http.StatusOK {
				t.Fatalf("%s: grant = %d %s", extra, code, raw)
			}
			if _, present := fields["cloudJwtRegions"]; present || len(grantVariables(t, fields)) != 1 {
				t.Fatalf("%s: answered regions: %s", extra, raw)
			}
		}
	})

	t.Run("an empty regions list is answered and mints nothing regional", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1")
		_, fields, raw := env.grantWith(`,"cloudJwtRegions":[]`)
		if string(fields["cloudJwtRegions"]) != `[]` || len(grantVariables(t, fields)) != 1 {
			t.Fatalf("grant = %s", raw)
		}
	})
}

func TestRegionalGrantFailuresStayInTheirRegion(t *testing.T) {
	t.Run("a regional login needing re-authorization costs only its region", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1", "r2")
		env.mint[regionalTestLogins[0].Platform] = credential.MintResult{Reason: credential.MintReauthRequired, Detail: "s1 login is no longer valid"}
		code, fields, raw := env.grantWith(`,"cloudJwtRegions":["r1","r2"]`)
		variables := grantVariables(t, fields)
		if code != http.StatusOK || variables["DEVICE_CLI_TOKEN_R1"] != "" || variables["DEVICE_CLI_TOKEN_R2"] == "" || variables["DEVICE_CLI_TOKEN"] == "" {
			t.Fatalf("grant = %d %s", code, raw)
		}
		doc, err := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform))
		if err != nil || doc.Status != store.CredentialReauthRequired {
			t.Fatalf("r1 record = %+v (%v), want reauth_required", doc, err)
		}
		primary, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", testDevicePlatform)
		if primary.Status != store.CredentialActive {
			t.Fatalf("primary record = %+v", primary)
		}
		// A record marked for re-authorization is not asked again.
		env.mu.Lock()
		env.minted = nil
		env.mu.Unlock()
		env.grantWith(`,"cloudJwtRegions":["r1","r2"]`)
		for _, platform := range env.mintedPlatforms() {
			if platform == regionalTestLogins[0].Platform {
				t.Fatal("minted a regional record marked for re-authorization")
			}
		}
	})

	t.Run("a regional write-back lands on the regional record", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1")
		before, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform))
		renewed := env.sealed("u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform), "renewed")
		result := regionalTestToken(regionalTestLogins[0].Platform, time.Hour)
		result.UpdatedSealed, result.RefreshExpiresAt = &renewed, 99
		env.mint[regionalTestLogins[0].Platform] = result
		if code, _, raw := env.grantWith(`,"cloudJwtRegions":["r1"]`); code != http.StatusOK {
			t.Fatalf("grant = %d %s", code, raw)
		}
		after, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform))
		if after.Version == before.Version || after.RefreshExpiresAt != 99 {
			t.Fatalf("regional record not written back: %+v -> %+v", before, after)
		}
	})

	t.Run("a refused grant hands out no regional token", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1")
		env.mint[regionalTestPrimary] = credential.MintResult{Reason: credential.MintReauthRequired, Detail: "login is no longer valid"}
		code, _, raw := env.grantWith(`,"cloudJwtRegions":["r1"]`)
		if code != http.StatusConflict || strings.Contains(raw, "DEVICE_CLI_TOKEN") {
			t.Fatalf("grant = %d %s", code, raw)
		}
	})

	t.Run("the vault checks run before any regional mint", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-carol", "r1")
		r := env.grant(strings.TrimSuffix(grantBody("u-carol", regionalTestPrimary), "}")+`,"cloudJwtRegions":["r1"]}`, env.token(), "")
		if r.Code != http.StatusForbidden || len(env.mintedPlatforms()) != 0 {
			t.Fatalf("grant = %d %s, minted %v", r.Code, r.Body.String(), env.mintedPlatforms())
		}
	})

	t.Run("a regional record is not a platform of its own", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1")
		r := env.grant(grantBody("u-bob", regionalTestLogins[0].Platform), env.token(), "")
		if r.Code != http.StatusBadRequest || len(env.mintedPlatforms()) != 0 {
			t.Fatalf("grant = %d %s", r.Code, r.Body.String())
		}
	})

	t.Run("a platform without regions does not answer them", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorize("u-bob", store.CredentialPlatformLarkCLI, nil)
		env.apex.Credentials.Mint = func(context.Context, store.CredentialDoc) credential.MintResult { return env.mintResult }
		r := env.grant(strings.TrimSuffix(grantBody("u-bob", "lark-cli"), "}")+`,"cloudJwtRegions":["r1"]}`, env.token(), "")
		if r.Code != http.StatusOK || strings.Contains(r.Body.String(), "cloudJwtRegions") {
			t.Fatalf("grant = %d %s", r.Code, r.Body.String())
		}
	})
}

func newRegionalCredentialEnv(t *testing.T) (*credentialTestEnv, *fakeRegionalDeviceLogin) {
	t.Helper()
	env := newCredentialTestEnv(t)
	regional := &fakeRegionalDeviceLogin{fakeDeviceLogin: env.device}
	env.apex.Credentials.Providers.DeviceLogins = []credential.DeviceLogin{regional}
	return env, regional
}

func TestRegionalLoginsAreAuthorizedOneByOne(t *testing.T) {
	env, regional := newRegionalCredentialEnv(t)
	post := func(path, body string) map[string]any {
		r := env.do(path, credentialRequest{method: http.MethodPost, body: body})
		out := decodeBody(t, r)
		out["status"] = float64(r.Code)
		return out
	}
	authorize := func(body string) map[string]any { return post("/api/credentials/device-cli/region", body) }
	// A regional login hangs off the platform's own authorization.
	if got := authorize(`{"region":"r1"}`); got["status"] != float64(http.StatusConflict) || got["error"] != "primary_required" {
		t.Fatalf("authorize without the primary = %v", got)
	}
	for _, body := range []string{`{"region":"nope"}`, `{"region":7}`, `{}`} {
		if got := authorize(body); got["status"] != float64(http.StatusBadRequest) {
			t.Fatalf("authorize %s = %v", body, got)
		}
	}
	// The platform's own route does not take a region: a pod from before
	// regional logins would read it as the platform's login.
	if got := post("/api/credentials/device-cli/authorize", `{"region":"r1"}`); got["status"] != float64(http.StatusBadRequest) {
		t.Fatalf("platform authorize with a region = %v", got)
	}
	if len(regional.begun) != 0 {
		t.Fatalf("a refused authorize began a login: %v", regional.begun)
	}

	env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginAuthorized })
	primary := post("/api/credentials/device-cli/authorize", `{}`)
	if done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + primary["pendingId"].(string) + `"}`}); done.Code != http.StatusOK {
		t.Fatalf("primary complete = %d %s", done.Code, done.Body.String())
	}

	begun := authorize(`{"region":"r2"}`)
	if begun["status"] != float64(http.StatusOK) || begun["authUrl"] != "https://sso.test/v?r2" || strings.Join(regional.begun, ",") != "r2" {
		t.Fatalf("regional authorize = %v (began %v)", begun, regional.begun)
	}
	list := decodeBody(t, env.do("/api/credentials", credentialRequest{}))
	if pending, _ := list["pending"].(map[string]any); pending["platform"] != regionalTestLogins[1].Platform {
		t.Fatalf("pending = %v", list["pending"])
	}
	done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + begun["pendingId"].(string) + `"}`})
	assertCredentialResponse(t, done, http.StatusOK, `{"state":"authorized"}`)
	stored, err := env.stored("u-alice", store.CredentialPlatform(regionalTestLogins[1].Platform))
	if err != nil || env.openStored(stored) != `{"login":"archive"}` {
		t.Fatalf("regional record = %+v (%v)", stored, err)
	}

	list = decodeBody(t, env.do("/api/credentials", credentialRequest{}))
	platforms, _ := list["platforms"].([]any)
	card, _ := platforms[1].(map[string]any)
	regions, _ := card["regions"].([]any)
	if card["platform"] != regionalTestPrimary || len(regions) != len(regionalTestLogins) {
		t.Fatalf("card = %v", card)
	}
	if first, _ := regions[0].(map[string]any); first["region"] != "r1" || first["platform"] != regionalTestLogins[0].Platform || first["site"] != "s1" {
		t.Fatalf("card regions = %v", regions)
	}

	// Revoking one region leaves the platform; revoking the platform takes
	// every region with it.
	authorize(`{"region":"r3"}`)
	pending := decodeBody(t, env.do("/api/credentials", credentialRequest{}))["pending"].(map[string]any)
	env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + pending["id"].(string) + `"}`})
	if got := env.do("/api/credentials/device-cli?region=r2", credentialRequest{method: http.MethodDelete}); got.Code != http.StatusBadRequest {
		t.Fatalf("revoking a region on the platform's route = %d %s", got.Code, got.Body.String())
	}
	if _, err := env.stored("u-alice", testDevicePlatform); err != nil {
		t.Fatalf("a region-scoped revoke on the platform's route removed the platform: %v", err)
	}
	revoked := env.do("/api/credentials/device-cli/region?region=r2", credentialRequest{method: http.MethodDelete})
	assertCredentialResponse(t, revoked, http.StatusOK, `{"ok":true,"removed":true}`)
	if _, err := env.stored("u-alice", store.CredentialPlatform(regionalTestLogins[1].Platform)); err == nil {
		t.Fatal("regional record survived its revocation")
	}
	if _, err := env.stored("u-alice", testDevicePlatform); err != nil {
		t.Fatalf("revoking a region removed the platform: %v", err)
	}
	if got := env.do("/api/credentials/device-cli/region?region=nope", credentialRequest{method: http.MethodDelete}); got.Code != http.StatusBadRequest {
		t.Fatalf("revoke unknown region = %d", got.Code)
	}
	assertCredentialResponse(t, env.do("/api/credentials/device-cli", credentialRequest{method: http.MethodDelete}), http.StatusOK, `{"ok":true,"removed":true}`)
	for _, platform := range []string{regionalTestPrimary, regionalTestLogins[2].Platform} {
		if _, err := env.stored("u-alice", store.CredentialPlatform(platform)); err == nil {
			t.Fatalf("%s survived revoking the platform", platform)
		}
	}
}

// A regional login hangs off a live authorization of its platform. Revoked
// while a regional login is still being authorized, the platform must not get
// that region back with its next authorization.
func TestRegionalLoginDoesNotOutliveItsPlatformsRevocation(t *testing.T) {
	setup := func(t *testing.T) (*credentialTestEnv, string) {
		env, _ := newRegionalCredentialEnv(t)
		env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginAuthorized })
		primary := decodeBody(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}))
		env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + primary["pendingId"].(string) + `"}`})
		begun := decodeBody(t, env.do("/api/credentials/device-cli/region", credentialRequest{method: http.MethodPost, body: `{"region":"r1"}`}))
		return env, begun["pendingId"].(string)
	}
	noRegionalRecord := func(t *testing.T, env *credentialTestEnv) {
		t.Helper()
		if _, err := env.stored("u-alice", store.CredentialPlatform(regionalTestLogins[0].Platform)); err == nil {
			t.Fatal("a regional login landed without its platform's authorization")
		}
	}

	t.Run("revoking the platform drops the regional login being authorized", func(t *testing.T) {
		env, pendingID := setup(t)
		assertCredentialResponse(t, env.do("/api/credentials/device-cli", credentialRequest{method: http.MethodDelete}), http.StatusOK, `{"ok":true,"removed":true}`)
		done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + pendingID + `"}`})
		assertCredentialResponse(t, done, http.StatusNotFound, `{"error":"pending_not_found"}`)
		noRegionalRecord(t, env)
	})

	t.Run("a regional login completing after the platform is gone is not stored", func(t *testing.T) {
		env, pendingID := setup(t)
		if err := env.apex.CredentialStore.Delete(context.Background(), "u-alice", testDevicePlatform); err != nil {
			t.Fatal(err)
		}
		done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + pendingID + `"}`})
		assertCredentialResponse(t, done, http.StatusConflict, `{"error":"primary_required"}`)
		noRegionalRecord(t, env)
		if docs := env.rawDocs("credential_pending"); len(docs) != 0 {
			t.Fatalf("pending left behind: %v", docs)
		}
	})
}

func TestRegionalMintsNeverCostTheDefaultTicket(t *testing.T) {
	t.Run("a slow regional mint is left out, finished in the background and written back", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.apex.Credentials.RegionalWait = 50 * time.Millisecond
		env.authorizeRegions("u-bob", "r1", "r2")
		release := make(chan struct{})
		renewed := env.sealed("u-bob", store.CredentialPlatform(regionalTestLogins[1].Platform), "renewed")
		env.device.set(func(f *fakeDeviceLogin) {
			mint := f.mint
			f.mint = func(rec credential.Record) credential.MintResult {
				if rec.Platform != regionalTestLogins[1].Platform {
					return mint(rec)
				}
				<-release
				result := regionalTestToken(rec.Platform, time.Hour)
				result.UpdatedSealed, result.RefreshExpiresAt = &renewed, 77
				return result
			}
		})
		type answer struct {
			code   int
			fields map[string]json.RawMessage
			raw    string
		}
		answered := make(chan answer, 1)
		go func() {
			code, fields, raw := env.grantWith(`,"cloudJwtRegions":["r1","r2"]`)
			answered <- answer{code, fields, raw}
		}()
		var got answer
		select {
		case got = <-answered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("the grant waited for a slow regional mint")
		}
		close(release)
		variables := grantVariables(t, got.fields)
		if got.code != http.StatusOK || variables["DEVICE_CLI_TOKEN"] == "" || variables["DEVICE_CLI_TOKEN_R1"] == "" || variables["DEVICE_CLI_TOKEN_R2"] != "" {
			t.Fatalf("grant = %d %s", got.code, got.raw)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			doc, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[1].Platform))
			if doc.RefreshExpiresAt == 77 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the late regional mint was never written back: %+v", doc)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("a refused default ticket still writes back what the regional mints changed", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1", "r2")
		renewed := env.sealed("u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform), "renewed")
		result := regionalTestToken(regionalTestLogins[0].Platform, time.Hour)
		result.UpdatedSealed, result.RefreshExpiresAt = &renewed, 55
		env.mint[regionalTestLogins[0].Platform] = result
		env.mint[regionalTestLogins[1].Platform] = credential.MintResult{Reason: credential.MintReauthRequired, Detail: "s2 login is no longer valid"}
		env.mint[regionalTestPrimary] = credential.MintResult{Reason: credential.MintUnavailable, Detail: "provider down"}
		code, _, raw := env.grantWith(`,"cloudJwtRegions":["r1","r2"]`)
		if code != http.StatusBadGateway || strings.Contains(raw, "DEVICE_CLI_TOKEN") {
			t.Fatalf("grant = %d %s", code, raw)
		}
		// The refusal does not wait for them; they are settled as they finish.
		deadline := time.Now().Add(5 * time.Second)
		for {
			r1, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[0].Platform))
			r2, _ := env.apex.CredentialStore.Get(context.Background(), "u-bob", store.CredentialPlatform(regionalTestLogins[1].Platform))
			if r1.RefreshExpiresAt == 55 && r2.Status == store.CredentialReauthRequired {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("regional records not settled: r1=%+v r2=%+v", r1, r2)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("a regional ticket about to expire is left out instead of expiring the grant", func(t *testing.T) {
		env := newRegionalGrantEnv(t)
		env.authorizeRegions("u-bob", "r1", "r2")
		env.mint[regionalTestLogins[0].Platform] = regionalTestToken(regionalTestLogins[0].Platform, 5*time.Second)
		env.mint[regionalTestLogins[1].Platform] = regionalTestToken(regionalTestLogins[1].Platform, -30*time.Second)
		code, fields, raw := env.grantWith(`,"cloudJwtRegions":["r1","r2"]`)
		variables := grantVariables(t, fields)
		if code != http.StatusOK || len(variables) != 1 || variables["DEVICE_CLI_TOKEN"] == "" {
			t.Fatalf("grant = %d %s", code, raw)
		}
		if expiresAt := grantExpiresAt(t, fields); expiresAt < time.Now().Add(50*time.Minute).UnixMilli() {
			t.Fatalf("expiresAt %d follows a dying regional ticket", expiresAt)
		}
	})
}

// A regional record left behind without its platform (a pod from before
// regional logins revokes only the platform; a revocation racing a regional
// login completing) is unreachable, and must stay gone when the platform is
// authorized anew.
func TestNewPlatformAuthorizationStartsWithoutRegionalLogins(t *testing.T) {
	env, _ := newRegionalCredentialEnv(t)
	env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginAuthorized })
	leftover := store.CredentialPlatform(regionalTestLogins[0].Platform)
	sealed, err := credential.SealPayload(env.keys, "u-alice", string(leftover), map[string]string{"login": "from before"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: leftover, Kind: "device-archive", Sealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}
	connect := func() {
		t.Helper()
		begun := decodeBody(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}))
		done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + begun["pendingId"].(string) + `"}`})
		assertCredentialResponse(t, done, http.StatusOK, `{"state":"authorized"}`)
	}
	connect()
	if _, err := env.stored("u-alice", leftover); err == nil {
		t.Fatal("a regional login from before came back with the new authorization")
	}

	// A re-authorization of a live platform keeps its regional logins.
	if _, err := env.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: leftover, Kind: "device-archive", Sealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}
	connect()
	if _, err := env.stored("u-alice", leftover); err != nil {
		t.Fatalf("re-authorizing the platform dropped its regional login: %v", err)
	}
}

// noPanic runs a request handler and fails the test, rather than the whole
// test binary, when it panics: a panicking handler is the bug these tests pin.
func noPanic(t *testing.T, what string, run func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	run()
}

// The region routes are reached for every known platform: lark-cli, which has
// no device-login provider, and device logins without regions. Any signed-in
// person with the page's Origin can call them, so each is refused as invalid
// (400), never by a panicking handler, and starts no login.
func TestRegionRoutesRefuseAPlatformWithoutRegions(t *testing.T) {
	for _, linked := range []string{"device login without regions", "device login with regions"} {
		t.Run(linked, func(t *testing.T) {
			env := newCredentialTestEnv(t)
			platforms := []string{string(store.CredentialPlatformLarkCLI), regionalTestPrimary}
			if linked == "device login with regions" {
				env, _ = newRegionalCredentialEnv(t)
				platforms = platforms[:1]
			}
			// With the platform authorized, a refusal cannot be primary_required.
			env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginAuthorized })
			begun := decodeBody(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}))
			assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: `{"pendingId":"` + begun["pendingId"].(string) + `"}`}), http.StatusOK, `{"state":"authorized"}`)

			for _, platform := range platforms {
				for _, body := range []string{`{"region":"r1"}`, `{"region":"i18n"}`, `{}`} {
					var got *httptest.ResponseRecorder
					noPanic(t, "POST "+platform+"/region "+body, func() {
						got = env.do("/api/credentials/"+platform+"/region", credentialRequest{method: http.MethodPost, body: body})
					})
					assertCredentialResponse(t, got, http.StatusBadRequest, `{"error":"invalid"}`)
				}
				var got *httptest.ResponseRecorder
				noPanic(t, "DELETE "+platform+"/region", func() {
					got = env.do("/api/credentials/"+platform+"/region?region=r1", credentialRequest{method: http.MethodDelete})
				})
				assertCredentialResponse(t, got, http.StatusBadRequest, `{"error":"invalid"}`)
			}
			if pending := decodeBody(t, env.do("/api/credentials", credentialRequest{}))["pending"]; pending != nil {
				t.Fatalf("a refused regional authorize left a pending login: %v", pending)
			}
		})
	}
}

// The handlers behind the routes refuse on their own as well, not only
// because the route never hands them lark-cli: no provider, or a region the
// provider does not log in at, is invalid. A region is never served by the
// platform's own login in its place.
func TestDeviceLoginHandlersRefuseWithoutTheProvider(t *testing.T) {
	env, regional := newRegionalCredentialEnv(t)
	session := &auth.SessionPayload{Kind: "session", UnionID: "u-alice"}
	plain := &fakeDeviceLogin{available: true, complete: credential.DeviceLoginPending}
	for _, tc := range []struct {
		name     string
		provider credential.DeviceLogin
		region   string
	}{
		{"begin without a provider", nil, ""},
		{"begin a region without a provider", nil, "r1"},
		{"begin a region of a provider without regions", plain, "r1"},
		{"begin a region the provider does not have", regional, "nope"},
	} {
		recorder := httptest.NewRecorder()
		noPanic(t, tc.name, func() {
			env.apex.beginDeviceCredential(context.Background(), recorder, session, tc.provider, tc.region)
		})
		assertCredentialResponse(t, recorder, http.StatusBadRequest, `{"error":"invalid"}`)
	}
	if pending := decodeBody(t, env.do("/api/credentials", credentialRequest{}))["pending"]; pending != nil || len(regional.begun) != 0 {
		t.Fatalf("a refused begin started a login: pending %v, regions %v", pending, regional.begun)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/credentials/lark-cli/complete", strings.NewReader(`{"pendingId":"cp_0123456789abcdef01234567"}`))
	noPanic(t, "complete without a provider", func() {
		env.apex.completeDeviceCredential(context.Background(), recorder, request, session, nil)
	})
	assertCredentialResponse(t, recorder, http.StatusBadRequest, `{"error":"invalid"}`)
}
