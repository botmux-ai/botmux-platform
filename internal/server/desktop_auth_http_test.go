package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of test/server-desktop-auth.test.ts (the route-level cases; the pure
// token cases live with internal/auth).

func newDesktopHarness(t *testing.T) *deviceHarness {
	h := newDeviceHarness(t)
	h.a.Config.SigningSecret = "desktop-auth-test-secret"
	h.a.Config.RelaySigningSecret = "desktop-relay-test-secret"
	h.a.Config.RelayTokenIssuer = "https://platform.example.test"
	h.a.Config.RelayTokenAudience = "botmux-relay-test"
	h.a.Config.RelayTokenTTL = 600 * time.Second
	h.a.Config.DevLogin = true
	h.a.Config.DevUnionID = "u-dev"
	h.a.Config.DevName = "Dev User"
	return h
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64url(b)
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:])
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func authorizeQuery(overrides map[string]string) string {
	q := url.Values{
		"client_id":             {auth.DesktopClientID},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"nonce":                 {"nonce"},
		"state":                 {"state"},
		"code_challenge":        {challengeS256(strings.Repeat("a", 43))},
		"code_challenge_method": {"S256"},
		"local_profile_id":      {"local-1"},
		"redirect_uri":          {"http://127.0.0.1:41234/auth/callback"},
	}
	for k, v := range overrides {
		q.Set(k, v)
	}
	return "/v1/desktop/auth/authorize?" + q.Encode()
}

func TestDesktopAuthorizeRejectsNonLoopbackAndBadChallenge(t *testing.T) {
	h := newDesktopHarness(t)
	for _, redirectURI := range []string{
		"https://evil.example/auth/callback",
		"http://127.0.0.1/auth/callback",
		"http://127.0.0.2:41234/auth/callback",
		"http://127.0.0.1:41234/auth/callback?next=/evil",
		"http://user@127.0.0.1:41234/auth/callback",
	} {
		got := h.call(http.MethodGet, authorizeQuery(map[string]string{"redirect_uri": redirectURI}), nil, nil)
		expectStatus(t, got, http.StatusBadRequest, "invalid_redirect_uri")
	}
	got := h.call(http.MethodGet, authorizeQuery(map[string]string{"code_challenge": strings.Repeat("a", 44)}), nil, nil)
	expectStatus(t, got, http.StatusBadRequest, "invalid_code_challenge")
	got = h.call(http.MethodGet, authorizeQuery(map[string]string{"client_id": "other"}), nil, nil)
	expectStatus(t, got, http.StatusBadRequest, "invalid_client")
}

func TestDesktopAuthorizeDevLoginAndSessionExchange(t *testing.T) {
	h := newDesktopHarness(t)
	verifier := randomB64(32)
	state, nonce := randomB64(16), randomB64(16)
	redirectURI := "http://127.0.0.1:41234/auth/callback"
	got := h.call(http.MethodGet, authorizeQuery(map[string]string{
		"redirect_uri": redirectURI, "state": state, "nonce": nonce, "code_challenge": challengeS256(verifier),
		"local_profile_id": "local-default", "scope": "openid profile email offline_access",
	}), nil, nil)
	if got.status != http.StatusFound || got.header.Get("Cache-Control") != "no-store" ||
		got.header.Get("Referrer-Policy") != "no-referrer" || got.header.Get("Pragma") != "no-cache" || len(got.raw) != 0 {
		t.Fatalf("authorize = %d %v %s", got.status, got.header, got.raw)
	}
	location := got.header.Get("Location")
	if !strings.HasPrefix(location, redirectURI+"?code=") {
		t.Fatalf("location = %s", location)
	}
	back, _ := url.Parse(location)
	if back.Query().Get("state") != state || back.Query().Get("code") == "" {
		t.Fatalf("location = %s", location)
	}
	code := back.Query().Get("code")

	exchange := map[string]any{"code": code, "codeVerifier": verifier, "nonce": nonce, "redirectUri": redirectURI, "state": state, "localProfileId": "local-default"}
	// A wrong verifier never exchanges (and does not burn the code).
	bad := h.call(http.MethodPost, "/v1/desktop/auth/session", map[string]any{
		"code": code, "codeVerifier": randomB64(32), "nonce": nonce, "redirectUri": redirectURI, "state": state, "localProfileId": "local-default",
	}, nil)
	expectStatus(t, bad, http.StatusBadRequest, "invalid_grant")

	session := h.call(http.MethodPost, "/v1/desktop/auth/session", exchange, nil)
	expectStatus(t, session, http.StatusOK, "")
	expectKeys(t, session.raw, "accessToken", "refreshToken", "expiresAt", "cloud", "organizations", "capabilities")
	cloud := session.body["cloud"].(map[string]any)
	if cloud["userId"] != "u-dev" || cloud["displayName"] != "Dev User" || !strings.Contains(cloud["email"].(string), "@users.botmux.local") {
		t.Fatalf("cloud = %v", cloud)
	}
	if orgs, _ := session.body["organizations"].([]any); len(orgs) < 1 {
		t.Fatalf("organizations = %v", session.body["organizations"])
	}
	if _, ok := session.body["capabilities"].(map[string]any)["flags"].(map[string]any); !ok {
		t.Fatalf("capabilities = %v", session.body["capabilities"])
	}
}

func TestDesktopSessionValidation(t *testing.T) {
	h := newDesktopHarness(t)
	pending := auth.DesktopAuthPending{
		ClientID: auth.DesktopClientID, RedirectURI: "http://127.0.0.1:9999/auth/callback",
		CodeChallenge: challengeS256(strings.Repeat("v", 43)), CodeChallengeMethod: "S256",
		State: "st", Nonce: "nn", LocalProfileID: "prof-1",
	}
	code := auth.MintDesktopAuthCode(h.a.Config, auth.DesktopUser{UnionID: "u-alice", Name: "Alice"}, pending)
	body := func(mutate func(map[string]any)) map[string]any {
		b := map[string]any{"code": code, "codeVerifier": strings.Repeat("v", 43), "nonce": "nn", "redirectUri": pending.RedirectURI, "state": "st", "localProfileId": "prof-1"}
		if mutate != nil {
			mutate(b)
		}
		return b
	}
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", body(func(b map[string]any) { delete(b, "state") }), nil),
		http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", "null", nil), http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", body(func(b map[string]any) { b["redirectUri"] = "https://evil.example/auth/callback" }), nil),
		http.StatusBadRequest, "invalid_redirect_uri")
	for _, mutate := range []func(map[string]any){
		func(b map[string]any) { b["code"] = "junk" },
		func(b map[string]any) { b["nonce"] = "other" },
		func(b map[string]any) { b["state"] = "other" },
		func(b map[string]any) { b["localProfileId"] = "prof-2" },
		func(b map[string]any) { b["redirectUri"] = "http://127.0.0.1:9998/auth/callback" },
		func(b map[string]any) { b["codeVerifier"] = strings.Repeat("w", 43) },
	} {
		expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", body(mutate), nil), http.StatusBadRequest, "invalid_grant")
	}
	// Fields are trimmed before comparison.
	padded := h.call(http.MethodPost, "/v1/desktop/auth/session", body(func(b map[string]any) { b["state"] = "  st\n" }), nil)
	expectStatus(t, padded, http.StatusOK, "")

	// The consume fence is required: degraded store answers 503 and never
	// issues tickets.
	code2 := auth.MintDesktopAuthCode(h.a.Config, auth.DesktopUser{UnionID: "u-alice", Name: "Alice"}, pending)
	h.a.DesktopSessions = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", body(func(b map[string]any) { b["code"] = code2 }), nil),
		http.StatusServiceUnavailable, "store_unavailable")
}

func TestDesktopRefreshCapabilitiesLogoutChain(t *testing.T) {
	h := newDesktopHarness(t)
	pending := auth.DesktopAuthPending{
		ClientID: auth.DesktopClientID, RedirectURI: "http://127.0.0.1:9999/auth/callback",
		CodeChallenge: challengeS256(strings.Repeat("v", 43)), CodeChallengeMethod: "S256",
		State: "st", Nonce: "nn", LocalProfileID: "prof-1",
	}
	code := auth.MintDesktopAuthCode(h.a.Config, auth.DesktopUser{UnionID: "u-alice", Name: "Alice"}, pending)
	exchange := map[string]any{"code": code, "codeVerifier": strings.Repeat("v", 43), "nonce": "nn", "redirectUri": pending.RedirectURI, "state": "st", "localProfileId": "prof-1"}
	session := h.call(http.MethodPost, "/v1/desktop/auth/session", exchange, nil)
	expectStatus(t, session, http.StatusOK, "")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/session", exchange, nil), http.StatusBadRequest, "invalid_grant")

	linkedAt := session.body["cloud"].(map[string]any)["linkedAt"]
	refreshed := h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": session.str("refreshToken")}, nil)
	expectStatus(t, refreshed, http.StatusOK, "")
	if cloud := refreshed.body["cloud"].(map[string]any); cloud["userId"] != "u-alice" || cloud["linkedAt"] != linkedAt {
		t.Fatalf("refreshed cloud = %v", cloud)
	}
	if refreshed.str("accessToken") == "" || refreshed.str("accessToken") == session.str("accessToken") {
		t.Fatal("refresh did not mint a new access token")
	}

	caps := h.call(http.MethodPost, "/v1/desktop/auth/capabilities", nil, bearer(refreshed.str("accessToken")))
	expectStatus(t, caps, http.StatusOK, "")
	expectKeys(t, caps.raw, "cloud", "organizations", "capabilities")
	cloud := caps.body["cloud"].(map[string]any)
	if cloud["userId"] != "u-alice" || cloud["linkedAt"] != linkedAt || cloud["activeOrgId"] != auth.PersonalOrgFor("u-alice").OrgID {
		t.Fatalf("caps cloud = %v", cloud)
	}
	if caps.body["capabilities"].(map[string]any)["flags"].(map[string]any)["relay.use"] != true {
		t.Fatalf("caps = %s", caps.raw)
	}

	logout := h.call(http.MethodPost, "/v1/desktop/auth/logout", map[string]any{"refreshToken": refreshed.str("refreshToken")}, bearer(refreshed.str("accessToken")))
	expectStatus(t, logout, http.StatusOK, "")
	if string(logout.raw) != `{"ok":true}` {
		t.Fatalf("logout = %s", logout.raw)
	}
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": refreshed.str("refreshToken")}, nil),
		http.StatusUnauthorized, "invalid_grant")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/capabilities", nil, bearer(refreshed.str("accessToken"))),
		http.StatusUnauthorized, "session_revoked")
}

func TestDesktopRefreshAndLogoutEdgeCases(t *testing.T) {
	h := newDesktopHarness(t)
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", nil, nil), http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": "junk"}, nil), http.StatusUnauthorized, "invalid_grant")
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-a", Name: "A", LocalProfileID: "lp"})
	// An access ticket is not a refresh ticket.
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": session.AccessToken}, nil),
		http.StatusUnauthorized, "invalid_grant")

	// Invalid credentials still sign out locally: 200 with nothing revoked.
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/logout", nil, nil), http.StatusOK, "")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/logout", map[string]any{"refreshToken": "junk"}, bearer("junk")), http.StatusOK, "")

	h.a.DesktopSessions = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": session.RefreshToken}, nil),
		http.StatusServiceUnavailable, "store_unavailable")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/logout", map[string]any{"refreshToken": session.RefreshToken}, nil),
		http.StatusServiceUnavailable, "store_unavailable")
}

func TestDesktopRelayToken(t *testing.T) {
	h := newDesktopHarness(t)
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-relay", Name: "Relay User", LocalProfileID: "local-relay"})
	hostPublicKey := make([]byte, 32)
	_, _ = rand.Read(hostPublicKey)
	relayHostID := auth.RelayHostIDForPublicKey(hostPublicKey)
	keyB64 := base64.StdEncoding.EncodeToString(hostPublicKey)

	issued := h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{"relayHostId": relayHostID, "hostPublicKeyB64": keyB64}, bearer(session.AccessToken))
	expectStatus(t, issued, http.StatusOK, "")
	expectKeys(t, issued.raw, "relayToken", "expiresAt")
	if issued.num("expiresAt") <= float64(time.Now().UnixMilli()) {
		t.Fatalf("expiresAt = %v", issued.body["expiresAt"])
	}
	payload, err := auth.VerifyDesktopRelayToken(h.a.Config, issued.str("relayToken"))
	if err != nil || payload.Sub != "u-relay" || payload.RelayHostID != relayHostID || payload.HostPublicKeyB64 != keyB64 {
		t.Fatalf("payload = %+v %v", payload, err)
	}

	mismatched := h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{"relayHostId": strings.Repeat("A", 16), "hostPublicKeyB64": keyB64}, bearer(session.AccessToken))
	expectStatus(t, mismatched, http.StatusBadRequest, "invalid_relay_host_key")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{"relayHostId": "short", "hostPublicKeyB64": keyB64}, bearer(session.AccessToken)),
		http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{"relayHostId": relayHostID, "hostPublicKeyB64": strings.Repeat("A", 129)}, bearer(session.AccessToken)),
		http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{"relayHostId": relayHostID, "hostPublicKeyB64": keyB64}, nil),
		http.StatusUnauthorized, "unauthenticated")
}

func TestDesktopRelayDisabledFailsClosedTogether(t *testing.T) {
	h := newDesktopHarness(t)
	h.a.Config.RelaySigningSecret = ""
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-no-relay", Name: "No Relay User", LocalProfileID: "local-no-relay"})
	caps := h.call(http.MethodPost, "/v1/desktop/auth/capabilities", nil, bearer(session.AccessToken))
	expectStatus(t, caps, http.StatusOK, "")
	if caps.body["capabilities"].(map[string]any)["flags"].(map[string]any)["relay.use"] != false {
		t.Fatalf("caps = %s", caps.raw)
	}
	hostPublicKey := make([]byte, 32)
	relay := h.call(http.MethodPost, "/v1/desktop/auth/relay-token", map[string]any{
		"relayHostId": auth.RelayHostIDForPublicKey(hostPublicKey), "hostPublicKeyB64": base64.StdEncoding.EncodeToString(hostPublicKey),
	}, bearer(session.AccessToken))
	expectStatus(t, relay, http.StatusServiceUnavailable, "relay_unavailable")
}

func TestDesktopMachineBind(t *testing.T) {
	h := newDesktopHarness(t)
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-desktop-machine", Name: "Desktop Machine Owner", LocalProfileID: "local-machine"})
	machineID := strings.Repeat("ab", 16)
	issued := h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": machineID}, bearer(session.AccessToken))
	expectStatus(t, issued, http.StatusOK, "")
	expectKeys(t, issued.raw, "platformUrl", "machineId", "machineToken")
	if issued.str("platformUrl") != h.a.Config.PublicBaseURL || issued.str("machineId") != machineID {
		t.Fatalf("issued = %s", issued.raw)
	}
	payload, err := auth.VerifyMachineToken(h.a.Config, issued.str("machineToken"))
	if err != nil || payload.UnionID != "u-desktop-machine" || payload.MachineID != machineID || payload.OwnerName != "Desktop Machine Owner" {
		t.Fatalf("payload = %+v %v", payload, err)
	}

	rebound := h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": machineID}, bearer(session.AccessToken))
	expectStatus(t, rebound, http.StatusOK, "")
	if rebound.str("machineId") != machineID {
		t.Fatalf("rebound = %s", rebound.raw)
	}

	other := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-other-desktop-owner", Name: "Other Owner", LocalProfileID: "local-other-owner"})
	// Another owner presenting the same id gets a fresh one; the original
	// record keeps its owner.
	reassigned := h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": machineID}, bearer(other.AccessToken))
	expectStatus(t, reassigned, http.StatusOK, "")
	if id := reassigned.str("machineId"); id == machineID || !desktopMachineIDPattern.MatchString(id) || len(id) != 32 || !strings.Contains(string(reassigned.raw), `"reassigned":true`) {
		t.Fatalf("conflicting desktop bind = %s", reassigned.raw)
	}
	if doc, err := h.repo.GetMachine(context.Background(), machineID); err != nil || doc.UnionID != "u-desktop-machine" {
		t.Fatalf("owner doc = %+v err = %v", doc, err)
	}
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": "../not-a-machine"}, bearer(session.AccessToken)),
		http.StatusBadRequest, "invalid_machine_id")

	// A retired id is never resurrected: a fresh id is bound instead.
	if err := h.repo.RetireMachine(context.Background(), machineID); err != nil {
		t.Fatal(err)
	}
	fresh := h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": machineID}, bearer(session.AccessToken))
	expectStatus(t, fresh, http.StatusOK, "")
	if id := fresh.str("machineId"); id == machineID || !desktopMachineIDPattern.MatchString(id) || len(id) != 32 {
		t.Fatalf("fresh = %s", fresh.raw)
	}

	h.a.Repository = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/machine-bind", map[string]any{"machineId": strings.Repeat("cd", 16)}, bearer(session.AccessToken)),
		http.StatusServiceUnavailable, "store_unavailable")
}

func TestDesktopProfileOnlyPersonalOrgAndIsolatedFamily(t *testing.T) {
	h := newDesktopHarness(t)
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-org", Name: "Org User", LocalProfileID: "local-org"})
	source, err := auth.VerifyDesktopAccessToken(h.a.Config, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	rejected := h.call(http.MethodPost, "/v1/desktop/auth/profile", map[string]any{"orgId": "org-arbitrary", "name": "Work", "localProfileId": "cloud-profile-rejected"}, bearer(session.AccessToken))
	expectStatus(t, rejected, http.StatusNotFound, "org_not_found")

	org := auth.PersonalOrgFor("u-org")
	accepted := h.call(http.MethodPost, "/v1/desktop/auth/profile", map[string]any{"orgId": org.OrgID, "name": "Work", "localProfileId": "cloud-profile-new"}, bearer(session.AccessToken))
	expectStatus(t, accepted, http.StatusOK, "")
	if accepted.body["cloud"].(map[string]any)["activeOrgId"] != org.OrgID || accepted.body["cloud"].(map[string]any)["displayName"] != "Work" {
		t.Fatalf("accepted = %s", accepted.raw)
	}
	created, err := auth.VerifyDesktopAccessToken(h.a.Config, accepted.str("accessToken"))
	if err != nil {
		t.Fatal(err)
	}
	createdRefresh, err := auth.VerifyDesktopRefreshToken(h.a.Config, accepted.str("refreshToken"))
	if err != nil {
		t.Fatal(err)
	}
	if created.LocalProfileID != "cloud-profile-new" || createdRefresh.LocalProfileID != "cloud-profile-new" ||
		created.CloudProfileID == source.CloudProfileID || created.SID == source.SID ||
		createdRefresh.CloudProfileID != created.CloudProfileID || createdRefresh.SID != created.SID ||
		!strings.HasPrefix(created.CloudProfileID, "dcp_") || len(created.CloudProfileID) != 28 {
		t.Fatalf("created = %+v refresh = %+v source = %+v", created, createdRefresh, source)
	}

	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/logout", map[string]any{"refreshToken": accepted.str("refreshToken")}, bearer(accepted.str("accessToken"))),
		http.StatusOK, "")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/capabilities", nil, bearer(session.AccessToken)), http.StatusOK, "")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/capabilities", nil, bearer(accepted.str("accessToken"))),
		http.StatusUnauthorized, "session_revoked")
}

func TestDesktopProfileDefaultsAndLocalIDRules(t *testing.T) {
	h := newDesktopHarness(t)
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-org", Name: "Org User", LocalProfileID: "local-org"})
	// No body: Personal org, the source name and a server-generated local id.
	got := h.call(http.MethodPost, "/v1/desktop/auth/profile", "", bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	created, err := auth.VerifyDesktopAccessToken(h.a.Config, got.str("accessToken"))
	if err != nil || created.Name != "Org User" || !strings.HasPrefix(created.LocalProfileID, "cloud-") || len(created.LocalProfileID) != len("cloud-")+36 {
		t.Fatalf("created = %+v %v", created, err)
	}
	// Reusing the source profile id or an invalid id is rejected.
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/profile", map[string]any{"localProfileId": "local-org"}, bearer(session.AccessToken)),
		http.StatusBadRequest, "invalid_local_profile_id")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/profile", map[string]any{"localProfileId": "-bad"}, bearer(session.AccessToken)),
		http.StatusBadRequest, "invalid_local_profile_id")
	// A blank name falls back to the source name.
	named := h.call(http.MethodPost, "/v1/desktop/auth/profile", map[string]any{"name": "   ", "localProfileId": "p2"}, bearer(session.AccessToken))
	expectStatus(t, named, http.StatusOK, "")
	if named.body["cloud"].(map[string]any)["displayName"] != "Org User" {
		t.Fatalf("named = %s", named.raw)
	}
}

func TestDesktopOrgSwitch(t *testing.T) {
	h := newDesktopHarness(t)
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: "u-org", Name: "Org User", LocalProfileID: "local-org"})
	org := auth.PersonalOrgFor("u-org")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/org", map[string]any{}, bearer(session.AccessToken)), http.StatusBadRequest, "invalid_request")
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/org", map[string]any{"orgId": "other"}, bearer(session.AccessToken)), http.StatusNotFound, "org_not_found")
	got := h.call(http.MethodPost, "/v1/desktop/auth/org", map[string]any{"orgId": " " + org.OrgID + " "}, bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	expectKeys(t, got.raw, "cloud", "organizations", "capabilities")
	cloud := got.body["cloud"].(map[string]any)
	if cloud["activeOrgId"] != org.OrgID || cloud["activeOrgName"] != "Personal" {
		t.Fatalf("org = %s", got.raw)
	}
	expectKeys(t, mustRawField(t, got.raw, "cloud"), "cloudProfileId", "userId", "email", "displayName", "activeOrgId", "activeOrgName", "linkedAt")
}

func TestDesktopLogoutFencesInFlightRefresh(t *testing.T) {
	// The handler clock drives token minting/verification; the tombstone
	// floor (now + refresh TTL + 60s) is store logic covered by
	// store.TestDesktopSessionFamilyRevocationFence with a moved store clock.
	h := newDesktopHarness(t)
	started := time.Now()
	current := started
	h.a.Desktop.Now = func() time.Time { return current }
	original := auth.MintDesktopSessionAt(h.a.Config, auth.DesktopSessionInput{UnionID: "u-race", Name: "Race", LocalProfileID: "local-race"}, started)
	access, err := auth.VerifyDesktopAccessTokenAt(h.a.Config, original.AccessToken, started)
	if err != nil {
		t.Fatal(err)
	}
	// A refresh passed the active check, then logout arrived, and the
	// refresh still returned R1 for the same sid.
	current = started.Add(30 * time.Minute)
	inFlight := auth.MintDesktopSessionAt(h.a.Config, auth.DesktopSessionInput{
		UnionID: access.UnionID, Name: access.Name, LocalProfileID: access.LocalProfileID, ActiveOrgID: access.ActiveOrgID,
		CloudProfileID: access.CloudProfileID, LinkedAt: access.LinkedAt, SessionID: access.SID,
	}, current)
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/logout", map[string]any{}, bearer(original.AccessToken)), http.StatusOK, "")

	// Past the logged-out access ticket's exp the refresh family stays fenced.
	current = started.Add((auth.DesktopAccessTTLSec + 60) * time.Second)
	if _, err := auth.VerifyDesktopRefreshTokenAt(h.a.Config, inFlight.RefreshToken, current); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/auth/refresh", map[string]any{"refreshToken": inFlight.RefreshToken}, nil),
		http.StatusUnauthorized, "invalid_grant")
}

func TestDesktopUnknownPathIsJSON404(t *testing.T) {
	h := newDesktopHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/desktop/auth/nope"},
		{http.MethodPost, "/v1/desktop/auth"},
		{http.MethodGet, "/v1/desktop/auth/session"},
		{http.MethodPost, "/v1/desktop/auth/authorize"},
	} {
		got := h.call(tc.method, tc.path, nil, nil)
		expectStatus(t, got, http.StatusNotFound, "not_found")
		if strings.Contains(string(got.raw), "<html") {
			t.Fatalf("%s %s served HTML", tc.method, tc.path)
		}
	}
}

func TestDesktopAuthorizeWithoutFeishuConfig(t *testing.T) {
	h := newDesktopHarness(t)
	h.a.Config.DevLogin = false
	got := h.call(http.MethodGet, authorizeQuery(nil), nil, nil)
	if got.status != http.StatusInternalServerError || string(got.raw) != "飞书登录未配置（缺 FEISHU_APP_ID/SECRET）。联调可临时设 DEV_LOGIN=true。" {
		t.Fatalf("authorize = %d %s", got.status, got.raw)
	}
}

func TestDesktopAuthorizeCarriesPendingThroughFeishuState(t *testing.T) {
	h := newDesktopHarness(t)
	h.a.Config.DevLogin = false
	h.a.Config.FeishuAppID = "cli_test"
	h.a.Config.FeishuAppSecret = "secret"
	h.a.Config.FeishuHost = "https://open.feishu.cn"
	got := h.call(http.MethodGet, authorizeQuery(map[string]string{"state": "desk-state"}), nil, nil)
	if got.status != http.StatusFound || got.header.Get("Cache-Control") != "no-store" || got.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("authorize = %d %v", got.status, got.header)
	}
	location, err := url.Parse(got.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cookie := got.header.Get("Set-Cookie")
	nonce := strings.SplitN(strings.SplitN(cookie, "=", 2)[1], ";", 2)[0]
	verified, err := auth.VerifyState(h.a.Config, location.Query().Get("state"), nonce)
	if err != nil || verified.Desktop == nil || verified.Desktop.State != "desk-state" || verified.Next != "/" {
		t.Fatalf("verified = %+v %v (location %s)", verified, err, location)
	}
}

// fakeFeishuLogin serves the three login exchange calls; failUserToken makes
// the user-token step answer an API error.
func fakeFeishuLogin(t *testing.T, failUserToken bool) *feishu.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"app_access_token":"app-token","expire":7200}`))
		case "/open-apis/authen/v1/oidc/access_token":
			if failUserToken {
				_, _ = w.Write([]byte(`{"code":20003,"msg":"invalid code"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"user-token","refresh_token":"r","expires_in":7200}}`))
		case "/open-apis/authen/v1/user_info":
			_, _ = w.Write([]byte(`{"code":0,"data":{"union_id":"u-feishu","open_id":"ou-1","name":"Feishu User","avatar_url":"https://a"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return feishu.NewClient(server.URL, "cli_test", "secret", server.Client())
}

func TestCompleteDesktopAuthFromFeishuCallback(t *testing.T) {
	h := newDesktopHarness(t)
	pending := &auth.DesktopAuthPending{
		ClientID: auth.DesktopClientID, RedirectURI: "http://LOCALHOST:08080/auth/callback#",
		CodeChallenge: challengeS256(strings.Repeat("v", 43)), CodeChallengeMethod: "S256",
		State: "a b~*", Nonce: "nn", LocalProfileID: "prof-1",
	}
	request := newDeviceRequest(http.MethodGet, "/auth/callback?code=x")

	bad := *pending
	bad.RedirectURI = "https://evil.example/auth/callback"
	recorder := httptest.NewRecorder()
	h.a.completeDesktopAuthFromFeishuCallback(recorder, request, "x", &bad)
	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "登录校验失败（redirect_uri 无效）" {
		t.Fatalf("bad redirect = %d %s", recorder.Code, recorder.Body.String())
	}

	// The exchange error is reported like String(e) of a JS Error.
	h.a.Feishu = fakeFeishuLogin(t, true)
	recorder = httptest.NewRecorder()
	h.a.completeDesktopAuthFromFeishuCallback(recorder, request, "x", pending)
	if recorder.Code != http.StatusBadGateway || recorder.Body.String() != "飞书登录失败：Error: 飞书 user_access_token 失败: code=20003 msg=invalid code" {
		t.Fatalf("exchange failure = %d %s", recorder.Code, recorder.Body.String())
	}

	h.a.Feishu = fakeFeishuLogin(t, false)
	recorder = httptest.NewRecorder()
	h.a.completeDesktopAuthFromFeishuCallback(recorder, request, "x", pending)
	location := recorder.Header().Get("Location")
	if recorder.Code != http.StatusFound || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Set-Cookie") != "" ||
		!strings.HasPrefix(location, "http://localhost:8080/auth/callback?code=") || !strings.HasSuffix(location, "&state=a+b%7E*#") {
		t.Fatalf("callback = %d %v", recorder.Code, recorder.Header())
	}
	back, _ := url.Parse(location)
	code, err := auth.VerifyDesktopAuthCode(h.a.Config, back.Query().Get("code"))
	if err != nil || code.UnionID != "u-feishu" || code.Name != "Feishu User" || code.State != "a b~*" || code.RedirectURI != pending.RedirectURI {
		t.Fatalf("code = %+v %v", code, err)
	}
	// The profile snapshot is written in the background.
	deadline := time.Now().Add(2 * time.Second)
	for {
		profiles, err := h.repo.GetUserProfiles(context.Background(), []string{"u-feishu"})
		if err == nil && profiles["u-feishu"].Name == "Feishu User" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("profile not upserted: %v %v", profiles, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDesktopLoopbackRedirectSerialization(t *testing.T) {
	for _, tc := range []struct{ redirect, want string }{
		{"http://127.0.0.1:41234/auth/callback", "http://127.0.0.1:41234/auth/callback?code=C&state=a+b%7E*%2F"},
		{"http://LOCALHOST:08080/auth/callback", "http://localhost:8080/auth/callback?code=C&state=a+b%7E*%2F"},
		{"http://[::1]:5000/auth/callback?", "http://[::1]:5000/auth/callback?code=C&state=a+b%7E*%2F"},
		{"HTTP://127.0.0.1:5000/auth/callback#", "http://127.0.0.1:5000/auth/callback?code=C&state=a+b%7E*%2F#"},
	} {
		if got := desktopLoopbackRedirect(tc.redirect, "C", "a b~*/"); got != tc.want {
			t.Fatalf("%s → %s, want %s", tc.redirect, got, tc.want)
		}
	}
}

func TestDesktopSearchParamsMatchesURLSearchParams(t *testing.T) {
	values := desktopSearchParams("state=abc%zz&state=second&nonce=a+b%20c&&x&local_profile_id=%E4%BD%A0%FF&=v")
	if values.Get("state") != "abc%zz" || len(values["state"]) != 2 || values.Get("nonce") != "a b c" {
		t.Fatalf("values = %v", values)
	}
	if _, ok := values["x"]; !ok || values.Get("local_profile_id") != "你\uFFFD" || values.Get("") != "v" {
		t.Fatalf("values = %v", values)
	}
}

// mustRawField returns the raw JSON of one top-level field.
func mustRawField(t *testing.T, raw []byte, key string) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[key]
}
