package auth

import (
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const (
	dashboardMID      = "feedfacefeedface"
	dashboardOtherMID = "deadbeefdeadbeef"
)

func dashboardTestConfig() config.Config {
	return config.Config{SigningSecret: "desktop-dashboard-access-test-secret", PublicBaseURL: "http://localhost"}
}

func mintSourceAccess(t *testing.T, cfg config.Config, now time.Time) *DesktopAccessPayload {
	t.Helper()
	session := MintDesktopSessionAt(cfg, DesktopSessionInput{
		UnionID: "u-alice", Name: "Alice", LocalProfileID: "cloud-local-profile",
		CloudProfileID: "dcp_cloud_profile", SessionID: "desktop-session-family-1", LinkedAt: 1_700_000_000_000,
	}, now)
	access, err := VerifyDesktopAccessTokenAt(cfg, session.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func TestDesktopDashboardTokenMatchesTypeScriptGoldenBytes(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	access, err := VerifyDesktopAccessTokenAt(cfg, goldenDesktopAccess, goldenNow)
	if err != nil {
		t.Fatal(err)
	}
	got := mintDesktopDashboardAccessToken(cfg, access, dashboardMID, DesktopDashboardObserve, goldenNow, &counterReader{})
	if got.AccessToken != goldenDashboardAccess {
		t.Fatalf("dashboard token mismatch:\n got %s\nwant %s", got.AccessToken, goldenDashboardAccess)
	}
	if got.ExpiresAt != (goldenNow.Unix()+DesktopDashboardAccessTTLSec)*1000 {
		t.Fatalf("expiresAt = %d", got.ExpiresAt)
	}
}

func TestDesktopDashboardTokenBindsClaimsWithFiveMinuteTTL(t *testing.T) {
	t.Parallel()
	cfg := dashboardTestConfig()
	now := time.Now()
	source := mintSourceAccess(t, cfg, now)
	issued := MintDesktopDashboardAccessTokenAt(cfg, source, dashboardMID, DesktopDashboardObserve, now)
	claims, err := VerifyDesktopDashboardAccessTokenAt(cfg, issued.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Kind != "desktop-dashboard-access" || claims.Aud != DesktopDashboardAudience || claims.SID != source.SID ||
		claims.Sub != source.UnionID || claims.CloudProfileID != source.CloudProfileID || claims.MachineID != dashboardMID ||
		claims.Scope != DesktopDashboardObserve {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Exp-claims.Iat != DesktopDashboardAccessTTLSec || DesktopDashboardAccessTTLSec != 300 {
		t.Fatalf("ttl = %d", claims.Exp-claims.Iat)
	}
	if issued.ExpiresAt != claims.Exp*1000 {
		t.Fatalf("expiresAt = %d exp = %d", issued.ExpiresAt, claims.Exp)
	}
	if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, issued.AccessToken, time.Unix(claims.Exp, 0)); err == nil {
		t.Fatal("exp boundary must already be expired")
	}
	if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, issued.AccessToken, time.Unix(claims.Exp-1, 999_000_000)); err != nil {
		t.Fatalf("one second before exp must verify: %v", err)
	}

	manage := MintDesktopDashboardAccessTokenAt(cfg, source, dashboardMID, DesktopDashboardManage, now)
	manageClaims, err := VerifyDesktopDashboardAccessTokenAt(cfg, manage.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if manageClaims.Scope != DesktopDashboardManage || manageClaims.JTI == claims.JTI {
		t.Fatalf("manage claims = %+v", manageClaims)
	}
}

func TestDesktopDashboardTokenNeverOutlivesSourceAccess(t *testing.T) {
	t.Parallel()
	cfg := dashboardTestConfig()
	now := time.Now()
	source := *mintSourceAccess(t, cfg, now)
	source.Exp = now.Unix() + 90
	issued := MintDesktopDashboardAccessTokenAt(cfg, &source, dashboardMID, DesktopDashboardObserve, now)
	claims, err := VerifyDesktopDashboardAccessTokenAt(cfg, issued.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Exp != source.Exp || issued.ExpiresAt != source.Exp*1000 {
		t.Fatalf("exp = %d expiresAt = %d want %d", claims.Exp, issued.ExpiresAt, source.Exp)
	}
}

func TestDesktopDashboardTokenIsBoundToSigningSecretAndKind(t *testing.T) {
	t.Parallel()
	cfg := dashboardTestConfig()
	now := time.Now()
	source := mintSourceAccess(t, cfg, now)
	issued := MintDesktopDashboardAccessTokenAt(cfg, source, dashboardMID, DesktopDashboardObserve, now)
	other := cfg
	other.SigningSecret = "another-platform-signing-secret"
	if _, err := VerifyDesktopDashboardAccessTokenAt(other, issued.AccessToken, now); err == nil {
		t.Fatal("must not verify across signing secrets")
	}
	session := MintDesktopSessionAt(cfg, DesktopSessionInput{UnionID: "u", Name: "n", LocalProfileID: "lp"}, now)
	if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, session.AccessToken, now); err == nil {
		t.Fatal("desktop access must not verify as a dashboard ticket")
	}
	if _, err := VerifyDesktopAccessTokenAt(cfg, issued.AccessToken, now); err == nil {
		t.Fatal("dashboard ticket must not verify as desktop access")
	}
}

func TestDesktopDashboardVerifyRejectsMalformedClaims(t *testing.T) {
	t.Parallel()
	cfg := dashboardTestConfig()
	now := time.Unix(1_800_000_000, 0)
	valid := func() DesktopDashboardAccessPayload {
		return DesktopDashboardAccessPayload{
			Kind: desktopDashboardAccessKind, Aud: DesktopDashboardAudience, SID: "desktop-session-family-1",
			Sub: "u-alice", CloudProfileID: "dcp_x", MachineID: dashboardMID, Scope: DesktopDashboardObserve,
			Iat: now.Unix(), JTI: "AAECAwQFBgcICQoL", Exp: now.Unix() + 300,
		}
	}
	sign := func(p DesktopDashboardAccessPayload) string {
		return mustIssueCompat(p.compatJSON(), dashboardAccessKey(cfg))
	}
	if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, sign(valid()), now); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}
	mutations := map[string]func(*DesktopDashboardAccessPayload){
		"aud":         func(p *DesktopDashboardAccessPayload) { p.Aud = "other" },
		"sid":         func(p *DesktopDashboardAccessPayload) { p.SID = "short" },
		"machine":     func(p *DesktopDashboardAccessPayload) { p.MachineID = "FEEDFACEFEEDFACE" },
		"sub":         func(p *DesktopDashboardAccessPayload) { p.Sub = "" },
		"profile":     func(p *DesktopDashboardAccessPayload) { p.CloudProfileID = "" },
		"scope":       func(p *DesktopDashboardAccessPayload) { p.Scope = "admin" },
		"ttl":         func(p *DesktopDashboardAccessPayload) { p.Exp = p.Iat + 301 },
		"exp<=iat":    func(p *DesktopDashboardAccessPayload) { p.Iat = p.Exp },
		"jti":         func(p *DesktopDashboardAccessPayload) { p.JTI = "short" },
		"expired":     func(p *DesktopDashboardAccessPayload) { p.Iat, p.Exp = now.Unix()-300, now.Unix() },
		"jti-invalid": func(p *DesktopDashboardAccessPayload) { p.JTI = "AAECAwQFBgcICQo+" },
	}
	for name, mutate := range mutations {
		p := valid()
		mutate(&p)
		if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, sign(p), now); err == nil {
			t.Errorf("%s: malformed claims must be rejected", name)
		}
	}
	// Fractional iat is not an integer and is rejected like Number.isInteger.
	raw := `{"kind":"desktop-dashboard-access","aud":"botmux-machine-dashboard","sid":"desktop-session-family-1","sub":"u","cloudProfileId":"dcp","machineId":"feedfacefeedface","scope":"observe","iat":1800000000.5,"jti":"AAECAwQFBgcICQoL","exp":1800000200}`
	if _, err := VerifyDesktopDashboardAccessTokenAt(cfg, mustIssueCompat([]byte(raw), dashboardAccessKey(cfg)), now); err == nil {
		t.Fatal("fractional iat must be rejected")
	}
}

func TestDashboardObserveAllowlist(t *testing.T) {
	t.Parallel()
	shell := []string{"/", "/assets/app.js", "/assets/style.css", "/assets/chunks/vendor.js", "/favicon.ico", "/apple-touch-icon.png"}
	moduleReads := []string{
		"/__health", "/__desktop/compat", "/api/asks/pending", "/api/groups", "/api/role-profiles",
		"/api/resources/current", "/api/resources/history", "/api/insights/summary", "/api/schedules",
		"/api/whiteboards", "/api/game/status", "/api/sessions", "/api/bots", "/api/skills", "/api/plugins",
		"/api/team/local", "/api/team/remote-roster", "/api/connectors", "/api/connectors/stats",
		"/api/settings", "/api/update/status",
	}
	for _, path := range append(shell, moduleReads...) {
		for _, method := range []string{"GET", "HEAD"} {
			if got := AuthorizeDesktopDashboardRequest(DesktopDashboardObserve, method, path); got != DashboardRequestOK {
				t.Errorf("observe %s %s = %s", method, path, got)
			}
		}
	}
	checks := []struct {
		method, path string
		want         DashboardRequestDecision
	}{
		{"GET", "/events", DashboardRequestOK},
		{"HEAD", "/events", DashboardRequestPathNotAllowed},
		{"POST", "/api/settings", DashboardRequestInsufficientScope},
		{"GET", "/api/settings/private", DashboardRequestInsufficientScope},
		{"GET", "/api/game/download", DashboardRequestInsufficientScope},
		{"POST", "/api/game/status", DashboardRequestInsufficientScope},
		{"GET", "/api/sessions/s1/history", DashboardRequestOK},
		{"GET", "/api/sessions/s1/insight/turn/t1", DashboardRequestOK},
		{"GET", "/api/sessions/s1/write-link", DashboardRequestPathNotAllowed},
		// Path decoding and case folding happen before matching.
		{"get", "/API/Settings", DashboardRequestOK},
		{"GET", "/api/%73ettings", DashboardRequestOK},
		{"GET", "/%61pi/workflows", DashboardRequestPathNotAllowed},
		{"GET", "/api/%E0%A4%A", DashboardRequestPathNotAllowed},
		{"GET", "/api/%ZZ", DashboardRequestPathNotAllowed},
		{"GET", "/api/%C0%AF", DashboardRequestPathNotAllowed},
	}
	for _, c := range checks {
		if got := AuthorizeDesktopDashboardRequest(DesktopDashboardObserve, c.method, c.path); got != c.want {
			t.Errorf("observe %s %s = %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestDashboardManageBlocksInternalSurfaces(t *testing.T) {
	t.Parallel()
	if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, "GET", "/api/team/local"); got != DashboardRequestOK {
		t.Fatalf("manage GET team = %s", got)
	}
	if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, "POST", "/api/team/sync"); got != DashboardRequestOK {
		t.Fatalf("manage POST team sync = %s", got)
	}
	blocked := [][2]string{
		{"GET", "/workflow"},
		{"GET", "/api/workflow"},
		{"POST", "/api/workflows/run"},
		{"GET", "/api/v3/workflows"},
		{"POST", "/api/trigger"},
		{"GET", "/api/federation/peers"},
		{"POST", "/webhook/secret"},
		{"POST", "/api/webhook/secret"},
		{"GET", "/api/internal/state"},
		{"GET", "/__daemon/status"},
		{"POST", "/__cli/run"},
		{"POST", "/api/sessions/session-1/write-link"},
		{"GET", "/s/session-1"},
		{"POST", "/api/terminal/session-1"},
		{"GET", "/api/sessions/session-1/pty"},
		{"OPTIONS", "/api/team/local"},
		{"POST", "/__health"},
		// U+0130 lower-cases to "i" + combining dot, so it can not alias /api/internal.
		{"GET", "/api/%C4%B0nternal/state"},
	}
	for _, b := range blocked {
		if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, b[0], b[1]); got != DashboardRequestPathNotAllowed {
			t.Errorf("manage %s %s = %s", b[0], b[1], got)
		}
	}
}

func TestDashboardManageCannotBypassFreshSSO(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/api/update/status", "/api/update/versions", "/api/update/changelog"} {
		for _, method := range []string{"GET", "HEAD"} {
			if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, method, path); got != DashboardRequestOK {
				t.Errorf("manage %s %s = %s", method, path, got)
			}
		}
	}
	for _, method := range []string{"GET", "POST"} {
		if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, method, "/api/update/run"); got != DashboardRequestPathNotAllowed {
			t.Errorf("manage %s /api/update/run = %s", method, got)
		}
	}
	for _, root := range []string{"skills", "plugins", "cli-options", "settings"} {
		if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, "GET", "/api/"+root); got != DashboardRequestOK {
			t.Errorf("manage GET /api/%s = %s", root, got)
		}
		if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, "HEAD", "/api/"+root+"/status"); got != DashboardRequestOK {
			t.Errorf("manage HEAD /api/%s/status = %s", root, got)
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if got := AuthorizeDesktopDashboardRequest(DesktopDashboardManage, method, "/api/"+root+"/change"); got != DashboardRequestInsufficientScope {
				t.Errorf("manage %s /api/%s/change = %s", method, root, got)
			}
		}
	}
}

func TestDashboardExpiryLease(t *testing.T) {
	t.Parallel()
	const exp = 10_000
	var destroyed atomic.Bool
	RegisterDesktopDashboardExpiryLease(func() { destroyed.Store(true) }, exp, time.UnixMilli(exp*1000-10))
	deadline := time.Now().Add(2 * time.Second)
	for !destroyed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !destroyed.Load() {
		t.Fatal("lease must destroy the stream at exp")
	}

	var closedEarly atomic.Bool
	cleanup := RegisterDesktopDashboardExpiryLease(func() { closedEarly.Store(true) }, exp, time.UnixMilli(exp*1000-20))
	cleanup()
	time.Sleep(40 * time.Millisecond)
	if closedEarly.Load() {
		t.Fatal("cleanup must cancel the lease")
	}

	var past atomic.Bool
	RegisterDesktopDashboardExpiryLease(func() { past.Store(true) }, exp, time.UnixMilli(exp*1000+5000))
	deadline = time.Now().Add(2 * time.Second)
	for !past.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !past.Load() {
		t.Fatal("an already expired lease fires immediately")
	}
}

func TestStripDesktopDashboardAuthQuery(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://m-feedface.example.test/api/sessions" +
		"?t=one&T=two&token=three&TICKET=four&access_token=five" +
		"&auth=six&authorization=seven&dashboard_token=eight" +
		"&page=2&filter=active&filter=idle")
	if err != nil {
		t.Fatal(err)
	}
	stripped := StripDesktopDashboardAuthQuery(u)
	if stripped != "/api/sessions?page=2&filter=active&filter=idle" {
		t.Fatalf("stripped = %s", stripped)
	}
	for _, secret := range []string{"one", "two", "three", "four", "five", "six", "seven", "eight"} {
		if strings.Contains(stripped, secret) {
			t.Fatalf("%s leaked", secret)
		}
	}

	cases := map[string]string{
		// Untouched queries are forwarded byte-for-byte.
		"https://h/a%2Fb?x=%7e&y=a+b": "/a%2Fb?x=%7e&y=a+b",
		// Re-serialized queries use URLSearchParams encoding.
		"https://h/p?token=1&x=%7e&y=a+b&z=%E4%B8%AD": "/p?x=%7E&y=a+b&z=%E4%B8%AD",
		"https://h/p?token=only":                      "/p",
		"https://h/p":                                 "/p",
		"https://h/p?%74oken=1&keep":                  "/p?keep=",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := StripDesktopDashboardAuthQuery(u); got != want {
			t.Errorf("Strip(%s) = %s, want %s", raw, got, want)
		}
	}
}
