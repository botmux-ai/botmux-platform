package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// counterReader yields 0,1,2,... so golden tokens can be reproduced by the
// Node reference script (see the golden constants below).
type counterReader struct{ next byte }

func (r *counterReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.next
		r.next++
	}
	return len(p), nil
}

var goldenNow = time.UnixMilli(1700000000123)

func desktopTestConfig() config.Config {
	return config.Config{
		SigningSecret:      "compat-secret-123",
		RelaySigningSecret: "desktop-relay-test-secret",
		RelayTokenIssuer:   "https://platform.example.test",
		RelayTokenAudience: "botmux-relay-test",
		RelayTokenTTL:      600 * time.Second,
		PublicBaseURL:      "https://platform.test",
		FeishuHost:         "https://open.feishu.test",
		FeishuAppID:        "cli_app~*",
	}
}

func goldenPending() DesktopAuthPending {
	return DesktopAuthPending{
		ClientID:            DesktopClientID,
		RedirectURI:         "http://127.0.0.1:45678/auth/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "st<&>\u2028",
		Nonce:               "nonce-1",
		LocalProfileID:      "local-default",
	}
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomB64URL(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Golden tokens produced by JSON.stringify + issueToken in Node with the same
// inputs and the same deterministic random bytes. They pin key order, number
// formatting and JSON.stringify escaping of the signed payloads.
const (
	goldenDesktopAuthCode = "eyJraW5kIjoiZGVza3RvcC1hdXRoLWNvZGUiLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MIiwidW5pb25JZCI6Im9uX2FiYyIsIm5hbWUiOiLnjovlsI_mmI4iLCJjbGllbnRJZCI6ImJvdG11eC1kZXNrdG9wIiwicmVkaXJlY3RVcmkiOiJodHRwOi8vMTI3LjAuMC4xOjQ1Njc4L2F1dGgvY2FsbGJhY2siLCJjb2RlQ2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwic3RhdGUiOiJzdDwmPuKAqCIsIm5vbmNlIjoibm9uY2UtMSIsImxvY2FsUHJvZmlsZUlkIjoibG9jYWwtZGVmYXVsdCIsImxpbmtlZEF0IjoxNzAwMDAwMDAwMTIzLCJleHAiOjE3MDAwMDAxMjB9.SU0VOgCq0eeMIuVAuef3k1AoLGES4QmJLJ2mNMDGlWg"
	goldenDesktopAccess   = "eyJraW5kIjoiZGVza3RvcC1hY2Nlc3MiLCJzaWQiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVIiLCJ1bmlvbklkIjoib25fYWJjIiwibmFtZSI6Ik48PibigKgiLCJsb2NhbFByb2ZpbGVJZCI6ImxvY2FsLTEiLCJhY3RpdmVPcmdJZCI6InBlcnNvbmFsX2RhZWYxNWM2ODQ4YjUzOTAiLCJjbG91ZFByb2ZpbGVJZCI6ImRjcF9iYjkyYjI3NGVjNzBhMDljNmJkNWU1NzQiLCJsaW5rZWRBdCI6MTcwMDAwMDAwMDEyMywiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiIxMjEzMTQxNTE2MTcxODE5MWExYjFjMWQiLCJleHAiOjE3MDAwMDM2MDB9.t3ute40peLP9EJhpQUyGQKOCfcTneYYUMFjpXYpNjj0"
	goldenDesktopRefresh  = "eyJraW5kIjoiZGVza3RvcC1yZWZyZXNoIiwic2lkIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSIiwidW5pb25JZCI6Im9uX2FiYyIsIm5hbWUiOiJOPD4m4oCoIiwibG9jYWxQcm9maWxlSWQiOiJsb2NhbC0xIiwiYWN0aXZlT3JnSWQiOiJwZXJzb25hbF9kYWVmMTVjNjg0OGI1MzkwIiwiY2xvdWRQcm9maWxlSWQiOiJkY3BfYmI5MmIyNzRlYzcwYTA5YzZiZDVlNTc0IiwibGlua2VkQXQiOjE3MDAwMDAwMDAxMjMsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiMWUxZjIwMjEyMjIzMjQyNTI2MjcyODI5IiwiZXhwIjoxNzAyNTkyMDAwfQ.fhZoN4LNzmqa-O0YvH2e6llOBukBIKKIarZ7gjF9aKI"
	goldenDashboardAccess = "eyJraW5kIjoiZGVza3RvcC1kYXNoYm9hcmQtYWNjZXNzIiwiYXVkIjoiYm90bXV4LW1hY2hpbmUtZGFzaGJvYXJkIiwic2lkIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSIiwic3ViIjoib25fYWJjIiwiY2xvdWRQcm9maWxlSWQiOiJkY3BfYmI5MmIyNzRlYzcwYTA5YzZiZDVlNTc0IiwibWFjaGluZUlkIjoiZmVlZGZhY2VmZWVkZmFjZSIsInNjb3BlIjoib2JzZXJ2ZSIsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTCIsImV4cCI6MTcwMDAwMDMwMH0.MI2qjLkChP_p79JsUZ_CwRtZp3MA559ehaLa5dmoyjU"
	goldenRelay           = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3BsYXRmb3JtLmV4YW1wbGUudGVzdCIsImF1ZCI6ImJvdG11eC1yZWxheS10ZXN0Iiwic3ViIjoib25fYWJjIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDA2MDAsImp0aSI6IkFBRUNBd1FGQmdjSUNRb0wiLCJzY29wZSI6InJlbGF5Omhvc3QiLCJyZWxheUhvc3RJZCI6IjQtRm5nTDdQWUIxVjVIVWUiLCJob3N0UHVibGljS2V5QjY0IjoiWkdWbVoyaHBhbXRzYlc1dmNIRnljM1IxZG5kNGVYcDdmSDErZjRDQmdvTT0iLCJjbG91ZFByb2ZpbGVJZCI6ImRjcF9iYjkyYjI3NGVjNzBhMDljNmJkNWU1NzQiLCJhY3RpdmVPcmdJZCI6InBlcnNvbmFsX2RhZWYxNWM2ODQ4YjUzOTAifQ.majn5NhLro4FFlVfv3gT-V5MYQ9SV5vucJFqA6XSJ1Y"
	goldenRelayFractional = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3BsYXRmb3JtLmV4YW1wbGUudGVzdCIsImF1ZCI6ImJvdG11eC1yZWxheS10ZXN0Iiwic3ViIjoib25fYWJjIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDAxNTAuNSwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTCIsInNjb3BlIjoicmVsYXk6aG9zdCIsInJlbGF5SG9zdElkIjoiNC1GbmdMN1BZQjFWNUhVZSIsImhvc3RQdWJsaWNLZXlCNjQiOiJaR1ZtWjJocGFtdHNiVzV2Y0hGeWMzUjFkbmQ0ZVhwN2ZIMStmNENCZ29NPSIsImNsb3VkUHJvZmlsZUlkIjoiZGNwX2JiOTJiMjc0ZWM3MGEwOWM2YmQ1ZTU3NCIsImFjdGl2ZU9yZ0lkIjoicGVyc29uYWxfZGFlZjE1YzY4NDhiNTM5MCJ9.oKseEM79DHfABoEPqieH8qvGc4Eposly286oOoSWq54"
)

func goldenSession(t *testing.T) DesktopSessionExchangeResponse {
	t.Helper()
	return mintDesktopSession(desktopTestConfig(), DesktopSessionInput{UnionID: "on_abc", Name: "N<>&\u2028", LocalProfileID: "local-1"}, goldenNow, &counterReader{})
}

func TestDesktopTokensMatchTypeScriptGoldenBytes(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	if got := mintDesktopAuthCode(cfg, DesktopUser{UnionID: "on_abc", Name: "王小明"}, goldenPending(), goldenNow, &counterReader{}); got != goldenDesktopAuthCode {
		t.Errorf("auth code mismatch:\n got %s\nwant %s", got, goldenDesktopAuthCode)
	}
	session := goldenSession(t)
	if session.AccessToken != goldenDesktopAccess {
		t.Errorf("access mismatch:\n got %s\nwant %s", session.AccessToken, goldenDesktopAccess)
	}
	if session.RefreshToken != goldenDesktopRefresh {
		t.Errorf("refresh mismatch:\n got %s\nwant %s", session.RefreshToken, goldenDesktopRefresh)
	}
}

func TestDesktopIdentityDerivationsMatchTypeScript(t *testing.T) {
	t.Parallel()
	if got := CloudProfileIDFor("on_abc", "local-1"); got != "dcp_bb92b274ec70a09c6bd5e574" {
		t.Errorf("cloud profile id = %s", got)
	}
	if got := PersonalOrgFor("on_abc"); got != (DesktopOrgSummary{OrgID: "personal_daef15c6848b5390", Name: "Personal", Role: "Owner"}) {
		t.Errorf("personal org = %+v", got)
	}
	emails := map[string]string{
		"on_abc":                "on_abc@users.botmux.local",
		"a b\U0001F600c.d":      "a_b__c.d@users.botmux.local", // astral char = two UTF-16 units
		"":                      "user@users.botmux.local",
		strings.Repeat("滕", 70): strings.Repeat("_", 64) + "@users.botmux.local",
		strings.Repeat("x", 80): strings.Repeat("x", 64) + "@users.botmux.local",
	}
	for input, want := range emails {
		if got := SyntheticEmail(input); got != want {
			t.Errorf("SyntheticEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMintDesktopSessionShape(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Now()
	s := MintDesktopSessionAt(cfg, DesktopSessionInput{UnionID: "u1", Name: "N", LocalProfileID: "lp"}, now)
	if !strings.Contains(s.AccessToken, ".") || !strings.Contains(s.RefreshToken, ".") {
		t.Fatal("tokens must be signed tokens")
	}
	if s.ExpiresAt != (now.Unix()+DesktopAccessTTLSec)*1000 {
		t.Fatalf("expiresAt = %d", s.ExpiresAt)
	}
	if s.Cloud.UserID != "u1" || !strings.HasPrefix(s.Cloud.CloudProfileID, "dcp_") || s.Cloud.Email != "u1@users.botmux.local" {
		t.Fatalf("cloud = %+v", s.Cloud)
	}
	org := PersonalOrgFor("u1")
	if s.Cloud.ActiveOrgID != org.OrgID || s.Cloud.ActiveOrgName != "Personal" || len(s.Organizations) != 1 || s.Organizations[0] != org {
		t.Fatalf("org = %+v %+v", s.Cloud, s.Organizations)
	}
	if !s.Capabilities.Flags.RelayUse {
		t.Fatal("relay.use must follow RelaySigningSecret")
	}
	disabled := cfg
	disabled.RelaySigningSecret = ""
	if MintDesktopSessionAt(disabled, DesktopSessionInput{UnionID: "u1", Name: "N", LocalProfileID: "lp"}, now).Capabilities.Flags.RelayUse {
		t.Fatal("relay.use must be false without relay signing secret")
	}

	access, err := VerifyDesktopAccessTokenAt(cfg, s.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := VerifyDesktopRefreshTokenAt(cfg, s.RefreshToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if access.SID != refresh.SID || len(access.SID) != 24 || access.JTI == refresh.JTI || len(access.JTI) != 24 {
		t.Fatalf("access=%+v refresh=%+v", access, refresh)
	}
	if refresh.Exp-refresh.Iat != DesktopRefreshTTLSec || access.Exp-access.Iat != DesktopAccessTTLSec {
		t.Fatalf("ttl access=%d refresh=%d", access.Exp-access.Iat, refresh.Exp-refresh.Iat)
	}
}

func TestDesktopSessionJSONKeyOrder(t *testing.T) {
	t.Parallel()
	s := goldenSession(t)
	marshal := func(v any) []byte {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // same as server writeJSON
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	raw := marshal(s.Capabilities)
	want := `{"flags":{"share":true,"team":true,"share.create":true,"share.manage":true,"relay.use":true,"team.member":true,"enterprise.sso":true},"refreshedAt":1700000000123}`
	if string(raw) != want {
		t.Fatalf("capabilities JSON:\n got %s\nwant %s", raw, want)
	}
	raw = marshal(s.Cloud)
	// encoding/json always escapes U+2028; JSON.stringify emits it raw. Both
	// decode identically, and only signed payloads need byte equality.
	wantCloud := "{\"cloudProfileId\":\"dcp_bb92b274ec70a09c6bd5e574\",\"userId\":\"on_abc\",\"email\":\"on_abc@users.botmux.local\",\"displayName\":\"N<>&\\u2028\",\"activeOrgId\":\"personal_daef15c6848b5390\",\"activeOrgName\":\"Personal\",\"linkedAt\":1700000000123}"
	if string(raw) != wantCloud {
		t.Fatalf("cloud JSON:\n got %s\nwant %s", raw, wantCloud)
	}
}

func TestMintDesktopSessionPinsPersonalOrgAndKeepsRefreshIdentity(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	org := PersonalOrgFor("u-alice")
	s := MintDesktopSession(cfg, DesktopSessionInput{
		UnionID: "u-alice", Name: "Alice", LocalProfileID: "lp", ActiveOrgID: "evil-org",
		CloudProfileID: "dcp_cloud_profile", LinkedAt: 1_700_000_000_000, SessionID: "desktop-session-family-1",
	})
	access, err := VerifyDesktopAccessToken(cfg, s.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if access.ActiveOrgID != org.OrgID || access.CloudProfileID != "dcp_cloud_profile" || access.LinkedAt != 1_700_000_000_000 || access.SID != "desktop-session-family-1" {
		t.Fatalf("access = %+v", access)
	}
}

func TestDesktopTokenKeysAreIsolated(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Now()
	forged := DesktopAccessPayload{
		Kind: desktopAccessKind, SID: "sid-forged-000000", UnionID: "u-forged", Name: "Forged",
		LocalProfileID: "local-forged", ActiveOrgID: PersonalOrgFor("u-forged").OrgID,
		CloudProfileID: "dcp_forged", LinkedAt: now.UnixMilli(), Iat: now.Unix(), JTI: "jti", Exp: now.Unix() + 3600,
	}
	bare := mustIssueCompat(forged.compatJSON(), cfg.SigningSecret)
	if _, err := VerifyDesktopAccessToken(cfg, bare); err == nil {
		t.Fatal("a token signed with the bare signing secret must not verify")
	}
	s := MintDesktopSession(cfg, DesktopSessionInput{UnionID: "u-isolated", Name: "Isolated", LocalProfileID: "local-isolated"})
	if _, err := VerifyDesktopRefreshToken(cfg, s.AccessToken); err == nil {
		t.Fatal("access must not verify as refresh")
	}
	if _, err := VerifyDesktopAccessToken(cfg, s.RefreshToken); err == nil {
		t.Fatal("refresh must not verify as access")
	}
	code := MintDesktopAuthCode(cfg, DesktopUser{UnionID: "u", Name: "n"}, goldenPending())
	if _, err := VerifyDesktopAccessToken(cfg, code); err == nil {
		t.Fatal("auth code must not verify as access")
	}
}

func TestDesktopAuthCodeRoundTripAndExpiry(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Unix(1_800_000_000, 0)
	code := MintDesktopAuthCodeAt(cfg, DesktopUser{UnionID: "u", Name: "n"}, goldenPending(), now)
	payload, err := VerifyDesktopAuthCodeAt(cfg, code, now)
	if err != nil {
		t.Fatal(err)
	}
	if payload.State != goldenPending().State || payload.Exp != now.Unix()+DesktopAuthCodeTTLSec || len(payload.JTI) != 16 || payload.LinkedAt != now.UnixMilli() {
		t.Fatalf("payload = %+v", payload)
	}
	if _, err := VerifyDesktopAuthCodeAt(cfg, code, now.Add(DesktopAuthCodeTTLSec*time.Second)); err != nil {
		t.Fatal("exp == now is still valid for generic signed tokens")
	}
	if _, err := VerifyDesktopAuthCodeAt(cfg, code, now.Add((DesktopAuthCodeTTLSec+1)*time.Second)); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired code err = %v", err)
	}
	// A code with a malformed jti is refused even with a valid signature.
	bad := DesktopAuthCodePayload{Kind: desktopAuthCodeKind, JTI: "short", Exp: now.Unix() + 60}
	if _, err := VerifyDesktopAuthCodeAt(cfg, mustIssueCompat(bad.compatJSON(), desktopTokenKey(cfg, desktopAuthCodeKind)), now); err == nil {
		t.Fatal("malformed jti must be rejected")
	}
}

func TestDesktopSessionRejectsMalformedSID(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Now()
	for _, sid := range []string{"short", strings.Repeat("a", 65), "has space in it!!"} {
		payload := DesktopAccessPayload{Kind: desktopAccessKind, SID: sid, Exp: now.Unix() + 60}
		token := mustIssueCompat(payload.compatJSON(), desktopTokenKey(cfg, desktopAccessKind))
		if _, err := VerifyDesktopAccessTokenAt(cfg, token, now); err == nil {
			t.Errorf("sid %q must be rejected", sid)
		}
	}
}

func TestVerifyPKCES256(t *testing.T) {
	t.Parallel()
	verifier := randomB64URL(t, 32)
	if !VerifyPKCES256(verifier, codeChallengeS256(verifier)) {
		t.Fatal("valid verifier rejected")
	}
	if VerifyPKCES256(verifier, codeChallengeS256(verifier+"x")) {
		t.Fatal("wrong verifier accepted")
	}
	spaced := strings.Repeat("a", 42) + " "
	if VerifyPKCES256(spaced, codeChallengeS256(spaced)) {
		t.Fatal("verifier outside the unreserved set must be rejected")
	}
	if VerifyPKCES256(strings.Repeat("a", 42), codeChallengeS256(strings.Repeat("a", 42))) {
		t.Fatal("verifier shorter than 43 must be rejected")
	}
	if VerifyPKCES256(verifier, strings.Repeat("a", 44)) {
		t.Fatal("challenge must be 43 chars")
	}
}

func TestIsAllowedDesktopRedirectURI(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{
		"http://127.0.0.1:41234/auth/callback",
		"http://localhost:1/auth/callback",
		"http://[::1]:65535/auth/callback",
		"HTTP://LOCALHOST:5000/auth/callback",
	} {
		if !IsAllowedDesktopRedirectURI(ok) {
			t.Errorf("%s must be allowed", ok)
		}
	}
	for _, bad := range []string{
		"https://evil.example/auth/callback",
		"http://127.0.0.1/auth/callback",
		"http://127.0.0.1:80/auth/callback",
		"http://127.0.0.2:41234/auth/callback",
		"http://127.0.0.1:41234/auth/callback?next=/evil",
		"http://127.0.0.1:41234/auth/callback#frag",
		"http://user@127.0.0.1:41234/auth/callback",
		"http://user:pw@127.0.0.1:41234/auth/callback",
		"http://127.0.0.1:41234/auth/callback/",
		"http://127.0.0.1:41234/other",
		"http://127.0.0.1:70000/auth/callback",
		"https://127.0.0.1:41234/auth/callback",
		"not a url",
		"",
	} {
		if IsAllowedDesktopRedirectURI(bad) {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

func TestIsAllowedDesktopClientIDReadsEnvironment(t *testing.T) {
	if !IsAllowedDesktopClientID(DesktopClientID) || IsAllowedDesktopClientID("other") {
		t.Fatal("default allowlist is botmux-desktop only")
	}
	t.Setenv("BOTMUX_DESKTOP_CLIENT_IDS", " a , ,b ")
	if !IsAllowedDesktopClientID("a") || !IsAllowedDesktopClientID("b") || IsAllowedDesktopClientID(DesktopClientID) || IsAllowedDesktopClientID("") {
		t.Fatal("env allowlist must replace the default")
	}
}

func TestParseDesktopAuthorizeQuery(t *testing.T) {
	t.Parallel()
	base := func() url.Values {
		return url.Values{
			"client_id":             {DesktopClientID},
			"response_type":         {"code"},
			"redirect_uri":          {"http://127.0.0.1:41234/auth/callback"},
			"state":                 {"state"},
			"nonce":                 {"nonce"},
			"code_challenge":        {codeChallengeS256(strings.Repeat("a", 43))},
			"code_challenge_method": {"S256"},
			"local_profile_id":      {"local-1"},
		}
	}
	pending, err := ParseDesktopAuthorizeQuery(base())
	if err != nil {
		t.Fatal(err)
	}
	if pending.ClientID != DesktopClientID || pending.CodeChallengeMethod != "S256" || pending.LocalProfileID != "local-1" {
		t.Fatalf("pending = %+v", pending)
	}
	trimmed := base()
	trimmed.Set("state", "\u00a0 state \ufeff")
	if pending, err := ParseDesktopAuthorizeQuery(trimmed); err != nil || pending.State != "state" {
		t.Fatalf("JS trim semantics: %+v %v", pending, err)
	}

	cases := []struct {
		field, value string
		want         DesktopAuthorizeError
	}{
		{"client_id", "other", DesktopAuthorizeInvalidClient},
		{"client_id", "", DesktopAuthorizeInvalidClient},
		{"response_type", "token", DesktopAuthorizeUnsupportedResponseType},
		{"redirect_uri", "https://evil.example/auth/callback", DesktopAuthorizeInvalidRedirectURI},
		{"state", "", DesktopAuthorizeInvalidState},
		{"state", strings.Repeat("s", 257), DesktopAuthorizeInvalidState},
		{"nonce", strings.Repeat("n", 257), DesktopAuthorizeInvalidNonce},
		{"code_challenge", strings.Repeat("a", 44), DesktopAuthorizeInvalidCodeChallenge},
		{"code_challenge_method", "plain", DesktopAuthorizeInvalidCodeChallengeMethod},
		{"local_profile_id", strings.Repeat("l", 129), DesktopAuthorizeInvalidLocalProfileID},
	}
	for _, c := range cases {
		q := base()
		q.Set(c.field, c.value)
		_, err := ParseDesktopAuthorizeQuery(q)
		if err != c.want {
			t.Errorf("%s=%q: err=%v want %v", c.field, c.value, err, c.want)
		}
	}
	// 256 UTF-16 units of CJK (768 UTF-8 bytes) is still a valid state.
	cjk := base()
	cjk.Set("state", strings.Repeat("滕", 256))
	if _, err := ParseDesktopAuthorizeQuery(cjk); err != nil {
		t.Fatalf("length must be measured in UTF-16 units: %v", err)
	}
}

func TestParseBearer(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Bearer abc.def":     "abc.def",
		"bearer   abc":       "abc",
		"  BEARER\tabc  ":    "abc",
		"Bearer\xa0abc":      "abc", // latin1 NBSP is JS whitespace
		"Bearer abc def":     "",
		"Bearer":             "",
		"Bearer ":            "",
		"Bearerabc":          "",
		"Basic abc":          "",
		"":                   "",
		"Bearer \xc2\xa0abc": "", // UTF-8 NBSP decodes to U+00C2 U+00A0 under latin1
	}
	for input, want := range cases {
		if got := ParseBearer(input); got != want {
			t.Errorf("ParseBearer(%q) = %q, want %q", input, got, want)
		}
	}
}
