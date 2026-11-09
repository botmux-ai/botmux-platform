package auth

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	goldenOAuthState      = "eyJraW5kIjoib2F1dGgtc3RhdGUiLCJub25jZSI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIiwibmV4dCI6Ii8iLCJzZWFyY2hTY29wZSI6dHJ1ZSwiZGVza3RvcCI6eyJjbGllbnRJZCI6ImJvdG11eC1kZXNrdG9wIiwicmVkaXJlY3RVcmkiOiJodHRwOi8vMTI3LjAuMC4xOjQ1Njc4L2F1dGgvY2FsbGJhY2siLCJjb2RlQ2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwic3RhdGUiOiJzdDwmPuKAqCIsIm5vbmNlIjoibm9uY2UtMSIsImxvY2FsUHJvZmlsZUlkIjoibG9jYWwtZGVmYXVsdCJ9LCJjcmVkZW50aWFsIjoibGFyay1jbGkiLCJleHAiOjE3MDAwMDA2MDB9.A-VASkV0PHbyklQCjFsUqsreIRWlKbF133SWF4fEX1U"
	goldenOAuthStatePlain = "eyJraW5kIjoib2F1dGgtc3RhdGUiLCJub25jZSI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmIiwibmV4dCI6Ii90ZWFtcz94PTEiLCJleHAiOjE3MDAwMDA2MDB9.6Ityal3OQtJdXZu3vQIDelwsalM_gDFH-56gEDGJ2Og"
)

func cookieNonce(t *testing.T, setCookie string) string {
	t.Helper()
	first := strings.SplitN(setCookie, ";", 2)[0]
	parts := strings.SplitN(first, "=", 2)
	if len(parts) != 2 || parts[0] != OAuthStateCookieName {
		t.Fatalf("unexpected cookie %q", setCookie)
	}
	return parts[1]
}

func stateFromURL(t *testing.T, raw string) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state"), u.Query()
}

func TestOAuthStateMatchesTypeScriptGoldenBytes(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	pending := goldenPending()
	full := buildAuthorizeRedirect(cfg, "/teams?x=1", AuthorizeOptions{
		Desktop: &pending, SearchScope: true, Credential: OAuthCredentialLarkCLI,
	}, goldenNow, &counterReader{})
	if state, _ := stateFromURL(t, full.URL); state != goldenOAuthState {
		t.Fatalf("state mismatch:\n got %s\nwant %s", state, goldenOAuthState)
	}

	// The golden state omits searchScope, so the scope string is passed whole.
	plain := buildAuthorizeRedirect(cfg, "/teams?x=1", AuthorizeOptions{
		Scope: FeishuSearchScope + " offline_access docx:document:readonly",
	}, goldenNow, &counterReader{})
	wantURL := "https://open.feishu.test/open-apis/authen/v1/authorize?app_id=cli_app%7E*" +
		"&redirect_uri=https%3A%2F%2Fplatform.test%2Fauth%2Fcallback&state=" + goldenOAuthStatePlain +
		"&scope=contact%3Auser%3Asearch+offline_access+docx%3Adocument%3Areadonly"
	if plain.URL != wantURL {
		t.Fatalf("authorize URL mismatch:\n got %s\nwant %s", plain.URL, wantURL)
	}
	if plain.StateCookie != "botmux_oauth_state=000102030405060708090a0b0c0d0e0f; Path=/auth; HttpOnly; Max-Age=600; SameSite=Lax" {
		t.Fatalf("cookie = %s", plain.StateCookie)
	}
	secure := cfg
	secure.CookieSecure = true
	if got := buildAuthorizeRedirect(secure, "/", AuthorizeOptions{}, goldenNow, &counterReader{}).StateCookie; !strings.HasSuffix(got, "; SameSite=None; Secure") {
		t.Fatalf("secure cookie = %s", got)
	}
}

func TestOAuthStateKeepsWebSSOAndRoundTripsDesktopClaims(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	web := BuildAuthorizeRedirect(cfg, "//evil.example", AuthorizeOptions{})
	webState, query := stateFromURL(t, web.URL)
	verified, err := VerifyState(cfg, webState, cookieNonce(t, web.StateCookie))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*verified, VerifiedOAuthState{Next: "/"}) {
		t.Fatalf("verified = %+v", verified)
	}
	if _, err := VerifyState(cfg, webState, "wrong-cookie"); err == nil {
		t.Fatal("cookie nonce mismatch must be rejected")
	}
	if _, err := VerifyState(cfg, webState, ""); err != nil {
		t.Fatalf("missing cookie falls back to signature-only: %v", err)
	}
	// A plain login requests no scope at all (no confirmation dialog).
	if _, ok := query["scope"]; ok {
		t.Fatalf("plain login must not request a scope: %s", web.URL)
	}

	desktop := DesktopAuthPending{
		ClientID: DesktopClientID, RedirectURI: "http://127.0.0.1:45678/auth/callback",
		CodeChallenge: codeChallengeS256(strings.Repeat("x", 43)), CodeChallengeMethod: "S256",
		State: randomB64URL(t, 32), Nonce: randomB64URL(t, 32), LocalProfileID: "local-default",
	}
	redirect := BuildAuthorizeRedirect(cfg, "/ignored", AuthorizeOptions{Desktop: &desktop})
	desktopState, _ := stateFromURL(t, redirect.URL)
	verified, err = VerifyState(cfg, desktopState, cookieNonce(t, redirect.StateCookie))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Next != "/" || verified.SearchScope || verified.Credential != "" || verified.Desktop == nil || *verified.Desktop != desktop {
		t.Fatalf("verified = %+v", verified)
	}
	if len(redirect.URL) >= 2048 {
		t.Fatalf("authorize URL too long: %d", len(redirect.URL))
	}
}

func TestOAuthStateSearchScopeAndCredentialVariants(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	search := BuildAuthorizeRedirect(cfg, "/teams", AuthorizeOptions{SearchScope: true})
	state, query := stateFromURL(t, search.URL)
	if query.Get("scope") != FeishuSearchScope {
		t.Fatalf("scope = %q", query.Get("scope"))
	}
	verified, err := VerifyState(cfg, state, cookieNonce(t, search.StateCookie))
	if err != nil || !verified.SearchScope || verified.Next != "/teams" {
		t.Fatalf("verified = %+v err = %v", verified, err)
	}

	credential := BuildAuthorizeRedirect(cfg, "/credentials", AuthorizeOptions{Credential: OAuthCredentialLarkCLI, Scope: "  offline_access  "})
	state, query = stateFromURL(t, credential.URL)
	if query.Get("scope") != "offline_access" {
		t.Fatalf("credential scope = %q", query.Get("scope"))
	}
	verified, err = VerifyState(cfg, state, "")
	if err != nil || verified.Credential != OAuthCredentialLarkCLI || verified.SearchScope || verified.Desktop != nil {
		t.Fatalf("verified = %+v err = %v", verified, err)
	}

	blank := BuildAuthorizeRedirect(cfg, "/", AuthorizeOptions{Scope: " \t"})
	if _, query := stateFromURL(t, blank.URL); query.Has("scope") {
		t.Fatal("whitespace-only scope must be omitted")
	}
}

func TestOAuthStateExpiryAndSignature(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Unix(1_800_000_000, 0)
	redirect := buildAuthorizeRedirect(cfg, "/x", AuthorizeOptions{}, now, defaultRandom)
	state, _ := stateFromURL(t, redirect.URL)
	if _, err := VerifyStateAt(cfg, state, "", now.Add(oauthStateTTLSeconds*time.Second)); err != nil {
		t.Fatalf("exp == now is still valid: %v", err)
	}
	if _, err := VerifyStateAt(cfg, state, "", now.Add((oauthStateTTLSeconds+1)*time.Second)); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired state err = %v", err)
	}
	other := cfg
	other.SigningSecret = "other"
	if _, err := VerifyStateAt(other, state, "", now); err == nil {
		t.Fatal("state must be bound to the signing secret")
	}
}

func TestLegacyOAuthStateHelpers(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	state, cookie, err := IssueOAuthState(cfg, "https://evil.example")
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifyOAuthState(cfg, state, cookieNonce(t, cookie))
	if err != nil || next != "/" {
		t.Fatalf("next = %q err = %v", next, err)
	}
	state, cookie, _ = IssueOAuthState(cfg, "/teams/1")
	if next, err := VerifyOAuthState(cfg, state, cookieNonce(t, cookie)); err != nil || next != "/teams/1" {
		t.Fatalf("next = %q err = %v", next, err)
	}
}
