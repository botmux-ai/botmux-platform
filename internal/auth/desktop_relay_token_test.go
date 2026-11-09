package auth

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func goldenHostKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(100 + i)
	}
	return key
}

func goldenRelayInput() RelayHostInput {
	key := goldenHostKey()
	return RelayHostInput{RelayHostID: RelayHostIDForPublicKey(key), HostPublicKeyB64: base64.StdEncoding.EncodeToString(key)}
}

func TestDesktopRelayTokenMatchesTypeScriptGoldenBytes(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	access, err := VerifyDesktopAccessTokenAt(cfg, goldenDesktopAccess, goldenNow)
	if err != nil {
		t.Fatal(err)
	}
	input := goldenRelayInput()
	if input.RelayHostID != "4-FngL7PYB1V5HUe" {
		t.Fatalf("relay host id = %s", input.RelayHostID)
	}
	got, ok := mintDesktopRelayToken(cfg, access, input, goldenNow, &counterReader{})
	if !ok || got.RelayToken != goldenRelay {
		t.Fatalf("relay token mismatch (ok=%v):\n got %s\nwant %s", ok, got.RelayToken, goldenRelay)
	}
	if got.ExpiresAt != float64((goldenNow.Unix()+600)*1000) {
		t.Fatalf("expiresAt = %v", got.ExpiresAt)
	}

	fractional := cfg
	fractional.RelayTokenTTL = 150500 * time.Millisecond
	got, ok = mintDesktopRelayToken(fractional, access, input, goldenNow, &counterReader{})
	if !ok || got.RelayToken != goldenRelayFractional {
		t.Fatalf("fractional relay token mismatch (ok=%v):\n got %s\nwant %s", ok, got.RelayToken, goldenRelayFractional)
	}
	if got.ExpiresAt != 1700000150500 {
		t.Fatalf("fractional expiresAt = %v", got.ExpiresAt)
	}
	// Like Number.isInteger(exp) in TypeScript, a fractional exp never verifies.
	if _, err := VerifyDesktopRelayTokenAt(fractional, got.RelayToken, goldenNow); err == nil {
		t.Fatal("fractional exp must be rejected")
	}
}

func TestDesktopRelayTokenBindsUserHostAndKey(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	now := time.Now()
	session := MintDesktopSessionAt(cfg, DesktopSessionInput{UnionID: "u-relay", Name: "Relay User", LocalProfileID: "local-relay"}, now)
	access, err := VerifyDesktopAccessTokenAt(cfg, session.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := make([]byte, 32)
	if _, err := rand.Read(hostKey); err != nil {
		t.Fatal(err)
	}
	input := RelayHostInput{RelayHostID: RelayHostIDForPublicKey(hostKey), HostPublicKeyB64: base64.StdEncoding.EncodeToString(hostKey)}
	issued, ok := MintDesktopRelayTokenAt(cfg, access, input, now)
	if !ok || issued.RelayToken == "" || issued.ExpiresAt <= float64(now.UnixMilli()) {
		t.Fatalf("issued = %+v ok=%v", issued, ok)
	}
	payload, err := VerifyDesktopRelayTokenAt(cfg, issued.RelayToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Sub != "u-relay" || payload.RelayHostID != input.RelayHostID || payload.HostPublicKeyB64 != input.HostPublicKeyB64 ||
		payload.Scope != "relay:host" || payload.CloudProfileID != access.CloudProfileID || payload.ActiveOrgID != access.ActiveOrgID {
		t.Fatalf("payload = %+v", payload)
	}
	if _, err := VerifyDesktopRelayTokenAt(cfg, issued.RelayToken, time.Unix(payload.Exp, 0)); err == nil {
		t.Fatal("JWT must be expired at the exact exp boundary")
	}
	if _, err := VerifyDesktopRelayTokenAt(cfg, issued.RelayToken, time.Unix(payload.Exp-1, 0)); err != nil {
		t.Fatalf("one second before exp must verify: %v", err)
	}

	if _, ok := MintDesktopRelayTokenAt(cfg, access, RelayHostInput{RelayHostID: strings.Repeat("A", 16), HostPublicKeyB64: input.HostPublicKeyB64}, now); ok {
		t.Fatal("host id not derived from the key must be refused")
	}
	nonCanonical := strings.TrimSuffix(input.HostPublicKeyB64, "=")
	if _, ok := MintDesktopRelayTokenAt(cfg, access, RelayHostInput{RelayHostID: input.RelayHostID, HostPublicKeyB64: nonCanonical}, now); ok {
		t.Fatal("unpadded key must be refused")
	}

	for name, mutate := range map[string]func(c *struct{ iss, aud, secret string }){
		"issuer":   func(c *struct{ iss, aud, secret string }) { c.iss = "https://other.example" },
		"audience": func(c *struct{ iss, aud, secret string }) { c.aud = "other" },
		"secret":   func(c *struct{ iss, aud, secret string }) { c.secret = "other-secret" },
		"disabled": func(c *struct{ iss, aud, secret string }) { c.secret = "" },
	} {
		values := struct{ iss, aud, secret string }{cfg.RelayTokenIssuer, cfg.RelayTokenAudience, cfg.RelaySigningSecret}
		mutate(&values)
		other := cfg
		other.RelayTokenIssuer, other.RelayTokenAudience, other.RelaySigningSecret = values.iss, values.aud, values.secret
		if _, err := VerifyDesktopRelayTokenAt(other, issued.RelayToken, now); err == nil {
			t.Errorf("%s mismatch must be rejected", name)
		}
	}
}

func TestDesktopRelayTokenFailsClosedWithoutSigningSecret(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	cfg.RelaySigningSecret = ""
	access := &DesktopAccessPayload{UnionID: "u", CloudProfileID: "dcp", ActiveOrgID: "personal_x"}
	if _, ok := MintDesktopRelayToken(cfg, access, goldenRelayInput()); ok {
		t.Fatal("relay mint must be disabled without a relay signing secret")
	}
	if DefaultDesktopCapabilities(cfg.RelaySigningSecret != "").Flags.RelayUse {
		t.Fatal("relay.use capability must be false when relay is disabled")
	}
}

func TestVerifyDesktopRelayTokenRejectsTamperedStructure(t *testing.T) {
	t.Parallel()
	cfg := desktopTestConfig()
	sign := func(header, payload string) string {
		input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		return input + "." + relaySign(input, cfg.RelaySigningSecret)
	}
	input := goldenRelayInput()
	good := `{"iss":"https://platform.example.test","aud":"botmux-relay-test","sub":"u","iat":1,"exp":1700000600,"jti":"j","scope":"relay:host","relayHostId":"` +
		input.RelayHostID + `","hostPublicKeyB64":"` + input.HostPublicKeyB64 + `","cloudProfileId":"c","activeOrgId":"o"}`
	if _, err := VerifyDesktopRelayTokenAt(cfg, sign(`{"alg":"HS256","typ":"JWT"}`, good), goldenNow); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if _, err := VerifyDesktopRelayTokenAt(cfg, sign(`{"typ":"JWT","alg":"HS256"}`, good), goldenNow); err != nil {
		t.Fatalf("header key order must not matter: %v", err)
	}
	bad := map[string][2]string{
		"alg":       {`{"alg":"none","typ":"JWT"}`, good},
		"typ":       {`{"alg":"HS256"}`, good},
		"null":      {`{"alg":"HS256","typ":"JWT"}`, `null`},
		"scope":     {`{"alg":"HS256","typ":"JWT"}`, strings.Replace(good, "relay:host", "relay:admin", 1)},
		"exp-str":   {`{"alg":"HS256","typ":"JWT"}`, strings.Replace(good, `"exp":1700000600`, `"exp":"1700000600"`, 1)},
		"no-exp":    {`{"alg":"HS256","typ":"JWT"}`, strings.Replace(good, `"exp":1700000600,`, ``, 1)},
		"host-id":   {`{"alg":"HS256","typ":"JWT"}`, strings.Replace(good, input.RelayHostID, "AAAAAAAAAAAAAAAA", 1)},
		"not-json":  {`{"alg":"HS256","typ":"JWT"}`, `{`},
		"array":     {`{"alg":"HS256","typ":"JWT"}`, `[]`},
		"iss-array": {`{"alg":"HS256","typ":"JWT"}`, strings.Replace(good, `"https://platform.example.test"`, `["https://platform.example.test"]`, 1)},
	}
	for name, parts := range bad {
		if _, err := VerifyDesktopRelayTokenAt(cfg, sign(parts[0], parts[1]), goldenNow); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if _, err := VerifyDesktopRelayTokenAt(cfg, "a.b", goldenNow); err == nil {
		t.Fatal("two-part token must be rejected")
	}
}
