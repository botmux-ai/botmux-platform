package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// A device-login platform through the real grant handler and the real vault
// dispatch. Every vault check runs before the provider on every grant, so
// revoking, narrowing consent, leaving the team or needing re-authorization
// refuses the very next grant without asking the provider for anything (a
// provider may serve a cached token, so it must never be the last check).

type deviceGrantEnv struct {
	*grantTestEnv
	// records are the stored records the provider was asked to mint from.
	records []credential.Record
}

func newDeviceGrantEnv(t *testing.T) *deviceGrantEnv {
	t.Helper()
	env := &deviceGrantEnv{grantTestEnv: newGrantTestEnv(t)}
	env.device.set(func(f *fakeDeviceLogin) {
		f.mint = func(rec credential.Record) credential.MintResult {
			env.records = append(env.records, rec)
			return credential.MintResult{OK: true, Variables: credential.Variables{{Name: "DEVICE_CLI_TOKEN", Value: "t"}}, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
		}
	})
	env.apex.Credentials.Mint = nil
	env.apex.Credentials.Providers.Keys = credential.StaticKeySource(env.keys)
	env.authorize("u-bob", testDevicePlatform, nil)
	return env
}

func (e *deviceGrantEnv) mints() int {
	e.device.mu.Lock()
	defer e.device.mu.Unlock()
	return e.device.minted
}

func (e *deviceGrantEnv) grantBob() (int, string) {
	e.t.Helper()
	r := e.grant(grantBody("u-bob", string(testDevicePlatform)), e.token(), "")
	return r.Code, r.Body.String()
}

func (e *deviceGrantEnv) warm() {
	e.t.Helper()
	if code, body := e.grantBob(); code != http.StatusOK {
		e.t.Fatalf("grant = %d %s", code, body)
	}
	if got := e.mints(); got != 1 {
		e.t.Fatalf("provider minted %d times, want 1", got)
	}
}

func (e *deviceGrantEnv) expectRefusedWithoutMint(status int, errorCode string) {
	e.t.Helper()
	code, raw := e.grantBob()
	var body map[string]any
	_ = json.Unmarshal([]byte(raw), &body)
	if code != status || body["error"] != errorCode {
		e.t.Fatalf("grant = %d %s, want %d %s", code, raw, status, errorCode)
	}
	if got := e.mints(); got != 1 {
		e.t.Fatalf("a refused grant reached the provider (%d mints)", got)
	}
}

func TestDeviceLoginGrantNeverOutlivesTheVaultChecks(t *testing.T) {
	t.Run("credential deleted", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.warm()
		if err := env.apex.CredentialStore.Delete(context.Background(), "u-bob", testDevicePlatform); err != nil {
			t.Fatal(err)
		}
		env.expectRefusedWithoutMint(http.StatusNotFound, "credential_not_found")
	})
	t.Run("consent narrowed to another team", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.warm()
		if err := env.apex.CredentialStore.SetConsent(context.Background(), "u-bob", testDevicePlatform, store.ConsentToTeams([]string{"t-other"})); err != nil {
			t.Fatal(err)
		}
		env.expectRefusedWithoutMint(http.StatusForbidden, "consent_missing")
	})
	t.Run("left the shared team", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.warm()
		// Bob shares two teams with the machine owner (g1 and the base fixture's t2).
		for _, team := range []string{"g1", "t2"} {
			if err := env.repo.RemoveTeamMember(context.Background(), team, "u-bob"); err != nil {
				t.Fatal(err)
			}
		}
		env.expectRefusedWithoutMint(http.StatusForbidden, "not_teammate")
	})
	t.Run("marked for re-authorization", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.warm()
		doc, err := env.apex.CredentialStore.Get(context.Background(), "u-bob", testDevicePlatform)
		if err != nil {
			t.Fatal(err)
		}
		env.apex.CredentialStore.MarkReauthRequired(context.Background(), doc.ID, "login revoked upstream", nil)
		env.expectRefusedWithoutMint(http.StatusConflict, "credential_reauth_required")
	})
	t.Run("the provider sees a re-authorized login", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.warm()
		env.authorize("u-bob", testDevicePlatform, nil)
		if code, body := env.grantBob(); code != http.StatusOK {
			t.Fatalf("grant = %d %s", code, body)
		}
		if len(env.records) != 2 || env.records[0].Sealed == env.records[1].Sealed || env.records[1].Platform != string(testDevicePlatform) {
			t.Fatalf("minted from %+v", env.records)
		}
	})
	t.Run("an unlinked platform is invalid", func(t *testing.T) {
		env := newDeviceGrantEnv(t)
		env.apex.Credentials.Providers.DeviceLogins = nil
		code, raw := env.grantBob()
		if code != http.StatusBadRequest || raw != `{"error":"invalid"}` {
			t.Fatalf("grant = %d %s", code, raw)
		}
	})
}
