package platform

import (
	"context"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// sharingLogin records the token store it was bound to.
type sharingLogin struct {
	credential.DeviceLogin
	tokens credential.TokenStore
}

func (l sharingLogin) WithTokenStore(tokens credential.TokenStore) credential.DeviceLogin {
	l.tokens = tokens
	return l
}

type plainLogin struct{ credential.DeviceLogin }

// Device logins that can share tokens are bound to the coordination store
// when one is configured, and only then.
func TestWireCredentialsSharesTokensThroughTheCoordinationStore(t *testing.T) {
	kv := store.NewKVStore(store.NewMemoryKV(), "sandbox", 0, 0)
	logins := []credential.DeviceLogin{sharingLogin{}, plainLogin{}}
	for _, tc := range []struct {
		name   string
		addr   string
		shared bool
	}{
		{"coordination configured", "redis://redis:6379", true},
		{"single pod", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apex := &httpserver.Apex{}
			env := wireEnv{cfg: config.Config{CoordinationAddr: tc.addr}, kv: kv, deviceLogins: logins}
			if err := wireCredentials(env, apex); err != nil {
				t.Fatal(err)
			}
			got := apex.Credentials.Providers.DeviceLogins
			if len(got) != 2 {
				t.Fatalf("device logins = %d", len(got))
			}
			bound := got[0].(sharingLogin).tokens
			if tc.shared {
				if bound == nil {
					t.Fatal("the sharing login was not bound to the coordination store")
				}
				if err := bound.SetToken(context.Background(), "k", "v", time.Minute); err != nil {
					t.Fatal(err)
				}
				if v, _ := kv.GetToken(context.Background(), "k"); v != "v" {
					t.Fatal("bound to something other than the coordination store")
				}
			} else if bound != nil {
				t.Fatal("a single pod must keep tokens in process")
			}
			if _, ok := got[1].(plainLogin); !ok {
				t.Fatalf("a login that cannot share was replaced: %T", got[1])
			}
			if _, ok := logins[0].(sharingLogin); !ok || logins[0].(sharingLogin).tokens != nil {
				t.Fatal("the edition's device logins were modified in place")
			}
		})
	}
}
