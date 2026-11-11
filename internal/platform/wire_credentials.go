package platform

import (
	"github.com/botmux-ai/botmux-platform/internal/credential"
	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
)

// wireCredentials fills apex.Credentials (credential providers, vault keys).
// Owned by Phase 2 agent B3.
//
// The vault store itself (apex.CredentialStore) is wired by platform.go on the
// durable provider, which in memory mode is UnavailableDatabaseProvider: the
// TS vault has no in-memory fallback, so every credential route answers 503
// store_unavailable instead of keeping secrets in process memory.
func wireCredentials(env wireEnv, apex *httpserver.Apex) error {
	deviceLogins := env.deviceLogins
	if env.cfg.CoordinationAddr != "" && env.kv != nil {
		deviceLogins = shareTokens(env.deviceLogins, env.kv)
	}
	apex.Credentials.Providers = credential.Providers{
		Config: env.cfg,
		// The KEK is read once at boot; legacy keys stay readable for
		// envelopes sealed before a rotation.
		Keys:         credential.ConfigKeySource(env.cfg),
		Feishu:       env.feishu,
		DeviceLogins: deviceLogins,
	}
	return nil
}

// shareTokens binds every device login that can share minted tokens across
// pods to the coordination store. Only a configured coordination store is
// shared: the single-pod MemoryKV would duplicate the in-process token caches
// and never prunes an entry that is not read again.
func shareTokens(logins []credential.DeviceLogin, tokens credential.TokenStore) []credential.DeviceLogin {
	out := make([]credential.DeviceLogin, len(logins))
	for i, login := range logins {
		if sharer, ok := login.(credential.SharesTokens); ok {
			login = sharer.WithTokenStore(tokens)
		}
		out[i] = login
	}
	return out
}
