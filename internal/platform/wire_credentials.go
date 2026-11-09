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
	apex.Credentials.Providers = credential.Providers{
		Config: env.cfg,
		// The KEK is read once at boot; legacy keys stay readable for
		// envelopes sealed before a rotation.
		Keys:         credential.ConfigKeySource(env.cfg),
		Feishu:       env.feishu,
		DeviceLogins: env.deviceLogins,
	}
	return nil
}
