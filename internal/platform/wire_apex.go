package platform

import httpserver "github.com/botmux-ai/botmux-platform/internal/server"

// wireApex completes the apex routes that are not a separate module (login,
// fresh-SSO gate, mobile sessions, co-managers). Owned by Phase 2 agent B5b.
func wireApex(env wireEnv, apex *httpserver.Apex) error {
	return nil
}
