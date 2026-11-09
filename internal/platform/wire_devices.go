package platform

import httpserver "github.com/botmux-ai/botmux-platform/internal/server"

// wireDevices fills apex.Devices and apex.Desktop (device protocol, desktop
// PKCE and desktop dashboard). Owned by Phase 2 agent B1.
//
// The shared authorities (DeviceRepo, DesktopSessions, DeviceStates,
// DeviceSockets, Repository, Redis, Feishu, Registry) are already on the
// Apex; the modules only add the per-process enroll throttle. Clocks stay nil
// (time.Now) outside tests.
func wireDevices(env wireEnv, apex *httpserver.Apex) error {
	apex.Devices = httpserver.DevicesDeps{EnrollThrottle: httpserver.NewEnrollThrottle()}
	apex.Desktop = httpserver.DesktopDeps{}
	return nil
}
