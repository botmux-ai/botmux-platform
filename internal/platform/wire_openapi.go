package platform

import (
	"net/http"

	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
)

// wireOpenAPI fills apex.OpenAPI, apex.Stats and apex.MachineGroups (external
// OpenAPI, version dashboard, daemon group creation and agent directory).
// Owned by Phase 2 agent B4.
func wireOpenAPI(env wireEnv, apex *httpserver.Apex) error {
	machine := env.machine
	apex.OpenAPI = httpserver.OpenAPIDeps{
		VerifyJWT: env.openAPIVerifier,
		// The rewritten upgrade carries the machine-subdomain Host and the
		// owner proxy cookie, so the machine handler treats it exactly like
		// the platform UI opening a terminal or dashboard socket.
		// TODO(B5a): pass surface once the machine handler routes the
		// terminal subdomain separately (handleMachineWs(..., surface)).
		MachineWS: func(w http.ResponseWriter, r *http.Request, machineID, _ string) {
			machine.ServeMachine(w, r, machineID)
		},
	}
	apex.Stats = httpserver.StatsDeps{State: httpserver.NewVersionStatsState()}
	apex.MachineGroups = httpserver.MachineGroupsDeps{Throttle: httpserver.NewMachineGroupThrottle()}
	return nil
}
