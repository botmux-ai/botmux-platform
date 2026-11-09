package platform

import (
	"context"
	"errors"
	"fmt"

	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// wireMachine completes the machine-subdomain handler and the tunnel server
// (reserved-header stripping, backend fanout throttle, device proxy WS
// registration). Owned by Phase 2 agent B5a.
//
// The device authorities are the very instances the apex uses: the device
// state cache epochs must be shared so a same-pod revocation trips the
// device-stream epoch fence, and DeviceSocketWatcher.CloseDevice (called by
// the device revocation endpoints) must see the machine subdomain streams.
func wireMachine(env wireEnv, apex *httpserver.Apex, machine *httpserver.MachineHandler, tunnelServer *tunnel.Server) error {
	if apex.DeviceStates == nil || apex.DeviceSockets == nil {
		return fmt.Errorf("wire machine: apex device authorities are not configured")
	}
	machine.DeviceStates = apex.DeviceStates
	machine.DeviceSockets = apex.DeviceSockets
	machine.DesktopSessions = apex.DesktopSessions
	if env.repository != nil {
		machine.Machines = env.repository
		tunnelServer.Machines = machineRegistrationAuthority{repository: env.repository}
	}
	return nil
}

// machineRegistrationAuthority adapts the MachineDoc read to the tunnel's
// registration check. Like getMachineLookup without options it never uses
// the positive cache: registration is rare and must see the latest owner.
type machineRegistrationAuthority struct {
	repository *store.DocumentRepository
}

func (a machineRegistrationAuthority) LookupMachineRecord(ctx context.Context, machineID string) (tunnel.MachineRecord, bool, error) {
	doc, err := a.repository.LookupMachine(ctx, machineID, store.AuthorityCacheOptions{})
	if errors.Is(err, store.ErrNotFound) {
		return tunnel.MachineRecord{}, false, nil
	}
	if err != nil {
		return tunnel.MachineRecord{}, false, err
	}
	return tunnel.MachineRecord{UnionID: doc.UnionID, OwnerName: doc.OwnerName, Status: doc.Status}, true, nil
}

var _ tunnel.MachineAuthority = machineRegistrationAuthority{}
