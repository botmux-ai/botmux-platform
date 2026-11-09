package platform

import (
	"context"
	"errors"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

type machineTokenVerifier struct{ cfg config.Config }

// NewMachineTokenVerifier adapts the compatibility token implementation to
// the tunnel server's deliberately small verification interface.
func NewMachineTokenVerifier(cfg config.Config) tunnel.MachineTokenVerifier {
	return machineTokenVerifier{cfg: cfg}
}

func (v machineTokenVerifier) VerifyMachineToken(token string) (*tunnel.MachineClaims, bool) {
	payload, err := auth.VerifyMachineToken(v.cfg, token)
	if err != nil {
		return nil, false
	}
	issuedAt := int64(0)
	if payload.IAT != nil {
		issuedAt = *payload.IAT
	}
	return &tunnel.MachineClaims{
		MachineID: payload.MachineID,
		UnionID:   payload.UnionID,
		OwnerName: payload.OwnerName,
		IssuedAt:  issuedAt,
	}, true
}

type machinePersistence struct{ repository store.Repository }

// NewMachinePersistence adapts live tunnel models to the durable store
// models. It intentionally excludes DashboardToken, DirectHosts, Control and
// TeamSyncRev because those values are pod-local connection state or secrets.
func NewMachinePersistence(repository store.Repository) tunnel.MachinePersistence {
	return machinePersistence{repository: repository}
}

// ignoreNoActiveMachine treats "no matching ACTIVE document owned by the
// token's owner" as the legacy silent no-op: register/heartbeat never create
// documents or resurrect RETIRED tombstones, and that is not a dependency
// failure worth a warning.
func ignoreNoActiveMachine(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (p machinePersistence) PersistRegister(ctx context.Context, machine tunnel.MachineConn) error {
	if p.repository == nil {
		return store.ErrUnavailable
	}
	return ignoreNoActiveMachine(p.repository.PersistRegister(ctx, store.RegisterMachine{
		MachineID:     machine.MachineID,
		UnionID:       machine.UnionID,
		OwnerName:     machine.OwnerName,
		Name:          machine.Name,
		BotmuxVersion: machine.BotmuxVersion,
		DashboardPort: machine.DashboardPort,
		Memberships:   toStoreMemberships(machine.Memberships),
		Bots:          toStoreBots(machine.Bots),
		LastSeen:      machine.LastSeen.UnixMilli(),
	}))
}

func (p machinePersistence) PersistHeartbeat(ctx context.Context, machineID string, message tunnel.DaemonMessage, lastSeen time.Time) error {
	if p.repository == nil {
		return store.ErrUnavailable
	}
	update := store.HeartbeatUpdate{LastSeen: lastSeen.UnixMilli()}
	if message.BotmuxVersion != "" {
		version := message.BotmuxVersion
		update.BotmuxVersion = &version
	}
	// A nil slice means the daemon omitted the field; a non-nil empty slice
	// explicitly clears the stored value. Preserve that wire distinction.
	if message.Memberships != nil {
		memberships := toStoreMemberships(message.Memberships)
		update.Memberships = &memberships
	}
	if message.Bots != nil {
		bots := toStoreBots(message.Bots)
		update.Bots = &bots
	}
	return ignoreNoActiveMachine(p.repository.PersistHeartbeat(ctx, machineID, update))
}

func toStoreMemberships(values []tunnel.MembershipInfo) []store.MembershipInfo {
	if values == nil {
		return nil
	}
	out := make([]store.MembershipInfo, len(values))
	for i, value := range values {
		out[i] = store.MembershipInfo{TeamID: value.TeamID, TeamName: value.TeamName}
	}
	return out
}

func toStoreBots(values []tunnel.BotInfo) []store.BotInfo {
	if values == nil {
		return nil
	}
	out := make([]store.BotInfo, len(values))
	for i, value := range values {
		out[i] = store.BotInfo{
			AppID:      value.AppID,
			OpenID:     cloneString(value.OpenID),
			Name:       value.Name,
			Avatar:     value.Avatar,
			CLI:        value.CLI,
			ShowInTeam: cloneBool(value.ShowInTeam),
			UnionID:    value.UnionID,
			// Node persists the reported bot verbatim; keep the discovery
			// labels so the agent directory and /api/machines see them.
			Specialties: cloneSpecialties(value.Specialties),
			Mentionable: cloneBool(value.Mentionable),
		}
	}
	return out
}

func cloneSpecialties(values tunnel.Specialties) store.BotSpecialties {
	if values == nil {
		return nil
	}
	return append(store.BotSpecialties{}, values...)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

var (
	_ tunnel.MachineTokenVerifier = machineTokenVerifier{}
	_ tunnel.MachinePersistence   = machinePersistence{}
)
