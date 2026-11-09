package auth

import (
	"context"
	"errors"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Machine access decisions: the single entry point (DESIGN-machine-comanager.md
// §5.2). Every "may this person use this machine" check that co-managers
// should pass goes through ResolveMachineAccess/LookupMachineAccess; tunnel
// self-registration, bind, unbind, upgrade, rename and the device chain
// deliberately stay owner-only and do not call it.
//
// The owner (doc.UnionID) always has full access and is never downgraded by
// a coManagers entry. A co-manager gets the scopes of their entry, always a
// subset of the owner's; a viewer entry gets ViewerScopes only. Everyone else
// is denied.
//
// Fail-closed: when MongoDB is degraded, co-manager decisions are rejected
// (like the device chain) and never fall back to the in-memory tunnel
// registry, which has no coManagers at all.

// ComanagerMax is the maximum number of co-managers per machine. It is the
// semantic bound of "co-management": machines dozens of people need belong
// to team sharing.
const ComanagerMax = 20

// ComanagerDefaultScopes is the default co-manager grant: view machine, view
// sessions, take over the terminal; not dashboard:manage (fresh slice).
func ComanagerDefaultScopes() []string {
	return []string{store.DeviceScopeMachinesRead, store.DeviceScopeSessionsOpen, store.DeviceScopeTerminalControl}
}

// ComanagerGrantableScopes is the full set of scopes grantable to a
// co-manager (fresh slice). self:refresh is a device-only scope and never
// grantable. dashboard:manage only takes effect on machines whose botmux
// understands it (older machines ignore X-Botmux-Scopes).
func ComanagerGrantableScopes() []string {
	return []string{store.DeviceScopeMachinesRead, store.DeviceScopeSessionsOpen, store.DeviceScopeTerminalControl, store.DeviceScopeDashboardManage}
}

// OwnerHostScopes is the scope list reported for the owner, also injected
// by the reverse proxy as X-Botmux-Scopes (fresh slice).
func OwnerHostScopes() []string {
	return []string{store.DeviceScopeMachinesRead, store.DeviceScopeSessionsOpen, store.DeviceScopeTerminalControl, store.DeviceScopeDashboardManage}
}

// IsComanagerGrantableScope reports whether scope may be granted to a
// co-manager.
func IsComanagerGrantableScope(scope string) bool {
	return containsString(ComanagerGrantableScopes(), scope)
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// MachineRole is the role of an allowed machine access.
type MachineRole string

const (
	MachineRoleOwner     MachineRole = "owner"
	MachineRoleCoManager MachineRole = "co-manager"
	// MachineRoleViewer is the read-only grant: dashboard, session board and
	// terminal output. The reverse proxy restricts it to an explicit read
	// allowlist (ViewerDashboardRequestAllowed) and injects the daemon's
	// guest role, so it never inherits the legacy-owner treatment that
	// owners and co-managers get.
	MachineRoleViewer MachineRole = "viewer"
)

// ViewerScopes is the scope list of a viewer grant (fresh slice). It is fixed
// rather than stored: a viewer entry's stored scopes are ignored, so a stale
// or hand-edited entry can never widen it.
func ViewerScopes() []string {
	return []string{store.DeviceScopeMachinesRead}
}

// IsViewer reports whether an allowed access is the read-only viewer role.
func IsViewer(access MachineAccess) bool {
	return access.OK && access.Role == MachineRoleViewer
}

// MachineAccess is a machine access decision. When OK is false the other
// fields are empty. Entry is set for co-managers only.
type MachineAccess struct {
	OK     bool
	Role   MachineRole
	Scopes []string
	Entry  *store.MachineCoManager
}

// ResolveMachineAccess decides role and scopes for unionID on doc. A nil doc,
// an empty unionID, or a non-ACTIVE machine (RETIRED tombstone; a missing
// status means a pre-migration ACTIVE document) is denied, owner included.
// Stored co-manager scopes are intersected with the currently grantable set
// so a stale or hand-edited entry cannot over-grant; an entry left with no
// scopes is denied.
func ResolveMachineAccess(doc *store.MachineDoc, unionID string) MachineAccess {
	if doc == nil || unionID == "" {
		return MachineAccess{}
	}
	if doc.Status != "" && doc.Status != store.MachineStatusActive {
		return MachineAccess{}
	}
	if doc.UnionID == unionID {
		return MachineAccess{OK: true, Role: MachineRoleOwner, Scopes: OwnerHostScopes()}
	}
	for i := range doc.CoManagers {
		entry := doc.CoManagers[i]
		if entry.UnionID != unionID {
			continue
		}
		switch entry.Role {
		case store.CoManagerRoleViewer:
			entry.Scopes = append([]string(nil), entry.Scopes...)
			return MachineAccess{OK: true, Role: MachineRoleViewer, Scopes: ViewerScopes(), Entry: &entry}
		case "", store.CoManagerRoleManager:
		default:
			// Unknown grant kind (newer writer, corrupted document): deny
			// rather than guess it means the more powerful legacy role.
			return MachineAccess{}
		}
		scopes := []string{}
		for _, scope := range entry.Scopes {
			if IsComanagerGrantableScope(scope) {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) == 0 {
			return MachineAccess{}
		}
		entry.Scopes = append([]string(nil), entry.Scopes...)
		return MachineAccess{OK: true, Role: MachineRoleCoManager, Scopes: scopes, Entry: &entry}
	}
	return MachineAccess{}
}

// AccessHasScope reports whether an allowed access carries scope (always
// true for the owner).
func AccessHasScope(access MachineAccess, scope string) bool {
	return access.OK && containsString(access.Scopes, scope)
}

// AccessCanControlTerminal decides the injected X-Botmux-Role: the owner
// always may, a co-manager needs terminal:control.
func AccessCanControlTerminal(access MachineAccess) bool {
	return AccessHasScope(access, store.DeviceScopeTerminalControl)
}

// AccessCanUseDaemonAPI decides whether the person may call the machine's
// daemon API through the platform OpenAPI (sessions:open). This is only the
// platform-side gate; the machine checks the injected scopes again.
func AccessCanUseDaemonAPI(access MachineAccess) bool {
	return AccessHasScope(access, store.DeviceScopeSessionsOpen)
}

// MachineLookup is the store dependency of LookupMachineAccess. LookupMachine
// returns store.ErrNotFound for a missing machine and any other error when
// the authority cannot be read.
type MachineLookup interface {
	LookupMachine(ctx context.Context, machineID string, opts store.AuthorityCacheOptions) (store.MachineDoc, error)
}

// ErrMachineAccessDenied means the person has no access to the machine (or
// it does not exist / is retired): 403/404.
var ErrMachineAccessDenied = errors.New("machine access denied")

// LookupMachineAccess reads the machine record and decides access in one
// step, keeping "store unavailable" (store.ErrUnavailable or the context
// error: 503, retry later) strictly apart from ErrMachineAccessDenied, so a
// database hiccup never looks like a revoked permission. It never falls back
// to in-memory tunnel ownership.
func LookupMachineAccess(ctx context.Context, lookup MachineLookup, machineID, unionID string, opts store.AuthorityCacheOptions) (MachineAccess, store.MachineDoc, error) {
	if lookup == nil {
		return MachineAccess{}, store.MachineDoc{}, store.ErrUnavailable
	}
	doc, err := lookup.LookupMachine(ctx, machineID, opts)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return MachineAccess{}, store.MachineDoc{}, ErrMachineAccessDenied
	case err != nil:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return MachineAccess{}, store.MachineDoc{}, ctxErr
		}
		return MachineAccess{}, store.MachineDoc{}, store.ErrUnavailable
	}
	access := ResolveMachineAccess(&doc, unionID)
	if !access.OK {
		return MachineAccess{}, store.MachineDoc{}, ErrMachineAccessDenied
	}
	return access, doc, nil
}
