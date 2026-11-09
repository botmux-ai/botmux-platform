package store

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrNotFound    = errors.New("store: not found")
	ErrConflict    = errors.New("store: conflict")
	ErrUnavailable = errors.New("store: unavailable")
	// ErrReplayed reports that a one-time token (desktop auth code, proxy
	// ticket) was already consumed. It wraps ErrConflict.
	ErrReplayed = fmt.Errorf("%w: already consumed", ErrConflict)
)

// UserRepository persists user profile snapshots.
type UserRepository interface {
	UpsertUserProfile(context.Context, UserProfile) error
	GetUserProfiles(context.Context, []string) (map[string]UserProfile, error)
}

// MachineRepository is the authoritative machines collection contract.
// Callers must not translate ErrUnavailable into an authoritative empty result.
type MachineRepository interface {
	// BindMachineCAS claims machineID for unionID (see BindResult).
	BindMachineCAS(ctx context.Context, machineID, unionID, ownerName string) (BindResult, error)
	// RetireMachine turns the document into a RETIRED tombstone.
	RetireMachine(ctx context.Context, machineID string) error
	PersistRegister(context.Context, RegisterMachine) error
	PersistHeartbeat(context.Context, string, HeartbeatUpdate) error
	ListMachinesForUser(context.Context, string) ([]MachineDoc, error)
	ListMachinesForTeam(context.Context, string) ([]MachineDoc, error)
	ListMachinesForUsers(ctx context.Context, unionIDs []string) ([]MachineDoc, error)
	ListMachinesCoManagedBy(ctx context.Context, unionID string) ([]MachineDoc, error)
	ListMachineVersionSamples(ctx context.Context) ([]MachineVersionSample, error)
	GetMachine(context.Context, string) (MachineDoc, error)
	LookupMachine(ctx context.Context, machineID string, opts AuthorityCacheOptions) (MachineDoc, error)
	RenameMachine(context.Context, string, string) error
	SetMachineCoManagers(ctx context.Context, machineID, ownerUnionID string, coManagers []MachineCoManager) error
	DropCoManagerFromTeamMachines(ctx context.Context, teamID, unionID string) ([]string, error)
	RemoveMachineFromTeamBots(context.Context, string) error
}

// TeamRepository is the authoritative teams collection contract.
type TeamRepository interface {
	CreateTeam(context.Context, TeamDoc) error
	AddTeamMember(context.Context, string, string) error
	RemoveTeamMember(context.Context, string, string) error
	UpdateTeamBots(context.Context, string, []TeamBotRef, []TeamBotRef) error
	AddTeamGroupChat(context.Context, string, string) error
	CompareAndSetTeamHallChat(context.Context, string, string, string) (bool, error)
	GetTeams(context.Context, []string) (map[string]TeamDoc, error)
	ListTeamsForUser(context.Context, string) ([]TeamDoc, error)
	GetTeam(context.Context, string) (TeamDoc, error)
	AddPendingInvite(context.Context, string, PendingInvite) error
	RemovePendingInvite(context.Context, string, string) error
	PrunePendingInvites(context.Context, string, int64, []string) error
	UpdateTeamAdmins(ctx context.Context, teamID string, adminUnionIDs []string, known *TeamDoc) ([]string, error)
	UpdateTeamIssueSettings(ctx context.Context, teamID string, patch TeamIssueSettingsPatch) error
	RenameTeam(context.Context, string, string) error
	DeleteTeam(context.Context, string) error
	RemoveUserBotsFromTeam(context.Context, string, []string) error
}

// Repository is the authoritative machine/user/team persistence contract.
// Callers must not translate ErrUnavailable into an authoritative empty result.
type Repository interface {
	UserRepository
	MachineRepository
	TeamRepository
}

// DeviceRepository is the devices / device_grants contract. MongoDB is the
// only authority for the device chain and every operation is fail-closed:
// ErrUnavailable must make callers reject (503), never fall back.
type DeviceRepository interface {
	CreateDevice(ctx context.Context, doc DeviceDoc) error
	GetDevice(ctx context.Context, deviceID string) (DeviceDoc, error)
	ListDevicesForUser(ctx context.Context, unionID string) ([]DeviceDoc, error)
	RevokeDevice(ctx context.Context, deviceID, unionID string) error
	ForceRevokeDevice(ctx context.Context, deviceID string) (bool, error)
	RotateDeviceRefresh(ctx context.Context, in RotateDeviceRefreshInput) (RotateRefreshOutcome, error)
	TouchDeviceLastSeen(ctx context.Context, deviceID string, atMS int64) error

	CreateDeviceGrant(ctx context.Context, doc DeviceGrantDoc) error
	GetDeviceGrant(ctx context.Context, grantID string) (DeviceGrantDoc, error)
	ApproveDeviceGrant(ctx context.Context, grantID, ownerUnionID, deviceID string, nowMS int64) error
	DenyDeviceGrant(ctx context.Context, grantID, ownerUnionID string, nowMS int64) error
	VoidApprovedDeviceGrant(ctx context.Context, grantID string, nowMS int64) error
	ConsumeDeviceGrant(ctx context.Context, grantID, pollSecretHash string, nowMS int64) error
}

// DesktopSessionRepository holds the desktop session-family revocation fence
// and the single-use fences for desktop auth codes and proxy tickets.
type DesktopSessionRepository interface {
	RevokeDesktopSessionFamily(ctx context.Context, sessionID string, expiresAtMS int64) error
	GetDesktopSessionFamilyStatus(ctx context.Context, sessionID string, opts AuthorityCacheOptions) (DesktopFamilyStatus, error)
	ConsumeDesktopAuthCode(ctx context.Context, codeID string, expiresAtMS int64) error
	ConsumeProxyTicket(ctx context.Context, ticketID string, expiresAtMS int64) error
}
