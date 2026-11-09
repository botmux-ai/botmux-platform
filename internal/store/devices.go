package store

import (
	"context"
	"errors"
	"time"
)

// Device scopes. Changing a device's scopes requires credentialVersion++.
const (
	DeviceScopeMachinesRead    = "machines:read"
	DeviceScopeSessionsOpen    = "sessions:open"
	DeviceScopeTerminalControl = "terminal:control"
	DeviceScopeDashboardManage = "dashboard:manage"
	DeviceScopeSelfRefresh     = "self:refresh"
)

// DeviceMVPScopes returns the fixed MVP scope set (fresh slice).
func DeviceMVPScopes() []string {
	return []string{DeviceScopeMachinesRead, DeviceScopeSessionsOpen, DeviceScopeTerminalControl, DeviceScopeSelfRefresh}
}

// MobileDeviceScopes returns the mobile scope set: the MVP set plus the
// explicit owner dashboard capability (fresh slice). Older mobile devices
// without dashboard:manage must re-bind through fresh SSO.
func MobileDeviceScopes() []string { return append(DeviceMVPScopes(), DeviceScopeDashboardManage) }

// Device kinds.
const (
	DeviceKindDesktopIDE = "desktop-ide"
	DeviceKindMobile     = "mobile"
	DeviceKindBrowser    = "browser"
)

// Device status values.
const (
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
)

// Device approval channels.
const (
	DeviceApprovedViaFeishuConfirm = "f1-feishu-confirm"
	DeviceApprovedViaDeviceCode    = "f2-device-code"
	DeviceApprovedViaSSOMobile     = "sso-mobile"
)

// DeviceDoc mirrors the devices collection. Timestamps are Unix milliseconds.
type DeviceDoc struct {
	ID        string `json:"deviceId" bson:"_id"`
	UnionID   string `json:"unionId" bson:"unionId"`
	OwnerName string `json:"ownerName" bson:"ownerName"`
	// DeviceKind is one of DeviceKind*.
	DeviceKind string `json:"deviceKind" bson:"deviceKind"`
	// DeviceName is self-reported; UIs must label it as such.
	DeviceName string `json:"deviceName" bson:"deviceName"`
	// Scopes are authoritative: access tokens and derived tickets take their
	// effective scopes from here.
	Scopes            []string `json:"scopes" bson:"scopes"`
	CredentialVersion int64    `json:"credentialVersion" bson:"credentialVersion,truncate"`
	// Status is DeviceStatusActive or DeviceStatusRevoked.
	Status string `json:"status" bson:"status"`
	// Refresh token family: signed claims {deviceId, familyId, generation,
	// jti, credentialVersion, exp}. Re-enroll switches familyId.
	RefreshFamilyID   string `json:"refreshFamilyId" bson:"refreshFamilyId"`
	RefreshGeneration int64  `json:"refreshGeneration" bson:"refreshGeneration,truncate"`
	// RefreshTokenHash is the sha256 hex of the current refresh token.
	RefreshTokenHash string `json:"refreshTokenHash" bson:"refreshTokenHash"`
	// PrevRefreshTokenHash keeps one previous generation for exact replay.
	PrevRefreshTokenHash string `json:"prevRefreshTokenHash,omitempty" bson:"prevRefreshTokenHash,omitempty"`
	// RefreshCurrentJTI plus the other fields deterministically re-signs the
	// current refresh token byte-for-byte (no plaintext storage).
	RefreshCurrentJTI string `json:"refreshCurrentJti" bson:"refreshCurrentJti"`
	// RefreshRetryKeyHash is the hashed Idempotency-Key of the last rotation.
	RefreshRetryKeyHash string `json:"refreshRetryKeyHash" bson:"refreshRetryKeyHash"`
	RefreshRotatedAt    int64  `json:"refreshRotatedAt" bson:"refreshRotatedAt,truncate"`
	// ReplayUntil is rotation time + replay window; set only by a real
	// rotation, never sliding.
	ReplayUntil int64 `json:"replayUntil" bson:"replayUntil,truncate"`
	EnrolledAt  int64 `json:"enrolledAt" bson:"enrolledAt,truncate"`
	// DeviceExp is the absolute device expiry (enroll + 90d); refresh
	// rotation never extends it.
	DeviceExp  int64 `json:"deviceExp" bson:"deviceExp,truncate"`
	LastSeenAt int64 `json:"lastSeenAt" bson:"lastSeenAt,truncate"`
	// ApprovedVia is one of DeviceApprovedVia*.
	ApprovedVia string `json:"approvedVia" bson:"approvedVia"`
}

// jsNumberBSON reproduces the Node BSON serializer's choice for a JS number:
// integers in int32 range are stored as int32, everything else as a double.
func jsNumberBSON(v int64) any { return jsNumber(float64(v)) }

// deviceInsertDocument keeps the TS field order and Node BSON number types.
// insertOne stores the handlers' object-literal order, in which replayUntil
// precedes refreshRotatedAt (src/server/devices.ts, both issue paths).
type deviceInsertDocument struct {
	ID                   string   `bson:"_id"`
	UnionID              string   `bson:"unionId"`
	OwnerName            string   `bson:"ownerName"`
	DeviceKind           string   `bson:"deviceKind"`
	DeviceName           string   `bson:"deviceName"`
	Scopes               []string `bson:"scopes"`
	CredentialVersion    any      `bson:"credentialVersion"`
	Status               string   `bson:"status"`
	RefreshFamilyID      string   `bson:"refreshFamilyId"`
	RefreshGeneration    any      `bson:"refreshGeneration"`
	RefreshTokenHash     string   `bson:"refreshTokenHash"`
	PrevRefreshTokenHash string   `bson:"prevRefreshTokenHash,omitempty"`
	RefreshCurrentJTI    string   `bson:"refreshCurrentJti"`
	RefreshRetryKeyHash  string   `bson:"refreshRetryKeyHash"`
	ReplayUntil          any      `bson:"replayUntil"`
	RefreshRotatedAt     any      `bson:"refreshRotatedAt"`
	EnrolledAt           any      `bson:"enrolledAt"`
	DeviceExp            any      `bson:"deviceExp"`
	LastSeenAt           any      `bson:"lastSeenAt"`
	ApprovedVia          string   `bson:"approvedVia"`
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// CreateDevice inserts a new device document. Devices are persisted before
// any token is issued: ErrConflict (duplicate id) or ErrUnavailable must make
// the caller refuse to issue tokens.
func (s *DocumentRepository) CreateDevice(ctx context.Context, d DeviceDoc) error {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return err
	}
	return normalizeDBError(c.InsertOne(ctx, deviceInsertDocument{
		ID: d.ID, UnionID: d.UnionID, OwnerName: d.OwnerName, DeviceKind: d.DeviceKind, DeviceName: d.DeviceName,
		Scopes: nonNilStrings(d.Scopes), CredentialVersion: jsNumberBSON(d.CredentialVersion), Status: d.Status,
		RefreshFamilyID: d.RefreshFamilyID, RefreshGeneration: jsNumberBSON(d.RefreshGeneration),
		RefreshTokenHash: d.RefreshTokenHash, PrevRefreshTokenHash: d.PrevRefreshTokenHash,
		RefreshCurrentJTI: d.RefreshCurrentJTI, RefreshRetryKeyHash: d.RefreshRetryKeyHash,
		RefreshRotatedAt: jsNumberBSON(d.RefreshRotatedAt), ReplayUntil: jsNumberBSON(d.ReplayUntil),
		EnrolledAt: jsNumberBSON(d.EnrolledAt), DeviceExp: jsNumberBSON(d.DeviceExp),
		LastSeenAt: jsNumberBSON(d.LastSeenAt), ApprovedVia: d.ApprovedVia,
	}))
}

// GetDevice reads one device: ErrNotFound when it does not exist,
// ErrUnavailable when the store is degraded (callers answer 503).
func (s *DocumentRepository) GetDevice(ctx context.Context, deviceID string) (DeviceDoc, error) {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return DeviceDoc{}, err
	}
	var out DeviceDoc
	if err := c.FindOne(ctx, Document{"_id": deviceID}, &out); err != nil {
		return DeviceDoc{}, normalizeDBError(err)
	}
	return out, nil
}

// ListDevicesForUser lists every device (any status) of unionID.
func (s *DocumentRepository) ListDevicesForUser(ctx context.Context, unionID string) ([]DeviceDoc, error) {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return nil, err
	}
	out := []DeviceDoc{}
	if err := c.FindMany(ctx, Document{"unionId": unionID}, &out); err != nil {
		return nil, normalizeDBError(err)
	}
	return out, nil
}

// RevokeDevice revokes a device owned by unionID (CAS active -> revoked plus
// credentialVersion++). It is idempotent: an already revoked device owned by
// unionID succeeds. ErrNotFound covers a missing device or one owned by
// someone else (ownership is part of the CAS, so no cross-user revocation).
func (s *DocumentRepository) RevokeDevice(ctx context.Context, deviceID, unionID string) error {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": deviceID, "unionId": unionID, "status": DeviceStatusActive},
		Document{"$set": Document{"status": DeviceStatusRevoked}, "$inc": Document{"credentialVersion": int32(1)}}, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched > 0 {
		return nil
	}
	var doc DeviceDoc
	if err := c.FindOne(ctx, Document{"_id": deviceID}, &doc); err != nil {
		return normalizeDBError(err)
	}
	if doc.UnionID != unionID || doc.Status != DeviceStatusRevoked {
		return ErrNotFound
	}
	return nil
}

// ForceRevokeDevice revokes a device without an ownership condition (refresh
// reuse detection). revokedNow is true only when this call performed the
// active -> revoked transition, so exactly one alarm is sent; an already
// revoked or missing device reports false.
func (s *DocumentRepository) ForceRevokeDevice(ctx context.Context, deviceID string) (bool, error) {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return false, err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": deviceID, "status": DeviceStatusActive},
		Document{"$set": Document{"status": DeviceStatusRevoked}, "$inc": Document{"credentialVersion": int32(1)}}, false)
	if err != nil {
		return false, normalizeDBError(err)
	}
	return r.Matched > 0, nil
}

// RotateRefreshResult classifies a refresh rotation attempt. The store only
// provides the mechanism; the protocol layer maps results to policy.
type RotateRefreshResult string

const (
	// RotateRotated is the only write path: generation+1 with the new hash.
	RotateRotated RotateRefreshResult = "rotated"
	// RotateCurrentWithinWindow: the current token was presented again inside
	// the replay window; nothing is written and the caller re-signs the
	// current refresh token from Device.RefreshCurrentJTI.
	RotateCurrentWithinWindow RotateRefreshResult = "current_within_window"
	// RotateExactReplay: previous token + previous generation + same
	// Idempotency-Key inside the window (lost response recovery).
	RotateExactReplay RotateRefreshResult = "exact_replay"
	// RotateRefreshInProgress: previous token with a different key inside the
	// window (409; no token, no revoke, no write).
	RotateRefreshInProgress RotateRefreshResult = "refresh_in_progress"
	// RotateReplayExpired: previous token outside the window.
	RotateReplayExpired RotateRefreshResult = "replay_expired"
	// RotateStaleGeneration: a genuine older generation (reuse detection).
	RotateStaleGeneration RotateRefreshResult = "stale_generation"
	RotateInvalid         RotateRefreshResult = "invalid"
	RotateRevoked         RotateRefreshResult = "revoked"
	RotateExpired         RotateRefreshResult = "expired"
	RotateNotFound        RotateRefreshResult = "not_found"
)

// DefaultRefreshReplayWindowMS is the rotation replay/debounce window.
const DefaultRefreshReplayWindowMS int64 = 60_000

// RotateDeviceRefreshInput is the presented refresh token state plus the new
// token material for a rotation.
type RotateDeviceRefreshInput struct {
	DeviceID            string
	PresentedHash       string
	PresentedGeneration int64
	RetryKeyHash        string
	NewHash             string
	NewJTI              string
	NowMS               int64
	// ReplayWindowMS defaults to DefaultRefreshReplayWindowMS when <= 0.
	ReplayWindowMS int64
}

// RotateRefreshOutcome carries the classification and, for rotated /
// current_within_window / exact_replay, the device document.
type RotateRefreshOutcome struct {
	Result RotateRefreshResult
	Device *DeviceDoc
}

func classifyRefresh(doc DeviceDoc, in RotateDeviceRefreshInput) RotateRefreshOutcome {
	now := in.NowMS
	if doc.Status != DeviceStatusActive {
		return RotateRefreshOutcome{Result: RotateRevoked}
	}
	if now > doc.DeviceExp {
		return RotateRefreshOutcome{Result: RotateExpired}
	}
	if doc.RefreshTokenHash == in.PresentedHash && doc.RefreshGeneration == in.PresentedGeneration {
		if now <= doc.ReplayUntil {
			return RotateRefreshOutcome{Result: RotateCurrentWithinWindow, Device: &doc}
		}
		return RotateRefreshOutcome{Result: RotateInvalid}
	}
	isPrev := doc.PrevRefreshTokenHash != "" && doc.PrevRefreshTokenHash == in.PresentedHash &&
		in.PresentedGeneration == doc.RefreshGeneration-1
	if isPrev {
		if now > doc.ReplayUntil {
			return RotateRefreshOutcome{Result: RotateReplayExpired}
		}
		if doc.RefreshRetryKeyHash == in.RetryKeyHash {
			return RotateRefreshOutcome{Result: RotateExactReplay, Device: &doc}
		}
		return RotateRefreshOutcome{Result: RotateRefreshInProgress}
	}
	if in.PresentedGeneration < doc.RefreshGeneration {
		return RotateRefreshOutcome{Result: RotateStaleGeneration}
	}
	return RotateRefreshOutcome{Result: RotateInvalid}
}

// RotateDeviceRefresh performs the single CAS rotation: only when the
// presented token is the current generation, the device is active and
// unexpired, and the replay window has passed (now > replayUntil). Every
// other path is a read-only classification and never causes a second state
// transition. Store failures return ErrUnavailable.
func (s *DocumentRepository) RotateDeviceRefresh(ctx context.Context, in RotateDeviceRefreshInput) (RotateRefreshOutcome, error) {
	window := in.ReplayWindowMS
	if window <= 0 {
		window = DefaultRefreshReplayWindowMS
	}
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return RotateRefreshOutcome{}, err
	}
	now := in.NowMS
	var rotated DeviceDoc
	err = c.FindOneAndUpdate(ctx,
		Document{
			"_id": in.DeviceID, "status": DeviceStatusActive,
			"refreshTokenHash": in.PresentedHash, "refreshGeneration": in.PresentedGeneration,
			"deviceExp": Document{"$gte": bsonNumber(now)}, "replayUntil": Document{"$lt": bsonNumber(now)},
		},
		Document{
			"$set": Document{
				"refreshTokenHash": in.NewHash, "prevRefreshTokenHash": in.PresentedHash,
				"refreshCurrentJti": in.NewJTI, "refreshRetryKeyHash": in.RetryKeyHash,
				"refreshRotatedAt": jsNumberBSON(now), "replayUntil": jsNumberBSON(now + window),
				"lastSeenAt": jsNumberBSON(now),
			},
			"$inc": Document{"refreshGeneration": int32(1)},
		},
		FindOneAndUpdateOptions{ReturnAfter: true}, &rotated)
	if err == nil {
		return RotateRefreshOutcome{Result: RotateRotated, Device: &rotated}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return RotateRefreshOutcome{}, normalizeDBError(err)
	}
	doc, err := s.GetDevice(ctx, in.DeviceID)
	if errors.Is(err, ErrNotFound) {
		return RotateRefreshOutcome{Result: RotateNotFound}, nil
	}
	if err != nil {
		return RotateRefreshOutcome{}, err
	}
	return classifyRefresh(doc, in), nil
}

// TouchDeviceLastSeen updates the display-only lastSeenAt. It is the only
// best-effort device write; callers typically log and ignore the error.
func (s *DocumentRepository) TouchDeviceLastSeen(ctx context.Context, deviceID string, atMS int64) error {
	c, err := s.collection(ctx, collectionDevices)
	if err != nil {
		return err
	}
	_, err = c.UpdateOne(ctx, Document{"_id": deviceID}, Document{"$set": Document{"lastSeenAt": jsNumberBSON(atMS)}}, false)
	return normalizeDBError(err)
}

// Device grant status values.
const (
	DeviceGrantPending  = "pending"
	DeviceGrantApproved = "approved"
	DeviceGrantDenied   = "denied"
	DeviceGrantExpired  = "expired"
	DeviceGrantConsumed = "consumed"
)

// DeviceGrantKindF1MachineEnroll is the only grant kind so far.
const DeviceGrantKindF1MachineEnroll = "f1-machine-enroll"

// DeviceGrantDoc mirrors the device_grants collection.
type DeviceGrantDoc struct {
	ID   string `json:"grantId" bson:"_id"`
	Kind string `json:"kind" bson:"kind"`
	// UnionID is the approver (machine owner).
	UnionID    string   `json:"unionId" bson:"unionId"`
	MachineID  string   `json:"machineId" bson:"machineId"`
	DeviceKind string   `json:"deviceKind" bson:"deviceKind"`
	DeviceName string   `json:"deviceName" bson:"deviceName"`
	Scopes     []string `json:"scopes" bson:"scopes"`
	// PollSecretHash is the sha256 hex of the CLI poll secret.
	PollSecretHash string `json:"pollSecretHash" bson:"pollSecretHash"`
	Status         string `json:"status" bson:"status"`
	CreatedAt      int64  `json:"createdAt" bson:"createdAt,truncate"`
	// ExpiresAt (ms) is the logical expiry authority.
	ExpiresAt int64 `json:"expiresAt" bson:"expiresAt,truncate"`
	// ExpireAt is the TTL-index Date. CreateDeviceGrant derives it from
	// ExpiresAt; it is only populated on reads.
	ExpireAt  time.Time `json:"expireAt" bson:"expireAt"`
	DecidedAt int64     `json:"decidedAt,omitempty" bson:"decidedAt,omitempty,truncate"`
	// DeviceID is pre-allocated on approval.
	DeviceID string `json:"deviceId,omitempty" bson:"deviceId,omitempty"`
}

type deviceGrantInsertDocument struct {
	ID             string    `bson:"_id"`
	Kind           string    `bson:"kind"`
	UnionID        string    `bson:"unionId"`
	MachineID      string    `bson:"machineId"`
	DeviceKind     string    `bson:"deviceKind"`
	DeviceName     string    `bson:"deviceName"`
	Scopes         []string  `bson:"scopes"`
	PollSecretHash string    `bson:"pollSecretHash"`
	Status         string    `bson:"status"`
	CreatedAt      any       `bson:"createdAt"`
	ExpiresAt      any       `bson:"expiresAt"`
	ExpireAt       time.Time `bson:"expireAt"`
	DecidedAt      any       `bson:"decidedAt,omitempty"`
	DeviceID       string    `bson:"deviceId,omitempty"`
}

// CreateDeviceGrant inserts a grant (ErrConflict on duplicate id).
func (s *DocumentRepository) CreateDeviceGrant(ctx context.Context, g DeviceGrantDoc) error {
	c, err := s.collection(ctx, collectionDeviceGrants)
	if err != nil {
		return err
	}
	doc := deviceGrantInsertDocument{
		ID: g.ID, Kind: g.Kind, UnionID: g.UnionID, MachineID: g.MachineID, DeviceKind: g.DeviceKind,
		DeviceName: g.DeviceName, Scopes: nonNilStrings(g.Scopes), PollSecretHash: g.PollSecretHash, Status: g.Status,
		CreatedAt: jsNumberBSON(g.CreatedAt), ExpiresAt: jsNumberBSON(g.ExpiresAt), ExpireAt: msTime(g.ExpiresAt),
		DeviceID: g.DeviceID,
	}
	if g.DecidedAt != 0 {
		doc.DecidedAt = jsNumberBSON(g.DecidedAt)
	}
	return normalizeDBError(c.InsertOne(ctx, doc))
}

// GetDeviceGrant reads one grant (ErrNotFound / ErrUnavailable).
func (s *DocumentRepository) GetDeviceGrant(ctx context.Context, grantID string) (DeviceGrantDoc, error) {
	c, err := s.collection(ctx, collectionDeviceGrants)
	if err != nil {
		return DeviceGrantDoc{}, err
	}
	var out DeviceGrantDoc
	if err := c.FindOne(ctx, Document{"_id": grantID}, &out); err != nil {
		return DeviceGrantDoc{}, normalizeDBError(err)
	}
	return out, nil
}

// grantCAS applies one purpose-specific transition. The expiry check lives in
// the same atomic filter, so an approval/consume racing the expiry instant can
// never both pass. Results: nil, ErrConflict (precondition failed) or
// ErrUnavailable.
func (s *DocumentRepository) grantCAS(ctx context.Context, filter, set Document) error {
	c, err := s.collection(ctx, collectionDeviceGrants)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx, filter, Document{"$set": set}, false)
	if err != nil {
		err = normalizeDBError(err)
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			err = ErrUnavailable
		}
		return err
	}
	if r.Matched == 0 {
		return ErrConflict
	}
	return nil
}

// ApproveDeviceGrant: pending + owned by ownerUnionID + unexpired -> approved
// with the pre-allocated deviceID.
func (s *DocumentRepository) ApproveDeviceGrant(ctx context.Context, grantID, ownerUnionID, deviceID string, nowMS int64) error {
	return s.grantCAS(ctx,
		Document{"_id": grantID, "status": DeviceGrantPending, "unionId": ownerUnionID, "expiresAt": Document{"$gt": bsonNumber(nowMS)}},
		Document{"status": DeviceGrantApproved, "deviceId": deviceID, "decidedAt": jsNumberBSON(nowMS)})
}

// DenyDeviceGrant: pending + owned by ownerUnionID + unexpired -> denied.
func (s *DocumentRepository) DenyDeviceGrant(ctx context.Context, grantID, ownerUnionID string, nowMS int64) error {
	return s.grantCAS(ctx,
		Document{"_id": grantID, "status": DeviceGrantPending, "unionId": ownerUnionID, "expiresAt": Document{"$gt": bsonNumber(nowMS)}},
		Document{"status": DeviceGrantDenied, "decidedAt": jsNumberBSON(nowMS)})
}

// VoidApprovedDeviceGrant is the server-side integrity action for an approved
// but not yet redeemed grant (e.g. ownership re-check failed before issuing):
// approved -> denied, without owner or expiry conditions.
func (s *DocumentRepository) VoidApprovedDeviceGrant(ctx context.Context, grantID string, nowMS int64) error {
	return s.grantCAS(ctx,
		Document{"_id": grantID, "status": DeviceGrantApproved},
		Document{"status": DeviceGrantDenied, "decidedAt": jsNumberBSON(nowMS)})
}

// ConsumeDeviceGrant redeems a grant exactly once on CLI poll: approved +
// matching poll secret hash + unexpired -> consumed.
func (s *DocumentRepository) ConsumeDeviceGrant(ctx context.Context, grantID, pollSecretHash string, nowMS int64) error {
	return s.grantCAS(ctx,
		Document{"_id": grantID, "status": DeviceGrantApproved, "pollSecretHash": pollSecretHash, "expiresAt": Document{"$gt": bsonNumber(nowMS)}},
		Document{"status": DeviceGrantConsumed})
}
