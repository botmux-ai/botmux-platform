package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Device protocol (src/server/devices.ts; DESIGN-device-pairing.md §3.4/§4):
// F1 enroll / confirm / poll, mobile SSO bind, the rotating refresh and device
// management. Management is SSO-only (D2: a device bearer can never manage
// devices) and every sensitive step requires a fresh SSO session. Every
// response carries Cache-Control: no-store.

const (
	enrollGrantTTLMS int64 = 5 * 60_000
	// deviceLifetimeMS is the absolute device deadline (enroll + 90d); refresh
	// rotation never extends it.
	deviceLifetimeMS int64 = 90 * 24 * 3600 * 1000
	// enrollMinGapMS rate-limits grant creation per machine so a machine token
	// cannot flood the owner with confirmation cards.
	enrollMinGapMS       int64 = 10_000
	enrollPollIntervalMS       = 2000
)

var (
	deviceGrantPattern   = regexp.MustCompile(`^/api/devices/grants/([a-f0-9]{16,64})(?:/(approve|deny))?$`)
	deviceRevokePattern  = regexp.MustCompile(`^/api/devices/(d-[a-f0-9]{16})/revoke$`)
	enrollmentIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	deviceGrantIDPattern = regexp.MustCompile(`^[a-f0-9]{16,64}$`)
)

// DevicesDeps holds device-module seams that are not shared Apex authorities.
type DevicesDeps struct {
	// EnrollThrottle is the per-machine enroll rate limit. Nil falls back to
	// a process-wide throttle, like the TS module-level map.
	EnrollThrottle *EnrollThrottle
	// Now overrides the handler clock (tests); nil means time.Now.
	Now func() time.Time
}

// EnrollThrottle remembers the last successful enroll per machine.
type EnrollThrottle struct {
	mu   sync.Mutex
	last map[string]int64
}

// NewEnrollThrottle returns an empty throttle.
func NewEnrollThrottle() *EnrollThrottle {
	return &EnrollThrottle{last: make(map[string]int64)}
}

var defaultEnrollThrottle = NewEnrollThrottle()

func (t *EnrollThrottle) allowed(machineID string, nowMS int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return nowMS-t.last[machineID] >= enrollMinGapMS
}

func (t *EnrollThrottle) record(machineID string, nowMS int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last[machineID] = nowMS
}

func (a *Apex) devicesNow() time.Time {
	if a.Devices.Now != nil {
		return a.Devices.Now()
	}
	return time.Now()
}

func (a *Apex) enrollThrottle() *EnrollThrottle {
	if a.Devices.EnrollThrottle != nil {
		return a.Devices.EnrollThrottle
	}
	return defaultEnrollThrottle
}

// handleDevicesAPI serves /api/devices and /api/devices/* (self-authenticating).
// It reports whether the request was handled.
func (a *Apex) handleDevicesAPI(w http.ResponseWriter, r *http.Request) bool {
	path, method := r.URL.Path, r.Method
	var serve func()
	switch {
	case path == "/api/devices/refresh" && method == http.MethodPost:
		serve = func() { a.deviceRefresh(w, r) }
	case path == "/api/devices/mobile-bind" && method == http.MethodPost:
		serve = func() { a.deviceMobileBind(w, r) }
	case path == "/api/devices/enroll" && method == http.MethodPost:
		serve = func() { a.deviceEnroll(w, r) }
	case path == "/api/devices/enroll/poll" && method == http.MethodPost:
		serve = func() { a.deviceEnrollPoll(w, r) }
	}
	if serve == nil {
		if match := deviceGrantPattern.FindStringSubmatch(path); match != nil {
			if match[2] == "" && method == http.MethodGet {
				serve = func() { a.deviceGrantGet(w, r, match[1]) }
			} else if match[2] != "" && method == http.MethodPost {
				serve = func() { a.deviceGrantDecision(w, r, match[1], match[2]) }
			}
		}
	}
	if serve == nil && path == "/api/devices" && method == http.MethodGet {
		serve = func() { a.deviceList(w, r) }
	}
	if serve == nil && method == http.MethodPost {
		if match := deviceRevokePattern.FindStringSubmatch(path); match != nil {
			serve = func() { a.deviceRevoke(w, r, match[1]) }
		}
	}
	if serve == nil {
		return false
	}
	// MongoDB is the only device authority: without it nothing may be issued.
	if a.DeviceRepo == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}
	serve()
	return true
}

type deviceErrorWithLogin struct {
	Error    string `json:"error"`
	LoginURL string `json:"loginUrl"`
}

func writeStaleSession(w http.ResponseWriter) {
	writeJSONNoStore(w, http.StatusUnauthorized, deviceErrorWithLogin{Error: "stale_session", LoginURL: "/auth/login"})
}

// writeDevicePrincipalError is sendPrincipalError: conflicting_credentials
// 400, an unreachable device authority 503 store_unavailable, otherwise 401.
func writeDevicePrincipalError(w http.ResponseWriter, err error) {
	var principalErr auth.PrincipalError
	if !errors.As(err, &principalErr) || principalErr == auth.ErrDeviceUnavailable {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if principalErr == auth.ErrConflictingCredentials {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": string(principalErr)})
		return
	}
	writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": string(principalErr)})
}

// freshDeviceManager resolves the fresh-SSO session required by device
// management, writing the error response when there is none.
func (a *Apex) freshDeviceManager(w http.ResponseWriter, r *http.Request) *auth.SessionPayload {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writeDevicePrincipalError(w, err)
		return nil
	}
	session := auth.RequireFreshSSO(principal, a.devicesNow())
	if session == nil {
		writeStaleSession(w)
	}
	return session
}

// ---------------------------------------------------------------------------
// Device management (§3.2: SSO-only + fresh SSO)
// ---------------------------------------------------------------------------

// deviceView is the management DTO: refresh-family internals never leave the
// server. deviceName is self-reported and must be labelled as such.
type deviceView struct {
	DeviceID   string   `json:"deviceId"`
	DeviceKind string   `json:"deviceKind"`
	DeviceName string   `json:"deviceName"`
	Status     string   `json:"status"`
	Scopes     []string `json:"scopes"`
	EnrolledAt int64    `json:"enrolledAt"`
	LastSeenAt int64    `json:"lastSeenAt"`
	DeviceExp  int64    `json:"deviceExp"`
}

// deviceList is GET /api/devices.
func (a *Apex) deviceList(w http.ResponseWriter, r *http.Request) {
	session := a.freshDeviceManager(w, r)
	if session == nil {
		return
	}
	docs, err := a.DeviceRepo.ListDevicesForUser(r.Context(), session.UnionID)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	sort.SliceStable(docs, func(i, j int) bool { return docs[i].EnrolledAt > docs[j].EnrolledAt })
	devices := make([]deviceView, 0, len(docs))
	for _, d := range docs {
		devices = append(devices, deviceView{
			DeviceID: d.ID, DeviceKind: d.DeviceKind, DeviceName: d.DeviceName, Status: d.Status,
			Scopes: d.Scopes, EnrolledAt: d.EnrolledAt, LastSeenAt: d.LastSeenAt, DeviceExp: d.DeviceExp,
		})
	}
	writeJSONNoStore(w, http.StatusOK, struct {
		Devices []deviceView `json:"devices"`
	}{devices})
}

// deviceRevoke is POST /api/devices/:id/revoke: credentialVersion++ so every
// outstanding access token fails within the cache/watcher window (§5).
// Idempotent: an already revoked device answers 200.
func (a *Apex) deviceRevoke(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !a.deviceSameOrigin(r) {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "bad_origin"})
		return
	}
	session := a.freshDeviceManager(w, r)
	if session == nil {
		return
	}
	err := a.DeviceRepo.RevokeDevice(r.Context(), deviceID, session.UnionID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "device_not_found"})
		return
	}
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	a.propagateDeviceRevocation(deviceID, "owner_revoked")
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}

// propagateDeviceRevocation is the same-pod < 1s promise: drop the positive
// cache (bumping its epoch) and then close every device socket on this pod.
// Other pods converge through the cache TTL and their watchers (§5.3).
func (a *Apex) propagateDeviceRevocation(deviceID, reason string) {
	if a.DeviceStates != nil {
		a.DeviceStates.Invalidate(deviceID)
	}
	if a.DeviceSockets != nil {
		a.DeviceSockets.CloseDevice(deviceID, reason)
	}
}

// ---------------------------------------------------------------------------
// Mobile SSO bind (§4-F3)
// ---------------------------------------------------------------------------

// mobileCredentialIssueError is the single admission rule for re-issuing
// mobile credentials. All three call sites (existing / duplicate race / right
// before issuing) share it so an expired device never receives instantly dead
// tokens and a create racing a revoke never answers 200 for a revoked record.
func mobileCredentialIssueError(doc store.DeviceDoc, unionID string, nowMS int64) string {
	if doc.UnionID != unionID || doc.DeviceKind != store.DeviceKindMobile || doc.ApprovedVia != store.DeviceApprovedViaSSOMobile {
		return "device_conflict"
	}
	if doc.Status != store.DeviceStatusActive {
		return "device_revoked"
	}
	if nowMS >= doc.DeviceExp {
		return "device_expired"
	}
	// dashboard:manage is a deliberate permission expansion: older mobile
	// enrollments must not gain it silently. recovery_required makes the
	// native client allocate a new enrollment family through fresh SSO.
	for _, scope := range doc.Scopes {
		if scope == store.DeviceScopeDashboardManage {
			return ""
		}
	}
	return "recovery_required"
}

// deviceMobileBind is POST /api/devices/mobile-bind: the mobile WebView
// finishes a fresh SSO and receives scoped device credentials directly. The
// enrollmentId lives in the native SecureStore; ids derive from it so network
// retries return the same device instead of creating duplicates.
func (a *Apex) deviceMobileBind(w http.ResponseWriter, r *http.Request) {
	if !a.deviceSameOrigin(r) {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "bad_origin"})
		return
	}
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writeDevicePrincipalError(w, err)
		return
	}
	if principal != nil && principal.Kind == auth.PrincipalDevice {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "sso_required"})
		return
	}
	session := auth.RequireFreshSSO(principal, a.devicesNow())
	if session == nil {
		writeStaleSession(w)
		return
	}
	body := readDeviceBody(r)
	enrollmentID := body.str("enrollmentId")
	if !enrollmentIDPattern.MatchString(enrollmentID) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_enrollment_id"})
		return
	}
	deviceName := deviceJSSlice(body.trimmed("deviceName"), 64)
	if deviceName == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "device_name_required"})
		return
	}

	ctx := r.Context()
	deviceID := "d-" + auth.SHA256Hex("mobile-device:" + session.UnionID + ":" + enrollmentID)[:16]
	familyID := "f-" + auth.SHA256Hex("mobile-family:" + session.UnionID + ":" + enrollmentID)[:24]
	initialJTI := auth.DeriveRefreshJTI(a.Config, "mobile-enroll:"+deviceID, enrollmentID, 1)
	existing, found, ok := a.lookupDevice(ctx, deviceID)
	if !ok {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if found {
		issueNow := a.devicesNow().UnixMilli()
		if code := mobileCredentialIssueError(existing, session.UnionID, issueNow); code != "" {
			writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": code})
			return
		}
		writeJSONNoStore(w, http.StatusOK, a.deviceIssued(existing, a.currentDeviceRefresh(existing), issueNow))
		return
	}

	now := a.devicesNow().UnixMilli()
	deviceExp := now + deviceLifetimeMS
	initialRefresh := auth.BuildDeviceRefreshToken(a.Config, auth.DeviceRefreshClaims{
		DeviceID: deviceID, FamilyID: familyID, Generation: 1, JTI: initialJTI, CredentialVersion: 1, DeviceExpMS: deviceExp,
	})
	doc := store.DeviceDoc{
		ID: deviceID, UnionID: session.UnionID, OwnerName: session.Name,
		DeviceKind: store.DeviceKindMobile, DeviceName: deviceName, Scopes: store.MobileDeviceScopes(),
		CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: familyID, RefreshGeneration: 1, RefreshTokenHash: auth.SHA256Hex(initialRefresh),
		RefreshCurrentJTI: initialJTI, RefreshRetryKeyHash: "", ReplayUntil: 0, RefreshRotatedAt: now,
		EnrolledAt: now, DeviceExp: deviceExp, LastSeenAt: now, ApprovedVia: store.DeviceApprovedViaSSOMobile,
	}
	if a.DeviceRepo.CreateDevice(ctx, doc) != nil {
		raced, found, ok := a.lookupDevice(ctx, deviceID)
		if !ok {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if !found {
			writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "device_conflict"})
			return
		}
		if code := mobileCredentialIssueError(raced, session.UnionID, a.devicesNow().UnixMilli()); code != "" {
			writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": code})
			return
		}
	}
	// Issue from the authoritative record, never from the local draft: a
	// concurrent revoke between create and issue must win.
	issued, found, ok := a.lookupDevice(ctx, deviceID)
	if !ok || !found {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	issueNow := a.devicesNow().UnixMilli()
	if code := mobileCredentialIssueError(issued, session.UnionID, issueNow); code != "" {
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": code})
		return
	}
	writeJSONNoStore(w, http.StatusOK, a.deviceIssued(issued, a.currentDeviceRefresh(issued), issueNow))
}

// lookupDevice is getDeviceLookup's three states: (doc, true, true) found,
// (_, false, true) authoritatively missing, ok=false when the store cannot
// answer (callers 503).
func (a *Apex) lookupDevice(ctx context.Context, deviceID string) (store.DeviceDoc, bool, bool) {
	doc, err := a.DeviceRepo.GetDevice(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return store.DeviceDoc{}, false, true
	}
	if err != nil {
		return store.DeviceDoc{}, false, false
	}
	return doc, true, true
}

// lookupDeviceGrant is getDeviceGrantLookup's three states.
func (a *Apex) lookupDeviceGrant(ctx context.Context, grantID string) (store.DeviceGrantDoc, bool, bool) {
	grant, err := a.DeviceRepo.GetDeviceGrant(ctx, grantID)
	if errors.Is(err, store.ErrNotFound) {
		return store.DeviceGrantDoc{}, false, true
	}
	if err != nil {
		return store.DeviceGrantDoc{}, false, false
	}
	return grant, true, true
}

// ---------------------------------------------------------------------------
// F1 enroll (§4-F1)
// ---------------------------------------------------------------------------

// grantDeviceIDs derives deviceId / familyId / the first jti from the grant,
// so a poll retried after a crash rebuilds the very same record and tokens.
func (a *Apex) grantDeviceIDs(grantID, pollSecret string) (deviceID, familyID, initialJTI string) {
	deviceID = "d-" + auth.SHA256Hex("device:" + grantID)[:16]
	familyID = "f-" + auth.SHA256Hex("family:" + grantID)[:24]
	initialJTI = auth.DeriveRefreshJTI(a.Config, "grant:"+grantID, pollSecret, 1)
	return deviceID, familyID, initialJTI
}

func machineDisplayName(m store.MachineDoc) string {
	return first(m.DisplayName, m.Name, prefix(m.ID, 8))
}

type deviceMachineOwnership int

const (
	deviceMachineOwned deviceMachineOwnership = iota
	deviceMachineUnavailable
	deviceMachineGone
	deviceMachineMismatch
)

// checkDeviceMachineOwnership is the one ownership rule shared by the three
// F1 checkpoints (enroll, approve, issue). A valid machine token only proves
// the platform once minted it; the current MachineDoc must still be ACTIVE
// and owned by the same person.
func (a *Apex) checkDeviceMachineOwnership(ctx context.Context, machineID, unionID string) (store.MachineDoc, deviceMachineOwnership) {
	if a.Repository == nil {
		return store.MachineDoc{}, deviceMachineUnavailable
	}
	doc, err := a.Repository.GetMachine(ctx, machineID)
	if errors.Is(err, store.ErrNotFound) {
		return store.MachineDoc{}, deviceMachineGone
	}
	if err != nil {
		return store.MachineDoc{}, deviceMachineUnavailable
	}
	if doc.Retired() {
		return doc, deviceMachineGone
	}
	if doc.UnionID != unionID {
		return doc, deviceMachineMismatch
	}
	return doc, deviceMachineOwned
}

// deviceEnroll is POST /api/devices/enroll (Bearer machineToken): the first
// ownership check, a PENDING grant, then the owner's Feishu confirmation card.
func (a *Apex) deviceEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var payload *auth.MachineTokenPayload
	if token := auth.BearerToken(r); token != "" {
		payload, _ = auth.VerifyMachineToken(a.Config, token)
	}
	if payload == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_machine_token"})
		return
	}
	// isMachineTokenRevoked keeps the machine chain's historical fail-open on
	// Redis errors; the ownership check below is the fail-closed backstop.
	if a.KV != nil {
		if revoked, err := a.KV.IsMachineTokenRevoked(ctx, payload.MachineID, payload.IAT); err == nil && revoked {
			writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "machine_revoked"})
			return
		}
	}

	body := readDeviceBody(r)
	// F1 only issues desktop-ide devices; mobile goes through SSO (§4-F3).
	if kind, _ := body.value("deviceKind"); kind != store.DeviceKindDesktopIDE {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "unsupported_device_kind"})
		return
	}
	deviceName := deviceJSSlice(body.trimmed("deviceName"), 64)
	if deviceName == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "device_name_required"})
		return
	}

	now := a.devicesNow().UnixMilli()
	throttle := a.enrollThrottle()
	if !throttle.allowed(payload.MachineID, now) {
		writeJSONNoStore(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_requests"})
		return
	}
	// First ownership check: an old token replayed after /api/bind moved the
	// machine to someone else must not reach the new owner's identity.
	machine, owned := a.checkDeviceMachineOwnership(ctx, payload.MachineID, payload.UnionID)
	switch owned {
	case deviceMachineUnavailable:
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	case deviceMachineGone, deviceMachineMismatch:
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "machine_ownership_mismatch"})
		return
	}

	grantID := randomID(16)
	pollSecret := randomID(32)
	grant := store.DeviceGrantDoc{
		ID: grantID, Kind: store.DeviceGrantKindF1MachineEnroll, UnionID: payload.UnionID, MachineID: payload.MachineID,
		DeviceKind: store.DeviceKindDesktopIDE, DeviceName: deviceName, Scopes: store.DeviceMVPScopes(),
		PollSecretHash: auth.SHA256Hex(pollSecret), Status: store.DeviceGrantPending,
		CreatedAt: now, ExpiresAt: now + enrollGrantTTLMS,
	}
	// Persist before the card: if the grant cannot be stored (fail-closed) the
	// owner is never bothered.
	if a.DeviceRepo.CreateDeviceGrant(ctx, grant) != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	throttle.record(payload.MachineID, now)

	confirm := feishu.DeviceConfirmMessage{
		DeviceName:   deviceName,
		MachineName:  machineDisplayName(machine),
		ConfirmURL:   a.Config.PublicBaseURL + "/devices/confirm?grant=" + grantID,
		ExpiresInSec: enrollGrantTTLMS / 1000,
	}
	ownerUnionID := payload.UnionID
	a.sendDeviceDM("设备确认卡片投递失败", "grantId", grantID, func(ctx context.Context) error {
		return a.Feishu.SendDeviceConfirmDM(ctx, ownerUnionID, confirm)
	})

	writeJSONNoStore(w, http.StatusOK, struct {
		GrantID        string `json:"grantId"`
		PollSecret     string `json:"pollSecret"`
		ExpiresAt      int64  `json:"expiresAt"`
		PollIntervalMS int    `json:"pollIntervalMs"`
	}{grantID, pollSecret, grant.ExpiresAt, enrollPollIntervalMS})
}

// sendDeviceDM delivers an owner DM after the response, like the TS
// `void send(...).catch(log)`: a Feishu failure never changes the protocol
// outcome. Unconfigured Feishu is the documented no-op.
func (a *Apex) sendDeviceDM(failure, idKey, idValue string, send func(context.Context) error) {
	if a.Feishu == nil || !a.Feishu.Configured() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := send(ctx); err != nil && !errors.Is(err, feishu.ErrNotConfigured) {
			slog.Warn(failure, idKey, idValue, "error", err)
		}
	}()
}

type deviceGrantView struct {
	GrantID     string   `json:"grantId"`
	DeviceKind  string   `json:"deviceKind"`
	DeviceName  string   `json:"deviceName"`
	MachineID   string   `json:"machineId"`
	MachineName string   `json:"machineName"`
	Scopes      []string `json:"scopes"`
	Status      string   `json:"status"`
	CreatedAt   int64    `json:"createdAt"`
	ExpiresAt   int64    `json:"expiresAt"`
}

// deviceGrantGet is GET /api/devices/grants/:id: confirmation page data, SSO
// and visible only to the grant's owner.
func (a *Apex) deviceGrantGet(w http.ResponseWriter, r *http.Request, grantID string) {
	ctx := r.Context()
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writeDevicePrincipalError(w, err)
		return
	}
	session := auth.RequireSSO(principal)
	if session == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	grant, found, ok := a.lookupDeviceGrant(ctx, grantID)
	if !ok {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if !found || grant.UnionID != session.UnionID {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "grant_not_found"})
		return
	}
	machineName := prefix(grant.MachineID, 8)
	if a.Repository != nil {
		if machine, err := a.Repository.GetMachine(ctx, grant.MachineID); err == nil {
			machineName = machineDisplayName(machine)
		}
	}
	status := grant.Status
	if status == store.DeviceGrantPending && a.devicesNow().UnixMilli() > grant.ExpiresAt {
		status = store.DeviceGrantExpired
	}
	writeJSONNoStore(w, http.StatusOK, deviceGrantView{
		GrantID: grant.ID, DeviceKind: grant.DeviceKind, DeviceName: grant.DeviceName,
		MachineID: grant.MachineID, MachineName: machineName, Scopes: grant.Scopes,
		Status: status, CreatedAt: grant.CreatedAt, ExpiresAt: grant.ExpiresAt,
	})
}

type deviceGrantConflict struct {
	Error  string `json:"error"`
	Status string `json:"status,omitempty"`
}

// deviceGrantDecision is POST /api/devices/grants/:id/approve|deny: fresh SSO
// plus the Origin CSRF gate. Approval is the second ownership check plus the
// CAS to approved (with the pre-allocated deviceId).
func (a *Apex) deviceGrantDecision(w http.ResponseWriter, r *http.Request, grantID, action string) {
	ctx := r.Context()
	// CSRF: decisions must come from the platform's own page (browsers always
	// send Origin on POST).
	if !a.deviceSameOrigin(r) {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "bad_origin"})
		return
	}
	session := a.freshDeviceManager(w, r)
	if session == nil {
		return
	}
	grant, found, ok := a.lookupDeviceGrant(ctx, grantID)
	if !ok {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if !found || grant.UnionID != session.UnionID {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "grant_not_found"})
		return
	}

	now := a.devicesNow().UnixMilli()
	if action == "deny" {
		err := a.DeviceRepo.DenyDeviceGrant(ctx, grantID, session.UnionID, now)
		if err == nil {
			writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantDenied})
			return
		}
		if !errors.Is(err, store.ErrConflict) {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		// Losing the CAS to a concurrent approve/consume must not report
		// "denied": only an authoritative denied state is an idempotent success.
		again, found, ok := a.lookupDeviceGrant(ctx, grantID)
		if !ok {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if !found || again.UnionID != session.UnionID {
			writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "grant_not_found"})
			return
		}
		if again.Status == store.DeviceGrantDenied {
			writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantDenied})
			return
		}
		status := again.Status
		if a.devicesNow().UnixMilli() >= again.ExpiresAt {
			status = store.DeviceGrantExpired
		}
		writeJSONNoStore(w, http.StatusConflict, deviceGrantConflict{Error: "grant_not_pending", Status: status})
		return
	}

	// Second ownership check: the machine still belongs to the approver.
	if _, owned := a.checkDeviceMachineOwnership(ctx, grant.MachineID, grant.UnionID); owned != deviceMachineOwned {
		if owned == deviceMachineUnavailable {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		_ = a.DeviceRepo.DenyDeviceGrant(ctx, grantID, session.UnionID, now)
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "machine_ownership_changed"})
		return
	}

	deviceID, _, _ := a.grantDeviceIDs(grantID, "")
	err := a.DeviceRepo.ApproveDeviceGrant(ctx, grantID, session.UnionID, deviceID, now)
	if err == nil {
		writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantApproved})
		return
	}
	if !errors.Is(err, store.ErrConflict) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	// Conflict: tell a repeated click (already approved/consumed) apart from
	// denied/expired.
	again, found, ok := a.lookupDeviceGrant(ctx, grantID)
	if ok && found && (again.Status == store.DeviceGrantApproved || again.Status == store.DeviceGrantConsumed) {
		writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantApproved})
		return
	}
	conflict := deviceGrantConflict{Error: "grant_not_pending"}
	if ok && found {
		conflict.Status = again.Status
	}
	writeJSONNoStore(w, http.StatusConflict, conflict)
}

// deviceEnrollPoll is POST /api/devices/enroll/poll: once approved, the third
// ownership check, the CAS consume, the deterministic DeviceDoc, then the
// credentials. Consume comes first so a crash can never leave an active
// DeviceDoc whose grant was not consumed; a crash after consume is recovered
// by the same pollSecret within the grant TTL.
func (a *Apex) deviceEnrollPoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body := readDeviceBody(r)
	grantID := body.str("grantId")
	pollSecret := body.str("pollSecret")
	if !deviceGrantIDPattern.MatchString(grantID) || pollSecret == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	grant, found, ok := a.lookupDeviceGrant(ctx, grantID)
	if !ok {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	// A wrong secret answers exactly like a missing grant (no existence oracle).
	if !found || grant.PollSecretHash != auth.SHA256Hex(pollSecret) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "grant_not_found"})
		return
	}

	now := a.devicesNow().UnixMilli()
	// expiresAt is the logical authority for every state (the TTL index only
	// cleans up): in particular a consumed grant must not re-sign credentials
	// with its pollSecret after the 5 minutes.
	if now >= grant.ExpiresAt {
		writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantExpired})
		return
	}
	switch grant.Status {
	case store.DeviceGrantPending:
		writeJSONNoStore(w, http.StatusOK, struct {
			Status         string `json:"status"`
			PollIntervalMS int    `json:"pollIntervalMs"`
		}{store.DeviceGrantPending, enrollPollIntervalMS})
		return
	case store.DeviceGrantDenied, store.DeviceGrantExpired:
		writeJSONNoStore(w, http.StatusOK, map[string]any{"status": grant.Status})
		return
	}

	deviceID, familyID, initialJTI := a.grantDeviceIDs(grantID, pollSecret)
	if grant.Status == store.DeviceGrantConsumed {
		// The previous response was lost: normally the device exists and is
		// re-issued; if the crash hit between consume and create, fall through
		// and finish the deterministic create inside the TTL.
		existingID := grant.DeviceID
		if existingID == "" {
			existingID = deviceID
		}
		dev, found, ok := a.lookupDevice(ctx, existingID)
		if !ok {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if found {
			if dev.UnionID != grant.UnionID {
				writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "grant_already_consumed"})
				return
			}
			if dev.Status != store.DeviceStatusActive {
				writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_revoked"})
				return
			}
			writeJSONNoStore(w, http.StatusOK, a.deviceIssued(dev, a.currentDeviceRefresh(dev), now))
			return
		}
	}

	// approved, or consumed with a crash before create: third ownership check.
	machine, owned := a.checkDeviceMachineOwnership(ctx, grant.MachineID, grant.UnionID)
	if owned != deviceMachineOwned {
		if owned == deviceMachineUnavailable {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if grant.Status == store.DeviceGrantApproved {
			_ = a.DeviceRepo.VoidApprovedDeviceGrant(ctx, grantID, now)
		}
		writeJSONNoStore(w, http.StatusOK, struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}{store.DeviceGrantDenied, "machine_ownership_changed"})
		return
	}

	if grant.Status == store.DeviceGrantApproved {
		// Consume atomically before creating the active DeviceDoc.
		err := a.DeviceRepo.ConsumeDeviceGrant(ctx, grantID, grant.PollSecretHash, now)
		if err != nil && !errors.Is(err, store.ErrConflict) {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if err != nil {
			again, found, ok := a.lookupDeviceGrant(ctx, grantID)
			if !ok {
				writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
				return
			}
			if !found || again.PollSecretHash != grant.PollSecretHash {
				writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "grant_not_found"})
				return
			}
			if a.devicesNow().UnixMilli() >= again.ExpiresAt || again.Status == store.DeviceGrantExpired {
				writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantExpired})
				return
			}
			if again.Status == store.DeviceGrantDenied {
				writeJSONNoStore(w, http.StatusOK, map[string]any{"status": store.DeviceGrantDenied})
				return
			}
			if again.Status != store.DeviceGrantConsumed {
				writeJSONNoStore(w, http.StatusConflict, deviceGrantConflict{Error: "grant_not_approved", Status: again.Status})
				return
			}
			// A concurrent poll won the consume: continue on the same
			// deterministic create/issue path.
		}
	}

	decidedAt := grant.DecidedAt
	if decidedAt == 0 {
		decidedAt = grant.CreatedAt
	}
	deviceExp := decidedAt + deviceLifetimeMS
	initialRefresh := auth.BuildDeviceRefreshToken(a.Config, auth.DeviceRefreshClaims{
		DeviceID: deviceID, FamilyID: familyID, Generation: 1, JTI: initialJTI, CredentialVersion: 1, DeviceExpMS: deviceExp,
	})
	doc := store.DeviceDoc{
		ID: deviceID, UnionID: grant.UnionID, OwnerName: machine.OwnerName,
		DeviceKind: store.DeviceKindDesktopIDE, DeviceName: grant.DeviceName, Scopes: append([]string{}, grant.Scopes...),
		CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: familyID, RefreshGeneration: 1, RefreshTokenHash: auth.SHA256Hex(initialRefresh),
		RefreshCurrentJTI: initialJTI, RefreshRetryKeyHash: "", ReplayUntil: 0, RefreshRotatedAt: now,
		EnrolledAt: now, DeviceExp: deviceExp, LastSeenAt: now, ApprovedVia: store.DeviceApprovedViaFeishuConfirm,
	}
	// Still persist before issuing; an existing record (concurrent poll or a
	// crash retry) is reused only when it is this grant's device.
	if a.DeviceRepo.CreateDevice(ctx, doc) != nil {
		existing, found, ok := a.lookupDevice(ctx, deviceID)
		if !ok {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		if !found || existing.UnionID != grant.UnionID || existing.ApprovedVia != store.DeviceApprovedViaFeishuConfirm {
			writeJSONNoStore(w, http.StatusInternalServerError, map[string]any{"error": "device_conflict"})
			return
		}
	}
	dev, found, ok := a.lookupDevice(ctx, deviceID)
	if !ok || !found {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	issued := a.deviceIssued(dev, a.currentDeviceRefresh(dev), now)
	issued.DeviceID = deviceID
	writeJSONNoStore(w, http.StatusOK, issued)
}

// deviceCredentials is the §3.4 wire contract shared by enroll, mobile bind
// and refresh: accessExpiresAt is Unix ms (= access exp × 1000) so clients
// never decode the token.
type deviceCredentials struct {
	AccessToken     string `json:"accessToken"`
	RefreshToken    string `json:"refreshToken"`
	DeviceExp       int64  `json:"deviceExp"`
	AccessExpiresAt int64  `json:"accessExpiresAt"`
}

type deviceIssuedResponse struct {
	Status   string `json:"status"`
	DeviceID string `json:"deviceId"`
	deviceCredentials
}

func (a *Apex) deviceCredentialsFor(doc store.DeviceDoc, refreshToken string, nowMS int64) deviceCredentials {
	return deviceCredentials{
		AccessToken:     auth.MintDeviceAccessToken(a.Config, doc, nowMS),
		RefreshToken:    refreshToken,
		DeviceExp:       doc.DeviceExp,
		AccessExpiresAt: auth.DeviceAccessExpSec(doc, nowMS) * 1000,
	}
}

func (a *Apex) deviceIssued(doc store.DeviceDoc, refreshToken string, nowMS int64) deviceIssuedResponse {
	return deviceIssuedResponse{Status: "issued", DeviceID: doc.ID, deviceCredentials: a.deviceCredentialsFor(doc, refreshToken, nowMS)}
}

// currentDeviceRefresh re-signs the current refresh token byte-for-byte from
// the authoritative record (exact replay / in-window refresh; no plaintext is
// ever stored).
func (a *Apex) currentDeviceRefresh(doc store.DeviceDoc) string {
	return auth.BuildDeviceRefreshToken(a.Config, auth.DeviceRefreshClaims{
		DeviceID: doc.ID, FamilyID: doc.RefreshFamilyID, Generation: doc.RefreshGeneration,
		JTI: doc.RefreshCurrentJTI, CredentialVersion: doc.CredentialVersion, DeviceExpMS: doc.DeviceExp,
	})
}

// revokeDeviceWithAlarm is the reuse / expired-window revocation. Only the
// call that actually performed the active → revoked transition propagates
// and alarms the owner, so a replay storm sends exactly one DM. It reports
// false when the store could not answer.
func (a *Apex) revokeDeviceWithAlarm(ctx context.Context, doc store.DeviceDoc, reason feishu.DeviceRevokedReason) bool {
	revokedNow, err := a.DeviceRepo.ForceRevokeDevice(ctx, doc.ID)
	if err != nil {
		return false
	}
	if revokedNow {
		a.propagateDeviceRevocation(doc.ID, string(reason))
		alarm := feishu.DeviceRevokedMessage{DeviceName: doc.DeviceName, Reason: reason}
		ownerUnionID := doc.UnionID
		a.sendDeviceDM("设备吊销告警投递失败", "deviceId", doc.ID, func(ctx context.Context) error {
			return a.Feishu.SendDeviceRevokedAlarmDM(ctx, ownerUnionID, alarm)
		})
	}
	return true
}

// deviceRefresh is POST /api/devices/refresh, the §3.4 six-branch decision
// order. Request: Idempotency-Key header + {refreshToken}; retries reuse the
// key. A forged token (bad MAC, foreign family, future generation) is always
// 401 with zero state change, so it can never be used for revocation DoS.
func (a *Apex) deviceRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idempotencyKey := deviceNodeHeader(r, "Idempotency-Key")
	refreshValue, _ := readDeviceBody(r).value("refreshToken")
	refreshToken, isString := refreshValue.(string)
	if idempotencyKey == "" || deviceJSLength(idempotencyKey) > 256 || !isString || refreshToken == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	// Branch 6 gate: an invalid MAC never reaches any write path.
	claims, err := auth.ParseDeviceRefreshToken(a.Config, refreshToken)
	if err != nil || claims == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_refresh"})
		return
	}

	now := a.devicesNow().UnixMilli()
	// Authoritative uncached read: refresh mutates credentials, fail-closed.
	doc, found, ok := a.lookupDevice(ctx, claims.DeviceID)
	switch {
	case !ok:
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	case !found:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_gone"})
		return
	case doc.Status != store.DeviceStatusActive:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_revoked"})
		return
	case doc.RefreshFamilyID != claims.FamilyID:
		// A genuine token of the pre-re-enroll family: 401 with zero change —
		// it must never revoke the new family.
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_refresh"})
		return
	case claims.Generation > doc.RefreshGeneration:
		// Never issued by this platform (or a rolled-back store): defensive 401.
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_refresh"})
		return
	case now > doc.DeviceExp:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_expired"})
		return
	}

	presentedHash := auth.SHA256Hex(refreshToken)
	// Pre-derive the next generation deterministically (same old token + same
	// key always yields the same token); it only takes effect when rotated.
	nextGeneration := claims.Generation + 1
	nextJTI := auth.DeriveRefreshJTI(a.Config, presentedHash, idempotencyKey, nextGeneration)
	nextToken := auth.BuildDeviceRefreshToken(a.Config, auth.DeviceRefreshClaims{
		DeviceID: doc.ID, FamilyID: doc.RefreshFamilyID, Generation: nextGeneration,
		JTI: nextJTI, CredentialVersion: doc.CredentialVersion, DeviceExpMS: doc.DeviceExp,
	})
	outcome, err := a.DeviceRepo.RotateDeviceRefresh(ctx, store.RotateDeviceRefreshInput{
		DeviceID: doc.ID, PresentedHash: presentedHash, PresentedGeneration: claims.Generation,
		RetryKeyHash: auth.SHA256Hex(idempotencyKey), NewHash: auth.SHA256Hex(nextToken), NewJTI: nextJTI, NowMS: now,
	})
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	switch outcome.Result {
	case store.RotateRotated:
		writeJSONNoStore(w, http.StatusOK, a.deviceCredentialsFor(*outcome.Device, nextToken, now))
	case store.RotateCurrentWithinWindow, store.RotateExactReplay:
		// Zero-write paths: the current refresh bytes plus a fresh access.
		writeJSONNoStore(w, http.StatusOK, a.deviceCredentialsFor(*outcome.Device, a.currentDeviceRefresh(*outcome.Device), now))
	case store.RotateRefreshInProgress:
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "refresh_in_progress"})
	case store.RotateReplayExpired:
		if !a.revokeDeviceWithAlarm(ctx, doc, feishu.DeviceRevokedRecoveryRequired) {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "recovery_required"})
	case store.RotateStaleGeneration:
		if !a.revokeDeviceWithAlarm(ctx, doc, feishu.DeviceRevokedRefreshReuse) {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_revoked"})
	case store.RotateRevoked:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_revoked"})
	case store.RotateExpired:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_expired"})
	case store.RotateNotFound:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "device_gone"})
	case store.RotateInvalid:
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_refresh"})
	default:
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
	}
}
