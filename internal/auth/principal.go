package auth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Unified request principal (DESIGN-device-pairing.md §3.2).
//
// Routes opt in: by default a route is SSO-only (RequireSSO /
// RequireFreshSSO); only routes that explicitly accept devices use
// RequireDeviceScope, so forgetting to declare is the safe mistake. A cookie
// and a Bearer token on the same request are a conflict, never silently
// resolved in favour of either.

// Fresh-SSO windows (§3.2 C3).
const (
	// FreshSSOWindowSec (STRICT, 10 minutes) guards irreversible or
	// credential-class operations: unbind, team dissolution, machine upgrade,
	// bind-code issuance, device list/revoke/trust/enroll approval, forced
	// issue detach/archive.
	FreshSSOWindowSec int64 = 600
	// FreshSSOWindowRoutineSec (ROUTINE, 12 hours) guards everyday
	// collaborative writes (team edits, invites, group chats, team bots,
	// issue board form/presets, admin appointment).
	FreshSSOWindowRoutineSec int64 = 12 * 3600
)

// Device state positive cache (§5.3 D1): absolute TTL, hits never extend it.
// Revocation propagates within one TTL plus the watcher period; watcher
// re-checks must bypass the cache.
const (
	DeviceStateCacheTTL     = 5 * time.Second
	DeviceStateCacheHardCap = 10 * time.Second
)

// PrincipalKind distinguishes SSO and device principals.
type PrincipalKind string

const (
	PrincipalSSO    PrincipalKind = "sso"
	PrincipalDevice PrincipalKind = "device"
)

// Principal is the authenticated subject of a request: exactly one of
// Session (Kind == PrincipalSSO) or Device (Kind == PrincipalDevice) is set.
type Principal struct {
	Kind    PrincipalKind
	Session *SessionPayload
	Device  *DeviceAccessPayload
}

// PrincipalError is a ReadPrincipal rejection; its string is the wire error
// code.
type PrincipalError string

const (
	// ErrConflictingCredentials: cookie and Bearer on one request (400).
	ErrConflictingCredentials PrincipalError = "conflicting_credentials"
	// ErrDeviceRevoked: device revoked or credentialVersion mismatch (401).
	ErrDeviceRevoked PrincipalError = "device_revoked"
	// ErrDeviceGone: the device record does not exist (401).
	ErrDeviceGone PrincipalError = "device_gone"
	// ErrDeviceUnavailable: the authoritative store is unavailable (503,
	// fail-closed).
	ErrDeviceUnavailable PrincipalError = "device_unavailable"
)

func (e PrincipalError) Error() string { return string(e) }

// HTTPStatus maps the error to its documented HTTP status.
func (e PrincipalError) HTTPStatus() int {
	switch e {
	case ErrConflictingCredentials:
		return http.StatusBadRequest
	case ErrDeviceRevoked, ErrDeviceGone:
		return http.StatusUnauthorized
	default:
		return http.StatusServiceUnavailable
	}
}

// DeviceReader is the store dependency of the device state cache.
// GetDevice must return store.ErrNotFound for a missing device and any other
// error when the authoritative store cannot answer.
type DeviceReader interface {
	GetDevice(ctx context.Context, deviceID string) (store.DeviceDoc, error)
}

// DeviceState is the authority-relevant part of a device record.
type DeviceState struct {
	Status            string
	CredentialVersion int64
}

type deviceStateEntry struct {
	state     DeviceState
	fetchedAt time.Time
}

// DeviceStateCache is the per-pod positive cache of device status and
// credentialVersion. Invalidate bumps a per-device epoch so a read that was
// already in flight when the device was revoked cannot backfill a stale
// "active" (the same-pod revocation promise is < 1s).
type DeviceStateCache struct {
	reader DeviceReader
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]deviceStateEntry
	epochs  map[string]uint64
}

// NewDeviceStateCache creates a cache reading through reader.
func NewDeviceStateCache(reader DeviceReader) *DeviceStateCache {
	return &DeviceStateCache{
		reader:  reader,
		now:     time.Now,
		entries: make(map[string]deviceStateEntry),
		epochs:  make(map[string]uint64),
	}
}

// DeviceStateOptions tune a single DeviceStateCache.Get call.
type DeviceStateOptions struct {
	// BypassCache forces an authoritative read (watcher re-checks).
	BypassCache bool
	// Now overrides the clock (tests); zero means the cache clock.
	Now time.Time
	// TTL overrides DeviceStateCacheTTL; it is capped at
	// DeviceStateCacheHardCap. Zero means the default.
	TTL time.Duration
}

// Epoch returns the invalidation epoch of deviceID.
func (c *DeviceStateCache) Epoch(deviceID string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epochs[deviceID]
}

// Invalidate drops the cached state and bumps the epoch. Call it right after
// revoking a device on this pod; other pods converge within one TTL.
func (c *DeviceStateCache) Invalidate(deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, deviceID)
	c.epochs[deviceID]++
}

// Reset clears all cached states (epochs are monotonic and kept).
func (c *DeviceStateCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]deviceStateEntry)
}

// Get returns the device's authoritative state. A nil state with a nil error
// means the device does not exist. Any error means the authority could not
// be read and the caller must fail closed (503); an expired cache entry is
// never used as a fallback. A read that races Invalidate is discarded and
// retried once; if that races too, Get fails closed.
func (c *DeviceStateCache) Get(ctx context.Context, deviceID string, opts DeviceStateOptions) (*DeviceState, error) {
	now := opts.Now
	if now.IsZero() {
		now = c.now()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DeviceStateCacheTTL
	}
	if ttl > DeviceStateCacheHardCap {
		ttl = DeviceStateCacheHardCap
	}
	if !opts.BypassCache {
		c.mu.Lock()
		hit, ok := c.entries[deviceID]
		c.mu.Unlock()
		if ok && now.Sub(hit.fetchedAt) <= ttl {
			state := hit.state
			return &state, nil
		}
	}
	if c.reader == nil {
		return nil, store.ErrUnavailable
	}
	for attempt := 0; attempt < 2; attempt++ {
		epochBefore := c.Epoch(deviceID)
		doc, err := c.reader.GetDevice(ctx, deviceID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, store.ErrUnavailable
		}
		c.mu.Lock()
		if c.epochs[deviceID] != epochBefore {
			c.mu.Unlock()
			continue
		}
		if err != nil {
			delete(c.entries, deviceID)
			c.mu.Unlock()
			return nil, nil
		}
		state := DeviceState{Status: doc.Status, CredentialVersion: doc.CredentialVersion}
		c.entries[deviceID] = deviceStateEntry{state: state, fetchedAt: now}
		c.mu.Unlock()
		return &state, nil
	}
	return nil, store.ErrUnavailable
}

// JavaScript's \s, used by the Bearer pattern below.
const jsSpaceClass = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// bearerPattern mirrors /^Bearer\s+(.+)$/i ("." excludes line terminators).
var bearerPattern = regexp.MustCompile(`(?i)^Bearer[` + jsSpaceClass + `]+([^\n\r\x{2028}\x{2029}]+)$`)

// BearerToken extracts the Bearer credential from the Authorization header
// ("" when absent or empty).
func BearerToken(req *http.Request) string {
	match := bearerPattern.FindStringSubmatch(req.Header.Get("Authorization"))
	if match == nil {
		return ""
	}
	return jsTrim(match[1])
}

// ReadPrincipal reads the request's principal:
//   - a valid session cookie together with a Bearer token is
//     ErrConflictingCredentials, whatever the Bearer's validity;
//   - a Bearer is verified as a device access token and then compared with
//     the authoritative device status/credentialVersion (fail-closed:
//     ErrDeviceUnavailable when the store cannot answer);
//   - a cookie alone yields an SSO principal; neither (or an invalid Bearer)
//     yields (nil, nil), leaving 401-vs-anonymous to the route.
func ReadPrincipal(ctx context.Context, cfg config.Config, req *http.Request, devices *DeviceStateCache) (*Principal, error) {
	bearer := BearerToken(req)
	session, sessionErr := ReadSession(cfg, req)
	if sessionErr != nil {
		session = nil
	}
	if bearer != "" && session != nil {
		return nil, ErrConflictingCredentials
	}
	if bearer == "" {
		if session == nil {
			return nil, nil
		}
		return &Principal{Kind: PrincipalSSO, Session: session}, nil
	}
	access, err := VerifyDeviceAccessToken(cfg, bearer)
	if err != nil {
		return nil, nil
	}
	if devices == nil {
		return nil, ErrDeviceUnavailable
	}
	state, err := devices.Get(ctx, access.DeviceID, DeviceStateOptions{})
	if err != nil {
		return nil, ErrDeviceUnavailable
	}
	if state == nil {
		return nil, ErrDeviceGone
	}
	if state.Status != store.DeviceStatusActive || state.CredentialVersion != access.CredentialVersion {
		return nil, ErrDeviceRevoked
	}
	return &Principal{Kind: PrincipalDevice, Device: access}, nil
}

// RequireSSO returns the session of an SSO principal; device bearers never
// qualify.
func RequireSSO(p *Principal) *SessionPayload {
	if p == nil || p.Kind != PrincipalSSO {
		return nil
	}
	return p.Session
}

// RequireFreshSSO requires an SSO principal authenticated within the STRICT
// window (FreshSSOWindowSec). Legacy cookies without authTime are never
// fresh. Calls that do not declare a tier get this strictest one.
func RequireFreshSSO(p *Principal, now time.Time) *SessionPayload {
	return RequireFreshSSOWithin(p, now, FreshSSOWindowSec)
}

// RequireFreshSSOWithin is RequireFreshSSO with an explicit window (seconds).
func RequireFreshSSOWithin(p *Principal, now time.Time, windowSec int64) *SessionPayload {
	session := RequireSSO(p)
	if session == nil || session.AuthTime == nil || now.Unix()-*session.AuthTime > windowSec {
		return nil
	}
	return session
}

// RequireRoutineSSO is RequireFreshSSO with the ROUTINE window
// (FreshSSOWindowRoutineSec) for frequent collaborative writes.
func RequireRoutineSSO(p *Principal, now time.Time) *SessionPayload {
	return RequireFreshSSOWithin(p, now, FreshSSOWindowRoutineSec)
}

// RequireDeviceScope is for routes that accept devices: a device needs
// scope, an SSO principal always qualifies (a person ⊇ their devices). It
// returns the effective unionId for ownership checks.
func RequireDeviceScope(p *Principal, scope string) (unionID string, ok bool) {
	if p == nil {
		return "", false
	}
	switch p.Kind {
	case PrincipalSSO:
		if p.Session != nil {
			return p.Session.UnionID, true
		}
	case PrincipalDevice:
		if p.Device != nil && p.Device.HasScope(scope) {
			return p.Device.UnionID, true
		}
	}
	return "", false
}
