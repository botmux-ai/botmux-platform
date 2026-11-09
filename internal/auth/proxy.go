package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const (
	ProxyCookieName = "botmux_proxy_session"
	proxyTicketTTL  = 30 * time.Second
)

type ProxyIdentity struct {
	UnionID   string
	MachineID string
}

// ProxyTicketPayload is the short-lived machine subdomain bootstrap ticket.
// JTI (32 lowercase hex chars) identifies the ticket for the single-use
// fence (store ConsumeProxyTicket).
type ProxyTicketPayload struct {
	Kind      string `json:"kind"`
	JTI       string `json:"jti"`
	UnionID   string `json:"unionId"`
	MachineID string `json:"machineId"`
	Exp       int64  `json:"exp"`
}

type ProxySessionPayload struct {
	Kind      string `json:"kind"`
	UnionID   string `json:"unionId"`
	MachineID string `json:"machineId"`
	Exp       int64  `json:"exp"`
}

func IssueProxyTicket(cfg config.Config, identity ProxyIdentity) string {
	return IssueProxyTicketAt(cfg, identity, time.Now())
}

func IssueProxyTicketAt(cfg config.Config, identity ProxyIdentity, now time.Time) string {
	return issueProxyTicket(cfg, identity, now, randomTicketID())
}

func issueProxyTicket(cfg config.Config, identity ProxyIdentity, now time.Time, jti string) string {
	payload := ProxyTicketPayload{
		Kind:      "proxy-ticket",
		JTI:       jti,
		UnionID:   identity.UnionID,
		MachineID: identity.MachineID,
		Exp:       now.Unix() + int64(proxyTicketTTL/time.Second),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

// randomTicketID returns 16 random bytes as lowercase hex.
func randomTicketID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}

var ticketIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func VerifyProxyTicket(cfg config.Config, token string) (*ProxyTicketPayload, error) {
	return VerifyProxyTicketAt(cfg, token, time.Now())
}

// VerifyProxyTicketAt verifies a proxy ticket; tickets without a well-formed
// jti (legacy, pre-fence) are rejected.
func VerifyProxyTicketAt(cfg config.Config, token string, now time.Time) (*ProxyTicketPayload, error) {
	var payload ProxyTicketPayload
	if err := VerifyToken(token, cfg.SigningSecret, "proxy-ticket", now, &payload); err != nil {
		return nil, err
	}
	if !ticketIDPattern.MatchString(payload.JTI) {
		return nil, ErrInvalidToken
	}
	return &payload, nil
}

func MintProxySession(cfg config.Config, identity ProxyIdentity) string {
	return MintProxySessionAt(cfg, identity, time.Now())
}

func MintProxySessionAt(cfg config.Config, identity ProxyIdentity, now time.Time) string {
	payload := ProxySessionPayload{
		Kind:      "proxy-session",
		UnionID:   identity.UnionID,
		MachineID: identity.MachineID,
		Exp:       now.Unix() + int64(cfg.SessionTTL/time.Second),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

func VerifyProxySession(cfg config.Config, token string) (*ProxySessionPayload, error) {
	return VerifyProxySessionAt(cfg, token, time.Now())
}

func VerifyProxySessionAt(cfg config.Config, token string, now time.Time) (*ProxySessionPayload, error) {
	var payload ProxySessionPayload
	if err := VerifyToken(token, cfg.SigningSecret, "proxy-session", now, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func ReadProxySession(cfg config.Config, req *http.Request) (*ProxySessionPayload, error) {
	token := ParseCookie(req.Header.Get("Cookie"))[ProxyCookieName]
	if token == "" {
		return nil, ErrInvalidToken
	}
	return VerifyProxySession(cfg, token)
}

func ProxySessionRequestCookie(cfg config.Config, identity ProxyIdentity) string {
	return ProxyCookieName + "=" + MintProxySession(cfg, identity)
}

func ProxySessionCookieHeader(cfg config.Config, token string) string {
	parts := []string{
		ProxyCookieName + "=" + token,
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		"Max-Age=" + durationSecondsString(cfg.SessionTTL),
	}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func (p ProxyTicketPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "jti", p.JTI, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "machineId", p.MachineID, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

// ProxySessionCookieHeaders is the Set-Cookie list for an SSO ticket
// exchange: the owner proxy session plus clearing both purpose-isolated
// device cookies, so a stale device cookie in a shared WebView jar cannot
// shadow the new owner principal.
func ProxySessionCookieHeaders(cfg config.Config, token string) []string {
	return []string{
		ProxySessionCookieHeader(cfg, token),
		ClearDeviceProxySessionCookieHeader(cfg, DeviceProxyPurposeDashboardMobile),
		ClearDeviceProxySessionCookieHeader(cfg, DeviceProxyPurposeTerminal),
	}
}

// ClearProxySessionCookieHeader expires the owner proxy session cookie.
func ClearProxySessionCookieHeader(cfg config.Config) string {
	parts := []string{ProxyCookieName + "=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

// Device-derived proxy tickets (DESIGN-device-pairing.md §5.1/§5.2) use their
// own kinds instead of optional fields on proxy-ticket/proxy-session, so a
// device origin can never be laundered into a long-lived owner session.

const (
	deviceDashboardProxyCookie = "botmux_device_proxy_session"
	deviceTerminalProxyCookie  = "botmux_device_terminal_session"
	deviceProxyTicketTTLSec    = 30
)

// DeviceProxyPurpose is the route-selected, signed purpose of a device proxy
// ticket/session. There is no "no purpose = everything" fallback.
type DeviceProxyPurpose string

const (
	DeviceProxyPurposeDashboardMobile DeviceProxyPurpose = "dashboard-mobile"
	DeviceProxyPurposeTerminal        DeviceProxyPurpose = "terminal"
)

// DeviceProxyClaims are the common device-derived ticket claims. Times are
// Unix seconds.
type DeviceProxyClaims struct {
	UnionID           string `json:"unionId"`
	MachineID         string `json:"machineId"`
	DeviceID          string `json:"deviceId"`
	CredentialVersion int64  `json:"credentialVersion"`
	// EffectiveScopes snapshots the authoritative scopes at issue time; a
	// renewal may only narrow them.
	EffectiveScopes []string `json:"effectiveScopes"`
	// SID is the desktop session chain id, unchanged across renewals.
	SID string `json:"sid"`
	// SessionMaxExp = min(deviceExp, first issue + 12h); nothing in the chain
	// may outlive it.
	SessionMaxExp int64 `json:"sessionMaxExp"`
	// AuthExp is the current lease = min(access token exp, deviceExp,
	// SessionMaxExp), about 15 minutes.
	AuthExp int64              `json:"authExp"`
	Purpose DeviceProxyPurpose `json:"purpose"`
}

// DeviceProxyTicketPayload is a single-use device proxy ticket.
type DeviceProxyTicketPayload struct {
	DeviceProxyClaims
	Kind string `json:"kind"`
	JTI  string `json:"jti"`
	Exp  int64  `json:"exp"`
}

// DeviceProxySessionPayload is a device proxy session (cookie value or
// renewal chain handle). JTI is carried over when the session was minted
// from a ticket, mirroring the TypeScript claims spread.
type DeviceProxySessionPayload struct {
	DeviceProxyClaims
	Kind string `json:"kind"`
	JTI  string `json:"jti,omitempty"`
	Exp  int64  `json:"exp"`
}

// valid is the all-or-nothing claims check (§5.1): any missing or mistyped
// device field rejects the token.
func (c DeviceProxyClaims) valid() bool {
	if c.UnionID == "" || c.MachineID == "" || c.DeviceID == "" || c.SID == "" {
		return false
	}
	if c.CredentialVersion < 1 || c.EffectiveScopes == nil {
		return false
	}
	for _, scope := range c.EffectiveScopes {
		if scope == "" {
			return false
		}
	}
	if c.SessionMaxExp <= 0 || c.AuthExp <= 0 || c.AuthExp > c.SessionMaxExp {
		return false
	}
	return c.Purpose == DeviceProxyPurposeDashboardMobile || c.Purpose == DeviceProxyPurposeTerminal
}

func (c DeviceProxyClaims) appendCompat(dst []byte, first *bool) []byte {
	dst = appendStringField(dst, "unionId", c.UnionID, first)
	dst = appendStringField(dst, "machineId", c.MachineID, first)
	dst = appendStringField(dst, "deviceId", c.DeviceID, first)
	dst = appendInt64Field(dst, "credentialVersion", c.CredentialVersion, first)
	dst = appendStringArrayField(dst, "effectiveScopes", c.EffectiveScopes, first)
	dst = appendStringField(dst, "sid", c.SID, first)
	dst = appendInt64Field(dst, "sessionMaxExp", c.SessionMaxExp, first)
	dst = appendInt64Field(dst, "authExp", c.AuthExp, first)
	return appendStringField(dst, "purpose", string(c.Purpose), first)
}

func deviceProxyCompatJSON(claims DeviceProxyClaims, kind, jti string, exp int64) []byte {
	dst := []byte{'{'}
	first := true
	dst = claims.appendCompat(dst, &first)
	dst = appendStringField(dst, "kind", kind, &first)
	if jti != "" {
		dst = appendStringField(dst, "jti", jti, &first)
	}
	dst = appendInt64Field(dst, "exp", exp, &first)
	return append(dst, '}')
}

// IssueDeviceProxyTicket signs a 30-second single-use device ticket; its exp
// never exceeds claims.AuthExp.
func IssueDeviceProxyTicket(cfg config.Config, claims DeviceProxyClaims) string {
	return IssueDeviceProxyTicketAt(cfg, claims, time.Now())
}

// IssueDeviceProxyTicketAt is IssueDeviceProxyTicket with an explicit clock.
func IssueDeviceProxyTicketAt(cfg config.Config, claims DeviceProxyClaims, now time.Time) string {
	return issueDeviceProxyTicket(cfg, claims, now, randomTicketID())
}

func issueDeviceProxyTicket(cfg config.Config, claims DeviceProxyClaims, now time.Time, jti string) string {
	exp := now.Unix() + deviceProxyTicketTTLSec
	if claims.AuthExp < exp {
		exp = claims.AuthExp
	}
	return mustIssueCompat(deviceProxyCompatJSON(claims, "device-proxy-ticket", jti, exp), cfg.SigningSecret)
}

// VerifyDeviceProxyTicket verifies a device proxy ticket (kind, signature,
// expiry, jti format and the all-or-nothing claims).
func VerifyDeviceProxyTicket(cfg config.Config, token string) (*DeviceProxyTicketPayload, error) {
	return VerifyDeviceProxyTicketAt(cfg, token, time.Now())
}

// VerifyDeviceProxyTicketAt is VerifyDeviceProxyTicket with an explicit clock.
func VerifyDeviceProxyTicketAt(cfg config.Config, token string, now time.Time) (*DeviceProxyTicketPayload, error) {
	var payload DeviceProxyTicketPayload
	if err := VerifyToken(token, cfg.SigningSecret, "device-proxy-ticket", now, &payload); err != nil {
		return nil, err
	}
	if !ticketIDPattern.MatchString(payload.JTI) || !payload.valid() {
		return nil, ErrInvalidToken
	}
	return &payload, nil
}

// MintDeviceProxySession mints a device proxy session from fresh claims;
// exp is pinned to claims.AuthExp (a session never outlives its lease).
func MintDeviceProxySession(cfg config.Config, claims DeviceProxyClaims) string {
	return mintDeviceProxySession(cfg, claims, "")
}

// MintDeviceProxySessionFromTicket exchanges a verified ticket for a session
// with the same claims. Like the TypeScript spread of the ticket payload,
// the ticket's jti is carried into the session.
func MintDeviceProxySessionFromTicket(cfg config.Config, ticket *DeviceProxyTicketPayload) string {
	return mintDeviceProxySession(cfg, ticket.DeviceProxyClaims, ticket.JTI)
}

// RenewDeviceProxySession re-mints a verified session with its own claims
// (and jti, if any); exp is pinned to AuthExp.
func RenewDeviceProxySession(cfg config.Config, session *DeviceProxySessionPayload) string {
	return mintDeviceProxySession(cfg, session.DeviceProxyClaims, session.JTI)
}

func mintDeviceProxySession(cfg config.Config, claims DeviceProxyClaims, jti string) string {
	return mustIssueCompat(deviceProxyCompatJSON(claims, "device-proxy-session", jti, claims.AuthExp), cfg.SigningSecret)
}

// VerifyDeviceProxySessionToken verifies a device proxy session token
// (cookie value or renewal chain).
func VerifyDeviceProxySessionToken(cfg config.Config, token string) (*DeviceProxySessionPayload, error) {
	return VerifyDeviceProxySessionTokenAt(cfg, token, time.Now())
}

// VerifyDeviceProxySessionTokenAt is VerifyDeviceProxySessionToken with an
// explicit clock.
func VerifyDeviceProxySessionTokenAt(cfg config.Config, token string, now time.Time) (*DeviceProxySessionPayload, error) {
	var payload DeviceProxySessionPayload
	if err := VerifyToken(token, cfg.SigningSecret, "device-proxy-session", now, &payload); err != nil {
		return nil, err
	}
	if !payload.valid() {
		return nil, ErrInvalidToken
	}
	return &payload, nil
}

// ReadDeviceProxySession reads the purpose's device cookie; a session signed
// for another purpose is rejected.
func ReadDeviceProxySession(cfg config.Config, req *http.Request, purpose DeviceProxyPurpose) (*DeviceProxySessionPayload, error) {
	token := ParseCookie(req.Header.Get("Cookie"))[deviceProxyCookieName(purpose)]
	if token == "" {
		return nil, ErrInvalidToken
	}
	claims, err := VerifyDeviceProxySessionToken(cfg, token)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != purpose {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func deviceProxyCookieName(purpose DeviceProxyPurpose) string {
	if purpose == DeviceProxyPurposeTerminal {
		return deviceTerminalProxyCookie
	}
	return deviceDashboardProxyCookie
}

func deviceProxyCookiePath(purpose DeviceProxyPurpose) string {
	if purpose == DeviceProxyPurposeTerminal {
		return "/s"
	}
	return "/"
}

// ClearDeviceProxySessionCookieHeader expires the purpose's device cookie
// (the Path must match the one used when it was set).
func ClearDeviceProxySessionCookieHeader(cfg config.Config, purpose DeviceProxyPurpose) string {
	parts := []string{deviceProxyCookieName(purpose) + "=", "Path=" + deviceProxyCookiePath(purpose), "HttpOnly", "SameSite=Lax", "Max-Age=0"}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

// HasDeviceProxySessionCookie is the principal-presence fence: a malformed
// or expired device cookie must still prevent falling back to a longer-lived
// SSO owner cookie in the same WebView jar.
func HasDeviceProxySessionCookie(req *http.Request, purpose DeviceProxyPurpose) bool {
	expected := deviceProxyCookieName(purpose)
	for _, header := range req.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			if separator := strings.IndexByte(part, '='); separator >= 0 && strings.TrimSpace(part[:separator]) == expected {
				return true
			}
		}
	}
	return false
}

// DeviceProxySessionCookieHeader sets the purpose's device cookie. Dashboard
// and terminal use distinct names and paths so neither can shadow the other.
// maxAgeSec is floored and clamped at 0.
func DeviceProxySessionCookieHeader(cfg config.Config, token string, maxAgeSec int64, purpose DeviceProxyPurpose) string {
	if maxAgeSec < 0 {
		maxAgeSec = 0
	}
	parts := []string{
		deviceProxyCookieName(purpose) + "=" + token,
		"Path=" + deviceProxyCookiePath(purpose),
		"HttpOnly",
		"SameSite=Lax",
		"Max-Age=" + strconv.FormatInt(maxAgeSec, 10),
	}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func (p ProxySessionPayload) compatJSON() []byte {
	return proxyCompatJSON(p.Kind, p.UnionID, p.MachineID, p.Exp)
}

func proxyCompatJSON(kind, unionID, machineID string, exp int64) []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", kind, &first)
	dst = appendStringField(dst, "unionId", unionID, &first)
	dst = appendStringField(dst, "machineId", machineID, &first)
	dst = appendInt64Field(dst, "exp", exp, &first)
	return append(dst, '}')
}
