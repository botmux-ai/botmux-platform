package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// Desktop -> single remote Dashboard purpose-bound short ticket. It is honored
// only on the machine subdomain's explicit REST allowlist; it never replaces
// Desktop Cloud access, Web SSO or the device proxy session, and never carries
// the machine's .dashboard-token.

const (
	DesktopDashboardAccessTTLSec = 5 * 60
	DesktopDashboardAudience     = "botmux-machine-dashboard"
	desktopDashboardAccessKind   = "desktop-dashboard-access"
)

type DesktopDashboardScope string

const (
	DesktopDashboardObserve DesktopDashboardScope = "observe"
	DesktopDashboardManage  DesktopDashboardScope = "manage"
)

var dashboardMachineIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

// DesktopDashboardAccessPayload is the signed claim set (TypeScript order).
type DesktopDashboardAccessPayload struct {
	Kind string `json:"kind"`
	Aud  string `json:"aud"`
	// SID is the Desktop session family; revoking it kills this ticket too.
	SID string `json:"sid"`
	// Sub is the machine owner's unionId.
	Sub            string                `json:"sub"`
	CloudProfileID string                `json:"cloudProfileId"`
	MachineID      string                `json:"machineId"`
	Scope          DesktopDashboardScope `json:"scope"`
	Iat            int64                 `json:"iat"`
	JTI            string                `json:"jti"`
	Exp            int64                 `json:"exp"`
}

func (p DesktopDashboardAccessPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "aud", p.Aud, &first)
	dst = appendStringField(dst, "sid", p.SID, &first)
	dst = appendStringField(dst, "sub", p.Sub, &first)
	dst = appendStringField(dst, "cloudProfileId", p.CloudProfileID, &first)
	dst = appendStringField(dst, "machineId", p.MachineID, &first)
	dst = appendStringField(dst, "scope", string(p.Scope), &first)
	dst = appendInt64Field(dst, "iat", p.Iat, &first)
	dst = appendStringField(dst, "jti", p.JTI, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

func dashboardAccessKey(cfg config.Config) string {
	mac := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	_, _ = mac.Write([]byte("botmux-desktop-dashboard-access-mac-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

// DesktopDashboardAccessToken is the mint result; ExpiresAt is Unix ms.
type DesktopDashboardAccessToken struct {
	AccessToken string
	ExpiresAt   int64
}

func MintDesktopDashboardAccessToken(cfg config.Config, access *DesktopAccessPayload, machineID string, scope DesktopDashboardScope) DesktopDashboardAccessToken {
	return mintDesktopDashboardAccessToken(cfg, access, machineID, scope, time.Now(), defaultRandom)
}

func MintDesktopDashboardAccessTokenAt(cfg config.Config, access *DesktopAccessPayload, machineID string, scope DesktopDashboardScope, now time.Time) DesktopDashboardAccessToken {
	return mintDesktopDashboardAccessToken(cfg, access, machineID, scope, now, defaultRandom)
}

func mintDesktopDashboardAccessToken(cfg config.Config, access *DesktopAccessPayload, machineID string, scope DesktopDashboardScope, now time.Time, random io.Reader) DesktopDashboardAccessToken {
	nowSec := now.Unix()
	// A delegated machine ticket never outlives the Desktop access ticket that
	// authorized it; normal callers refresh long before this boundary.
	exp := min(nowSec+DesktopDashboardAccessTTLSec, access.Exp)
	payload := DesktopDashboardAccessPayload{
		Kind:           desktopDashboardAccessKind,
		Aud:            DesktopDashboardAudience,
		SID:            access.SID,
		Sub:            access.UnionID,
		CloudProfileID: access.CloudProfileID,
		MachineID:      machineID,
		Scope:          scope,
		Iat:            nowSec,
		JTI:            randomBase64URLFrom(random, 12),
		Exp:            exp,
	}
	return DesktopDashboardAccessToken{
		AccessToken: mustIssueCompat(payload.compatJSON(), dashboardAccessKey(cfg)),
		ExpiresAt:   exp * 1000,
	}
}

func VerifyDesktopDashboardAccessToken(cfg config.Config, token string) (*DesktopDashboardAccessPayload, error) {
	return VerifyDesktopDashboardAccessTokenAt(cfg, token, time.Now())
}

// VerifyDesktopDashboardAccessTokenAt validates signature, audience, claim
// shapes and the strict five-minute lifetime. Unlike the generic signed-token
// check, exp == now is already expired here, so a zero-length lease cannot
// still land one request.
func VerifyDesktopDashboardAccessTokenAt(cfg config.Config, token string, now time.Time) (*DesktopDashboardAccessPayload, error) {
	nowSec := now.Unix()
	var raw map[string]json.RawMessage
	if err := VerifyToken(token, dashboardAccessKey(cfg), desktopDashboardAccessKind, time.Unix(nowSec, 0), &raw); err != nil {
		return nil, err
	}
	str := func(name string) string {
		var value string
		if json.Unmarshal(raw[name], &value) != nil {
			return ""
		}
		return value
	}
	integer := func(name string) (int64, bool) {
		var value float64
		if len(raw[name]) == 0 || json.Unmarshal(raw[name], &value) != nil || value != math.Trunc(value) {
			return 0, false
		}
		return int64(value), true
	}
	iat, iatOK := integer("iat")
	exp, expOK := integer("exp")
	payload := &DesktopDashboardAccessPayload{
		Kind:           str("kind"),
		Aud:            str("aud"),
		SID:            str("sid"),
		Sub:            str("sub"),
		CloudProfileID: str("cloudProfileId"),
		MachineID:      str("machineId"),
		Scope:          DesktopDashboardScope(str("scope")),
		Iat:            iat,
		JTI:            str("jti"),
		Exp:            exp,
	}
	if payload.Aud != DesktopDashboardAudience ||
		!desktopSessionIDFormat.MatchString(payload.SID) ||
		!dashboardMachineIDPattern.MatchString(payload.MachineID) ||
		payload.Sub == "" ||
		payload.CloudProfileID == "" ||
		(payload.Scope != DesktopDashboardObserve && payload.Scope != DesktopDashboardManage) ||
		!iatOK || !expOK ||
		exp <= iat ||
		exp <= nowSec ||
		exp-iat > DesktopDashboardAccessTTLSec ||
		!desktopJTIPattern.MatchString(payload.JTI) {
		return nil, ErrInvalidToken
	}
	return payload, nil
}

// DashboardRequestDecision is the wire decision of the allowlist check.
type DashboardRequestDecision string

const (
	DashboardRequestOK                DashboardRequestDecision = "ok"
	DashboardRequestInsufficientScope DashboardRequestDecision = "insufficient_scope"
	DashboardRequestPathNotAllowed    DashboardRequestDecision = "path_not_allowed"
)

var manageAPIRoots = map[string]bool{
	"asks": true, "bot-onboarding": true, "bots": true, "cli-options": true,
	"connectors": true, "feishu-login": true, "game": true, "groups": true,
	"insights": true, "owner-profile": true, "plugins": true, "resources": true,
	"role-profiles": true, "roles": true, "schedules": true, "sessions": true,
	"settings": true, "skills": true, "trigger-logs": true, "team": true,
	"vc-meeting": true, "webhook-logs": true, "webhook-secrets": true, "whiteboards": true,
}

// freshSSOWriteAPIRoots change the daemon/CLI execution environment, which is
// equivalent to a high-sensitivity local owner action. Delegated manage
// tickets carry no fresh-SSO proof, so these roots are read-only for them.
var freshSSOWriteAPIRoots = map[string]bool{
	"cli-options": true, "plugins": true, "settings": true, "skills": true,
}

var observeExactPaths = map[string]bool{
	"/__health":               true,
	"/__selfcheck":            true,
	"/__desktop/compat":       true,
	"/api/asks/pending":       true,
	"/api/bots":               true,
	"/api/connectors":         true,
	"/api/connectors/stats":   true,
	"/api/game/status":        true,
	"/api/groups":             true,
	"/api/insights/summary":   true,
	"/api/owner-profile":      true,
	"/api/plugins":            true,
	"/api/plugins/dashboard":  true,
	"/api/resources/current":  true,
	"/api/resources/history":  true,
	"/api/role-profiles":      true,
	"/api/schedules":          true,
	"/api/sessions":           true,
	"/api/settings":           true,
	"/api/skills":             true,
	"/api/team/local":         true,
	"/api/team/remote-roster": true,
	"/api/update/status":      true,
	"/api/update/versions":    true,
	"/api/update/changelog":   true,
	"/api/whiteboards":        true,
}

var (
	terminalWriteLinkPattern = regexp.MustCompile(`^/api/sessions/[^/]+/write-link(?:/|$)`)
	terminalSessionPattern   = regexp.MustCompile(`^/api/sessions/[^/]+/(?:pty|terminal|attach|open-terminal)(?:/|$)`)
	observeSessionPattern    = regexp.MustCompile(`^/api/sessions/[^/]+/(?:history|insight|sandbox-diff)$`)
	observeInsightTurn       = regexp.MustCompile(`^/api/sessions/[^/]+/insight/turn/[^/]+$`)
	manageAPIRootPattern     = regexp.MustCompile(`^/api/([^/]+)(?:/|$)`)
)

// exactOrUnder matches "/x" or "/x/..." (but not "/xy").
func exactOrUnder(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func isDashboardShellRead(method, path string) bool {
	if method != "GET" && method != "HEAD" {
		return false
	}
	return path == "/" || path == "/favicon.ico" || path == "/favicon.png" || path == "/apple-touch-icon.png" ||
		strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/game/") || strings.HasPrefix(path, "/plugins/")
}

func isTerminalCredentialPath(path string) bool {
	return terminalWriteLinkPattern.MatchString(path) || terminalSessionPattern.MatchString(path) ||
		exactOrUnder(path, "/api/terminal") || exactOrUnder(path, "/api/terminals") || exactOrUnder(path, "/api/pty")
}

// AuthorizeDesktopDashboardRequest opens only explicitly listed control-plane
// REST: observe reads runtime/monitoring data, manage may operate listed API
// roots, and Workflow, daemon/CLI internals, webhook ingress, federation,
// terminals and long streams are always refused.
//
// escapedPath must be the still-percent-encoded request path (for net/http,
// r.URL.EscapedPath()): it is decoded here with decodeURIComponent semantics
// so that malformed escapes are refused rather than reinterpreted.
func AuthorizeDesktopDashboardRequest(scope DesktopDashboardScope, method, escapedPath string) DashboardRequestDecision {
	decoded, ok := decodeURIComponentJS(escapedPath)
	if !ok {
		return DashboardRequestPathNotAllowed
	}
	path := jsLowerCase(decoded)
	method = strings.ToUpper(method)

	for _, root := range []string{
		"/s", "/webhook", "/__cli", "/__daemon", "/__dev", "/api/workflow", "/api/workflows",
		"/api/v3", "/api/trigger", "/api/federation", "/api/internal",
	} {
		if exactOrUnder(path, root) {
			return DashboardRequestPathNotAllowed
		}
	}
	if path == "/api/update/run" || isTerminalCredentialPath(path) {
		return DashboardRequestPathNotAllowed
	}

	if isDashboardShellRead(method, path) {
		return DashboardRequestOK
	}
	if path == "/events" {
		if method == "GET" {
			return DashboardRequestOK
		}
		return DashboardRequestPathNotAllowed
	}

	if scope == DesktopDashboardObserve {
		if method != "GET" && method != "HEAD" {
			return DashboardRequestInsufficientScope
		}
		if observeExactPaths[path] {
			return DashboardRequestOK
		}
		// History/insight/sandbox diff are observable; write-link is a write
		// entry point and was refused above.
		if observeSessionPattern.MatchString(path) || observeInsightTurn.MatchString(path) {
			return DashboardRequestOK
		}
		return DashboardRequestInsufficientScope
	}

	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		return DashboardRequestPathNotAllowed
	}
	if path == "/__health" || path == "/__selfcheck" || path == "/__desktop/compat" {
		if method == "GET" || method == "HEAD" {
			return DashboardRequestOK
		}
		return DashboardRequestPathNotAllowed
	}
	if (method == "GET" || method == "HEAD") && observeExactPaths[path] {
		return DashboardRequestOK
	}
	match := manageAPIRootPattern.FindStringSubmatch(path)
	if match == nil || !manageAPIRoots[match[1]] {
		return DashboardRequestPathNotAllowed
	}
	if freshSSOWriteAPIRoots[match[1]] && method != "GET" && method != "HEAD" {
		return DashboardRequestInsufficientScope
	}
	return DashboardRequestOK
}

// RegisterDesktopDashboardExpiryLease makes sure a successful SSE/long HTTP
// request cannot turn a five-minute ticket into an unbounded stream: destroy
// runs at the ticket's exp. Call the returned cleanup when the stream closes
// normally; destroy must tolerate an already-closed stream.
func RegisterDesktopDashboardExpiryLease(destroy func(), expiresAtSec int64, now time.Time) (cleanup func()) {
	delay := time.Duration(max(0, expiresAtSec*1000-now.UnixMilli())) * time.Millisecond
	timer := time.AfterFunc(delay, destroy)
	return func() { timer.Stop() }
}

var dashboardAuthQueryKeys = map[string]bool{
	"access_token": true, "auth": true, "authorization": true, "dashboard_token": true,
	"t": true, "ticket": true, "token": true,
}

// StripDesktopDashboardAuthQuery removes every query parameter that could
// carry authentication material and returns the forward target
// (escaped path + query). Like URLSearchParams#delete, the query is
// re-serialized only when something was removed.
func StripDesktopDashboardAuthQuery(u *url.URL) string {
	pairs := parseFormURLEncoded(u.RawQuery)
	kept := pairs[:0:0]
	for _, pair := range pairs {
		if !dashboardAuthQueryKeys[jsLowerCase(pair.name)] {
			kept = append(kept, pair)
		}
	}
	query := u.RawQuery
	if len(kept) != len(pairs) {
		query = serializeFormURLEncoded(kept)
	}
	if query == "" {
		return u.EscapedPath()
	}
	return u.EscapedPath() + "?" + query
}
