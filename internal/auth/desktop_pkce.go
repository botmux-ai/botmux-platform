package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// Desktop Cloud PKCE (Electron loopback login). The flow is
// authorize -> Feishu -> /auth/callback (desktop-mounted state) -> one-time
// code -> /v1/desktop/auth/session exchange -> refresh. Every artefact is an
// HMAC-signed token so any pod can verify it without shared storage.

const (
	DesktopClientID = "botmux-desktop"
	// DesktopAuthCodeTTLSec bounds the loopback hop: the desktop exchanges the
	// one-time code immediately after Feishu redirects back.
	DesktopAuthCodeTTLSec = 120
	// DesktopAccessTTLSec is the short access ticket (expiresAt is sent in ms).
	DesktopAccessTTLSec = 60 * 60
	// DesktopRefreshTTLSec is the long refresh ticket; session-family
	// revocation tombstones must outlive it.
	DesktopRefreshTTLSec = 30 * 24 * 60 * 60
)

const (
	desktopAuthCodeKind = "desktop-auth-code"
	desktopAccessKind   = "desktop-access"
	desktopRefreshKind  = "desktop-refresh"
)

var (
	pkceChallengePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifierPattern    = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	desktopJTIPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`)
	desktopSessionIDFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

// desktopTokenKey derives a purpose-bound MAC key per Desktop token kind, so
// neither the bare signing secret nor another Desktop kind's key can mint a
// token that verifies here even if some other path allowed a custom kind.
func desktopTokenKey(cfg config.Config, kind string) string {
	mac := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	_, _ = mac.Write([]byte("botmux-" + kind + "-mac-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

// DesktopAuthPending is the PKCE mount carried inside the Feishu OAuth state.
// Field order is the TypeScript literal order (it is part of signed state).
type DesktopAuthPending struct {
	ClientID            string `json:"clientId"`
	RedirectURI         string `json:"redirectUri"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	// State is the desktop's own OAuth state, echoed back to the loopback.
	State string `json:"state"`
	// Nonce is the desktop's OIDC nonce, compared at session exchange.
	Nonce          string `json:"nonce"`
	LocalProfileID string `json:"localProfileId"`
}

func (p DesktopAuthPending) appendCompatJSON(dst []byte) []byte {
	dst = append(dst, '{')
	first := true
	dst = appendStringField(dst, "clientId", p.ClientID, &first)
	dst = appendStringField(dst, "redirectUri", p.RedirectURI, &first)
	dst = appendStringField(dst, "codeChallenge", p.CodeChallenge, &first)
	dst = appendStringField(dst, "codeChallengeMethod", p.CodeChallengeMethod, &first)
	dst = appendStringField(dst, "state", p.State, &first)
	dst = appendStringField(dst, "nonce", p.Nonce, &first)
	dst = appendStringField(dst, "localProfileId", p.LocalProfileID, &first)
	return append(dst, '}')
}

// DesktopAuthCodePayload is the one-time code minted at the Feishu callback.
type DesktopAuthCodePayload struct {
	Kind                string `json:"kind"`
	JTI                 string `json:"jti"`
	UnionID             string `json:"unionId"`
	Name                string `json:"name"`
	ClientID            string `json:"clientId"`
	RedirectURI         string `json:"redirectUri"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	LocalProfileID      string `json:"localProfileId"`
	// LinkedAt is the first-link time in Unix ms; refresh keeps it unchanged.
	LinkedAt int64 `json:"linkedAt"`
	Exp      int64 `json:"exp"`
}

func (p DesktopAuthCodePayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "jti", p.JTI, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "name", p.Name, &first)
	dst = appendStringField(dst, "clientId", p.ClientID, &first)
	dst = appendStringField(dst, "redirectUri", p.RedirectURI, &first)
	dst = appendStringField(dst, "codeChallenge", p.CodeChallenge, &first)
	dst = appendStringField(dst, "codeChallengeMethod", p.CodeChallengeMethod, &first)
	dst = appendStringField(dst, "state", p.State, &first)
	dst = appendStringField(dst, "nonce", p.Nonce, &first)
	dst = appendStringField(dst, "localProfileId", p.LocalProfileID, &first)
	dst = appendInt64Field(dst, "linkedAt", p.LinkedAt, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

// DesktopAccessPayload is shared by access and refresh tickets (they differ
// only in kind, key and lifetime).
type DesktopAccessPayload struct {
	Kind string `json:"kind"`
	// SID is the revocable session-family id shared by access and refresh.
	SID            string `json:"sid"`
	UnionID        string `json:"unionId"`
	Name           string `json:"name"`
	LocalProfileID string `json:"localProfileId"`
	ActiveOrgID    string `json:"activeOrgId,omitempty"`
	CloudProfileID string `json:"cloudProfileId"`
	LinkedAt       int64  `json:"linkedAt"`
	// Iat is in seconds; tickets minted in the same second differ by JTI.
	Iat int64  `json:"iat"`
	JTI string `json:"jti"`
	Exp int64  `json:"exp"`
}

// DesktopRefreshPayload has the same claims as the access ticket.
type DesktopRefreshPayload = DesktopAccessPayload

func (p DesktopAccessPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "sid", p.SID, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "name", p.Name, &first)
	dst = appendStringField(dst, "localProfileId", p.LocalProfileID, &first)
	if p.ActiveOrgID != "" {
		dst = appendStringField(dst, "activeOrgId", p.ActiveOrgID, &first)
	}
	dst = appendStringField(dst, "cloudProfileId", p.CloudProfileID, &first)
	dst = appendInt64Field(dst, "linkedAt", p.LinkedAt, &first)
	dst = appendInt64Field(dst, "iat", p.Iat, &first)
	dst = appendStringField(dst, "jti", p.JTI, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

// DesktopCloudSummary is the cloud identity block of Desktop responses.
// displayName is always present on every TypeScript code path.
type DesktopCloudSummary struct {
	CloudProfileID string `json:"cloudProfileId"`
	UserID         string `json:"userId"`
	Email          string `json:"email"`
	DisplayName    string `json:"displayName"`
	ActiveOrgID    string `json:"activeOrgId,omitempty"`
	ActiveOrgName  string `json:"activeOrgName,omitempty"`
	LinkedAt       int64  `json:"linkedAt"`
}

type DesktopOrgSummary struct {
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
	Role  string `json:"role,omitempty"`
}

// DesktopCapabilityFlags is a struct rather than a map so the JSON key order
// matches the TypeScript object literal (Go maps encode sorted).
type DesktopCapabilityFlags struct {
	Share         bool `json:"share"`
	Team          bool `json:"team"`
	ShareCreate   bool `json:"share.create"`
	ShareManage   bool `json:"share.manage"`
	RelayUse      bool `json:"relay.use"`
	TeamMember    bool `json:"team.member"`
	EnterpriseSSO bool `json:"enterprise.sso"`
}

type DesktopCapabilities struct {
	Flags DesktopCapabilityFlags `json:"flags"`
	// RefreshedAt is Unix ms.
	RefreshedAt int64 `json:"refreshedAt"`
}

type DesktopSessionExchangeResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	// ExpiresAt is Unix ms; the desktop schedules refresh from it.
	ExpiresAt     int64               `json:"expiresAt"`
	Cloud         DesktopCloudSummary `json:"cloud"`
	Organizations []DesktopOrgSummary `json:"organizations,omitempty"`
	Capabilities  DesktopCapabilities `json:"capabilities"`
}

// IsAllowedDesktopClientID checks BOTMUX_DESKTOP_CLIENT_IDS (comma separated,
// read on every call like the TypeScript process.env lookup).
func IsAllowedDesktopClientID(clientID string) bool {
	allowed := os.Getenv("BOTMUX_DESKTOP_CLIENT_IDS")
	if allowed == "" {
		allowed = DesktopClientID
	}
	for _, candidate := range strings.Split(allowed, ",") {
		if candidate = jsTrim(candidate); candidate != "" && candidate == clientID {
			return true
		}
	}
	return false
}

// IsAllowedDesktopRedirectURI accepts only the desktop loopback callback
// http://{127.0.0.1|localhost|[::1]}:<port>/auth/callback with no userinfo,
// query or fragment. It is intentionally a strict subset of the WHATWG-URL
// based TypeScript check: exotic spellings that WHATWG would normalize (IPv4
// shorthand, dot segments, empty userinfo) are rejected rather than accepted.
func IsAllowedDesktopRedirectURI(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || !strings.EqualFold(u.Scheme, "http") || u.Opaque != "" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "localhost", "::1":
	default:
		return false
	}
	if u.EscapedPath() != "/auth/callback" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	// WHATWG drops the scheme default port, so Number(u.port) is 0 for :80.
	if err != nil || port < 1 || port > 65535 || port == 80 {
		return false
	}
	return true
}

// VerifyPKCES256 checks an RFC 7636 S256 verifier against its challenge.
func VerifyPKCES256(codeVerifier, codeChallenge string) bool {
	if !pkceVerifierPattern.MatchString(codeVerifier) || !pkceChallengePattern.MatchString(codeChallenge) {
		return false
	}
	digest := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(codeChallenge)) == 1
}

// CloudProfileIDFor derives the stable cloud profile id for a local profile.
func CloudProfileIDFor(unionID, localProfileID string) string {
	sum := sha256.Sum256([]byte("desktop-cloud-profile\x00" + unionID + "\x00" + localProfileID))
	return "dcp_" + hex.EncodeToString(sum[:])[:24]
}

// PersonalOrgFor returns the only organization this phase supports.
func PersonalOrgFor(unionID string) DesktopOrgSummary {
	sum := sha256.Sum256([]byte("desktop-org\x00" + unionID))
	return DesktopOrgSummary{OrgID: "personal_" + hex.EncodeToString(sum[:])[:16], Name: "Personal", Role: "Owner"}
}

// SyntheticEmail fabricates the non-empty email the desktop contract needs;
// Feishu does not guarantee one. The JS regex runs per UTF-16 unit, so an
// astral character becomes two underscores.
func SyntheticEmail(unionID string) string {
	var b strings.Builder
	for _, r := range unionID {
		switch {
		case r == '.' || r == '_' || r == '-' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		case r > 0xFFFF:
			b.WriteString("__")
		default:
			b.WriteByte('_')
		}
	}
	safe := b.String()
	if len(safe) > 64 {
		safe = safe[:64]
	}
	if safe == "" {
		safe = "user"
	}
	return safe + "@users.botmux.local"
}

// DefaultDesktopCapabilities returns the capability flags for this deployment.
func DefaultDesktopCapabilities(relayEnabled bool) DesktopCapabilities {
	return DefaultDesktopCapabilitiesAt(relayEnabled, time.Now())
}

func DefaultDesktopCapabilitiesAt(relayEnabled bool, now time.Time) DesktopCapabilities {
	return DesktopCapabilities{
		Flags: DesktopCapabilityFlags{
			Share:         true,
			Team:          true,
			ShareCreate:   true,
			ShareManage:   true,
			RelayUse:      relayEnabled,
			TeamMember:    true,
			EnterpriseSSO: true,
		},
		RefreshedAt: now.UnixMilli(),
	}
}

// DesktopCloudSummaryInput feeds BuildDesktopCloudSummary. Empty
// CloudProfileID and zero LinkedAt fall back like the TypeScript `||`.
type DesktopCloudSummaryInput struct {
	UnionID        string
	Name           string
	LocalProfileID string
	ActiveOrgID    string
	ActiveOrgName  string
	CloudProfileID string
	LinkedAt       int64
}

func BuildDesktopCloudSummary(args DesktopCloudSummaryInput) DesktopCloudSummary {
	return buildDesktopCloudSummaryAt(args, time.Now())
}

func buildDesktopCloudSummaryAt(args DesktopCloudSummaryInput, now time.Time) DesktopCloudSummary {
	cloudProfileID := args.CloudProfileID
	if cloudProfileID == "" {
		cloudProfileID = CloudProfileIDFor(args.UnionID, args.LocalProfileID)
	}
	linkedAt := args.LinkedAt
	if linkedAt == 0 {
		linkedAt = now.UnixMilli()
	}
	return DesktopCloudSummary{
		CloudProfileID: cloudProfileID,
		UserID:         args.UnionID,
		Email:          SyntheticEmail(args.UnionID),
		DisplayName:    args.Name,
		ActiveOrgID:    args.ActiveOrgID,
		ActiveOrgName:  args.ActiveOrgName,
		LinkedAt:       linkedAt,
	}
}

// DesktopUser is the Feishu identity behind a desktop auth code.
type DesktopUser struct {
	UnionID string
	Name    string
}

func MintDesktopAuthCode(cfg config.Config, user DesktopUser, pending DesktopAuthPending) string {
	return mintDesktopAuthCode(cfg, user, pending, time.Now(), defaultRandom)
}

func MintDesktopAuthCodeAt(cfg config.Config, user DesktopUser, pending DesktopAuthPending, now time.Time) string {
	return mintDesktopAuthCode(cfg, user, pending, now, defaultRandom)
}

func mintDesktopAuthCode(cfg config.Config, user DesktopUser, pending DesktopAuthPending, now time.Time, random io.Reader) string {
	payload := DesktopAuthCodePayload{
		Kind:                desktopAuthCodeKind,
		JTI:                 randomBase64URLFrom(random, 12),
		UnionID:             user.UnionID,
		Name:                user.Name,
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		State:               pending.State,
		Nonce:               pending.Nonce,
		LocalProfileID:      pending.LocalProfileID,
		LinkedAt:            now.UnixMilli(),
		Exp:                 now.Unix() + DesktopAuthCodeTTLSec,
	}
	return mustIssueCompat(payload.compatJSON(), desktopTokenKey(cfg, desktopAuthCodeKind))
}

func VerifyDesktopAuthCode(cfg config.Config, code string) (*DesktopAuthCodePayload, error) {
	return VerifyDesktopAuthCodeAt(cfg, code, time.Now())
}

func VerifyDesktopAuthCodeAt(cfg config.Config, code string, now time.Time) (*DesktopAuthCodePayload, error) {
	var payload DesktopAuthCodePayload
	if err := VerifyToken(code, desktopTokenKey(cfg, desktopAuthCodeKind), desktopAuthCodeKind, now, &payload); err != nil {
		return nil, err
	}
	if !desktopJTIPattern.MatchString(payload.JTI) {
		return nil, ErrInvalidToken
	}
	return &payload, nil
}

// DesktopSessionInput describes the identity a desktop session is minted for.
// Empty/zero optional fields fall back exactly like the TypeScript `||`.
type DesktopSessionInput struct {
	UnionID        string
	Name           string
	LocalProfileID string
	ActiveOrgID    string
	CloudProfileID string
	LinkedAt       int64
	SessionID      string
}

func MintDesktopSession(cfg config.Config, user DesktopSessionInput) DesktopSessionExchangeResponse {
	return mintDesktopSession(cfg, user, time.Now(), defaultRandom)
}

func MintDesktopSessionAt(cfg config.Config, user DesktopSessionInput, now time.Time) DesktopSessionExchangeResponse {
	return mintDesktopSession(cfg, user, now, defaultRandom)
}

func mintDesktopSession(cfg config.Config, user DesktopSessionInput, now time.Time, random io.Reader) DesktopSessionExchangeResponse {
	nowSec := now.Unix()
	org := PersonalOrgFor(user.UnionID)
	// Only the Personal org exists in this phase. Never write an arbitrary org
	// id from an old ticket or a buggy caller into a new ticket.
	activeOrgID := org.OrgID
	if user.ActiveOrgID == org.OrgID {
		activeOrgID = user.ActiveOrgID
	}
	cloudProfileID := user.CloudProfileID
	if cloudProfileID == "" {
		cloudProfileID = CloudProfileIDFor(user.UnionID, user.LocalProfileID)
	}
	linkedAt := user.LinkedAt
	if linkedAt == 0 {
		linkedAt = now.UnixMilli()
	}
	sessionID := user.SessionID
	if sessionID == "" {
		sessionID = randomBase64URLFrom(random, 18)
	}
	access := DesktopAccessPayload{
		Kind:           desktopAccessKind,
		SID:            sessionID,
		UnionID:        user.UnionID,
		Name:           user.Name,
		LocalProfileID: user.LocalProfileID,
		ActiveOrgID:    activeOrgID,
		CloudProfileID: cloudProfileID,
		LinkedAt:       linkedAt,
		Iat:            nowSec,
		JTI:            randomHexFrom(random, 12),
		Exp:            nowSec + DesktopAccessTTLSec,
	}
	refresh := access
	refresh.Kind = desktopRefreshKind
	refresh.JTI = randomHexFrom(random, 12)
	refresh.Exp = nowSec + DesktopRefreshTTLSec

	return DesktopSessionExchangeResponse{
		AccessToken:  mustIssueCompat(access.compatJSON(), desktopTokenKey(cfg, desktopAccessKind)),
		RefreshToken: mustIssueCompat(refresh.compatJSON(), desktopTokenKey(cfg, desktopRefreshKind)),
		ExpiresAt:    (nowSec + DesktopAccessTTLSec) * 1000,
		Cloud: buildDesktopCloudSummaryAt(DesktopCloudSummaryInput{
			UnionID:        user.UnionID,
			Name:           user.Name,
			LocalProfileID: user.LocalProfileID,
			ActiveOrgID:    activeOrgID,
			ActiveOrgName:  org.Name,
			CloudProfileID: cloudProfileID,
			LinkedAt:       linkedAt,
		}, now),
		Organizations: []DesktopOrgSummary{org},
		Capabilities:  DefaultDesktopCapabilitiesAt(cfg.RelaySigningSecret != "", now),
	}
}

func VerifyDesktopAccessToken(cfg config.Config, token string) (*DesktopAccessPayload, error) {
	return VerifyDesktopAccessTokenAt(cfg, token, time.Now())
}

func VerifyDesktopAccessTokenAt(cfg config.Config, token string, now time.Time) (*DesktopAccessPayload, error) {
	return verifyDesktopSessionToken(cfg, token, desktopAccessKind, now)
}

func VerifyDesktopRefreshToken(cfg config.Config, token string) (*DesktopRefreshPayload, error) {
	return VerifyDesktopRefreshTokenAt(cfg, token, time.Now())
}

func VerifyDesktopRefreshTokenAt(cfg config.Config, token string, now time.Time) (*DesktopRefreshPayload, error) {
	return verifyDesktopSessionToken(cfg, token, desktopRefreshKind, now)
}

func verifyDesktopSessionToken(cfg config.Config, token, kind string, now time.Time) (*DesktopAccessPayload, error) {
	var payload DesktopAccessPayload
	if err := VerifyToken(token, desktopTokenKey(cfg, kind), kind, now, &payload); err != nil {
		return nil, err
	}
	if !desktopSessionIDFormat.MatchString(payload.SID) {
		return nil, ErrInvalidToken
	}
	return &payload, nil
}

// ParseBearer mirrors /^Bearer\s+(\S+)$/i over the trimmed header value and
// returns "" when it does not match. Node decodes header bytes as latin1, so a
// raw 0xA0 byte counts as whitespace exactly as it does in JavaScript.
func ParseBearer(authorization string) string {
	isSpace := func(c byte) bool {
		switch c {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0:
			return true
		}
		return false
	}
	start, end := 0, len(authorization)
	for start < end && isSpace(authorization[start]) {
		start++
	}
	for end > start && isSpace(authorization[end-1]) {
		end--
	}
	value := authorization[start:end]
	const scheme = "bearer"
	if len(value) <= len(scheme) || !strings.EqualFold(value[:len(scheme)], scheme) {
		return ""
	}
	rest := value[len(scheme):]
	i := 0
	for i < len(rest) && isSpace(rest[i]) {
		i++
	}
	if i == 0 || i == len(rest) {
		return ""
	}
	token := rest[i:]
	for j := 0; j < len(token); j++ {
		if isSpace(token[j]) {
			return ""
		}
	}
	return token
}

// DesktopAuthorizeError is the wire error code for a rejected authorize query
// (invalid_client, invalid_redirect_uri, ...).
type DesktopAuthorizeError string

func (e DesktopAuthorizeError) Error() string { return string(e) }

const (
	DesktopAuthorizeInvalidClient              DesktopAuthorizeError = "invalid_client"
	DesktopAuthorizeUnsupportedResponseType    DesktopAuthorizeError = "unsupported_response_type"
	DesktopAuthorizeInvalidRedirectURI         DesktopAuthorizeError = "invalid_redirect_uri"
	DesktopAuthorizeInvalidState               DesktopAuthorizeError = "invalid_state"
	DesktopAuthorizeInvalidNonce               DesktopAuthorizeError = "invalid_nonce"
	DesktopAuthorizeInvalidCodeChallenge       DesktopAuthorizeError = "invalid_code_challenge"
	DesktopAuthorizeInvalidCodeChallengeMethod DesktopAuthorizeError = "invalid_code_challenge_method"
	DesktopAuthorizeInvalidLocalProfileID      DesktopAuthorizeError = "invalid_local_profile_id"
)

// ParseDesktopAuthorizeQuery validates the authorize query and returns the
// PKCE mount, or a DesktopAuthorizeError carrying the wire error code. Checks
// run in the TypeScript order so the first failing field wins identically.
func ParseDesktopAuthorizeQuery(params url.Values) (DesktopAuthPending, error) {
	get := func(name string) string { return jsTrim(params.Get(name)) }
	clientID := get("client_id")
	responseType := get("response_type")
	redirectURI := get("redirect_uri")
	state := get("state")
	nonce := get("nonce")
	codeChallenge := get("code_challenge")
	codeChallengeMethod := get("code_challenge_method")
	localProfileID := get("local_profile_id")

	switch {
	case clientID == "" || !IsAllowedDesktopClientID(clientID):
		return DesktopAuthPending{}, DesktopAuthorizeInvalidClient
	case responseType != "code":
		return DesktopAuthPending{}, DesktopAuthorizeUnsupportedResponseType
	case redirectURI == "" || !IsAllowedDesktopRedirectURI(redirectURI):
		return DesktopAuthPending{}, DesktopAuthorizeInvalidRedirectURI
	case state == "" || jsLength(state) > 256:
		return DesktopAuthPending{}, DesktopAuthorizeInvalidState
	case nonce == "" || jsLength(nonce) > 256:
		return DesktopAuthPending{}, DesktopAuthorizeInvalidNonce
	case !pkceChallengePattern.MatchString(codeChallenge):
		return DesktopAuthPending{}, DesktopAuthorizeInvalidCodeChallenge
	case codeChallengeMethod != "S256":
		return DesktopAuthPending{}, DesktopAuthorizeInvalidCodeChallengeMethod
	case localProfileID == "" || jsLength(localProfileID) > 128:
		return DesktopAuthPending{}, DesktopAuthorizeInvalidLocalProfileID
	}
	return DesktopAuthPending{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		State:               state,
		Nonce:               nonce,
		LocalProfileID:      localProfileID,
	}, nil
}
