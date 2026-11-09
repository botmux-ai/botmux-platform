package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
)

// Providers port src/auth/credential-providers.ts: per platform, "refresh
// credential → short-lived token" (DESIGN §3.1/§3.2).
//
//   - lark-cli: the platform Feishu app's OAuth refresh_token. A cached
//     access_token is handed out while it lasts; otherwise the refresh token
//     is exchanged (Feishu rotates it, so the result must be CAS-written back).
//     Variables: LARKSUITE_CLI_APP_ID + LARKSUITE_CLI_USER_ACCESS_TOKEN.
//   - DeviceLogins: platforms an edition links in, each minting its own.
//
// Nothing here fails hard: a failure is either reauth_required (the stored
// credential is dead, a person must authorize again → 409) or unavailable
// (transient, keep the credential → 502).
type Providers struct {
	Config config.Config
	// Keys is the vault key source; nil serves the config KEKs.
	Keys KeySource
	// Feishu renews lark-cli tokens.
	Feishu *feishu.Client
	// DeviceLogins are the other vault platforms, in page order.
	DeviceLogins []DeviceLogin
	// Now is the clock (ms precision); nil is time.Now.
	Now func() time.Time
}

const (
	PlatformLarkCLI = "lark-cli"

	// larkAccessMinRemaining: a cached access_token is reused only while at
	// least this much of it is left.
	larkAccessMinRemaining = 5 * time.Minute
)

// Record is the part of a stored credential the providers read
// (CredentialDoc unionId / platform / sealed / meta.appId / refreshExpiresAt).
type Record struct {
	UnionID  string
	Platform string
	Sealed   Sealed
	// AppID is meta.appId ("" falls back to the platform app).
	AppID string
	// RefreshExpiresAt is the stored refresh expiry in ms (0 = unknown).
	RefreshExpiresAt int64
}

// MintFailure is MintResult.Reason.
type MintFailure string

const (
	MintReauthRequired MintFailure = "reauth_required"
	MintUnavailable    MintFailure = "unavailable"
)

// MintResult is the TS MintResult union: OK with variables, or a Reason with
// a Detail.
type MintResult struct {
	OK        bool
	Variables Variables
	// ExpiresAt is the token expiry (ms).
	ExpiresAt int64
	// UpdatedSealed is the refreshed envelope to CAS-write back (nil: unchanged).
	UpdatedSealed *Sealed
	// RefreshExpiresAt is the new refresh expiry (ms, 0 = not known).
	RefreshExpiresAt int64

	Reason MintFailure
	Detail string
}

func mintFailed(reason MintFailure, detail string) MintResult {
	return MintResult{Reason: reason, Detail: detail}
}

// DescribeFailure is describeMintFailure.
func (r MintResult) DescribeFailure() string { return string(r.Reason) + ": " + r.Detail }

// Variable is one short-lived environment variable handed to a machine.
type Variable struct {
	Name  string
	Value string
}

// Variables keeps the TS object-literal insertion order on the wire (the
// tool's primary variable first). Only names are ever logged.
type Variables []Variable

func (v Variables) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, item := range v {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := marshalNoEscape(item.Name)
		if err != nil {
			return nil, err
		}
		value, err := marshalNoEscape(item.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Keys returns the variable names (variableKeys: never the values).
func (v Variables) Keys() []string {
	out := make([]string, 0, len(v))
	for _, item := range v {
		out = append(out, item.Name)
	}
	return out
}

// Get returns the named value ("" when absent).
func (v Variables) Get(name string) string {
	for _, item := range v {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

// LarkOAuthPayload is the sealed lark-cli plaintext (TS LarkOauthPayload).
// Times are ms; float64 keeps a TS-written value readable whatever its
// numeric form and encodes integers exactly like JSON.stringify.
type LarkOAuthPayload struct {
	// OAuth "v2" = minted on the OAuth v2 endpoint and renewable only there;
	// empty = an early v1 OIDC token.
	OAuth            string  `json:"oauth,omitempty"`
	RefreshToken     string  `json:"refreshToken"`
	AccessToken      string  `json:"accessToken,omitempty"`
	AccessExpiresAt  float64 `json:"accessExpiresAt,omitempty"`
	RefreshExpiresAt float64 `json:"refreshExpiresAt,omitempty"`
}

// OAuthV2 is LarkOAuthPayload.OAuth for credentials minted on the v2 endpoint.
const OAuthV2 = "v2"

func (p Providers) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p Providers) nowMS() int64 { return p.now().UnixMilli() }

// keys is getCredentialKeys: nil when the vault has no usable key.
func (p Providers) keys(ctx context.Context) *Keys {
	source := p.Keys
	if source == nil {
		source = ConfigKeySource(p.Config)
	}
	keys, err := source(ctx)
	if err != nil {
		return nil
	}
	return keys
}

// SealPayload seals payload's JSON under the current KEK, bound to
// unionID|platform.
func SealPayload(keys *Keys, unionID, platform string, payload any) (Sealed, error) {
	plain, err := marshalNoEscape(payload)
	if err != nil {
		return Sealed{}, err
	}
	defer clear(plain)
	return Seal(keys.Current, plain, AAD(unionID, platform))
}

// OpenPayload returns the sealed JSON plaintext; ok=false when no key opens
// it (wrong KEK, tampering, or a record moved to another identity).
func OpenPayload(keys *Keys, unionID, platform string, sealed Sealed) (plaintext []byte, ok bool) {
	if keys == nil {
		return nil, false
	}
	return Open(keys.All, sealed, AAD(unionID, platform))
}

// openFields is openPayload<T> followed by the caller's `if (!payload)`:
// the plaintext's members, with opened=false when it cannot be opened or
// parses to a falsy JSON value. A truthy non-object has no members.
func openFields(keys *Keys, unionID, platform string, sealed Sealed) (fields map[string]json.RawMessage, opened bool) {
	plain, ok := OpenPayload(keys, unionID, platform, sealed)
	if !ok {
		return nil, false
	}
	defer clear(plain)
	var value json.RawMessage
	if json.Unmarshal(plain, &value) != nil || !jsTruthy(value) {
		return nil, false
	}
	fields = map[string]json.RawMessage{}
	if trimmed := bytes.TrimSpace(value); len(trimmed) > 0 && trimmed[0] == '{' {
		_ = json.Unmarshal(trimmed, &fields)
	}
	return fields, true
}

// ---- lark-cli ----

// MintLark hands out the cached access_token while it has at least five
// minutes left, otherwise renews it with the refresh token in the scheme that
// issued it.
func (p Providers) MintLark(ctx context.Context, rec Record) MintResult {
	keys := p.keys(ctx)
	if keys == nil {
		return mintFailed(MintUnavailable, "credential keys unavailable")
	}
	payload, opened := openFields(keys, rec.UnionID, rec.Platform, rec.Sealed)
	if !opened {
		return mintFailed(MintReauthRequired, "stored credential cannot be opened")
	}
	refreshToken, isString := jsonString(payload["refreshToken"])
	if !isString || refreshToken == "" {
		// Authorized without offline_access (legacy): readable, but nothing to renew.
		return mintFailed(MintReauthRequired, "stored credential has no refresh token (re-authorize with offline_access)")
	}
	appID := rec.AppID
	if appID == "" {
		appID = p.Config.FeishuAppID
	}
	if appID == "" || p.Config.FeishuAppSecret == "" {
		return mintFailed(MintUnavailable, "platform feishu app not configured")
	}

	nowMS := float64(p.nowMS())
	accessToken := jsTruthyString(payload["accessToken"])
	accessExpiresAt := jsonNumber(payload["accessExpiresAt"])
	if accessToken != "" && accessExpiresAt != 0 && accessExpiresAt-nowMS > float64(larkAccessMinRemaining.Milliseconds()) {
		return MintResult{
			OK:        true,
			Variables: larkVariables(appID, accessToken),
			ExpiresAt: int64(accessExpiresAt),
		}
	}
	storedRefreshExpiresAt := jsonNumber(payload["refreshExpiresAt"])
	if storedRefreshExpiresAt != 0 && storedRefreshExpiresAt <= nowMS {
		return mintFailed(MintReauthRequired, "refresh token expired")
	}

	if p.Feishu == nil {
		return mintFailed(MintUnavailable, "platform feishu app not configured")
	}
	oauth, _ := jsonString(payload["oauth"])
	refreshed, err := p.Feishu.RefreshCredentialToken(ctx, oauth == OAuthV2, appID, refreshToken)
	if err != nil {
		return mintFailed(MintUnavailable, "feishu refresh failed: "+feishu.JSErrorString(err))
	}
	if !refreshed.OK {
		if refreshed.Reauth {
			return mintFailed(MintReauthRequired, refreshed.Detail)
		}
		return mintFailed(MintUnavailable, refreshed.Detail)
	}
	nowMS = float64(p.nowMS())
	expiresIn := refreshed.ExpiresInSec
	if math.IsNaN(expiresIn) {
		expiresIn = 7000
	}
	expiresAt := nowMS + math.Max(60, expiresIn)*1000
	refreshExpiresAt := storedRefreshExpiresAt
	if refreshed.RefreshExpiresInSec != 0 && !math.IsNaN(refreshed.RefreshExpiresInSec) {
		refreshExpiresAt = nowMS + refreshed.RefreshExpiresInSec*1000
	}
	nextRefresh := refreshed.RefreshToken
	if nextRefresh == "" {
		nextRefresh = refreshToken
	}
	next := LarkOAuthPayload{
		RefreshToken:     nextRefresh,
		AccessToken:      refreshed.AccessToken,
		AccessExpiresAt:  expiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}
	if jsTruthy(payload["oauth"]) {
		next.OAuth = oauth
	}
	sealed, err := SealPayload(keys, rec.UnionID, rec.Platform, next)
	if err != nil {
		return mintFailed(MintUnavailable, "credential keys unavailable")
	}
	return MintResult{
		OK:               true,
		Variables:        larkVariables(appID, refreshed.AccessToken),
		ExpiresAt:        int64(expiresAt),
		UpdatedSealed:    &sealed,
		RefreshExpiresAt: int64(refreshExpiresAt),
	}
}

func larkVariables(appID, accessToken string) Variables {
	return Variables{{"LARKSUITE_CLI_APP_ID", appID}, {"LARKSUITE_CLI_USER_ACCESS_TOKEN", accessToken}}
}

// Mint is mintFor: dispatch on the record's platform.
func (p Providers) Mint(ctx context.Context, rec Record) MintResult {
	if rec.Platform == PlatformLarkCLI {
		return p.MintLark(ctx, rec)
	}
	provider := p.DeviceLogin(rec.Platform)
	if provider == nil {
		return mintFailed(MintUnavailable, "provider not configured")
	}
	keys := p.keys(ctx)
	if keys == nil {
		return mintFailed(MintUnavailable, "credential keys unavailable")
	}
	return provider.Mint(ctx, keys, rec)
}

// DeviceLogin returns the device-login provider for platform (nil when none).
func (p Providers) DeviceLogin(platform string) DeviceLogin {
	for _, provider := range p.DeviceLogins {
		if provider.Descriptor().Platform == platform {
			return provider
		}
	}
	return nil
}

// Known reports whether platform is lark-cli or a linked device login.
func (p Providers) Known(platform string) bool {
	return platform == PlatformLarkCLI || p.DeviceLogin(platform) != nil
}

// LogMint logs the outcome; token values never reach the log, only names.
func LogMint(platform, unionID string, result MintResult) {
	if result.OK {
		slog.Info("credential minted", "platform", platform, "unionId", unionID, "keys", result.Variables.Keys(), "expiresAt", result.ExpiresAt)
		return
	}
	slog.Warn("credential mint failed", "platform", platform, "unionId", unionID, "reason", string(result.Reason), "detail", result.Detail)
}

// ---- JSON helpers with the JavaScript semantics the TS provider relies on ----

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// jsTruthy is JavaScript truthiness of a decoded JSON value (missing = undefined).
func jsTruthy(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case 'n', 'f':
		return false
	case 't', '{', '[':
		return true
	case '"':
		return string(raw) != `""`
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return false
	}
	return f != 0 && !math.IsNaN(f)
}

// jsonString is `typeof v === 'string'` plus the value.
func jsonString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// jsTruthyString returns a non-empty string member ("" for anything else).
func jsTruthyString(raw json.RawMessage) string {
	s, _ := jsonString(raw)
	return s
}

// jsonNumber returns a numeric member; non-numbers read as 0, which every
// caller treats like the falsy / absent value it is in TS.
func jsonNumber(raw json.RawMessage) float64 {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !(raw[0] == '-' || ('0' <= raw[0] && raw[0] <= '9')) {
		return 0
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return 0
	}
	return f
}
