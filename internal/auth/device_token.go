package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Device credentials (DESIGN-device-pairing.md §3.4):
//   - the access token is a 15-minute signed lease that becomes a device
//     principal after its status/credentialVersion match the MongoDB record;
//   - the refresh token is opaque to clients. It is signed with a
//     domain-separated key derived from the signing secret (never the raw
//     secret shared with sessions/machine tokens).
//
// Determinism is a hard contract: BuildDeviceRefreshToken must produce the
// same bytes for the same claims, because exact idempotent replay re-signs
// the current token instead of storing it.

// DeviceAccessTTLSec is the device access token lifetime (15 minutes).
const DeviceAccessTTLSec int64 = 15 * 60

const (
	deviceRefreshMACDomain = "botmux-device-refresh-mac-v1"
	deviceRefreshJTIDomain = "botmux-device-refresh-jti-v1"
)

// derivedKey is hex(HMAC-SHA256(signingSecret, domain)); the hex string
// itself is the key material, as in the TypeScript implementation.
func derivedKey(cfg config.Config, domain string) string {
	mac := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	_, _ = mac.Write([]byte(domain))
	return hex.EncodeToString(mac.Sum(nil))
}

// SHA256Hex returns the lowercase hex SHA-256 of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// floorDiv is Math.floor(a / b) for b > 0.
func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && a < 0 {
		q--
	}
	return q
}

// DeviceAccessPayload is the device access token payload.
type DeviceAccessPayload struct {
	Kind              string   `json:"kind"`
	UnionID           string   `json:"unionId"`
	DeviceID          string   `json:"deviceId"`
	CredentialVersion int64    `json:"credentialVersion"`
	Scopes            []string `json:"scopes"`
	// IAT is the issue instant in Unix milliseconds (same unit as machine
	// tokens, for audit/revocation comparisons).
	IAT int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

// HasScope reports whether the access token carries scope.
func (p DeviceAccessPayload) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (p DeviceAccessPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "deviceId", p.DeviceID, &first)
	dst = appendInt64Field(dst, "credentialVersion", p.CredentialVersion, &first)
	dst = appendStringArrayField(dst, "scopes", p.Scopes, &first)
	dst = appendInt64Field(dst, "iat", p.IAT, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

func appendStringArrayField(dst []byte, name string, values []string, first *bool) []byte {
	dst = appendFieldName(dst, name, first)
	dst = append(dst, '[')
	for i, v := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, v)
	}
	return append(dst, ']')
}

// DeviceAccessExpSec is the absolute access-token expiry (Unix seconds):
// the 15-minute lease never outlives the device's absolute deadline.
func DeviceAccessExpSec(doc store.DeviceDoc, nowMS int64) int64 {
	exp := floorDiv(nowMS, 1000) + DeviceAccessTTLSec
	if deviceExp := floorDiv(doc.DeviceExp, 1000); deviceExp < exp {
		exp = deviceExp
	}
	return exp
}

// MintDeviceAccessToken signs an access token for doc at nowMS (Unix ms).
func MintDeviceAccessToken(cfg config.Config, doc store.DeviceDoc, nowMS int64) string {
	scopes := append([]string{}, doc.Scopes...)
	payload := DeviceAccessPayload{
		Kind:              "device-access",
		UnionID:           doc.UnionID,
		DeviceID:          doc.ID,
		CredentialVersion: doc.CredentialVersion,
		Scopes:            scopes,
		IAT:               nowMS,
		Exp:               DeviceAccessExpSec(doc, nowMS),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

// VerifyDeviceAccessToken verifies signature, kind and expiry. The result is
// not yet a principal: callers must still compare status/credentialVersion
// with the authoritative device record (see ReadPrincipal).
func VerifyDeviceAccessToken(cfg config.Config, token string) (*DeviceAccessPayload, error) {
	return VerifyDeviceAccessTokenAt(cfg, token, time.Now())
}

// VerifyDeviceAccessTokenAt is VerifyDeviceAccessToken with an explicit clock.
func VerifyDeviceAccessTokenAt(cfg config.Config, token string, now time.Time) (*DeviceAccessPayload, error) {
	var payload DeviceAccessPayload
	if err := VerifyToken(token, cfg.SigningSecret, "device-access", now, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// DeriveRefreshJTI deterministically derives the next refresh-token jti as
// hex(HMAC(derived JTI key, prevTokenHash "\n" idempotencyKey "\n"
// nextGeneration)). The same request (same previous token and key) always
// yields the same jti; a different key yields a different one, and the
// storage CAS rejects the fork.
func DeriveRefreshJTI(cfg config.Config, prevTokenHash, idempotencyKey string, nextGeneration int64) string {
	mac := hmac.New(sha256.New, []byte(derivedKey(cfg, deviceRefreshJTIDomain)))
	_, _ = mac.Write([]byte(prevTokenHash + "\n" + idempotencyKey + "\n" + strconv.FormatInt(nextGeneration, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeviceRefreshClaims are the inputs of BuildDeviceRefreshToken.
type DeviceRefreshClaims struct {
	DeviceID          string
	FamilyID          string
	Generation        int64
	JTI               string
	CredentialVersion int64
	// DeviceExpMS is the device's absolute deadline (Unix ms); the token exp
	// is floor(DeviceExpMS/1000).
	DeviceExpMS int64
}

// DeviceRefreshPayload is the refresh token payload.
type DeviceRefreshPayload struct {
	Kind              string `json:"kind"`
	DeviceID          string `json:"deviceId"`
	FamilyID          string `json:"familyId"`
	Generation        int64  `json:"generation"`
	JTI               string `json:"jti"`
	CredentialVersion int64  `json:"credentialVersion"`
	Exp               int64  `json:"exp"`
}

func (p DeviceRefreshPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "deviceId", p.DeviceID, &first)
	dst = appendStringField(dst, "familyId", p.FamilyID, &first)
	dst = appendInt64Field(dst, "generation", p.Generation, &first)
	dst = appendStringField(dst, "jti", p.JTI, &first)
	dst = appendInt64Field(dst, "credentialVersion", p.CredentialVersion, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

// BuildDeviceRefreshToken deterministically builds (or re-signs) a refresh
// token: identical claims always produce identical bytes.
func BuildDeviceRefreshToken(cfg config.Config, claims DeviceRefreshClaims) string {
	payload := DeviceRefreshPayload{
		Kind:              "device-refresh",
		DeviceID:          claims.DeviceID,
		FamilyID:          claims.FamilyID,
		Generation:        claims.Generation,
		JTI:               claims.JTI,
		CredentialVersion: claims.CredentialVersion,
		Exp:               floorDiv(claims.DeviceExpMS, 1000),
	}
	return mustIssueCompat(payload.compatJSON(), derivedKey(cfg, deviceRefreshMACDomain))
}

// ParseDeviceRefreshToken verifies a refresh token's MAC, kind and expiry. A
// valid MAC only proves the platform issued it; whether it is current
// (generation, revocation, family) is decided by the MongoDB record.
func ParseDeviceRefreshToken(cfg config.Config, token string) (*DeviceRefreshPayload, error) {
	return ParseDeviceRefreshTokenAt(cfg, token, time.Now())
}

// ParseDeviceRefreshTokenAt is ParseDeviceRefreshToken with an explicit clock.
func ParseDeviceRefreshTokenAt(cfg config.Config, token string, now time.Time) (*DeviceRefreshPayload, error) {
	var payload DeviceRefreshPayload
	if err := VerifyToken(token, derivedKey(cfg, deviceRefreshMACDomain), "device-refresh", now, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}
