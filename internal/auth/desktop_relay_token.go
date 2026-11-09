package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// Desktop relay tokens are HS256 JWTs for the external relay service, signed
// with a dedicated secret. An empty RelaySigningSecret disables the capability
// (fail closed) instead of falling back to the platform signing secret.

const relayHostScope = "relay:host"

var (
	relayHostPublicKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	relayHostIDPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`)
)

// DesktopRelayTokenPayload is the relay JWT claim set (TypeScript field order).
type DesktopRelayTokenPayload struct {
	Iss              string `json:"iss"`
	Aud              string `json:"aud"`
	Sub              string `json:"sub"`
	Iat              int64  `json:"iat"`
	Exp              int64  `json:"exp"`
	JTI              string `json:"jti"`
	Scope            string `json:"scope"`
	RelayHostID      string `json:"relayHostId"`
	HostPublicKeyB64 string `json:"hostPublicKeyB64"`
	CloudProfileID   string `json:"cloudProfileId"`
	ActiveOrgID      string `json:"activeOrgId"`
}

// CanonicalRelayHostPublicKey decodes a 32-byte X25519 public key that must be
// in canonical padded standard base64 (re-encoding must round-trip exactly).
func CanonicalRelayHostPublicKey(value string) ([]byte, bool) {
	if !relayHostPublicKeyPattern.MatchString(value) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

// RelayHostIDForPublicKey binds a relay host id to its public key.
func RelayHostIDForPublicKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}

// RelayHostInput is the host identity a relay token is requested for.
type RelayHostInput struct {
	RelayHostID      string
	HostPublicKeyB64 string
}

// DesktopRelayToken is the mint result. ExpiresAt is Unix ms; it is a float
// because RELAY_TOKEN_TTL_SEC may be fractional and TypeScript then emits a
// fractional exp (never the case with integer TTLs).
type DesktopRelayToken struct {
	RelayToken string
	ExpiresAt  float64
}

// MintDesktopRelayToken returns ok=false when relay signing is disabled or the
// host id is not derived from the supplied public key.
func MintDesktopRelayToken(cfg config.Config, access *DesktopAccessPayload, input RelayHostInput) (DesktopRelayToken, bool) {
	return mintDesktopRelayToken(cfg, access, input, time.Now(), defaultRandom)
}

func MintDesktopRelayTokenAt(cfg config.Config, access *DesktopAccessPayload, input RelayHostInput, now time.Time) (DesktopRelayToken, bool) {
	return mintDesktopRelayToken(cfg, access, input, now, defaultRandom)
}

func mintDesktopRelayToken(cfg config.Config, access *DesktopAccessPayload, input RelayHostInput, now time.Time, random io.Reader) (DesktopRelayToken, bool) {
	if cfg.RelaySigningSecret == "" || access == nil {
		return DesktopRelayToken{}, false
	}
	publicKey, ok := CanonicalRelayHostPublicKey(input.HostPublicKeyB64)
	if !ok || RelayHostIDForPublicKey(publicKey) != input.RelayHostID {
		return DesktopRelayToken{}, false
	}
	nowSec := now.Unix()
	exp := float64(nowSec) + cfg.RelayTokenTTL.Seconds()

	body := []byte{'{'}
	first := true
	body = appendStringField(body, "iss", cfg.RelayTokenIssuer, &first)
	body = appendStringField(body, "aud", cfg.RelayTokenAudience, &first)
	body = appendStringField(body, "sub", access.UnionID, &first)
	body = appendInt64Field(body, "iat", nowSec, &first)
	body = appendNumberJSONField(body, "exp", exp, &first)
	body = appendStringField(body, "jti", randomBase64URLFrom(random, 12), &first)
	body = appendStringField(body, "scope", relayHostScope, &first)
	body = appendStringField(body, "relayHostId", input.RelayHostID, &first)
	body = appendStringField(body, "hostPublicKeyB64", input.HostPublicKeyB64, &first)
	body = appendStringField(body, "cloudProfileId", access.CloudProfileID, &first)
	body = appendStringField(body, "activeOrgId", access.ActiveOrgID, &first)
	body = append(body, '}')

	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	return DesktopRelayToken{
		RelayToken: signingInput + "." + relaySign(signingInput, cfg.RelaySigningSecret),
		ExpiresAt:  exp * 1000,
	}, true
}

func relaySign(input, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyDesktopRelayToken checks the exact issuer/audience/scope, the HS256
// key and that the host id still derives from the embedded public key. The
// exp boundary itself counts as expired.
func VerifyDesktopRelayToken(cfg config.Config, token string) (*DesktopRelayTokenPayload, error) {
	return VerifyDesktopRelayTokenAt(cfg, token, time.Now())
}

func VerifyDesktopRelayTokenAt(cfg config.Config, token string, now time.Time) (*DesktopRelayTokenPayload, error) {
	if cfg.RelaySigningSecret == "" {
		return nil, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	expected := relaySign(parts[0]+"."+parts[1], cfg.RelaySigningSecret)
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return nil, ErrInvalidToken
	}
	headerJSON, err := decodeBase64URLLoose(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	payloadJSON, err := decodeBase64URLLoose(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg any `json:"alg"`
		Typ any `json:"typ"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Alg != "HS256" || header.Typ != "JWT" {
		return nil, ErrInvalidToken
	}
	// Decode loosely like the TypeScript cast: unrelated claim types must not
	// make an otherwise valid token fail, but checked claims must be exact.
	var raw map[string]json.RawMessage
	if json.Unmarshal(payloadJSON, &raw) != nil {
		return nil, ErrInvalidToken
	}
	str := func(name string) string {
		var value string
		if json.Unmarshal(raw[name], &value) != nil {
			return ""
		}
		return value
	}
	num := func(name string) (float64, bool) {
		var value float64
		if len(raw[name]) == 0 || json.Unmarshal(raw[name], &value) != nil {
			return 0, false
		}
		return value, true
	}
	exp, hasExp := num("exp")
	iat, _ := num("iat")
	payload := &DesktopRelayTokenPayload{
		Iss:              str("iss"),
		Aud:              str("aud"),
		Sub:              str("sub"),
		Iat:              int64(iat),
		Exp:              int64(exp),
		JTI:              str("jti"),
		Scope:            str("scope"),
		RelayHostID:      str("relayHostId"),
		HostPublicKeyB64: str("hostPublicKeyB64"),
		CloudProfileID:   str("cloudProfileId"),
		ActiveOrgID:      str("activeOrgId"),
	}
	if !isJSONString(raw["iss"]) || payload.Iss != cfg.RelayTokenIssuer ||
		!isJSONString(raw["aud"]) || payload.Aud != cfg.RelayTokenAudience ||
		payload.Scope != relayHostScope ||
		!hasExp || exp != math.Trunc(exp) || exp <= float64(now.Unix()) ||
		!relayHostIDPattern.MatchString(payload.RelayHostID) {
		return nil, ErrInvalidToken
	}
	publicKey, ok := CanonicalRelayHostPublicKey(payload.HostPublicKeyB64)
	if !ok || RelayHostIDForPublicKey(publicKey) != payload.RelayHostID {
		return nil, ErrInvalidToken
	}
	return payload, nil
}

func isJSONString(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] == '"'
}
