package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid signed token")
	ErrExpiredToken = errors.New("expired signed token")
)

// IssueToken serializes payload as compact JSON and signs it using the legacy
// TypeScript wire format: base64url(json).base64url(HMAC-SHA256(payloadB64)).
// Fixed-purpose token helpers below use their own field-ordered compatibility
// encoders; this generic helper is intended for new payload types.
func IssueToken(payload any, secret string) (string, error) {
	raw, err := marshalJSONNoHTMLEscape(payload)
	if err != nil {
		return "", err
	}
	return IssueTokenJSON(raw, secret)
}

// IssueTokenJSON signs already-canonical JSON without reserializing it.
func IssueTokenJSON(payloadJSON []byte, secret string) (string, error) {
	if !json.Valid(payloadJSON) {
		return "", fmt.Errorf("marshal signed token: invalid JSON")
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return payloadB64 + "." + signPayload(payloadB64, secret), nil
}

// VerifyToken verifies kind/signature/expiry, then decodes into dst. The
// compatibility boundary deliberately treats exp == now as valid because the
// TypeScript implementation rejects only exp < now.
func VerifyToken(token, secret, expectedKind string, now time.Time, dst any) error {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return ErrInvalidToken
	}
	payloadB64 := token[:dot]
	signature := token[dot+1:]
	expected := signPayload(payloadB64, secret)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrInvalidToken
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return ErrInvalidToken
	}
	var base struct {
		Kind string `json:"kind"`
		Exp  *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &base); err != nil || base.Exp == nil || base.Kind != expectedKind {
		return ErrInvalidToken
	}
	if *base.Exp < now.Unix() {
		return ErrExpiredToken
	}
	if dst != nil {
		if err := json.Unmarshal(payloadJSON, dst); err != nil {
			return ErrInvalidToken
		}
	}
	return nil
}

func signPayload(payloadB64, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payloadB64))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func marshalJSONNoHTMLEscape(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}
