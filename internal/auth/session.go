package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const SessionCookieName = "botmux_platform_session"

type SessionUserToken struct {
	AccessToken  string `json:"a"`
	RefreshToken string `json:"r"`
	ExpiresAt    int64  `json:"e"`
}

type SessionUser struct {
	UnionID   string
	OpenID    string
	Name      string
	Avatar    string
	UserToken *SessionUserToken
	// SearchScope records that this login granted the people-search scope
	// (contact:user:search). Encoded as "ss": true only when set.
	SearchScope bool
}

type SessionPayload struct {
	Kind      string            `json:"kind"`
	UnionID   string            `json:"unionId"`
	OpenID    string            `json:"openId,omitempty"`
	Name      string            `json:"name"`
	Avatar    string            `json:"avatar,omitempty"`
	UserToken *SessionUserToken `json:"ut,omitempty"`
	// SearchScope ("ss") reports whether the login granted people search; a
	// false value prompts incremental authorization instead of a doomed search.
	SearchScope bool `json:"ss,omitempty"`
	// AuthTime is the SSO authentication instant (Unix seconds) stamped by
	// MintSession. It is the "fresh SSO" criterion for sensitive operations;
	// legacy cookies lack it (nil) and are never fresh.
	AuthTime *int64 `json:"authTime,omitempty"`
	Exp      int64  `json:"exp"`

	// raw is the verified payload JSON, kept so RenewSessionUserToken can
	// re-sign it with the TypeScript spread semantics (original key order,
	// unknown keys preserved).
	raw string
}

func MintSession(cfg config.Config, user SessionUser) string {
	return MintSessionAt(cfg, user, time.Now())
}

// MintSessionAt mints a login session. Only a real SSO login may call this:
// it stamps AuthTime = now, which makes the session "fresh" for sensitive
// operations. Background user-token refreshes must use RenewSessionUserToken.
func MintSessionAt(cfg config.Config, user SessionUser, now time.Time) string {
	nowSec := now.Unix()
	payload := SessionPayload{
		Kind:        "session",
		UnionID:     user.UnionID,
		OpenID:      user.OpenID,
		Name:        user.Name,
		Avatar:      user.Avatar,
		UserToken:   user.UserToken,
		SearchScope: user.SearchScope,
		AuthTime:    &nowSec,
		Exp:         nowSec + int64(cfg.SessionTTL/time.Second),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

// RenewSessionUserToken re-signs session with a new user token and a new
// exp, without touching the SSO authentication time: re-minting a "now"
// authTime would let an old session bypass RequireFreshSSO, and a legacy
// cookie without authTime must stay "not fresh".
//
// Mirrors TS `{...session, ut, exp}`: keys keep their original order (an
// absent "ut" is appended after the existing keys) and unknown keys are
// preserved when session came from VerifySession. For a verified payload the
// verified JSON is authoritative: edits to its struct fields are not re-signed.
func RenewSessionUserToken(cfg config.Config, session *SessionPayload, ut SessionUserToken) string {
	return RenewSessionUserTokenAt(cfg, session, ut, time.Now())
}

// RenewSessionUserTokenAt is RenewSessionUserToken with an explicit clock.
func RenewSessionUserTokenAt(cfg config.Config, session *SessionPayload, ut SessionUserToken, now time.Time) string {
	// A payload built in Go has no source order: use the canonical one, in
	// which an absent ut is likewise appended after exp.
	base := session.compatJSON()
	if session.raw != "" {
		base = []byte(session.raw)
	}
	fields, err := parseOrderedObject(base)
	if err != nil {
		// raw always comes from a verified token, so this is unreachable.
		fields, _ = parseOrderedObject(session.compatJSON())
	}
	fields = setOrderedField(fields, "ut", sessionUserTokenJSON(ut))
	fields = setOrderedField(fields, "exp", strconv.AppendInt(nil, now.Unix()+int64(cfg.SessionTTL/time.Second), 10))
	return mustIssueCompat(encodeOrderedObject(fields), cfg.SigningSecret)
}

func VerifySession(cfg config.Config, token string) (*SessionPayload, error) {
	return VerifySessionAt(cfg, token, time.Now())
}

func VerifySessionAt(cfg config.Config, token string, now time.Time) (*SessionPayload, error) {
	var payload SessionPayload
	if err := VerifyToken(token, cfg.SigningSecret, "session", now, &payload); err != nil {
		return nil, err
	}
	// VerifyToken already proved the token has a valid payload segment.
	if raw, err := base64.RawURLEncoding.DecodeString(token[:strings.IndexByte(token, '.')]); err == nil {
		payload.raw = string(raw)
	}
	return &payload, nil
}

func ReadSession(cfg config.Config, req *http.Request) (*SessionPayload, error) {
	token := ParseCookie(req.Header.Get("Cookie"))[SessionCookieName]
	if token == "" {
		return nil, ErrInvalidToken
	}
	return VerifySession(cfg, token)
}

func SessionCookieHeader(cfg config.Config, token string) string {
	parts := []string{
		SessionCookieName + "=" + token,
		"Path=/",
		"HttpOnly",
		"Max-Age=" + durationSecondsString(cfg.SessionTTL),
	}
	if cfg.CookieSecure {
		parts = append(parts, "SameSite=None")
	} else {
		parts = append(parts, "SameSite=Lax")
	}
	if cfg.CookieDomain != "" {
		parts = append(parts, "Domain="+cfg.CookieDomain)
	}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func ClearSessionCookieHeader(cfg config.Config) string {
	parts := []string{SessionCookieName + "=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"}
	if cfg.CookieDomain != "" {
		parts = append(parts, "Domain="+cfg.CookieDomain)
	}
	if cfg.CookieSecure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

// ParseCookie mirrors the legacy parser: split on semicolons, split each pair
// at its first equals sign, URL-decode values, and let later duplicates win.
func ParseCookie(header string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(header, ";") {
		index := strings.IndexByte(part, '=')
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(part[:index])
		value := strings.TrimSpace(part[index+1:])
		if key == "" {
			continue
		}
		if decoded, err := url.PathUnescape(value); err == nil {
			value = decoded
		}
		result[key] = value
	}
	return result
}

func (p SessionPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	if p.OpenID != "" {
		dst = appendStringField(dst, "openId", p.OpenID, &first)
	}
	dst = appendStringField(dst, "name", p.Name, &first)
	if p.Avatar != "" {
		dst = appendStringField(dst, "avatar", p.Avatar, &first)
	}
	if p.UserToken != nil {
		dst = appendFieldName(dst, "ut", &first)
		dst = append(dst, sessionUserTokenJSON(*p.UserToken)...)
	}
	if p.SearchScope {
		dst = appendFieldName(dst, "ss", &first)
		dst = append(dst, "true"...)
	}
	if p.AuthTime != nil {
		dst = appendInt64Field(dst, "authTime", *p.AuthTime, &first)
	}
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

func sessionUserTokenJSON(ut SessionUserToken) []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "a", ut.AccessToken, &first)
	dst = appendStringField(dst, "r", ut.RefreshToken, &first)
	dst = appendInt64Field(dst, "e", ut.ExpiresAt, &first)
	return append(dst, '}')
}

// orderedField is one top-level member of a JSON object in source order.
type orderedField struct {
	key   string
	value []byte
}

// parseOrderedObject splits a JSON object into its members in source order.
// Like JSON.parse, a duplicated key keeps its first position and last value.
func parseOrderedObject(raw []byte) ([]orderedField, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, ErrInvalidToken
	}
	var fields []orderedField
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, ErrInvalidToken
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, value); err != nil {
			return nil, err
		}
		fields = setOrderedField(fields, key, compact.Bytes())
	}
	return fields, nil
}

// setOrderedField replaces key in place, or appends it (object spread /
// assignment semantics).
func setOrderedField(fields []orderedField, key string, value []byte) []orderedField {
	for i := range fields {
		if fields[i].key == key {
			fields[i].value = value
			return fields
		}
	}
	return append(fields, orderedField{key: key, value: value})
}

func encodeOrderedObject(fields []orderedField) []byte {
	dst := []byte{'{'}
	first := true
	for _, f := range fields {
		dst = appendFieldName(dst, f.key, &first)
		dst = append(dst, f.value...)
	}
	return append(dst, '}')
}
