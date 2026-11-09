package auth

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

type BindIdentity struct {
	UnionID   string
	OwnerName string
}

type BindTokenPayload struct {
	Kind      string `json:"kind"`
	UnionID   string `json:"unionId"`
	OwnerName string `json:"ownerName"`
	Exp       int64  `json:"exp"`
}

type BindBlob struct {
	PlatformBaseURL string `json:"u"`
	Token           string `json:"t"`
}

func IssueBindToken(cfg config.Config, identity BindIdentity) string {
	return IssueBindTokenAt(cfg, identity, time.Now())
}

func IssueBindTokenAt(cfg config.Config, identity BindIdentity, now time.Time) string {
	payload := BindTokenPayload{
		Kind:      "bind",
		UnionID:   identity.UnionID,
		OwnerName: identity.OwnerName,
		Exp:       now.Unix() + int64(cfg.BindCodeTTL/time.Second),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

func VerifyBindToken(cfg config.Config, token string) (*BindTokenPayload, error) {
	return VerifyBindTokenAt(cfg, token, time.Now())
}

func VerifyBindTokenAt(cfg config.Config, token string, now time.Time) (*BindTokenPayload, error) {
	var payload BindTokenPayload
	if err := VerifyToken(token, cfg.SigningSecret, "bind", now, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func EncodeBindBlob(platformBaseURL, bindToken string) string {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "u", platformBaseURL, &first)
	dst = appendStringField(dst, "t", bindToken, &first)
	dst = append(dst, '}')
	return base64.RawURLEncoding.EncodeToString(dst)
}

func DecodeBindBlob(encoded string) (BindBlob, error) {
	var blob BindBlob
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return blob, err
	}
	err = json.Unmarshal(raw, &blob)
	return blob, err
}

func (p BindTokenPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "ownerName", p.OwnerName, &first)
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}
