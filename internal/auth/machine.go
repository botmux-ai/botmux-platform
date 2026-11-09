package auth

import (
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

type MachineIdentity struct {
	UnionID   string
	OwnerName string
	MachineID string
}

type MachineTokenPayload struct {
	Kind      string `json:"kind"`
	UnionID   string `json:"unionId"`
	OwnerName string `json:"ownerName"`
	MachineID string `json:"machineId"`
	// IAT is Unix milliseconds. Nil represents a legacy token issued before
	// cutoff-based revocation was introduced.
	IAT *int64 `json:"iat,omitempty"`
	Exp int64  `json:"exp"`
}

func MintMachineToken(cfg config.Config, identity MachineIdentity) string {
	return MintMachineTokenAt(cfg, identity, time.Now())
}

func MintMachineTokenAt(cfg config.Config, identity MachineIdentity, now time.Time) string {
	iat := now.UnixMilli()
	payload := MachineTokenPayload{
		Kind:      "machine",
		UnionID:   identity.UnionID,
		OwnerName: identity.OwnerName,
		MachineID: identity.MachineID,
		IAT:       &iat,
		Exp:       now.Unix() + int64(cfg.MachineTokenTTL/time.Second),
	}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)
}

func VerifyMachineToken(cfg config.Config, token string) (*MachineTokenPayload, error) {
	return VerifyMachineTokenAt(cfg, token, time.Now())
}

func VerifyMachineTokenAt(cfg config.Config, token string, now time.Time) (*MachineTokenPayload, error) {
	var payload MachineTokenPayload
	if err := VerifyToken(token, cfg.SigningSecret, "machine", now, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (p MachineTokenPayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "unionId", p.UnionID, &first)
	dst = appendStringField(dst, "ownerName", p.OwnerName, &first)
	dst = appendStringField(dst, "machineId", p.MachineID, &first)
	if p.IAT != nil {
		dst = appendInt64Field(dst, "iat", *p.IAT, &first)
	}
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}
