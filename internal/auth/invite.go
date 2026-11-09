package auth

import (
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

type TeamInvitePayload struct {
	Kind           string `json:"kind"`
	TeamID         string `json:"teamId"`
	TeamName       string `json:"teamName"`
	InviterUnionID string `json:"inviterUnionId"`
	InviterName    string `json:"inviterName"`
	InviterOpenID  string `json:"inviterOpenId,omitempty"`
	Exp            int64  `json:"exp"`
}

func IssueTeamInvite(cfg config.Config, payload TeamInvitePayload) (string, error) {
	payload.Kind = "team-invite"
	payload.Exp = time.Now().Add(30 * 24 * time.Hour).Unix()
	return IssueToken(payload, cfg.SigningSecret)
}

func VerifyTeamInvite(cfg config.Config, token string) (*TeamInvitePayload, error) {
	var payload TeamInvitePayload
	if err := VerifyToken(token, cfg.SigningSecret, "team-invite", time.Now(), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}
