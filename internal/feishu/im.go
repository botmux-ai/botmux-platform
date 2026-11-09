package feishu

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Direct messages are sent by the platform app (bot) with the tenant token.
// Results mirror the TypeScript `{ ok, error }`: nil on success, otherwise an
// error whose text is the TypeScript `error` string where Feishu answered
// (`feishu code=<code> <msg>`).

const (
	tenantTokenDefaultExpireSec = 3600
	tenantTokenMaxTTL           = 90 * time.Minute
	tenantTokenMinTTL           = time.Minute
)

// TenantAccessToken mints a fresh tenant token (no cache).
func (c *Client) TenantAccessToken(ctx context.Context) (string, error) {
	token, _, err := c.TenantAccessTokenWithExpiry(ctx)
	return token, err
}

// TenantAccessTokenWithExpiry also returns Feishu's `expire` in seconds (3600
// when absent or not a positive number). Failure text:
// `tenant_access_token 失败 code=<code> <msg>`.
func (c *Client) TenantAccessTokenWithExpiry(ctx context.Context) (string, float64, error) {
	e, err := c.doJSON(ctx, http.MethodPost, tenantTokenPath, "", jsObj{{"app_id", c.appID}, {"app_secret", c.appSecret}})
	if err != nil {
		return "", 0, err
	}
	token := e.str("tenant_access_token")
	if !e.ok() || !truthy(e.fields["tenant_access_token"]) || token == "" {
		return "", 0, e.apiError("tenant_access_token 失败 code=" + e.codeText() + " " + e.msgOrEmpty())
	}
	expire, isNumber := numberValue(e.fields["expire"])
	if !isNumber || math.IsInf(expire, 0) || expire <= 0 {
		expire = tenantTokenDefaultExpireSec
	}
	return token, expire, nil
}

// TenantAccessTokenCached caches the tenant token for
// max(1min, min(90min, expire*0.75)) so per-request callers (OpenAPI email ->
// union_id) do not mint a token every time while honoring a short expire.
func (c *Client) TenantAccessTokenCached(ctx context.Context) (string, error) {
	now := c.now()
	c.tenantMu.Lock()
	if c.tenantToken != "" && now.Before(c.tenantTokenExp) {
		token := c.tenantToken
		c.tenantMu.Unlock()
		return token, nil
	}
	c.tenantMu.Unlock()
	token, expireSec, err := c.TenantAccessTokenWithExpiry(ctx)
	if err != nil {
		return "", err
	}
	ttl := min(tenantTokenMaxTTL, time.Duration(math.Floor(expireSec*1000*0.75))*time.Millisecond)
	c.tenantMu.Lock()
	c.tenantToken, c.tenantTokenExp = token, now.Add(max(tenantTokenMinTTL, ttl))
	c.tenantMu.Unlock()
	return token, nil
}

type InviteMessage struct {
	TeamName       string
	InviterName    string
	InviterOpenID  string
	InviterUnionID string
	InviteURL      string
}
type TeamJoinedMessage struct {
	JoinerName    string
	JoinerOpenID  string
	JoinerUnionID string
	TeamName      string
	InviterOpenID string
}
type TeamDisbandedMessage struct {
	TeamName         string
	DissolverName    string
	DissolverOpenID  string
	DissolverUnionID string
}

// CredentialFirstUseMessage notifies the owner that a delegated credential was
// used on a machine for the first time.
type CredentialFirstUseMessage struct {
	Platform    string
	MachineName string
	MachineID   string
	OwnerName   string
	AppID       string
	ManageURL   string
}

// DeviceConfirmMessage is the F1 enroll confirmation card (link only, no
// credential material).
type DeviceConfirmMessage struct {
	DeviceName   string
	MachineName  string
	ConfirmURL   string
	ExpiresInSec int64
}

type DeviceRevokedReason string

const (
	DeviceRevokedRefreshReuse     DeviceRevokedReason = "refresh_reuse"
	DeviceRevokedRecoveryRequired DeviceRevokedReason = "recovery_required"
)

type DeviceRevokedMessage struct {
	DeviceName string
	Reason     DeviceRevokedReason
}

// resolveMention returns the explicit open_id or resolves it from union_id
// (old sessions/invites without open_id); failures fall back to a plain name.
func (c *Client) resolveMention(ctx context.Context, token, openID, unionID string) string {
	if openID != "" {
		return openID
	}
	resolved, _ := c.ResolveOpenID(ctx, token, unionID)
	return resolved
}

func card(template, title string, elements ...any) jsObj {
	return jsObj{
		{"config", jsObj{{"wide_screen_mode", true}}},
		{"header", jsObj{{"template", template}, {"title", jsObj{{"tag", "plain_text"}, {"content", title}}}}},
		{"elements", elements},
	}
}

func markdownDiv(content string) jsObj {
	return jsObj{{"tag", "div"}, {"text", jsObj{{"tag", "lark_md"}, {"content", content}}}}
}

func primaryButton(label, url string) jsObj {
	return jsObj{{"tag", "action"}, {"actions", []any{jsObj{
		{"tag", "button"},
		{"text", jsObj{{"tag", "plain_text"}, {"content", label}}},
		{"type", "primary"},
		{"url", url},
	}}}}
}

// SendInviteDM sends a team invite card to an open_id, @-mentioning the
// recipient and the inviter.
func (c *Client) SendInviteDM(ctx context.Context, recipientOpenID string, info InviteMessage) error {
	if !c.Configured() {
		return ErrFeishuNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	inviterOpenID := c.resolveMention(ctx, token, info.InviterOpenID, info.InviterUnionID)
	return c.sendInteractive(ctx, token, "open_id", recipientOpenID, card("blue", "botmux 团队邀请",
		markdownDiv("<at id="+recipientOpenID+"></at> 你好，"+atOrName(inviterOpenID, info.InviterName)+" 邀请你加入团队 **"+escapeMarkdown(info.TeamName)+"**。\n加入后可在 botmux 平台看到团队成员的机器与版本。"),
		primaryButton("接受邀请", info.InviteURL),
	))
}

// SendCredentialFirstUseDM tells the credential owner where their delegated
// authorization was first used: the last line of visibility for "someone ran
// something as me".
func (c *Client) SendCredentialFirstUseDM(ctx context.Context, unionID string, info CredentialFirstUseMessage) error {
	if !c.Configured() || unionID == "" {
		return ErrNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	content := strings.Join([]string{
		"**" + escapeMarkdown(info.Platform) + "** 授权刚刚在机器 **" + escapeMarkdown(info.MachineName) + "**（所有者 " + escapeMarkdown(info.OwnerName) + "）上，由 bot `" + escapeMarkdown(info.AppID) + "` 以你的身份调用。",
		"这是你在平台开启的「按触发人身份调用」：只有你在该群/话题里发出的消息才会用到你的授权。",
		"如果不是你触发的，请立即在平台撤销该授权。",
	}, "\n")
	return c.sendInteractive(ctx, token, "union_id", unionID, card("blue", "botmux：你的授权首次在一台新机器上使用",
		markdownDiv(content),
		primaryButton("查看 / 管理我的凭据", info.ManageURL),
	))
}

// SendTeamJoinedDM tells the inviter that the invite was accepted.
func (c *Client) SendTeamJoinedDM(ctx context.Context, inviterUnionID string, info TeamJoinedMessage) error {
	if !c.Configured() || inviterUnionID == "" {
		return ErrNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	inviterOpenID := c.resolveMention(ctx, token, info.InviterOpenID, inviterUnionID)
	joinerOpenID := c.resolveMention(ctx, token, info.JoinerOpenID, info.JoinerUnionID)
	prefix := ""
	if inviterOpenID != "" {
		prefix = "<at id=" + inviterOpenID + "></at> "
	}
	return c.sendInteractive(ctx, token, "union_id", inviterUnionID, card("green", "botmux 团队邀请已接受",
		markdownDiv(prefix+atOrName(joinerOpenID, info.JoinerName)+" 已接受你的邀请，加入团队 **"+escapeMarkdown(info.TeamName)+"** 🎉"),
	))
}

// SendTeamDisbandedDM tells a member that the team was disbanded.
func (c *Client) SendTeamDisbandedDM(ctx context.Context, memberUnionID string, info TeamDisbandedMessage) error {
	if !c.Configured() || memberUnionID == "" {
		return ErrNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	dissolverOpenID := c.resolveMention(ctx, token, info.DissolverOpenID, info.DissolverUnionID)
	return c.sendInteractive(ctx, token, "union_id", memberUnionID, card("grey", "botmux 团队已解散",
		markdownDiv(atOrName(dissolverOpenID, info.DissolverName)+" 解散了团队 **"+escapeMarkdown(info.TeamName)+"**。团队机器人大厅与成员间的免授权互信已随之失效。"),
	))
}

// SendDeviceConfirmDM sends the device enroll confirmation card to the owner.
func (c *Client) SendDeviceConfirmDM(ctx context.Context, ownerUnionID string, info DeviceConfirmMessage) error {
	if !c.Configured() || ownerUnionID == "" {
		return ErrNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	content := "你的机器 **" + escapeMarkdown(info.MachineName) + "** 上有设备请求以你的身份接入平台：\n" +
		"设备名称（自报）：**" + escapeMarkdown(info.DeviceName) + "**\n" +
		"批准后该设备可查看你的机器列表并打开终端。**不是你发起的请就拒绝。**\n" +
		"本请求 " + strconv.FormatInt(jsRound(float64(info.ExpiresInSec)/60), 10) + " 分钟内有效。"
	return c.sendInteractive(ctx, token, "union_id", ownerUnionID, card("blue", "botmux 新设备接入确认",
		markdownDiv(content),
		primaryButton("查看并确认", info.ConfirmURL),
	))
}

// SendDeviceRevokedAlarmDM alarms the owner after an automatic device
// revocation (refresh reuse / recovery window timeout). Callers deduplicate.
func (c *Client) SendDeviceRevokedAlarmDM(ctx context.Context, ownerUnionID string, info DeviceRevokedMessage) error {
	if !c.Configured() || ownerUnionID == "" {
		return ErrNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return err
	}
	reason := "设备凭证恢复窗口超时，无法安全续期"
	if info.Reason == DeviceRevokedRefreshReuse {
		reason = "检测到该设备的旧凭证被重复使用（疑似凭证泄露）"
	}
	return c.sendInteractive(ctx, token, "union_id", ownerUnionID, card("red", "botmux 设备已被自动吊销",
		markdownDiv("设备 **"+escapeMarkdown(info.DeviceName)+"**（自报名称）："+reason+"，已自动吊销其全部访问凭证。若是你本人的设备，请重新配对（enroll）；若非本人操作，请检查该设备安全。"),
	))
}

func (c *Client) sendInteractive(ctx context.Context, token, receiveIDType, receiveID string, card jsObj) error {
	e, err := c.doJSON(ctx, http.MethodPost, "/open-apis/im/v1/messages?receive_id_type="+receiveIDType, token, jsObj{
		{"receive_id", receiveID},
		{"msg_type", "interactive"},
		{"content", stringifyJS(card)},
	})
	if err != nil {
		return err
	}
	if !e.ok() {
		return e.apiError("feishu code=" + e.codeText() + " " + e.msgOrEmpty())
	}
	return nil
}

// jsRound is Math.round (halves round toward +Infinity).
func jsRound(x float64) int64 {
	r := math.Floor(x)
	if x-r >= 0.5 {
		r++
	}
	return int64(r)
}

// atOrName @-mentions by open_id when known, otherwise a bold plain name.
func atOrName(openID, name string) string {
	if openID != "" {
		return "<at id=" + openID + "></at>"
	}
	return "**" + escapeMarkdown(name) + "**"
}

var markdownMeta = strings.NewReplacer("*", "", "_", "", "`", "", "[", "", "]", "")

func escapeMarkdown(s string) string { return markdownMeta.Replace(s) }
