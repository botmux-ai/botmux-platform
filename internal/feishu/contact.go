package feishu

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
)

type TenantUser struct {
	UnionID string `json:"unionId"`
	OpenID  string `json:"openId"`
	Name    string `json:"name"`
	Email   string `json:"email,omitempty"`
	Avatar  string `json:"avatar,omitempty"`
}

var invalidTokenMessage = regexp.MustCompile(`(?i)token (expired|invalid)|Authentication token`)

// SearchUsers searches the tenant by name / email prefix. It needs a user
// access token with contact:user:search. ErrTokenInvalid covers both a missing
// token and Feishu's token-expired/invalid answers (the caller refreshes once
// and otherwise asks for re-authorization); other failures are APIErrors with
// the TypeScript text `feishu code=<code> <msg>`.
func (c *Client) SearchUsers(ctx context.Context, query, userAccessToken string) ([]TenantUser, error) {
	if userAccessToken == "" {
		return nil, ErrTokenInvalid
	}
	path := "/open-apis/search/v1/user?query=" + encodeURIComponent(query) + "&page_size=20"
	e, err := c.doJSON(ctx, http.MethodGet, path, userAccessToken, nil)
	if err != nil {
		return nil, err
	}
	if tokenCode(e.Code) || invalidTokenMessage.MatchString(e.msgOrEmpty()) {
		return nil, ErrTokenInvalid
	}
	if !e.ok() {
		return nil, e.apiError("feishu code=" + e.codeText() + " " + e.msgOrEmpty())
	}
	items, _ := arrayItems(e.dataFields()["users"])
	out := make([]TenantUser, 0, len(items))
	for _, item := range items {
		u := objectFields(item)
		openID := str(u, "open_id")
		if openID == "" {
			continue // invites are delivered by open_id
		}
		name := str(u, "name")
		if name == "" {
			name = str(u, "en_name")
		}
		email := str(u, "email")
		if email == "" {
			email = str(u, "enterprise_email")
		}
		avatar := str(objectFields(u["avatar"]), "avatar_72")
		if avatar == "" {
			avatar = str(u, "avatar_url")
		}
		out = append(out, TenantUser{UnionID: str(u, "union_id"), OpenID: openID, Name: name, Email: email, Avatar: avatar})
	}
	return out, nil
}

func tokenCode(code int) bool {
	for _, c := range []int{99991663, 99991661, 99991668, 99991677, 20005} {
		if c == code {
			return true
		}
	}
	return false
}

// ResolveOpenID maps a union_id to the platform app's open_id (card <at> only
// accepts open_id) with the tenant token. Successful lookups are cached; any
// failure is an error and callers fall back to a plain name.
func (c *Client) ResolveOpenID(ctx context.Context, tenantToken, unionID string) (string, error) {
	uid := jsTrim(unionID)
	if uid == "" {
		return "", ErrUserNotFound
	}
	c.openIDMu.Lock()
	if hit := c.openIDs[uid]; hit != "" {
		c.openIDMu.Unlock()
		return hit, nil
	}
	c.openIDMu.Unlock()
	path := "/open-apis/contact/v3/users/" + encodeURIComponent(uid) + "?user_id_type=union_id&department_id_type=open_department_id"
	e, err := c.doJSON(ctx, http.MethodGet, path, tenantToken, nil)
	if err != nil {
		return "", err
	}
	openID := str(objectFields(e.dataFields()["user"]), "open_id")
	if !e.ok() || openID == "" {
		slog.Warn("feishu union_id to open_id failed; mention falls back to name", "code", e.codeText(), "msg", e.msgText())
		if !e.ok() {
			return "", e.apiError("")
		}
		return "", ErrUserNotFound
	}
	c.openIDMu.Lock()
	if len(c.openIDs) > 5000 {
		clear(c.openIDs)
	}
	c.openIDs[uid] = openID
	c.openIDMu.Unlock()
	return openID, nil
}

// ResolveUnionIDByEmail maps a corporate email to a Feishu union_id with the
// tenant token (contact/v3/users/batch_get_id, no user scope needed); it is
// the inbound identity bridge for OpenAPI tokens. The email is trimmed and
// lower-cased; successful lookups are cached by that key. ErrUserNotFound
// means the email is outside the directory/authorized range; any other error
// is a lookup failure. Both must fail closed.
func (c *Client) ResolveUnionIDByEmail(ctx context.Context, tenantToken, email string) (string, error) {
	mail := jsLowerCase(jsTrim(email))
	if mail == "" {
		return "", ErrUserNotFound
	}
	c.unionIDMu.Lock()
	if hit := c.unionIDByEmail[mail]; hit != "" {
		c.unionIDMu.Unlock()
		return hit, nil
	}
	c.unionIDMu.Unlock()
	e, err := c.doJSON(ctx, http.MethodPost, "/open-apis/contact/v3/users/batch_get_id?user_id_type=union_id", tenantToken, jsObj{{"emails", []string{mail}}})
	if err != nil {
		return "", err
	}
	if !e.ok() {
		slog.Warn("feishu email to union_id failed", "code", e.codeText(), "msg", e.msgText())
		return "", e.apiError("")
	}
	// data.user_list[]: hits carry user_id (the union_id here), misses do not.
	items, _ := arrayItems(e.dataFields()["user_list"])
	unionID := ""
	for _, item := range items {
		u := objectFields(item)
		if jsLowerCase(str(u, "email")) == mail && truthy(u["user_id"]) {
			unionID = str(u, "user_id")
			break
		}
	}
	if unionID == "" {
		return "", ErrUserNotFound
	}
	c.unionIDMu.Lock()
	if len(c.unionIDByEmail) > 5000 {
		clear(c.unionIDByEmail)
	}
	c.unionIDByEmail[mail] = unionID
	c.unionIDMu.Unlock()
	return unionID, nil
}
