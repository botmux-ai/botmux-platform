package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSendCredentialRequestDMCard(t *testing.T) {
	rec, c := newRecorder(t, func(r *http.Request, call goldenCall) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/tenant_access_token/internal") {
			return jsonResponse(map[string]any{"code": 0, "tenant_access_token": "t-1", "expire": 7200})
		}
		return jsonResponse(map[string]any{"code": 0})
	})
	err := c.SendCredentialRequestDM(context.Background(), "on_person", CredentialRequestMessage{
		BotName: "Bot *A*", OwnerName: "Own_er", MachineName: "mac[1]",
		Services: []string{"飞书", "Device`"}, AuthorizeURL: "https://platform.test/credentials?request=cr_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := rec.take()
	if len(calls) != 2 || calls[1].URL != goldenHost+"/open-apis/im/v1/messages?receive_id_type=union_id" || calls[1].Auth != "Bearer t-1" {
		t.Fatalf("calls = %+v", calls)
	}
	var message struct {
		ReceiveID string `json:"receive_id"`
		MsgType   string `json:"msg_type"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal([]byte(calls[1].Body), &message); err != nil || message.ReceiveID != "on_person" || message.MsgType != "interactive" {
		t.Fatalf("message = %+v (%v)", message, err)
	}
	for _, want := range []string{
		"botmux：有 bot 请求使用你的授权",
		"bot **Bot A** 想以你的身份使用 **飞书**、**Device**。",
		"允许后，Owner的机器「mac1」上的 bot 可以用你的身份使用这些服务。",
		"如果不是你刚刚让它做的事，请忽略这条消息。",
		`"url":"https://platform.test/credentials?request=cr_1"`,
		`"content":"授权"`,
	} {
		if !strings.Contains(message.Content, want) {
			t.Errorf("card lacks %q: %s", want, message.Content)
		}
	}
}

func TestSendCredentialRequestDMReportsFailures(t *testing.T) {
	_, c := newRecorder(t, func(r *http.Request, call goldenCall) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/tenant_access_token/internal") {
			return jsonResponse(map[string]any{"code": 0, "tenant_access_token": "t-1", "expire": 7200})
		}
		return jsonResponse(map[string]any{"code": 230013, "msg": "Bot has NO availability to this user."})
	})
	err := c.SendCredentialRequestDM(context.Background(), "on_person", CredentialRequestMessage{BotName: "b"})
	if err == nil || !strings.HasPrefix(err.Error(), "feishu code=230013 ") {
		t.Fatalf("err = %v", err)
	}
	if err := c.SendCredentialRequestDM(context.Background(), "", CredentialRequestMessage{}); err != ErrNotConfigured {
		t.Fatalf("empty recipient: %v", err)
	}
}
