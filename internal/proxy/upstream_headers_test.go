package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of the buildUpstreamHeaders half of
// test/server-machine-header-strip.test.ts: the proxy layer is the second,
// independent line of defense behind the entry-point strip in
// server/machine.go, so it is tested directly (a stubbed proxy never runs it).

func headerStripMachine() tunnel.MachineConn {
	return tunnel.MachineConn{MachineID: "aaaabbbbccccdddd", UnionID: "u-owner", DashboardPort: 7777, DashboardToken: "dash-token"}
}

func incomingHeaders(pairs map[string]string) http.Header {
	header := http.Header{}
	for name, value := range pairs {
		header.Set(name, value)
	}
	return header
}

func TestUpstreamHeadersDropClientPlatformAuthorityHeaders(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"x-botmux-role":      "owner",
		"x-botmux-actor":     "ou_attacker",
		"x-botmux-scopes":    "dashboard:manage",
		"x-botmux-login-url": "https://evil.example",
		"x-other-header":     "keep-me",
	}), "", headerStripMachine(), false, false, PlatformHeaders{})
	for _, name := range []string{"x-botmux-role", "x-botmux-actor", "x-botmux-scopes", "x-botmux-login-url"} {
		if out.Get(name) != "" {
			t.Fatalf("%s leaked: %q", name, out.Get(name))
		}
	}
	if out.Get("x-other-header") != "keep-me" {
		t.Fatalf("non x-botmux header dropped: %v", out)
	}
}

func TestUpstreamHeadersDropForgedDaemonInternalHeaders(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"x-botmux-terminal-control":              "forged-grant",
		"x-botmux-terminal-view":                 "forged-proof",
		"x-botmux-platform-readonly":             "1",
		"x-botmux-daemon-sig":                    "forged",
		"x-botmux-cli-auth":                      "forged",
		"x-botmux-companion-signature":           "forged",
		"x-botmux-workflow-ipc-signature":        "forged",
		"x-botmux-native-runtime-auth":           "forged",
		"x-botmux-dispatch-launch-ipc-signature": "forged",
		"x-botmux-vc-daemon-auth":                "forged",
	}), "", headerStripMachine(), false, false, PlatformHeaders{})
	for name := range out {
		if strings.HasPrefix(strings.ToLower(name), "x-botmux-") {
			t.Fatalf("internal header %s reached the tunnel", name)
		}
	}
}

func TestUpstreamHeadersKeepWebhookProtocolHeaders(t *testing.T) {
	protocol := map[string]string{
		"x-botmux-chat-id":         "oc_target_chat",
		"x-botmux-session-id":      "sess-1",
		"x-botmux-root-message-id": "om_root",
		"x-botmux-token":           "webhook-token",
		"x-botmux-idempotency-key": "idem-1",
		"x-botmux-signature":       "sig",
		"x-botmux-timestamp":       "1700000000",
		"x-botmux-nonce":           "n-1",
		"x-botmux-wait":            "1",
		"x-botmux-async":           "0",
		"x-botmux-dry-run":         "1",
		"x-botmux-timeout-ms":      "5000",
	}
	out := upstreamHeaders(incomingHeaders(protocol), "", headerStripMachine(), false, true, PlatformHeaders{})
	for name, value := range protocol {
		if out.Get(name) != value {
			t.Fatalf("%s = %q, want %q", name, out.Get(name), value)
		}
	}
}

func TestUpstreamHeadersKeepDaemonCSRFTicket(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{"x-botmux-csrf": "ticket-abc"}), "", headerStripMachine(), false, false, PlatformHeaders{})
	if out.Get("x-botmux-csrf") != "ticket-abc" {
		t.Fatalf("csrf = %q", out.Get("x-botmux-csrf"))
	}
}

func TestUpstreamHeadersStripAndKeepInOneRequest(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"x-botmux-role":    "owner",
		"x-botmux-chat-id": "oc_target",
		"x-botmux-csrf":    "ticket",
	}), "", headerStripMachine(), false, true, PlatformHeaders{})
	if out.Get("x-botmux-role") != "" || out.Get("x-botmux-chat-id") != "oc_target" || out.Get("x-botmux-csrf") != "ticket" {
		t.Fatalf("mixed = %v", out)
	}
}

func TestUpstreamHeadersKeepForwardLoopGuard(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{ForwardHeader: "1"}), "", headerStripMachine(), false, false, PlatformHeaders{})
	if out.Get(ForwardHeader) != "1" || ForwardHeader != "X-Botmux-Forwarded" {
		t.Fatalf("loop guard = %q (%s)", out.Get(ForwardHeader), ForwardHeader)
	}
}

func TestUpstreamHeadersInjectPlatformDecision(t *testing.T) {
	out := upstreamHeaders(http.Header{}, "", headerStripMachine(), false, false, PlatformHeaders{
		Role: "owner", Actor: "ou_alice", Scopes: "machines:read,sessions:open,terminal:control", LoginURL: "https://platform.example/open/m1",
	})
	if out.Get("x-botmux-role") != "owner" || out.Get("x-botmux-actor") != "ou_alice" ||
		out.Get("x-botmux-scopes") != "machines:read,sessions:open,terminal:control" ||
		out.Get("x-botmux-login-url") != "https://platform.example/open/m1" {
		t.Fatalf("injected = %v", out)
	}
	manage := upstreamHeaders(http.Header{}, "", headerStripMachine(), false, false, PlatformHeaders{
		Role: "owner", Actor: "ou_comanager", Scopes: "machines:read,sessions:open,terminal:control,dashboard:manage",
	})
	if !strings.Contains(manage.Get("x-botmux-scopes"), "dashboard:manage") {
		t.Fatalf("manage scopes = %q", manage.Get("x-botmux-scopes"))
	}
	guest := upstreamHeaders(http.Header{}, "", headerStripMachine(), false, false, PlatformHeaders{Role: "guest"})
	if guest.Get("x-botmux-role") != "guest" || guest.Get("x-botmux-actor") != "" {
		t.Fatalf("guest = %v", guest)
	}
}

func TestUpstreamHeadersPlatformValueWinsOverForgery(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"x-botmux-role":   "owner",
		"x-botmux-scopes": "dashboard:manage",
		"x-botmux-actor":  "ou_attacker",
	}), "", headerStripMachine(), false, false, PlatformHeaders{Role: "guest", Actor: "ou_real", Scopes: "terminal:control"})
	if out.Get("x-botmux-role") != "guest" || out.Get("x-botmux-actor") != "ou_real" || out.Get("x-botmux-scopes") != "terminal:control" {
		t.Fatalf("forged + decided = %v", out)
	}
	if len(out.Values("x-botmux-role")) != 1 {
		t.Fatalf("role values = %q", out.Values("x-botmux-role"))
	}
}

func TestUpstreamHeadersInjectNothingWithoutPlatformDecision(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{"x-botmux-role": "owner"}), "", headerStripMachine(), false, false, PlatformHeaders{})
	if out.Get("x-botmux-role") != "" || out.Get("x-botmux-actor") != "" || out.Get("x-botmux-scopes") != "" {
		t.Fatalf("no decision = %v", out)
	}
}

func TestUpstreamHeadersWebSocketCarriesPlatformDecision(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}), "", headerStripMachine(), true, false,
		PlatformHeaders{Role: "owner", Actor: "ou_alice", Scopes: "terminal:control"})
	if out.Get("x-botmux-role") != "owner" || out.Get("x-botmux-actor") != "ou_alice" {
		t.Fatalf("ws = %v", out)
	}
	if out.Get("Upgrade") != "websocket" || out.Get("Connection") != "Upgrade" {
		t.Fatalf("upgrade headers dropped: %v", out)
	}
}

func TestUpstreamHeadersPartialDecisionDoesNotBackfillClientValues(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"x-botmux-role":      "guest",
		"x-botmux-actor":     "ou_attacker",
		"x-botmux-scopes":    "dashboard:manage",
		"x-botmux-login-url": "https://evil.example/phish",
	}), "", headerStripMachine(), false, false, PlatformHeaders{Role: "owner"})
	if out.Get("x-botmux-role") != "owner" || out.Get("x-botmux-actor") != "" || out.Get("x-botmux-scopes") != "" || out.Get("x-botmux-login-url") != "" {
		t.Fatalf("partial = %v", out)
	}
}

func TestUpstreamHeadersRewriteHostCookieAndCredentials(t *testing.T) {
	out := upstreamHeaders(incomingHeaders(map[string]string{
		"Cookie":              "botmux_proxy_session=platform-secret",
		"Authorization":       "Bearer desktop",
		"Proxy-Authorization": "Basic x",
		"X-Forwarded-Host":    "evil.example",
		"X-Forwarded-Proto":   "https",
	}), "m-aaaabbbbccccdddd.example.com", headerStripMachine(), false, false, PlatformHeaders{})
	if out.Get("Cookie") != "botmux_dashboard_token=dash-token" || out.Get("Host") != "127.0.0.1:7777" ||
		out.Get("X-Forwarded-Host") != "m-aaaabbbbccccdddd.example.com" || out.Get("X-Forwarded-Proto") != "" ||
		out.Get("Authorization") != "" || out.Get("Proxy-Authorization") != "" {
		t.Fatalf("rewritten = %v", out)
	}
}
