package proxy

import (
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPlatformAuthorityHeadersAreReservedCaseInsensitively(t *testing.T) {
	t.Parallel()
	names := PlatformAuthorityHeaders()
	for _, name := range names {
		if !IsReservedBotmuxHeader(name) {
			t.Errorf("%s must be reserved", name)
		}
		if !IsReservedBotmuxHeader(strings.ToUpper(name)) {
			t.Errorf("%s must be reserved case-insensitively", name)
		}
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	want := []string{"x-botmux-actor", "x-botmux-login-url", "x-botmux-role", "x-botmux-scopes"}
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("authority headers = %v, want %v", sorted, want)
	}
	names[0] = "mutated"
	if PlatformAuthorityHeaders()[0] == "mutated" {
		t.Fatal("PlatformAuthorityHeaders must return a copy")
	}
}

func TestDaemonInternalHeadersAreReserved(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"x-botmux-terminal-control",
		"x-botmux-terminal-view",
		"x-botmux-platform-readonly",
		"x-botmux-daemon-sig",
		"x-botmux-cli-auth",
		"x-botmux-companion-signature",
		"x-botmux-workflow-ipc-signature",
		"x-botmux-native-runtime-auth",
		"x-botmux-dispatch-launch-ipc-signature",
		"x-botmux-vc-daemon-auth",
	} {
		if !IsReservedBotmuxHeader(name) {
			t.Errorf("%s must be reserved", name)
		}
	}
}

func TestWebhookProtocolAndCSRFHeadersAreNotReserved(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"x-botmux-chat-id", "x-botmux-session-id", "x-botmux-root-message-id",
		"x-botmux-token", "x-botmux-idempotency-key",
		"x-botmux-signature", "x-botmux-timestamp", "x-botmux-nonce",
		"x-botmux-wait", "x-botmux-async", "x-botmux-dry-run", "x-botmux-timeout-ms",
		"x-botmux-csrf",
	} {
		if IsReservedBotmuxHeader(name) {
			t.Errorf("%s is a third-party/daemon protocol header and must not be reserved", name)
		}
	}
}

func TestNonBotmuxHeadersAreOutOfScope(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"authorization", "x-forwarded-host", "x-botmuxarbitrary"} {
		if IsReservedBotmuxHeader(name) {
			t.Errorf("%s must not be reserved", name)
		}
	}
}

func TestForwardLoopGuardIsTheOnlyException(t *testing.T) {
	t.Parallel()
	if IsReservedBotmuxHeader(ForwardHeader) || IsReservedBotmuxHeader("x-botmux-forwarded") {
		t.Fatal("the cross-pod loop guard must survive stripping")
	}
}

func TestStripReservedBotmuxHeadersKeepsProtocolHeaders(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	header.Set("X-Botmux-Role", "owner")
	header.Set("X-Botmux-Actor", "ou_attacker")
	header.Set("X-Botmux-Scopes", "dashboard:manage")
	header.Set("X-Botmux-Login-Url", "https://evil.example/phish")
	header.Set("X-Botmux-Terminal-Control", "forged-grant")
	header.Set("X-Botmux-Daemon-Sig", "forged")
	header.Set("X-Botmux-Chat-Id", "oc_target_chat")
	header.Set("X-Botmux-Idempotency-Key", "idem-1")
	header.Set("X-Botmux-Signature", "sig")
	header.Set("X-Botmux-Csrf", "ticket")
	header.Set(ForwardHeader, "1")
	header.Set("X-Other-Header", "keep-me")
	// Raw non-canonical keys must be handled too (http.Header may be built by hand).
	header["x-botmux-role"] = []string{"owner"}

	StripReservedBotmuxHeaders(header)

	for _, gone := range []string{"X-Botmux-Role", "X-Botmux-Actor", "X-Botmux-Scopes", "X-Botmux-Login-Url", "X-Botmux-Terminal-Control", "X-Botmux-Daemon-Sig"} {
		if header.Get(gone) != "" {
			t.Errorf("%s must be stripped", gone)
		}
	}
	if _, ok := header["x-botmux-role"]; ok {
		t.Error("non-canonical reserved key must be stripped")
	}
	for name, want := range map[string]string{
		"X-Botmux-Chat-Id":         "oc_target_chat",
		"X-Botmux-Idempotency-Key": "idem-1",
		"X-Botmux-Signature":       "sig",
		"X-Botmux-Csrf":            "ticket",
		ForwardHeader:              "1",
		"X-Other-Header":           "keep-me",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
