package proxy

import (
	"net/http"
	"strings"
)

// The x-botmux-* namespace is shared by three unrelated owners: headers the
// platform injects after authentication, headers exchanged only between daemon
// components, and third-party webhook protocol parameters (plus the daemon's
// own CSRF ticket). Only the first two may be stripped from client input. The
// legacy prefix-wide rule also deleted -chat-id/-signature/-csrf, which broke
// webhooks routed through the central domain and every terminal control call.
//
// This is deliberately a named blocklist rather than an allowlist: connector
// HMAC header names are user-configurable on the daemon side, so an allowlist
// can never be complete. Every new internal header must be registered here.

// platformAuthorityHeaders are trusted by name alone on the daemon: role gates
// terminal writes, scopes gate the management surface, actor feeds audit and
// terminal leases, and login-url renders the sign-in button (phishing vector).
var platformAuthorityHeaders = [...]string{
	"x-botmux-role",
	"x-botmux-actor",
	"x-botmux-scopes",
	"x-botmux-login-url",
}

// daemonInternalHeaders carry their own MAC/signature checks, so this is a
// second layer. It still matters: their other leg is a loopback check, and the
// tunnel makes every proxied request look like 127.0.0.1 to the daemon.
var daemonInternalHeaders = [...]string{
	"x-botmux-terminal-control",
	"x-botmux-terminal-view",
	"x-botmux-platform-readonly",
	"x-botmux-vc-daemon-auth",
}

// daemonInternalPrefixes cover whole IPC families shaped like
// <family>-ts/-nonce/-signature. There is intentionally no bare "x-botmux-"
// prefix and no -signature/-timestamp/-nonce suffix rule: connector HMAC uses
// exactly those bare names.
var daemonInternalPrefixes = [...]string{
	"x-botmux-daemon-",
	"x-botmux-cli-",
	"x-botmux-companion-",
	"x-botmux-workflow-ipc-",
	"x-botmux-native-runtime-",
	"x-botmux-dispatch-launch-ipc-",
}

// PlatformAuthorityHeaders returns the lower-case names the platform injects
// after authentication (role/actor/scopes/login-url). A copy is returned so the
// blocklist cannot be mutated by callers.
func PlatformAuthorityHeaders() []string {
	return append([]string(nil), platformAuthorityHeaders[:]...)
}

// IsReservedBotmuxHeader reports whether a header belongs to the platform or
// daemon internals and must be removed from client input. Names outside the
// x-botmux- namespace always return false; matching is case-insensitive. The
// cross-pod loop guard (ForwardHeader) is not reserved: it only prevents
// forwarding loops and is never a trust assertion.
func IsReservedBotmuxHeader(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasPrefix(lower, "x-botmux-") {
		return false
	}
	if lower == strings.ToLower(ForwardHeader) {
		return false
	}
	for _, reserved := range platformAuthorityHeaders {
		if lower == reserved {
			return true
		}
	}
	for _, reserved := range daemonInternalHeaders {
		if lower == reserved {
			return true
		}
	}
	for _, prefix := range daemonInternalPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// StripReservedBotmuxHeaders deletes every reserved x-botmux-* header in place.
// Both the machine entry point and the dashboard proxy must apply the same set;
// an asymmetry between those two layers is how webhook protocol headers were
// previously lost.
func StripReservedBotmuxHeaders(header http.Header) {
	for name := range header {
		if IsReservedBotmuxHeader(name) {
			delete(header, name)
		}
	}
}
