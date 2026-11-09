package auth

import (
	"regexp"
	"strconv"
	"strings"
)

// Read-only machine viewer (MachineRoleViewer): what the platform reverse
// proxy lets through. This is the authoritative gate for the role. The
// daemon is the second layer: the proxy also injects X-Botmux-Role: guest so
// the daemon applies its own Workbench allowlist and audience redaction, but
// the platform does not rely on it, because a daemon that predates platform
// guest identities would treat the request as its legacy owner.
//
// Allowlist, never a denylist: a route the daemon adds later is refused for
// viewers until it is listed here on purpose.

// viewerExactReadPaths are the GET/HEAD paths a viewer may read: the SPA
// shell, the session board and its event stream, and the Workbench identity
// probes. Everything that configures, operates or hands out credentials is
// absent on purpose (settings, schedules, bots, groups, write-link,
// spawn-command, debug terminal, preview interaction, workflow, ...).
var viewerExactReadPaths = map[string]bool{
	"/":                           true,
	"/favicon.ico":                true,
	"/favicon.png":                true,
	"/apple-touch-icon.png":       true,
	"/workbench.webmanifest":      true,
	"/workbench":                  true,
	"/workbench/dock":             true,
	"/events":                     true,
	"/api/sessions":               true,
	"/api/workbench/h5-context":   true,
	"/api/workbench/capabilities": true,
}

// viewerSessionReadPattern: per-session reads. view-link mints a short-lived
// read-only terminal grant bound to the viewer's own auth session (it can
// never send input); control without a suffix is the read-only lease status.
// write-link, spawn-command, control/takeover etc. do not match. The session
// id segment is restricted to plain id characters: no percent-escapes, so an
// encoded slash can never smuggle another route into the id position.
var viewerSessionReadPattern = regexp.MustCompile(`^/api/sessions/[A-Za-z0-9_.:-]{1,200}/(?:view-link|control)$`)

// ViewerDashboardRequestAllowed reports whether a viewer may send this
// request to the machine dashboard. pathname must be the WHATWG-normalized
// pathname the daemon will route on (requestPathQuery in the server
// package), still percent-encoded: an encoded variant of a listed path is
// simply not listed and is refused.
func ViewerDashboardRequestAllowed(method, pathname string) bool {
	if method != "GET" && method != "HEAD" {
		return false
	}
	if viewerExactReadPaths[pathname] {
		return true
	}
	if strings.HasPrefix(pathname, "/assets/") {
		return true
	}
	return viewerSessionReadPattern.MatchString(pathname)
}

// ViewerTerminalRequestAllowed is the terminal-surface (t-<id>, /s/*) gate
// for viewers: reads only. Terminal input travels over the WebSocket, where
// the injected guest role makes the worker drop every input frame.
func ViewerTerminalRequestAllowed(method string) bool {
	return method == "GET" || method == "HEAD"
}

// ViewerMinBotmuxVersion is the first botmux release whose daemon maps an
// injected platform guest role to a Workbench-only identity (allowlisted
// routes, redacted session board / SSE). Older daemons ignore the role on the
// dashboard and answer as the legacy owner, so even allowlisted reads would
// carry owner-only fields; the proxy refuses viewers on them.
var ViewerMinBotmuxVersion = [3]int{3, 16, 0}

var botmuxReleaseVersion = regexp.MustCompile(`^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(-.*)?$`)

// BotmuxVersionSupportsViewer reports whether the daemon version reported in
// the machine heartbeat is known to enforce the guest role on the dashboard.
// Unknown, unparsable and the 0.0.0 source-build placeholder fail closed, as
// does a prerelease of exactly the minimum version.
func BotmuxVersionSupportsViewer(version string) bool {
	match := botmuxReleaseVersion.FindStringSubmatch(strings.TrimSpace(version))
	if match == nil {
		return false
	}
	var parts [3]int
	for i := range parts {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return false
		}
		parts[i] = n
	}
	if parts == [3]int{} {
		return false
	}
	for i := range parts {
		if parts[i] != ViewerMinBotmuxVersion[i] {
			return parts[i] > ViewerMinBotmuxVersion[i]
		}
	}
	return match[4] == ""
}
