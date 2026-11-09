package proxy

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// MachineSurface names the origin a machine subdomain request arrived on.
// Dashboard and device terminal use different origins so a shared WebView
// cookie jar can never carry one purpose's HttpOnly cookie into the other.
type MachineSurface string

const (
	SurfaceDashboard MachineSurface = "dashboard"
	SurfaceTerminal  MachineSurface = "terminal"
)

// MachineSubdomainRoute is the parsed m-<id>/t-<id> host of a request.
type MachineSubdomainRoute struct {
	MachineID string
	Surface   MachineSurface
}

var machineIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

func terminalPrefix(cfg config.Config) string {
	if cfg.TerminalSubdomainPrefix != "" {
		return cfg.TerminalSubdomainPrefix
	}
	return "t-"
}

func matchPrefixedMachineID(host, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) || len(host) < len(prefix)+len(suffix) {
		return "", false
	}
	id := host[len(prefix) : len(host)-len(suffix)]
	if !machineIDPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

// MatchMachineSubdomainRoute mirrors host.ts matchMachineSubdomainRoute: the
// host is everything before the first ':' lower-cased, the dashboard prefix is
// tried first and the terminal prefix (default "t-") second. The prefixes are
// compared as configured, exactly like Node.
func MatchMachineSubdomainRoute(cfg config.Config, hostHeader string) (MachineSubdomainRoute, bool) {
	if hostHeader == "" {
		return MachineSubdomainRoute{}, false
	}
	host := strings.ToLower(strings.SplitN(hostHeader, ":", 2)[0])
	suffix := "." + strings.ToLower(cfg.RootHost)
	if id, ok := matchPrefixedMachineID(host, cfg.MachineSubdomainPrefix, suffix); ok {
		return MachineSubdomainRoute{MachineID: id, Surface: SurfaceDashboard}, true
	}
	if id, ok := matchPrefixedMachineID(host, terminalPrefix(cfg), suffix); ok {
		return MachineSubdomainRoute{MachineID: id, Surface: SurfaceTerminal}, true
	}
	return MachineSubdomainRoute{}, false
}

// MachineBaseURL returns the public origin of one machine surface, keeping the
// scheme and port of PublicBaseURL (URL.origin in Node: no path, no trailing
// slash, default ports elided).
func MachineBaseURL(cfg config.Config, machineID string, surface MachineSurface) string {
	prefix := cfg.MachineSubdomainPrefix
	if surface == SurfaceTerminal {
		prefix = terminalPrefix(cfg)
	}
	hostname := prefix + machineID + "." + cfg.RootHost
	base, err := url.Parse(cfg.PublicBaseURL)
	if err != nil || base.Scheme == "" {
		return cfg.PublicBaseURL
	}
	port := base.Port()
	if (base.Scheme == "http" && port == "80") || (base.Scheme == "https" && port == "443") {
		port = ""
	}
	origin := strings.ToLower(base.Scheme) + "://" + strings.ToLower(hostname)
	if port != "" {
		origin += ":" + port
	}
	return origin
}
