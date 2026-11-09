package proxy

import (
	"net/http"
	"strings"
)

// hopByHopHeaderNames returns both the fixed HTTP/1.1 hop-by-hop fields and
// fields nominated by Connection. A proxy must consume these at each hop;
// forwarding them can leak connection state into an unrelated pooled socket.
func hopByHopHeaderNames(header http.Header) map[string]struct{} {
	blocked := map[string]struct{}{
		"connection":          {},
		"proxy-connection":    {}, // non-standard but still emitted by clients
		"keep-alive":          {},
		"proxy-authenticate":  {},
		"proxy-authorization": {},
		"te":                  {},
		"trailer":             {},
		"transfer-encoding":   {},
		"upgrade":             {},
	}
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				blocked[name] = struct{}{}
			}
		}
	}
	return blocked
}

func removeHopByHopHeaders(header http.Header) {
	blocked := hopByHopHeaderNames(header)
	for name := range header {
		if _, drop := blocked[strings.ToLower(name)]; drop {
			delete(header, name)
		}
	}
}
