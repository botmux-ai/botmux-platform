package platform

import (
	"net/http"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Support is a remote-support relay linked in by an entrypoint. Its sockets
// are claimed ahead of machine subdomains and the machine tunnel, because some
// load balancers keep only the /tunnel/control upgrade path open for them.
type Support interface {
	// Matches reports whether r is one of the relay's sockets.
	Matches(r *http.Request) bool
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	// ServeApex serves the relay's public apex routes, such as the downloads
	// an agent needs, and reports whether it handled r.
	ServeApex(w http.ResponseWriter, r *http.Request) bool
	Close() error
}

// SupportEnv is what the platform hands a remote-support relay.
type SupportEnv struct {
	Config config.Config
	Lookup func(string) (string, bool)
	// Routes records which pod holds each support session.
	Routes *store.RuntimeRouteAdapter
	// ForwardRawWS hands a socket to the pod that holds its session.
	ForwardRawWS func(owner string, w http.ResponseWriter, r *http.Request) error
}
