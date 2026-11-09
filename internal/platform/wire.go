package platform

import (
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/teamsync"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// wireEnv is what the per-module wire functions (wire_<module>.go) build
// their dependencies from. Each module fills only its own Apex Deps field;
// shared authorities are already set on Apex before any wire runs.
type wireEnv struct {
	cfg        config.Config
	repository *store.DocumentRepository
	// durableProvider is MongoDB, or UnavailableDatabaseProvider in memory mode.
	durableProvider store.DatabaseProvider
	kv              *store.KVStore
	routes          *store.RuntimeRouteAdapter
	registry        *tunnel.Registry
	dashboard       *proxy.Dashboard
	feishu          *feishu.Client
	teamSync        *teamsync.Service
	// machine is the machine-subdomain handler; the OpenAPI WebSocket proxy
	// delegates rewritten upgrades to it.
	machine *httpserver.MachineHandler
	// deviceLogins are the edition's extra credential-vault platforms.
	deviceLogins []credential.DeviceLogin
	// openAPIVerifier is the edition's OpenAPI token check (nil: no OpenAPI).
	openAPIVerifier httpserver.OpenAPIVerifier
	// addCloser registers a shutdown hook (background loops, pools).
	addCloser func(func() error)
}
