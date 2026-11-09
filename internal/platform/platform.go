package platform

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/teamsync"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
	"github.com/gorilla/websocket"
)

// App owns the complete Botmux backend and all process-local state. Keeping a
// single owner is intentional: tunnel control sockets, pending data streams,
// support sessions and upstream connection pools are pod-local.
type App struct {
	listenAddr string
	handler    http.Handler
	statusPath string
	closeOnce  sync.Once
	closers    []func() error
}

// Drivers are the infrastructure clients an entrypoint links in. The zero
// value links MongoDB and Redis with self-hosted configuration defaults.
type Drivers struct {
	// Defaults supplies configuration fallbacks for unset environment values.
	Defaults config.Defaults
	// Lookup reads configuration values; nil reads the process environment.
	Lookup func(string) (string, bool)
	// Database dials the durable document store at Config.DatabaseURI; nil
	// uses MongoDB.
	Database func(uri, database string) *store.RetryingDatabaseProvider
	// Coordination opens the cross-pod KV at Config.CoordinationAddr; nil
	// uses Redis.
	Coordination store.KVClientFactory
	// DeviceLogins are the credential-vault platforms besides lark-cli.
	DeviceLogins []credential.DeviceLogin
	// OpenAPIVerifier checks the tokens of the external /openapi/* surface;
	// nil leaves it unserved.
	OpenAPIVerifier httpserver.OpenAPIVerifier
	// Support builds the remote-support relay; nil leaves it unserved.
	Support func(SupportEnv) Support
}

func (d Drivers) withFallbacks() Drivers {
	if d.Lookup == nil {
		d.Lookup = os.LookupEnv
	}
	if d.Database == nil {
		d.Database = store.NewMongoDatabaseProvider
	}
	if d.Coordination == nil {
		d.Coordination = store.RedisFactory{}
	}
	return d
}

// NewFromEnvironment constructs the complete service before the listener is
// published. A configured durable dependency is never replaced with a local
// in-memory authority after a connection failure.
func NewFromEnvironment(drivers Drivers) (*App, error) {
	drivers = drivers.withFallbacks()
	cfg := config.LoadWithDefaults(drivers.Lookup, drivers.Defaults)
	if value, _ := drivers.Lookup("BOTMUX_LISTEN_ADDR"); strings.TrimSpace(value) != "" {
		cfg.ListenAddr = strings.TrimSpace(value)
	}
	if err := cfg.ValidateProduction(); err != nil {
		return nil, fmt.Errorf("validate production configuration: %w", err)
	}
	return newApp(cfg, drivers)
}

func newApp(cfg config.Config, drivers Drivers) (*App, error) {
	drivers = drivers.withFallbacks()
	a := &App{
		listenAddr: cfg.ListenAddr,
		statusPath: filepath.Join(cfg.StatuszDir, cfg.StatuszName),
	}
	cleanupOnError := func(err error) (*App, error) {
		_ = a.Close()
		return nil, err
	}

	repository, durableProvider, repositoryCloser, err := buildRepository(cfg, drivers.Database)
	if err != nil {
		return cleanupOnError(err)
	}
	if repositoryCloser != nil {
		a.closers = append(a.closers, repositoryCloser)
	}
	issueStore := store.NewIssueStore(durableProvider)
	credentialStore := store.NewCredentialStore(durableProvider)
	if cfg.DatabaseURI != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := issueStore.EnsureIndexes(ctx); err != nil {
			slog.Warn("ensure issue indexes", "error", err)
		}
		if err := credentialStore.EnsureIndexes(ctx); err != nil {
			slog.Warn("ensure credential indexes", "error", err)
		}
		cancel()
	}
	deviceStates := auth.NewDeviceStateCache(repository)

	kv, kvCloser, err := buildCoordinationStore(cfg, drivers.Coordination)
	if err != nil {
		return cleanupOnError(err)
	}
	if kvCloser != nil {
		a.closers = append(a.closers, kvCloser)
	}
	routes := store.NewRuntimeRouteAdapter(kv)
	routingConfigured := cfg.CoordinationAddr != ""
	if routingConfigured && cfg.SelfPodAddr == "" {
		return cleanupOnError(errors.New("cross-pod coordination is configured but this pod has no peer-reachable address"))
	}

	registry := tunnel.NewRegistry(cfg.StaleAfter, cfg.SelfPodAddr, routes)
	dashboard := proxy.NewDashboard(registry)
	peerLifecycle := proxy.NewLifecycle()
	registry.SetDropHook(dashboard.DropMachine)
	var support Support
	if drivers.Support != nil {
		support = drivers.Support(SupportEnv{Config: cfg, Lookup: drivers.Lookup, Routes: routes, ForwardRawWS: peerLifecycle.ForwardWebSocket})
	}
	a.closers = append(a.closers, registry.Close, dashboard.Close)
	if support != nil {
		a.closers = append(a.closers, support.Close)
	}
	a.closers = append(a.closers, peerLifecycle.Close)

	feishuClient := feishu.NewClient(cfg.FeishuHost, cfg.FeishuAppID, cfg.FeishuAppSecret, nil)
	teamSync := teamsync.NewService(repository, registry, feishuClient)
	// A newly deployed Go cluster is read-only for irreversible Feishu side
	// effects unless an operator explicitly enables them after the soak gate.
	feishuWritesEnabled := environmentEnabled("TEAMSYNC_FEISHU_WRITES", false)
	teamSync.SetFeishuWrites(feishuWritesEnabled)

	tunnelServer := tunnel.NewServer(registry, NewMachineTokenVerifier(cfg))
	tunnelServer.Routes = routes
	tunnelServer.Persistence = NewMachinePersistence(repository)
	tunnelServer.TeamSync = teamSync
	tunnelServer.ForwardRawWS = peerLifecycle.ForwardWebSocket
	tunnelServer.SelfPodAddress = cfg.SelfPodAddr
	tunnelServer.RouteTTL = cfg.RouteTTL
	tunnelServer.StaleAfter = cfg.StaleAfter

	machineHandler := &httpserver.MachineHandler{
		Config: cfg, Registry: registry, Dashboard: dashboard, Routes: routes,
		ForwardHTTP: peerLifecycle.ForwardHTTP, ForwardRawWS: peerLifecycle.ForwardWebSocket,
	}
	machineAPI := httpserver.NewMachineAPI(cfg)
	apex := &httpserver.Apex{
		Config:               cfg,
		Registry:             registry,
		Repository:           repository,
		Routes:               routes,
		KV:                   kv,
		RoutingConfigured:    routingConfigured,
		Feishu:               feishuClient,
		TeamSync:             teamSync,
		MachineAPI:           machineAPI,
		ForwardHTTP:          peerLifecycle.ForwardHTTP,
		FeishuWritesDisabled: !feishuWritesEnabled,
		DeviceRepo:           repository,
		DesktopSessions:      repository,
		DeviceStates:         deviceStates,
		DeviceSockets:        httpserver.NewDeviceSocketWatcher(deviceStates),
		IssueStore:           issueStore,
		CredentialStore:      credentialStore,
	}
	if support != nil {
		apex.PublicRoutes = support.ServeApex
	}

	env := wireEnv{
		cfg: cfg, repository: repository, durableProvider: durableProvider, kv: kv,
		routes: routes, registry: registry, dashboard: dashboard, feishu: feishuClient, teamSync: teamSync,
		machine:         machineHandler,
		deviceLogins:    drivers.DeviceLogins,
		openAPIVerifier: drivers.OpenAPIVerifier,
		addCloser:       func(closer func() error) { a.closers = append(a.closers, closer) },
	}
	for _, wire := range []func() error{
		func() error { return wireDevices(env, apex) },
		func() error { return wireIssues(env, apex) },
		func() error { return wireCredentials(env, apex) },
		func() error { return wireOpenAPI(env, apex) },
		func() error { return wireMachine(env, apex, machineHandler, tunnelServer) },
		func() error { return wireApex(env, apex) },
	} {
		if err := wire(); err != nil {
			return cleanupOnError(err)
		}
	}

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if support != nil && support.Matches(r) {
			support.ServeHTTP(w, r)
			return
		}
		// Like index.ts: machine subdomains (m-/t-) win over the tunnel paths,
		// and only upgrades reach the tunnel server; a plain request to
		// /tunnel/* on the apex is an ordinary apex request.
		if machineID, ok := httpserver.MatchMachineSubdomain(cfg, r.Host); ok {
			machineHandler.ServeMachine(w, r, machineID)
			return
		}
		if (r.URL.Path == "/tunnel/control" || r.URL.Path == "/tunnel/data") && websocket.IsWebSocketUpgrade(r) {
			tunnelServer.ServeHTTP(w, r)
			return
		}
		apex.ServeHTTP(w, r)
	})
	a.handler = securityHeaders(cfg, dispatch)
	return a, nil
}

// buildRepository returns the document repository. Without a database URI
// (local/smoke mode) the very same implementation runs on the Mongo-semantics
// in-memory database, so local behaviour matches production queries.
//
// durableProvider backs the stores that have no in-memory fallback in Node
// (issues, credentials): the database provider, or UnavailableDatabaseProvider
// in memory mode so they fail closed with store_unavailable.
func buildRepository(cfg config.Config, dial func(uri, database string) *store.RetryingDatabaseProvider) (repository *store.DocumentRepository, durableProvider store.DatabaseProvider, closer func() error, err error) {
	if cfg.DatabaseURI == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		repository, err := initializeDocumentRepository(ctx, store.NewMemoryDatabaseProvider())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("initialize in-memory document repository: %w", err)
		}
		return repository, store.UnavailableDatabaseProvider{}, nil, nil
	}
	provider := dial(cfg.DatabaseURI, cfg.DatabaseName)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repository, err = initializeDocumentRepository(ctx, provider)
	if err != nil {
		_ = provider.Close()
		return nil, nil, nil, fmt.Errorf("initialize document repository: %w", err)
	}
	return repository, provider, provider.Close, nil
}

func initializeDocumentRepository(ctx context.Context, provider store.DatabaseProvider) (*store.DocumentRepository, error) {
	// Database performs the production provider's real Ping. Keep this separate
	// from index creation: the legacy Node service tolerates missing create-index
	// permission once the authoritative database itself is reachable.
	if _, err := provider.Database(ctx); err != nil {
		return nil, err
	}
	repository := store.NewDocumentRepository(provider)
	if err := repository.EnsureIndexes(ctx); err != nil {
		slog.Warn("ensure MongoDB indexes", "error", err)
	}
	return repository, nil
}

func buildCoordinationStore(cfg config.Config, factory store.KVClientFactory) (*store.KVStore, func() error, error) {
	if cfg.CoordinationAddr == "" {
		return store.NewKVStore(store.NewMemoryKV(), cfg.CoordinationTable, cfg.RouteTTL, cfg.SupportSessionTTL), nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ab, closer, err := store.OpenProductionKVStore(ctx, store.KVConfig{
		Address: cfg.CoordinationAddr, Table: cfg.CoordinationTable,
		RouteTTL: cfg.RouteTTL, SupportSessionTTL: cfg.SupportSessionTTL,
	}, factory)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize runtime coordination: %w", err)
	}
	var closeFn func() error
	if closer != nil {
		closeFn = closer.Close
	}
	return ab, closeFn, nil
}

func environmentEnabled(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "off", "no":
		return false
	case "1", "true", "on", "yes":
		return true
	default:
		// Unknown values must not accidentally enable an irreversible side
		// effect such as creating or disbanding a Feishu group.
		return false
	}
}

func (a *App) ListenAddress() string { return a.listenAddr }

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler.ServeHTTP(w, r)
}

// securityHeaders mirrors the Node entrypoint: the session cookie is Secure,
// so plain-http requests are upgraded and HTTPS responses carry HSTS — but only
// when cookies are actually Secure (local/dev HTTP must keep working).
// Content-sniffing protection is set per response type, as in the Node backend.
func securityHeaders(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.CookieSecure {
			if r.Header.Get("X-Forwarded-Proto") == "http" {
				w.Header().Set("Location", "https://"+r.Host+r.URL.RequestURI())
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) MarkReady() error    { return writeStatus(a.statusPath, "ready") }
func (a *App) MarkNotReady() error { return writeStatus(a.statusPath, "not_ready") }

func writeStatus(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create status directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write status %q: %w", value, err)
	}
	return nil
}

func (a *App) Close() error {
	var errs []error
	a.closeOnce.Do(func() {
		for i := len(a.closers) - 1; i >= 0; i-- {
			if err := a.closers[i](); err != nil {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}
