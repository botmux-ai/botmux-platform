package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort              = 8080
	defaultSessionTTL        = 7 * 24 * time.Hour
	defaultMachineTokenTTL   = 180 * 24 * time.Hour
	defaultBindCodeTTL       = 5 * time.Minute
	defaultStaleAfter        = 90 * time.Second
	defaultSupportSessionTTL = 30 * time.Minute
	defaultRelayTokenTTL     = 10 * time.Minute
	defaultReleaseRegistries = "https://registry.npmjs.org"
	defaultCoordinationTable = "botmux"
	credentialKEKBytes       = 32
)

// Config is the complete runtime configuration shared by the HTTP, tunnel,
// proxy, persistence, and support-session layers.
//
// Durations intentionally replace the TypeScript service's mixed seconds and
// milliseconds fields. Wire encoders are responsible for converting them back
// to the original units where compatibility requires it.
type Config struct {
	Production bool

	Port       int
	ListenAddr string

	PublicBaseURL string
	RootHost      string

	FeishuAppID     string
	FeishuAppSecret string
	FeishuHost      string
	// PlatformAppName is only a friendly label returned when the platform bot
	// is missing from a chat; clients fall back to FeishuAppID when empty.
	PlatformAppName string

	SigningSecret   string
	SessionTTL      time.Duration
	MachineTokenTTL time.Duration
	BindCodeTTL     time.Duration
	StaleAfter      time.Duration

	CookieSecure           bool
	CookieDomain           string
	MachineSubdomainPrefix string
	// TerminalSubdomainPrefix isolates device terminal origins from machine
	// dashboard origins (t-<machineId> vs m-<machineId>).
	TerminalSubdomainPrefix string

	// Mobile/Desktop Relay JWTs use a dedicated secret. Empty disables the
	// relay capability rather than falling back to SigningSecret.
	RelaySigningSecret string
	RelayTokenIssuer   string
	RelayTokenAudience string
	RelayTokenTTL      time.Duration

	// CredentialKEK wraps every credential data key. Nil disables the vault
	// (fail-closed); a malformed value is treated as absent. Legacy KEKs are
	// decrypt-only during rotation.
	CredentialKEK        []byte
	CredentialKEKLegacy  [][]byte
	LarkCredentialScopes string

	// OpenAPICORSOrigins are the browser origins allowed to call /openapi/*
	// cross-origin (OPENAPI_CORS_ORIGINS, comma separated, exact
	// scheme://host[:port]; "*" allows any origin). Empty disables CORS.
	// Credentials are never allowed, so "*" never combines with cookies.
	OpenAPICORSOrigins []string

	// BotmuxReleaseRegistries are queried in parallel for the latest published
	// botmux version. An explicitly empty env disables the lookup.
	BotmuxReleaseRegistries []string

	DevLogin   bool
	DevUnionID string
	DevName    string

	// DatabaseURI is the MongoDB connection string of the durable store
	// (MONGODB_URI). Empty runs the in-memory store for local development.
	DatabaseURI  string
	DatabaseName string

	// CoordinationAddr is the Redis-compatible KV shared by all replicas for
	// cross-pod routes and support sessions (REDIS_URL). Empty keeps routing
	// process-local, which is only correct for a single replica.
	CoordinationAddr  string
	CoordinationTable string

	// SelfPodAddr is the peer-reachable host address advertised through the
	// coordination store.
	// It uses the externally mapped port (PORT0), not the in-container listen port.
	SelfPodAddr  string
	ExternalPort int
	RouteTTL     time.Duration

	SupportSessionTTL time.Duration

	DashboardConnPool bool
	DashboardDirect   bool

	WebDir        string
	InstallerFile string

	StatuszDir  string
	StatuszName string
}

// Defaults are fallbacks for values the environment leaves unset. The zero
// value describes a self-hosted deployment: no durable store or cross-pod
// coordination unless configured.
// A deployment edition with its own infrastructure supplies non-zero values.
type Defaults struct {
	// ProductionDatabaseURI and ProductionCoordinationAddr apply only when
	// NODE_ENV=production.
	ProductionDatabaseURI      string
	ProductionCoordinationAddr string
	// CoordinationTable namespaces coordination keys ("botmux" when empty).
	CoordinationTable string
	// ReleaseRegistries is the comma-separated npm registry list queried for
	// the latest botmux release (the public npm registry when empty).
	ReleaseRegistries string
	// ProductionStatuszDir is where production publishes its readiness file
	// (the OS temporary directory when empty).
	ProductionStatuszDir string
}

// Load reads the process environment. Development keeps convenient local
// defaults; production callers must invoke ValidateProduction before exposing
// a listener.
func Load() Config {
	return LoadWithLookup(os.LookupEnv)
}

// LoadWithLookup is Load with an injectable environment, primarily for tests.
// Empty environment values have the same meaning as JavaScript's `env.X ||
// fallback`: they are treated as absent.
func LoadWithLookup(lookup func(string) (string, bool)) Config {
	return LoadWithDefaults(lookup, Defaults{})
}

// LoadWithDefaults is LoadWithLookup with edition-specific defaults.
func LoadWithDefaults(lookup func(string) (string, bool), defaults Defaults) Config {
	get := func(key string) string {
		value, ok := lookup(key)
		if !ok {
			return ""
		}
		return value
	}
	nonEmpty := func(key string) string {
		value := get(key)
		if value == "" {
			return ""
		}
		return value
	}

	production := get("NODE_ENV") == "production"
	port := firstInt(defaultPort, nonEmpty("PORT"))
	publicBaseURL := nonEmpty("PUBLIC_BASE_URL")
	if publicBaseURL == "" && !production {
		publicBaseURL = fmt.Sprintf("http://localhost:%d", port)
	}
	publicBaseURL = strings.TrimSuffix(publicBaseURL, "/")
	rootHost := parseRootHost(publicBaseURL)

	externalPort := firstInt(0, nonEmpty("PORT0"))
	if !production && externalPort == 0 {
		externalPort = firstInt(defaultPort, nonEmpty("PORT"))
	}

	signingSecret := nonEmpty("SIGNING_SECRET")
	if signingSecret == "" && !production {
		signingSecret = randomSecret()
	}

	staleAfter := millisDuration(nonEmpty("STALE_MS"), defaultStaleAfter)
	routeTTLDefault := time.Duration((2*staleAfter+time.Second-1)/time.Second) * time.Second
	supportTTL := secondsDuration(nonEmpty("SUPPORT_SESSION_TTL_SEC"), defaultSupportSessionTTL)
	if supportTTL < time.Minute {
		supportTTL = time.Minute
	}
	if supportTTL > time.Hour {
		supportTTL = time.Hour
	}

	cookieSecureDefault := production
	cookieSecure := cookieSecureDefault
	if value := nonEmpty("COOKIE_SECURE"); value != "" {
		cookieSecure = booleanOrFallback(value, cookieSecureDefault)
	}

	devLogin := !production && booleanOrFallback(get("DEV_LOGIN"), true)

	relayTTL := defaultRelayTokenTTL
	if value := nonEmpty("RELAY_TOKEN_TTL_SEC"); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) {
			relayTTL = time.Duration(math.Max(120, math.Min(3600, seconds)) * float64(time.Second))
		}
	}

	var credentialKEKLegacy [][]byte
	for _, part := range strings.Split(get("CREDENTIAL_KEK_LEGACY"), ",") {
		if key := ParseKEK(part); key != nil {
			credentialKEKLegacy = append(credentialKEKLegacy, key)
		}
	}

	releaseRegistriesRaw, releaseRegistriesSet := lookup("BOTMUX_RELEASE_REGISTRIES")
	if !releaseRegistriesSet {
		releaseRegistriesRaw = firstNonEmpty(defaults.ReleaseRegistries, defaultReleaseRegistries)
	}
	var releaseRegistries []string
	for _, part := range strings.Split(releaseRegistriesRaw, ",") {
		part = strings.TrimRight(strings.TrimSpace(part), "/")
		if part != "" {
			releaseRegistries = append(releaseRegistries, part)
		}
	}

	databaseURI := nonEmpty("MONGODB_URI")
	if databaseURI == "" && production {
		databaseURI = defaults.ProductionDatabaseURI
	}
	coordinationAddr := nonEmpty("REDIS_URL")
	if coordinationAddr == "" && production {
		coordinationAddr = defaults.ProductionCoordinationAddr
	}

	statuszDirDefault := filepath.Join(os.TempDir(), "botmux-platform-statusz")
	statuszNameDefault := "botmux-platform"
	if production {
		statuszDirDefault = firstNonEmpty(defaults.ProductionStatuszDir, statuszDirDefault)
	} else {
		statuszNameDefault = fmt.Sprintf("botmux-platform-%d", os.Getpid())
	}

	return Config{
		Production: production,

		Port:       port,
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", port),

		PublicBaseURL: publicBaseURL,
		RootHost:      rootHost,

		FeishuAppID:     nonEmpty("FEISHU_APP_ID"),
		FeishuAppSecret: nonEmpty("FEISHU_APP_SECRET"),
		FeishuHost:      strings.TrimSuffix(firstNonEmpty(nonEmpty("FEISHU_HOST"), "https://open.feishu.cn"), "/"),
		PlatformAppName: get("PLATFORM_APP_NAME"),

		SigningSecret:   signingSecret,
		SessionTTL:      secondsDuration(nonEmpty("SESSION_TTL_SEC"), defaultSessionTTL),
		MachineTokenTTL: secondsDuration(nonEmpty("MACHINE_TOKEN_TTL_SEC"), defaultMachineTokenTTL),
		BindCodeTTL:     secondsDuration(nonEmpty("BIND_CODE_TTL_SEC"), defaultBindCodeTTL),
		StaleAfter:      staleAfter,

		CookieSecure:            cookieSecure,
		CookieDomain:            deriveCookieDomain(rootHost, nonEmpty("COOKIE_DOMAIN")),
		MachineSubdomainPrefix:  firstNonEmpty(nonEmpty("MACHINE_SUBDOMAIN_PREFIX"), "m-"),
		TerminalSubdomainPrefix: firstNonEmpty(nonEmpty("TERMINAL_SUBDOMAIN_PREFIX"), "t-"),

		RelaySigningSecret: get("RELAY_SIGNING_SECRET"),
		RelayTokenIssuer:   firstNonEmpty(nonEmpty("RELAY_TOKEN_ISSUER"), publicBaseURL),
		RelayTokenAudience: firstNonEmpty(nonEmpty("RELAY_TOKEN_AUDIENCE"), "botmux-relay"),
		RelayTokenTTL:      relayTTL,

		CredentialKEK:        ParseKEK(get("CREDENTIAL_KEK")),
		CredentialKEKLegacy:  credentialKEKLegacy,
		LarkCredentialScopes: strings.TrimSpace(get("LARK_CREDENTIAL_SCOPES")),

		OpenAPICORSOrigins: ParseCORSOrigins(get("OPENAPI_CORS_ORIGINS")),

		BotmuxReleaseRegistries: releaseRegistries,

		DevLogin:   devLogin,
		DevUnionID: firstNonEmpty(nonEmpty("DEV_UNION_ID"), "dev-union-0001"),
		DevName:    firstNonEmpty(nonEmpty("DEV_NAME"), "本地开发者"),

		DatabaseURI:  databaseURI,
		DatabaseName: firstNonEmpty(nonEmpty("MONGODB_DB"), "botmux"),

		CoordinationAddr:  coordinationAddr,
		CoordinationTable: firstNonEmpty(nonEmpty("REDIS_KEY_NAMESPACE"), defaults.CoordinationTable, defaultCoordinationTable),

		SelfPodAddr:  resolveSelfPodAddr(get, externalPort, !production),
		ExternalPort: externalPort,
		RouteTTL:     secondsDuration(nonEmpty("ROUTE_TTL_SEC"), routeTTLDefault),

		SupportSessionTTL: supportTTL,

		DashboardConnPool: get("DASHBOARD_CONN_POOL") != "0",
		DashboardDirect:   get("DASHBOARD_DIRECT") != "0",

		WebDir:        filepath.Clean(firstNonEmpty(nonEmpty("WEB_DIR"), filepath.Join("dist", "web"))),
		InstallerFile: filepath.Clean(firstNonEmpty(nonEmpty("BOTMUX_INSTALLER_FILE"), "install.sh")),

		StatuszDir:  filepath.Clean(firstNonEmpty(nonEmpty("STATUSZ_DIR"), statuszDirDefault)),
		StatuszName: firstNonEmpty(nonEmpty("STATUSZ_NAME"), statuszNameDefault),
	}
}

// ValidateProduction rejects configurations that would otherwise let a
// healthy-looking pod mint incompatible credentials or advertise an invalid
// cross-pod route. Development deliberately retains its local fallbacks.
func (c Config) ValidateProduction() error {
	if !c.Production {
		return nil
	}

	var errs []error
	if strings.TrimSpace(c.SigningSecret) == "" {
		errs = append(errs, errors.New("SIGNING_SECRET is required in production"))
	}
	if err := validateProductionPublicBaseURL(c.PublicBaseURL); err != nil {
		errs = append(errs, err)
	}
	// Replicas only reach each other when they share a coordination store; a
	// single replica never advertises or dials a peer address.
	if c.CoordinationAddr != "" {
		if c.ExternalPort < 1 || c.ExternalPort > 65535 {
			errs = append(errs, errors.New("PORT0 must be a valid TCP port in production"))
		}
		if err := validateProductionPeerAddress(c.SelfPodAddr, c.ExternalPort); err != nil {
			errs = append(errs, err)
		}
	}
	if c.DevLogin {
		errs = append(errs, errors.New("DEV_LOGIN must be disabled in production"))
	}
	if strings.TrimSpace(c.FeishuAppID) == "" {
		errs = append(errs, errors.New("FEISHU_APP_ID is required in production"))
	}
	if strings.TrimSpace(c.FeishuAppSecret) == "" {
		errs = append(errs, errors.New("FEISHU_APP_SECRET is required in production"))
	}
	return errors.Join(errs...)
}

func validateProductionPeerAddress(address string, expectedPort int) error {
	host, portValue, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("MY_HOST_IP or MY_HOST_IPV6 (a peer-reachable host IP) is required in production")
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port != expectedPort {
		return errors.New("self pod peer address must use PORT0")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsGlobalUnicast() {
		return errors.New("self pod peer address must be reachable from other pods")
	}
	return nil
}

func validateProductionPublicBaseURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("PUBLIC_BASE_URL is required in production")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("PUBLIC_BASE_URL must be an absolute HTTPS origin without credentials, path, query, or fragment")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return errors.New("PUBLIC_BASE_URL must not use localhost in production")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return errors.New("PUBLIC_BASE_URL must be reachable outside this pod")
	}
	return nil
}

func parseRootHost(publicBaseURL string) string {
	u, err := url.Parse(publicBaseURL)
	if err != nil || u.Hostname() == "" {
		return "localhost"
	}
	return u.Hostname()
}

func deriveCookieDomain(rootHost, configured string) string {
	if configured != "" {
		return configured
	}
	if rootHost == "localhost" || net.ParseIP(rootHost) != nil || !strings.Contains(rootHost, ".") {
		return ""
	}
	return "." + rootHost
}

func resolveSelfPodAddr(get func(string) string, port int, allowInterfaceDiscovery bool) string {
	if port < 1 || port > 65535 {
		return ""
	}
	// IPv4 first, matching dual-stack deployments; IPv6-only pods only receive
	// MY_HOST_IPV6.
	host := firstNonEmpty(get("MY_HOST_IP"), get("MY_HOST_IPV6"))
	if host == "" && allowInterfaceDiscovery {
		host = firstRoutableIPv4()
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func firstRoutableIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		ip = ip.To4()
		if ip == nil || ip.IsLoopback() || isDockerBridgeOrLinkLocal(ip) {
			continue
		}
		return ip.String()
	}
	return ""
}

func isDockerBridgeOrLinkLocal(ip net.IP) bool {
	return (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 169 && ip[1] == 254)
}

// ParseKEK accepts a 32-byte key encoded as hex, base64url or base64, matching
// the Node service's Buffer decoding. Anything else is nil so that a malformed
// KEK disables the credential vault instead of sealing with a wrong key.
func ParseKEK(raw string) []byte {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	if len(value) == 2*credentialKEKBytes {
		if decoded, err := hex.DecodeString(value); err == nil {
			return decoded
		}
	}
	if decoded := decodeLenientBase64(value); len(decoded) == credentialKEKBytes {
		return decoded
	}
	return nil
}

// decodeLenientBase64 mirrors Node's Buffer.from(s, "base64"/"base64url"):
// both alphabets are accepted, padding is optional, decoding stops at the
// first '=' and other characters are skipped.
func decodeLenientBase64(value string) []byte {
	var cleaned strings.Builder
	for _, r := range value {
		switch {
		case r == '=':
			return decodeRawBase64(cleaned.String())
		case r == '-':
			cleaned.WriteByte('+')
		case r == '_':
			cleaned.WriteByte('/')
		case r == '+' || r == '/' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			cleaned.WriteRune(r)
		}
	}
	return decodeRawBase64(cleaned.String())
}

func decodeRawBase64(value string) []byte {
	// A single dangling sextet carries no complete byte; Node drops it.
	if len(value)%4 == 1 {
		value = value[:len(value)-1]
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	return decoded
}

// ParseCORSOrigins keeps "*" and well-formed http(s) origins (scheme and
// host lowercased, no path, query or trailing slash); anything else is
// dropped so a typo can never widen the allow-list.
func ParseCORSOrigins(raw string) []string {
	var origins []string
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		origin, ok := NormalizeCORSOrigin(part)
		if !ok || seen[origin] {
			continue
		}
		seen[origin] = true
		origins = append(origins, origin)
	}
	return origins
}

// NormalizeCORSOrigin returns the canonical form of an Origin value, or
// false when it is not "*" or a bare http(s)://host[:port].
func NormalizeCORSOrigin(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "*" {
		return raw, true
	}
	raw = strings.TrimSuffix(raw, "/")
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

func randomSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is extraordinarily rare. Preserve startup resilience
		// with a process-specific fallback rather than silently using a constant.
		return fmt.Sprintf("ephemeral-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func secondsDuration(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

func millisDuration(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	millis, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return time.Duration(millis * float64(time.Millisecond))
}

func firstInt(fallback int, values ...string) int {
	for _, value := range values {
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
		return fallback
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func booleanOrFallback(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	default:
		return fallback
	}
}
