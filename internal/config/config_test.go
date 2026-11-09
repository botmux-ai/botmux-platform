package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadDevelopmentDefaults(t *testing.T) {
	cfg := LoadWithLookup(mapLookup(map[string]string{"MY_HOST_IP": "10.0.0.7"}))

	if cfg.Production {
		t.Fatal("development config marked production")
	}
	if cfg.Port != 8080 || cfg.ListenAddr != "0.0.0.0:8080" {
		t.Fatalf("listen config = %d %q", cfg.Port, cfg.ListenAddr)
	}
	if cfg.PublicBaseURL != "http://localhost:8080" || cfg.RootHost != "localhost" {
		t.Fatalf("public URL = %q root = %q", cfg.PublicBaseURL, cfg.RootHost)
	}
	if cfg.CookieSecure || cfg.CookieDomain != "" {
		t.Fatalf("development cookie config = secure:%v domain:%q", cfg.CookieSecure, cfg.CookieDomain)
	}
	if !cfg.DevLogin || cfg.DevUnionID != "dev-union-0001" || cfg.DevName != "本地开发者" {
		t.Fatalf("development login config = %#v", cfg)
	}
	if cfg.SessionTTL != 7*24*time.Hour || cfg.MachineTokenTTL != 180*24*time.Hour || cfg.BindCodeTTL != 5*time.Minute {
		t.Fatalf("token TTLs = %s %s %s", cfg.SessionTTL, cfg.MachineTokenTTL, cfg.BindCodeTTL)
	}
	if cfg.StaleAfter != 90*time.Second || cfg.RouteTTL != 180*time.Second {
		t.Fatalf("routing durations = stale:%s route:%s", cfg.StaleAfter, cfg.RouteTTL)
	}
	if cfg.SupportSessionTTL != 30*time.Minute {
		t.Fatalf("support TTL = %s", cfg.SupportSessionTTL)
	}
	if cfg.SelfPodAddr != "10.0.0.7:8080" || cfg.ExternalPort != 8080 {
		t.Fatalf("self pod = %q external port = %d", cfg.SelfPodAddr, cfg.ExternalPort)
	}
	if cfg.DatabaseURI != "" || cfg.CoordinationAddr != "" || cfg.CoordinationTable != "botmux" {
		t.Fatalf("development stores unexpectedly enabled: %q %q %q", cfg.DatabaseURI, cfg.CoordinationAddr, cfg.CoordinationTable)
	}
	if !cfg.DashboardConnPool || !cfg.DashboardDirect {
		t.Fatal("dashboard optimizations should default on")
	}
	if cfg.WebDir != "dist/web" || cfg.InstallerFile != "install.sh" {
		t.Fatalf("static paths = %q %q", cfg.WebDir, cfg.InstallerFile)
	}
}

func TestLoadProductionOverridesAndPortSplit(t *testing.T) {
	env := map[string]string{
		"NODE_ENV":                 "production",
		"PUBLIC_BASE_URL":          "https://botmux.example/",
		"SIGNING_SECRET":           "secret",
		"FEISHU_APP_ID":            "cli_platform",
		"FEISHU_APP_SECRET":        "feishu-secret",
		"PORT":                     "8081",
		"PORT0":                    "11982",
		"MY_HOST_IP":               "10.2.3.4",
		"STALE_MS":                 "1234",
		"SUPPORT_SESSION_TTL_SEC":  "10",
		"COOKIE_SECURE":            "false",
		"COOKIE_DOMAIN":            ".auth.example",
		"MACHINE_SUBDOMAIN_PREFIX": "box-",
		"DEV_LOGIN":                "false",
		"MONGODB_URI":              "mongodb://db.example:27017",
		"MONGODB_DB":               "botmux-prod",
		"REDIS_URL":                "redis://kv.example:6379/0",
		"REDIS_KEY_NAMESPACE":      "prod",
		"DASHBOARD_CONN_POOL":      "0",
		"DASHBOARD_DIRECT":         "0",
		"WEB_DIR":                  "/srv/web",
		"BOTMUX_INSTALLER_FILE":    "/srv/install.sh",
	}
	cfg := LoadWithLookup(mapLookup(env))

	if !cfg.Production || cfg.Port != 8081 || cfg.ListenAddr != "0.0.0.0:8081" {
		t.Fatalf("listen config = production:%v port:%d addr:%q", cfg.Production, cfg.Port, cfg.ListenAddr)
	}
	if cfg.ExternalPort != 11982 || cfg.SelfPodAddr != "10.2.3.4:11982" {
		t.Fatalf("peer address = %q port=%d", cfg.SelfPodAddr, cfg.ExternalPort)
	}
	if cfg.PublicBaseURL != "https://botmux.example" || cfg.RootHost != "botmux.example" {
		t.Fatalf("public URL = %q root=%q", cfg.PublicBaseURL, cfg.RootHost)
	}
	if cfg.CookieSecure || cfg.CookieDomain != ".auth.example" || cfg.MachineSubdomainPrefix != "box-" {
		t.Fatalf("cookie/subdomain config = %#v", cfg)
	}
	if cfg.StaleAfter != 1234*time.Millisecond || cfg.RouteTTL != 3*time.Second {
		t.Fatalf("stale/route = %s/%s", cfg.StaleAfter, cfg.RouteTTL)
	}
	if cfg.SupportSessionTTL != time.Minute {
		t.Fatalf("support TTL clamp = %s", cfg.SupportSessionTTL)
	}
	if cfg.DatabaseURI != "mongodb://db.example:27017" || cfg.DatabaseName != "botmux-prod" {
		t.Fatalf("database config = %q %q", cfg.DatabaseURI, cfg.DatabaseName)
	}
	if cfg.CoordinationAddr != "redis://kv.example:6379/0" || cfg.CoordinationTable != "prod" {
		t.Fatalf("coordination config = %q %q", cfg.CoordinationAddr, cfg.CoordinationTable)
	}
	if cfg.DashboardConnPool || cfg.DashboardDirect {
		t.Fatal("dashboard optimizations should honor explicit disable")
	}
	if cfg.WebDir != "/srv/web" || cfg.InstallerFile != "/srv/install.sh" {
		t.Fatalf("static path overrides = %#v", cfg)
	}
	if err := cfg.ValidateProduction(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestValidateProductionRejectsFailOpenIdentityAndRoutingDefaults(t *testing.T) {
	valid := Config{
		Production:       true,
		PublicBaseURL:    "https://botmux.example",
		SigningSecret:    "shared-secret",
		FeishuAppID:      "cli_platform",
		FeishuAppSecret:  "feishu-secret",
		ExternalPort:     11982,
		SelfPodAddr:      "10.2.3.4:11982",
		CoordinationAddr: "redis://kv.example:6379",
	}
	if err := valid.ValidateProduction(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	single := valid
	single.CoordinationAddr, single.ExternalPort, single.SelfPodAddr = "", 0, ""
	if err := single.ValidateProduction(); err != nil {
		t.Fatalf("a single replica without coordination needs no peer address: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "signing secret", mutate: func(c *Config) { c.SigningSecret = "" }, want: "SIGNING_SECRET"},
		{name: "public URL missing", mutate: func(c *Config) { c.PublicBaseURL = "" }, want: "PUBLIC_BASE_URL"},
		{name: "public URL insecure", mutate: func(c *Config) { c.PublicBaseURL = "http://botmux.example" }, want: "absolute HTTPS origin"},
		{name: "public URL path", mutate: func(c *Config) { c.PublicBaseURL = "https://botmux.example/base" }, want: "absolute HTTPS origin"},
		{name: "public URL localhost", mutate: func(c *Config) { c.PublicBaseURL = "https://localhost" }, want: "must not use localhost"},
		{name: "external port", mutate: func(c *Config) { c.ExternalPort = 0 }, want: "PORT0"},
		{name: "peer address", mutate: func(c *Config) { c.SelfPodAddr = "" }, want: "MY_HOST_IP"},
		{name: "peer address localhost", mutate: func(c *Config) { c.SelfPodAddr = "localhost:11982" }, want: "reachable from other pods"},
		{name: "peer address hostname", mutate: func(c *Config) { c.SelfPodAddr = "pod-a:11982" }, want: "reachable from other pods"},
		{name: "peer port mismatch", mutate: func(c *Config) { c.SelfPodAddr = "10.2.3.4:8080" }, want: "must use PORT0"},
		{name: "peer loopback", mutate: func(c *Config) { c.SelfPodAddr = "127.0.0.1:11982" }, want: "reachable from other pods"},
		{name: "Feishu app id", mutate: func(c *Config) { c.FeishuAppID = "" }, want: "FEISHU_APP_ID"},
		{name: "Feishu secret", mutate: func(c *Config) { c.FeishuAppSecret = "" }, want: "FEISHU_APP_SECRET"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			if err := cfg.ValidateProduction(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateProduction() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadProductionDoesNotInventMissingSharedConfiguration(t *testing.T) {
	cfg := LoadWithLookup(mapLookup(map[string]string{
		"NODE_ENV":   "production",
		"MY_HOST_IP": "10.2.3.4",
		"REDIS_URL":  "redis://kv.example:6379",
	}))
	if cfg.SigningSecret != "" || cfg.PublicBaseURL != "" || cfg.ExternalPort != 0 || cfg.SelfPodAddr != "" {
		t.Fatalf("production fallbacks must fail closed: %#v", cfg)
	}
	err := cfg.ValidateProduction()
	for _, key := range []string{"SIGNING_SECRET", "PUBLIC_BASE_URL", "PORT0", "FEISHU_APP_ID", "FEISHU_APP_SECRET"} {
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("ValidateProduction() = %v, want %s", err, key)
		}
	}
}

func TestLoadProductionDoesNotInventPeerHost(t *testing.T) {
	cfg := LoadWithLookup(mapLookup(map[string]string{
		"NODE_ENV":          "production",
		"PUBLIC_BASE_URL":   "https://botmux.example",
		"SIGNING_SECRET":    "shared-secret",
		"FEISHU_APP_ID":     "cli_platform",
		"FEISHU_APP_SECRET": "feishu-secret",
		"PORT0":             "11982",
		"REDIS_URL":         "redis://kv.example:6379",
	}))
	if cfg.SelfPodAddr != "" {
		t.Fatalf("production peer address = %q, want empty without injected host", cfg.SelfPodAddr)
	}
	if err := cfg.ValidateProduction(); err == nil || !strings.Contains(err.Error(), "MY_HOST_IP") {
		t.Fatalf("ValidateProduction() = %v, want injected peer host error", err)
	}
}

func TestLoadDevelopmentUsesWritableStatusDefault(t *testing.T) {
	cfg := LoadWithLookup(mapLookup(nil))
	if !strings.HasPrefix(cfg.StatuszDir, os.TempDir()) {
		t.Fatalf("development statusz dir = %q", cfg.StatuszDir)
	}
}

func TestValidateProductionRejectsDevLoginAndStillRequiresFeishuCredentials(t *testing.T) {
	cfg := Config{
		Production: true, DevLogin: true,
		PublicBaseURL: "https://botmux.example", SigningSecret: "shared-secret",
		ExternalPort: 11982, SelfPodAddr: "10.2.3.4:11982",
	}
	err := cfg.ValidateProduction()
	for _, want := range []string{"DEV_LOGIN", "FEISHU_APP_ID", "FEISHU_APP_SECRET"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ValidateProduction() = %v, want %s", err, want)
		}
	}
}

func TestLoadProductionForcesDevLoginOffAndCookieSecureFailsSafe(t *testing.T) {
	base := map[string]string{
		"NODE_ENV":          "production",
		"DEV_LOGIN":         "true",
		"COOKIE_SECURE":     "typo",
		"PUBLIC_BASE_URL":   "https://botmux.example",
		"SIGNING_SECRET":    "shared-secret",
		"FEISHU_APP_ID":     "cli_platform",
		"FEISHU_APP_SECRET": "feishu-secret",
		"PORT0":             "11982",
		"MY_HOST_IP":        "10.2.3.4",
	}
	cfg := LoadWithLookup(mapLookup(base))
	if cfg.DevLogin {
		t.Fatal("DEV_LOGIN must never be enabled in production")
	}
	if !cfg.CookieSecure {
		t.Fatal("invalid COOKIE_SECURE must retain the secure production default")
	}

	base["COOKIE_SECURE"] = "TRUE"
	if cfg := LoadWithLookup(mapLookup(base)); !cfg.CookieSecure {
		t.Fatal("COOKIE_SECURE=TRUE should be recognized")
	}
}

func TestCookieDomainDerivation(t *testing.T) {
	for _, tc := range []struct {
		host string
		want string
	}{
		{host: "botmux.example", want: ".botmux.example"},
		{host: "localhost", want: ""},
		{host: "127.0.0.1", want: ""},
		{host: "singlelabel", want: ""},
	} {
		if got := deriveCookieDomain(tc.host, ""); got != tc.want {
			t.Errorf("deriveCookieDomain(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadFeatureConfigDefaults(t *testing.T) {
	cfg := LoadWithLookup(mapLookup(map[string]string{"PUBLIC_BASE_URL": "https://botmux.example.com"}))
	if cfg.TerminalSubdomainPrefix != "t-" || cfg.RelayTokenAudience != "botmux-relay" || cfg.RelayTokenIssuer != "https://botmux.example.com" {
		t.Fatalf("relay/terminal defaults: %+v", cfg)
	}
	if cfg.RelayTokenTTL != 10*time.Minute || cfg.RelaySigningSecret != "" {
		t.Fatalf("relay ttl/secret defaults: %v %q", cfg.RelayTokenTTL, cfg.RelaySigningSecret)
	}
	if cfg.CredentialKEK != nil || len(cfg.CredentialKEKLegacy) != 0 {
		t.Fatalf("credential vault must default to disabled")
	}
	if got := strings.Join(cfg.BotmuxReleaseRegistries, ","); got != "https://registry.npmjs.org" {
		t.Fatalf("release registries default: %q", got)
	}
}

func TestLoadWithDefaultsAppliesEditionFallbacks(t *testing.T) {
	defaults := Defaults{
		ProductionDatabaseURI:      "mongodb://edition-db:27017",
		ProductionCoordinationAddr: "edition-kv",
		CoordinationTable:          "edition",
		ReleaseRegistries:          "https://registry.example",
		ProductionStatuszDir:       "/srv/statusz",
	}
	dev := LoadWithDefaults(mapLookup(nil), defaults)
	if dev.DatabaseURI != "" || dev.CoordinationAddr != "" {
		t.Fatalf("production-only stores leaked into development: %q %q", dev.DatabaseURI, dev.CoordinationAddr)
	}
	if dev.CoordinationTable != "edition" {
		t.Fatalf("edition defaults not applied: %q", dev.CoordinationTable)
	}
	if got := strings.Join(dev.BotmuxReleaseRegistries, ","); got != "https://registry.example" {
		t.Fatalf("registry defaults: %q", got)
	}
	if !strings.HasPrefix(dev.StatuszDir, os.TempDir()) {
		t.Fatalf("development statusz dir = %q", dev.StatuszDir)
	}

	prod := LoadWithDefaults(mapLookup(map[string]string{"NODE_ENV": "production"}), defaults)
	if prod.DatabaseURI != "mongodb://edition-db:27017" || prod.CoordinationAddr != "edition-kv" || prod.StatuszDir != "/srv/statusz" {
		t.Fatalf("production edition defaults = %q %q %q", prod.DatabaseURI, prod.CoordinationAddr, prod.StatuszDir)
	}

	explicit := LoadWithDefaults(mapLookup(map[string]string{
		"NODE_ENV": "production", "MONGODB_URI": "mongodb://explicit", "REDIS_URL": "redis://explicit",
	}), defaults)
	if explicit.DatabaseURI != "mongodb://explicit" || explicit.CoordinationAddr != "redis://explicit" {
		t.Fatalf("explicit configuration must win: %q %q", explicit.DatabaseURI, explicit.CoordinationAddr)
	}
}

func TestLoadFeatureConfigOverrides(t *testing.T) {
	hexKEK := strings.Repeat("ab", 32)
	cfg := LoadWithLookup(mapLookup(map[string]string{
		"RELAY_TOKEN_TTL_SEC":       "5",
		"CREDENTIAL_KEK":            hexKEK,
		"CREDENTIAL_KEK_LEGACY":     "bad, " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + " ," + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)),
		"BOTMUX_RELEASE_REGISTRIES": "",
		"LARK_CREDENTIAL_SCOPES":    "  im:message  ",
	}))
	if cfg.RelayTokenTTL != 120*time.Second {
		t.Fatalf("relay ttl clamp: %v", cfg.RelayTokenTTL)
	}
	if hex.EncodeToString(cfg.CredentialKEK) != hexKEK {
		t.Fatalf("hex kek: %x", cfg.CredentialKEK)
	}
	if len(cfg.CredentialKEKLegacy) != 2 || !bytes.Equal(cfg.CredentialKEKLegacy[1], bytes.Repeat([]byte{0xfb}, 32)) {
		t.Fatalf("legacy keks: %x", cfg.CredentialKEKLegacy)
	}
	if len(cfg.BotmuxReleaseRegistries) != 0 {
		t.Fatalf("explicit empty registries must disable lookup: %v", cfg.BotmuxReleaseRegistries)
	}
	if cfg.LarkCredentialScopes != "im:message" {
		t.Fatalf("lark scopes trim: %q", cfg.LarkCredentialScopes)
	}
	if ParseKEK("short") != nil || ParseKEK(strings.Repeat("ab", 31)) != nil {
		t.Fatalf("malformed KEKs must be rejected")
	}
}

func TestLoadProductionFallsBackToIPv6HostIP(t *testing.T) {
	base := map[string]string{
		"NODE_ENV":     "production",
		"PORT0":        "11982",
		"REDIS_URL":    "redis://kv.example:6379",
		"MY_HOST_IPV6": "2001:db8:cd50:2000::17",
	}
	cfg := LoadWithLookup(mapLookup(base))
	if cfg.SelfPodAddr != "[2001:db8:cd50:2000::17]:11982" {
		t.Fatalf("IPv6-only peer address = %q", cfg.SelfPodAddr)
	}
	if err := validateProductionPeerAddress(cfg.SelfPodAddr, cfg.ExternalPort); err != nil {
		t.Fatalf("IPv6 peer address rejected: %v", err)
	}
	base["MY_HOST_IP"] = "10.2.3.4"
	if cfg := LoadWithLookup(mapLookup(base)); cfg.SelfPodAddr != "10.2.3.4:11982" {
		t.Fatalf("IPv4 must win when both are injected: %q", cfg.SelfPodAddr)
	}
}
