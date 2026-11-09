package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/teamsync"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Keep the composition-root contracts checked where the concrete packages
// meet. These assertions catch signature drift without coupling the leaf
// packages back to platform.
var (
	_ tunnel.RouteStore               = (*store.RuntimeRouteAdapter)(nil)
	_ tunnel.StreamOwnerStore         = (*store.RuntimeRouteAdapter)(nil)
	_ httpserver.RuntimeRoutes        = (*store.RuntimeRouteAdapter)(nil)
	_ httpserver.MachineRouteResolver = (*store.RuntimeRouteAdapter)(nil)
	_ tunnel.TeamSyncSender           = (*teamsync.Service)(nil)
	_ tunnel.RawWebSocketForwarder    = proxy.ForwardWebSocket
)

func TestMachineTokenVerifierMapsClaimsAndLegacyIAT(t *testing.T) {
	t.Parallel()
	cfg := config.Config{SigningSecret: "adapter-test-secret", MachineTokenTTL: time.Hour}
	now := time.Now().Truncate(time.Millisecond)
	token := auth.MintMachineTokenAt(cfg, auth.MachineIdentity{
		MachineID: "0123456789abcdef",
		UnionID:   "union-1",
		OwnerName: "Owner",
	}, now)
	verifier := NewMachineTokenVerifier(cfg)
	claims, ok := verifier.VerifyMachineToken(token)
	if !ok || claims == nil {
		t.Fatal("valid token rejected")
	}
	if claims.MachineID != "0123456789abcdef" || claims.UnionID != "union-1" || claims.OwnerName != "Owner" || claims.IssuedAt != now.UnixMilli() {
		t.Fatalf("claims = %+v", claims)
	}
	if claims, ok := verifier.VerifyMachineToken(token + "corrupt"); ok || claims != nil {
		t.Fatalf("invalid token accepted: %+v", claims)
	}

	legacy, err := auth.IssueToken(map[string]any{
		"kind": "machine", "unionId": "legacy-user", "ownerName": "Legacy",
		"machineId": "fedcba9876543210", "exp": time.Now().Add(time.Hour).Unix(),
	}, cfg.SigningSecret)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok = verifier.VerifyMachineToken(legacy)
	if !ok || claims == nil || claims.IssuedAt != 0 {
		t.Fatalf("legacy claims = %+v, ok=%v", claims, ok)
	}
}

func TestMachinePersistenceRegisterAndHeartbeat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repository := store.NewDocumentRepository(store.NewMemoryDatabaseProvider())
	persistence := NewMachinePersistence(repository)
	// Register only updates an ACTIVE bound machine; for an unbound one the
	// adapter reports success (the TS updateOne simply matched nothing).
	if err := persistence.PersistRegister(ctx, tunnel.MachineConn{MachineID: "machine-1", UnionID: "union-1", LastSeen: time.Now()}); err != nil {
		t.Fatalf("register before bind = %v", err)
	}
	if _, err := repository.GetMachine(ctx, "machine-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("register before bind created a document: %v", err)
	}
	if err := persistence.PersistHeartbeat(ctx, "machine-1", tunnel.DaemonMessage{Type: "heartbeat"}, time.Now()); err != nil {
		t.Fatalf("heartbeat before bind = %v", err)
	}
	if _, err := repository.BindMachineCAS(ctx, "machine-1", "union-1", "Owner"); err != nil {
		t.Fatal(err)
	}
	openID := "open-1"
	visible := false
	converted := toStoreBots([]tunnel.BotInfo{{OpenID: &openID, ShowInTeam: &visible}})
	if converted[0].OpenID == &openID || converted[0].ShowInTeam == &visible {
		t.Fatal("adapter leaked tunnel pointer fields into persistence model")
	}
	registeredAt := time.Unix(1_700_000_000, 987_654_321)
	err := persistence.PersistRegister(ctx, tunnel.MachineConn{
		MachineID: "machine-1", UnionID: "union-1", OwnerName: "Owner", Name: "host",
		BotmuxVersion: "2.80.0", DashboardToken: "must-not-persist", DashboardPort: 7891,
		DirectHosts: []string{"10.0.0.1:7891"},
		Memberships: []tunnel.MembershipInfo{{TeamID: "team-1", TeamName: "Team"}},
		Bots:        []tunnel.BotInfo{{AppID: "app-1", OpenID: &openID, Name: "Bot", ShowInTeam: &visible}},
		TeamSyncRev: stringPointer("revision"), LastSeen: registeredAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := repository.GetMachine(ctx, "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if doc.UnionID != "union-1" || doc.DashboardPort != 7891 || doc.LastSeen != registeredAt.UnixMilli() || len(doc.Memberships) != 1 || len(doc.Bots) != 1 {
		t.Fatalf("registered document = %+v", doc)
	}
	heartbeatAt := registeredAt.Add(time.Minute)
	if err := persistence.PersistHeartbeat(ctx, "machine-1", tunnel.DaemonMessage{Type: "heartbeat"}, heartbeatAt); err != nil {
		t.Fatal(err)
	}
	doc, _ = repository.GetMachine(ctx, "machine-1")
	if len(doc.Memberships) != 1 || len(doc.Bots) != 1 || doc.LastSeen != heartbeatAt.UnixMilli() {
		t.Fatalf("omitted heartbeat fields were not preserved: %+v", doc)
	}

	emptyMemberships := []tunnel.MembershipInfo{}
	emptyBots := []tunnel.BotInfo{}
	if err := persistence.PersistHeartbeat(ctx, "machine-1", tunnel.DaemonMessage{
		Type: "heartbeat", BotmuxVersion: "2.81.0", Memberships: emptyMemberships, Bots: emptyBots,
	}, heartbeatAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	doc, _ = repository.GetMachine(ctx, "machine-1")
	if doc.BotmuxVersion != "2.81.0" || len(doc.Memberships) != 0 || len(doc.Bots) != 0 {
		t.Fatalf("explicit heartbeat fields not applied: %+v", doc)
	}

	// A retired machine is never resurrected by register/heartbeat.
	if err := repository.RetireMachine(ctx, "machine-1"); err != nil {
		t.Fatal(err)
	}
	if err := persistence.PersistHeartbeat(ctx, "machine-1", tunnel.DaemonMessage{Type: "heartbeat", BotmuxVersion: "9.9.9"}, heartbeatAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("heartbeat on retired machine = %v", err)
	}
	doc, _ = repository.GetMachine(ctx, "machine-1")
	if !doc.Retired() || doc.BotmuxVersion != "2.81.0" {
		t.Fatalf("retired machine was updated: %+v", doc)
	}
}

func TestMachinePersistenceRejectsNilRepository(t *testing.T) {
	t.Parallel()
	persistence := NewMachinePersistence(nil)
	if err := persistence.PersistRegister(context.Background(), tunnel.MachineConn{}); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("register error = %v", err)
	}
	if err := persistence.PersistHeartbeat(context.Background(), "m", tunnel.DaemonMessage{}, time.Now()); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("heartbeat error = %v", err)
	}
}

func TestLocalCompositionStartsAndCloses(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		ListenAddr: ":0", PublicBaseURL: "http://localhost", RootHost: "localhost",
		MachineSubdomainPrefix: "m-", SigningSecret: "composition-test-secret",
		MachineTokenTTL: time.Hour, StaleAfter: 90 * time.Second, RouteTTL: 3 * time.Minute,
		SupportSessionTTL: 30 * time.Minute, CoordinationTable: "sandbox",
		FeishuHost: "https://open.feishu.cn", StatuszDir: t.TempDir(), StatuszName: "platform-test",
	}
	app, err := newApp(cfg, Drivers{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok" {
		t.Fatalf("health response = %d %q", response.Code, response.Body.String())
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

func stringPointer(value string) *string { return &value }
