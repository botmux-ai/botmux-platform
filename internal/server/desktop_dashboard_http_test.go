package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-desktop-dashboard.test.ts plus the MongoDB-mode list
// and the ownership/scope branches.

const dashboardMID = "feedfacefeedface"

func newDashboardHarness(t *testing.T) (*deviceHarness, auth.DesktopSessionExchangeResponse, *auth.DesktopAccessPayload) {
	h := newDeviceHarness(t)
	h.a.Config.SigningSecret = "desktop-dashboard-route-test-secret"
	session := auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{
		UnionID: "u-alice", Name: "Alice", LocalProfileID: "cloud-local-alice", CloudProfileID: "dcp_cloud_alice",
		SessionID: "desktop-dashboard-route-family", LinkedAt: time.Now().UnixMilli(),
	})
	access, err := auth.VerifyDesktopAccessToken(h.a.Config, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return h, session, access
}

func (h *deviceHarness) upsertLive(machineID, unionID, name string, lastSeen time.Time) {
	h.a.Registry.Upsert(&tunnel.MachineConn{
		MachineID: machineID, UnionID: unionID, OwnerName: name, Name: name, BotmuxVersion: "2.3.4",
		DashboardPort: 8800, LastSeen: lastSeen,
	})
}

func TestDesktopMachineListMemoryModeIsOwnerLiveView(t *testing.T) {
	h, session, _ := newDashboardHarness(t)
	h.upsertLive(dashboardMID, "u-alice", "Alice Mac", time.Now())
	h.upsertLive("deadbeefdeadbeef", "u-bob", "Bob Mac", time.Now())

	expectStatus(t, h.call(http.MethodGet, "/v1/desktop/machines", nil, nil), http.StatusUnauthorized, "unauthenticated")
	got := h.call(http.MethodGet, "/v1/desktop/machines", nil, bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	machines := got.body["machines"].([]any)
	if len(machines) != 1 {
		t.Fatalf("machines = %s", got.raw)
	}
	view := machines[0].(map[string]any)
	if view["machineId"] != dashboardMID || view["name"] != "Alice Mac" || view["online"] != true || view["botmuxVersion"] != "2.3.4" {
		t.Fatalf("view = %v", view)
	}
	if _, ok := view["lastSeenAt"].(float64); !ok {
		t.Fatalf("lastSeenAt = %v", view["lastSeenAt"])
	}
	var items []json.RawMessage
	if err := json.Unmarshal(mustRawField(t, got.raw, "machines"), &items); err != nil {
		t.Fatal(err)
	}
	expectKeys(t, items[0], "machineId", "name", "online", "lastSeenAt", "botmuxVersion")
}

func TestDesktopMachineListEmptyIsArray(t *testing.T) {
	h, session, _ := newDashboardHarness(t)
	got := h.call(http.MethodGet, "/v1/desktop/machines", nil, bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	if string(got.raw) != `{"machines":[]}` {
		t.Fatalf("empty = %s", got.raw)
	}
}

func TestDesktopMachineListDocumentMode(t *testing.T) {
	h, session, _ := newDashboardHarness(t)
	h.a.Config.DatabaseURI = "mongodb://parity" // the authoritative-store branch
	now := time.Now()
	h.seedMachine("aaaaaaaaaaaaaaa1", "u-alice", "Alice", "zeta")
	h.seedMachine("aaaaaaaaaaaaaaa2", "u-alice", "Alice", "")
	h.seedMachine("aaaaaaaaaaaaaaa3", "u-alice", "Alice", "Alpha")
	h.seedMachine("bbbbbbbbbbbbbbb1", "u-bob", "Bob", "bob")
	const retired = "aaaaaaaaaaaaaaa4"
	h.seedMachine(retired, "u-alice", "Alice", "gone")
	if err := h.repo.RetireMachine(context.Background(), retired); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.RenameMachine(context.Background(), "aaaaaaaaaaaaaaa3", "beta display"); err != nil {
		t.Fatal(err)
	}
	// A live tunnel refines name/version/online for its document.
	h.a.Registry.Upsert(&tunnel.MachineConn{MachineID: "aaaaaaaaaaaaaaa2", UnionID: "u-alice", Name: "Live Name", BotmuxVersion: "9.9.9", LastSeen: now.Add(time.Hour)})

	got := h.call(http.MethodGet, "/v1/desktop/machines", nil, bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	machines := got.body["machines"].([]any)
	if len(machines) != 3 {
		t.Fatalf("machines = %s", got.raw)
	}
	names := []string{}
	for _, m := range machines {
		names = append(names, m.(map[string]any)["name"].(string))
	}
	// localeCompare: case-insensitive first, so "beta display" < "Live Name" < "zeta".
	if names[0] != "beta display" || names[1] != "Live Name" || names[2] != "zeta" {
		t.Fatalf("names = %v", names)
	}
	live := machines[1].(map[string]any)
	if live["botmuxVersion"] != "9.9.9" || live["online"] != true || int64(live["lastSeenAt"].(float64)) != now.Add(time.Hour).UnixMilli() {
		t.Fatalf("live = %v", live)
	}
	offline := machines[2].(map[string]any)
	if offline["botmuxVersion"] != "1.0.0" || offline["online"] != true {
		t.Fatalf("offline = %v", offline)
	}
	// Past StaleAfter without a tunnel the document reads offline.
	h.a.Desktop.Now = func() time.Time { return now.Add(2 * time.Minute) }
	got = h.call(http.MethodGet, "/v1/desktop/machines", nil, bearer(session.AccessToken))
	if got.body["machines"].([]any)[2].(map[string]any)["online"] != false {
		t.Fatalf("stale = %s", got.raw)
	}
	h.a.Desktop.Now = nil

	h.a.Repository = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodGet, "/v1/desktop/machines", nil, bearer(session.AccessToken)), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDesktopDashboardAccessIssuesBoundShortTicket(t *testing.T) {
	h, session, access := newDashboardHarness(t)
	h.upsertLive(dashboardMID, "u-alice", "Alice Mac", time.Now())
	h.seedMachine(dashboardMID, "u-alice", "Alice", "Alice Mac")
	path := "/v1/desktop/machines/" + dashboardMID + "/dashboard-access"

	got := h.call(http.MethodPost, path, map[string]any{"scope": "manage"}, bearer(session.AccessToken))
	expectStatus(t, got, http.StatusOK, "")
	expectKeys(t, got.raw, "machineId", "scope", "audience", "accessToken", "expiresAt")
	claims, err := auth.VerifyDesktopDashboardAccessToken(h.a.Config, got.str("accessToken"))
	if err != nil {
		t.Fatal(err)
	}
	if got.str("machineId") != dashboardMID || got.str("scope") != "manage" || got.str("audience") != auth.DesktopDashboardAudience ||
		claims.MachineID != dashboardMID || claims.Scope != auth.DesktopDashboardManage || claims.Sub != access.UnionID ||
		claims.SID != access.SID || claims.CloudProfileID != access.CloudProfileID || int64(got.num("expiresAt")) != claims.Exp*1000 {
		t.Fatalf("got = %s claims = %+v", got.raw, claims)
	}

	// Scope defaults to observe; anything but the two exact strings is 400.
	observe := h.call(http.MethodPost, path, nil, bearer(session.AccessToken))
	if observe.str("scope") != "observe" {
		t.Fatalf("observe = %s", observe.raw)
	}
	if notObject := h.call(http.MethodPost, path, "[1]", bearer(session.AccessToken)); notObject.str("scope") != "observe" {
		t.Fatalf("array body = %s", notObject.raw)
	}
	for _, scope := range []any{"owner", nil, []string{"manage"}, "Manage"} {
		expectStatus(t, h.call(http.MethodPost, path, map[string]any{"scope": scope}, bearer(session.AccessToken)), http.StatusBadRequest, "invalid_scope")
	}

	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/machines/deadbeefdeadbeef/dashboard-access", nil, bearer(session.AccessToken)),
		http.StatusNotFound, "machine_not_found")
}

func TestDesktopDashboardAccessOwnership(t *testing.T) {
	h, session, _ := newDashboardHarness(t)
	path := func(id string) string { return "/v1/desktop/machines/" + id + "/dashboard-access" }

	// Live-only (memory mode, document not mirrored): the tunnel owner counts.
	h.upsertLive("1111111111111111", "u-alice", "Live Only", time.Now())
	expectStatus(t, h.call(http.MethodPost, path("1111111111111111"), nil, bearer(session.AccessToken)), http.StatusOK, "")
	h.upsertLive("2222222222222222", "u-bob", "Bob Live", time.Now())
	expectStatus(t, h.call(http.MethodPost, path("2222222222222222"), nil, bearer(session.AccessToken)), http.StatusNotFound, "machine_not_found")

	// The document is authoritative; a foreign live tunnel also denies.
	h.seedMachine("3333333333333333", "u-alice", "Alice", "doc")
	h.upsertLive("3333333333333333", "u-mallory", "Mallory", time.Now())
	expectStatus(t, h.call(http.MethodPost, path("3333333333333333"), nil, bearer(session.AccessToken)), http.StatusNotFound, "machine_not_found")
	h.seedMachine("4444444444444444", "u-bob", "Bob", "bob")
	h.upsertLive("4444444444444444", "u-alice", "Alice", time.Now())
	expectStatus(t, h.call(http.MethodPost, path("4444444444444444"), nil, bearer(session.AccessToken)), http.StatusNotFound, "machine_not_found")
	h.seedMachine("5555555555555555", "u-alice", "Alice", "retired")
	if err := h.repo.RetireMachine(context.Background(), "5555555555555555"); err != nil {
		t.Fatal(err)
	}
	h.upsertLive("5555555555555555", "u-alice", "Alice", time.Now())
	expectStatus(t, h.call(http.MethodPost, path("5555555555555555"), nil, bearer(session.AccessToken)), http.StatusNotFound, "machine_not_found")

	h.a.Repository = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, path("1111111111111111"), nil, bearer(session.AccessToken)), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDesktopDashboardAccessRefusesExpiringAccess(t *testing.T) {
	h, session, access := newDashboardHarness(t)
	h.seedMachine(dashboardMID, "u-alice", "Alice", "Alice Mac")
	h.a.Desktop.Now = func() time.Time { return time.Unix(access.Exp, 0) }
	expectStatus(t, h.call(http.MethodPost, "/v1/desktop/machines/"+dashboardMID+"/dashboard-access", nil, bearer(session.AccessToken)),
		http.StatusUnauthorized, "access_expired")
}

func TestDesktopFamilyRevocationKillsListAndTickets(t *testing.T) {
	h, session, access := newDashboardHarness(t)
	h.upsertLive(dashboardMID, "u-alice", "Alice Mac", time.Now())
	if err := h.repo.RevokeDesktopSessionFamily(context.Background(), access.SID, access.Exp*1000); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/desktop/machines"},
		{http.MethodPost, "/v1/desktop/machines/" + dashboardMID + "/dashboard-access"},
	} {
		got := h.call(tc.method, tc.path, nil, bearer(session.AccessToken))
		expectStatus(t, got, http.StatusUnauthorized, "session_revoked")
		if string(got.raw) != `{"error":"session_revoked"}` {
			t.Fatalf("%s = %s", tc.path, got.raw)
		}
	}
}

func TestDesktopDashboardUnknownPaths(t *testing.T) {
	h, session, _ := newDashboardHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/desktop/machines"},
		{http.MethodGet, "/v1/desktop/machines/" + dashboardMID + "/dashboard-access"},
		{http.MethodPost, "/v1/desktop/machines/XYZ/dashboard-access"},
		{http.MethodPost, "/v1/desktop/machines/" + dashboardMID},
	} {
		expectStatus(t, h.call(tc.method, tc.path, nil, bearer(session.AccessToken)), http.StatusNotFound, "not_found")
	}
}

func TestSortByLocaleName(t *testing.T) {
	machines := []desktopMachineView{{Name: "b"}, {Name: "B"}, {Name: "a"}, {Name: "_x"}, {Name: "10"}, {Name: "9"}, {Name: "é"}, {Name: "e"}, {Name: "f"}}
	sortByLocaleName(machines)
	got := []string{}
	for _, m := range machines {
		got = append(got, m.Name)
	}
	// ICU root collation (Node's localeCompare): punctuation, digits by
	// character, letters case-insensitive at the primary level with lower
	// case first, accents after the base letter.
	want := []string{"_x", "10", "9", "a", "b", "B", "e", "é", "f"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}
