package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-device-machines.test.ts (/api/machines for device and
// SSO principals) plus the device branch of POST /api/machines/:id/open
// (src/server/device-open.ts).

func seedLiveMachine(t *testing.T, f *mobileSessionsFixture, machineID, owner, name string, lastSeen time.Time) {
	t.Helper()
	if err := seedMachine(f.repository, store.RegisterMachine{MachineID: machineID, UnionID: owner, Name: name, BotmuxVersion: "9.8.7", LastSeen: lastSeen.UnixMilli() - 5000}); err != nil {
		t.Fatal(err)
	}
	upsertLiveMachine(f, machineID, owner, name, lastSeen)
}

func upsertLiveMachine(f *mobileSessionsFixture, machineID, owner, name string, lastSeen time.Time) {
	openID := "ou-secret"
	f.apex.Registry.Upsert(&tunnel.MachineConn{
		MachineID: machineID, UnionID: owner, Name: name, BotmuxVersion: "9.8.7",
		DashboardToken: "dashboard-secret", DashboardPort: 7891, DirectHosts: []string{"127.0.0.1:7891"},
		Memberships: []tunnel.MembershipInfo{{TeamID: "team-secret", TeamName: "Secret Team"}},
		Bots:        []tunnel.BotInfo{{AppID: "bot-secret", OpenID: &openID, Name: "Secret Bot"}},
		LastSeen:    lastSeen,
	})
}

func TestDeviceMachinesReadReturnsMinimalOwnDTO(t *testing.T) {
	f := newMobileSessionsFixture(t)
	now := time.UnixMilli(time.Now().UnixMilli())
	seedLiveMachine(t, f, "feedfacefeedface", "u-alice", "alice-mac", now)
	seedLiveMachine(t, f, "deadbeefdeadbeef", "u-bob", "bob-mac", now.Add(-time.Second))
	device := f.seedMobileDevice(t, func(d *store.DeviceDoc) {
		d.ID, d.DeviceKind, d.Scopes = "dev-machines-read", store.DeviceKindDesktopIDE, []string{store.DeviceScopeMachinesRead}
	})
	response := f.do(http.MethodGet, "/api/machines", map[string]string{"Authorization": f.bearer(device)})
	want := `{"machines":[{"machineId":"feedfacefeedface","name":"alice-mac","online":true,"lastSeenAt":` + jsonNumber(now.UnixMilli()) + `}]}`
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("device list = %d %s, want %s", response.Code, response.Body.String(), want)
	}
}

func TestDeviceMachinesRequireScopeAndRejectMixedCredentials(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, func(d *store.DeviceDoc) {
		d.DeviceKind, d.Scopes = store.DeviceKindDesktopIDE, []string{store.DeviceScopeSessionsOpen}
	})
	if response := f.do(http.MethodGet, "/api/machines", map[string]string{"Authorization": f.bearer(device)}); response.Code != http.StatusForbidden || response.Body.String() != `{"error":"insufficient_scope"}` {
		t.Fatalf("missing scope = %d %s", response.Code, response.Body.String())
	}
	mixed := f.do(http.MethodGet, "/api/machines", map[string]string{"Authorization": f.bearer(device), "Cookie": f.cookie("u-alice")})
	if mixed.Code != http.StatusBadRequest || mixed.Body.String() != `{"error":"conflicting_credentials"}` {
		t.Fatalf("mixed credentials = %d %s", mixed.Code, mixed.Body.String())
	}
}

func TestSSOMachinesKeepsFullContract(t *testing.T) {
	f := newMobileSessionsFixture(t)
	// Live data wins over the record (and is later than the seeded lastSeen).
	now := time.UnixMilli(time.Now().UnixMilli() + 1000)
	upsertLiveMachine(f, mobileMachineID, "u-alice", "alice-mac", now)
	response := f.do(http.MethodGet, "/api/machines", map[string]string{"Cookie": f.cookie("u-alice")})
	want := `{"machines":[{"machineId":"feedfacefeedface","name":"alice-mac","botmuxVersion":"9.8.7","stale":false,"online":true,"lastSeen":` + jsonNumber(now.UnixMilli()) +
		`,"memberships":[{"teamId":"team-secret","teamName":"Secret Team"}],"bots":[{"appId":"bot-secret","openId":"ou-secret","name":"Secret Bot"}],"coManagerCount":0}],"managedMachines":[],"latestVersion":"9.8.7"}`
	if response.Code != http.StatusOK || response.Body.String() != want {
		t.Fatalf("SSO list = %d %s\nwant %s", response.Code, response.Body.String(), want)
	}
}

func TestSSOMachinesLatestVersionIsNullWithoutParsableVersions(t *testing.T) {
	f := newMobileSessionsFixture(t)
	f.apex.Registry.Remove(mobileMachineID, nil)
	if err := f.repository.RetireMachine(context.Background(), mobileMachineID); err != nil {
		t.Fatal(err)
	}
	response := f.do(http.MethodGet, "/api/machines", map[string]string{"Cookie": f.cookie("u-alice")})
	if response.Body.String() != `{"machines":[],"managedMachines":[],"latestVersion":null}` {
		t.Fatalf("empty list = %s", response.Body.String())
	}
}

type deviceOpenBody struct {
	OpenURL             string `json:"openUrl"`
	SID                 string `json:"sid"`
	RenewalChain        string `json:"renewalChain"`
	AuthExpiresAt       int64  `json:"authExpiresAt"`
	SessionMaxExpiresAt int64  `json:"sessionMaxExpiresAt"`
}

func (f *mobileSessionsFixture) deviceOpen(t *testing.T, device store.DeviceDoc, machineID, body string) (int, string, deviceOpenBody) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/machines/"+machineID+"/open", strings.NewReader(body))
	request.Header.Set("Authorization", f.bearer(device))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	f.apex.ServeHTTP(recorder, request)
	var parsed deviceOpenBody
	_ = json.Unmarshal(recorder.Body.Bytes(), &parsed)
	return recorder.Code, recorder.Body.String(), parsed
}

func TestDeviceOpenIssuesDashboardMobileTicket(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, nil)
	status, raw, body := f.deviceOpen(t, device, mobileMachineID, "{}")
	if status != http.StatusOK {
		t.Fatalf("open = %d %s", status, raw)
	}
	open, err := url.Parse(body.OpenURL)
	if err != nil {
		t.Fatal(err)
	}
	if open.Hostname() != "m-"+mobileMachineID+".localhost" || open.Query().Has("next") {
		t.Fatalf("openUrl = %s", body.OpenURL)
	}
	claims, err := auth.VerifyDeviceProxyTicket(f.cfg, open.Query().Get("ticket"))
	if err != nil || claims.DeviceID != device.ID || claims.Purpose != auth.DeviceProxyPurposeDashboardMobile || claims.SID != body.SID {
		t.Fatalf("ticket = %#v err=%v", claims, err)
	}
	// Both expiries are milliseconds on the wire.
	nowMS := time.Now().UnixMilli()
	if body.RenewalChain == "" || body.AuthExpiresAt <= nowMS || body.SessionMaxExpiresAt < body.AuthExpiresAt ||
		body.SessionMaxExpiresAt > nowMS+deviceSessionChainMaxSec*1000 {
		t.Fatalf("open body = %s", raw)
	}
	// A renewal keeps the session id and the absolute chain cap.
	status, raw, renewed := f.deviceOpen(t, device, mobileMachineID, `{"chain":"`+body.RenewalChain+`"}`)
	if status != http.StatusOK || renewed.SID != body.SID || renewed.SessionMaxExpiresAt != body.SessionMaxExpiresAt {
		t.Fatalf("renewal = %d %s (first %+v)", status, raw, body)
	}
}

func TestDeviceOpenScopeFailures(t *testing.T) {
	f := newMobileSessionsFixture(t)
	mobile := f.seedMobileDevice(t, func(d *store.DeviceDoc) { d.Scopes = store.DeviceMVPScopes() })
	if status, raw, _ := f.deviceOpen(t, mobile, mobileMachineID, "{}"); status != http.StatusUnauthorized || raw != `{"error":"recovery_required"}` {
		t.Fatalf("mobile without dashboard:manage = %d %s", status, raw)
	}
	g := newMobileSessionsFixture(t)
	desktop := g.seedMobileDevice(t, func(d *store.DeviceDoc) {
		d.DeviceKind, d.Scopes = store.DeviceKindDesktopIDE, store.DeviceMVPScopes()
	})
	if status, raw, _ := g.deviceOpen(t, desktop, mobileMachineID, "{}"); status != http.StatusForbidden || raw != `{"error":"insufficient_scope"}` {
		t.Fatalf("desktop without dashboard:manage = %d %s", status, raw)
	}
}

func TestDeviceOpenRejectsForeignAndOfflineMachines(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, nil)
	seedLiveMachine(t, f, "deadbeefdeadbeef", "u-bob", "bob-mac", time.Now())
	if status, raw, _ := f.deviceOpen(t, device, "deadbeefdeadbeef", "{}"); status != http.StatusNotFound || raw != `{"error":"machine_not_found"}` {
		t.Fatalf("foreign = %d %s", status, raw)
	}
	f.apex.Registry.Remove(mobileMachineID, nil)
	if status, raw, _ := f.deviceOpen(t, device, mobileMachineID, "{}"); status != http.StatusConflict || raw != `{"error":"machine_offline"}` {
		t.Fatalf("offline = %d %s", status, raw)
	}
}

func TestDeviceOpenRetiredMachineIsNotFound(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, nil)
	if err := f.repository.RetireMachine(context.Background(), mobileMachineID); err != nil {
		t.Fatal(err)
	}
	if status, raw, _ := f.deviceOpen(t, device, mobileMachineID, "{}"); status != http.StatusNotFound || raw != `{"error":"machine_not_found"}` {
		t.Fatalf("retired = %d %s", status, raw)
	}
}

func jsonNumber(value int64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
