package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// markedServer serves one surface with a relay marker on every request (like
// the deployment's relayAware wrapper) and reports, per request, the status
// the handler marked as not a platform failure; 0 means a 5xx counts.
func markedServer(t *testing.T, h *MachineHandler, surface proxy.MachineSurface) (string, <-chan int) {
	t.Helper()
	marks := make(chan int, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, marker := proxy.WithRelayMarker(r.Context())
		h.ServeMachineSurface(w, r.WithContext(ctx), testMID, surface)
		marks <- marker.Status()
	}))
	t.Cleanup(server.Close)
	return server.URL, marks
}

func nextMark(t *testing.T, marks <-chan int) int {
	t.Helper()
	select {
	case mark := <-marks:
		return mark
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
		return 0
	}
}

type markedSurfaces struct {
	dashboard, terminal           string
	dashboardMarks, terminalMarks <-chan int
}

func newMarkedSurfaces(t *testing.T, h *MachineHandler) markedSurfaces {
	t.Helper()
	var s markedSurfaces
	s.dashboard, s.dashboardMarks = markedServer(t, h, proxy.SurfaceDashboard)
	s.terminal, s.terminalMarks = markedServer(t, h, proxy.SurfaceTerminal)
	return s
}

// checkNoTunnelAnswers asks for the webhook, the terminal page and the
// terminal WebSocket of a machine this pod holds no tunnel for. The answers
// must be the usual ones; marked says whether the webhook and terminal page
// answers are excluded from the failure rate. The WebSocket reject is written
// on the hijacked connection, which Hertz records as 200, so it is never
// marked.
func (s markedSurfaces) checkNoTunnelAnswers(t *testing.T, name string, headers map[string]string, marked bool) {
	t.Helper()
	want := func(status int) int {
		if marked {
			return status
		}
		return 0
	}
	got := machineDo(t, http.MethodGet, s.dashboard+"/webhook/a/b", headers)
	if got.Status != http.StatusBadGateway || got.Body != "机器当前不在线" {
		t.Fatalf("%s: webhook = %d %q", name, got.Status, got.Body)
	}
	if mark := nextMark(t, s.dashboardMarks); mark != want(http.StatusBadGateway) {
		t.Errorf("%s: webhook marked %d, want %d", name, mark, want(http.StatusBadGateway))
	}
	got = machineDo(t, http.MethodGet, s.terminal+"/s/x", headers)
	if got.Status != http.StatusServiceUnavailable || got.Body != reconnectHTML {
		t.Fatalf("%s: terminal page = %d", name, got.Status)
	}
	if mark := nextMark(t, s.terminalMarks); mark != want(http.StatusServiceUnavailable) {
		t.Errorf("%s: terminal page marked %d, want %d", name, mark, want(http.StatusServiceUnavailable))
	}
	if raw := rawUpgrade(t, s.terminal, "/s/x", headers); raw != "HTTP/1.1 502 Bad Gateway\r\n\r\n" {
		t.Fatalf("%s: terminal ws = %q", name, raw)
	}
	if mark := nextMark(t, s.terminalMarks); mark != 0 {
		t.Errorf("%s: terminal ws marked %d", name, mark)
	}
}

func TestOfflineMachineAnswersAreNotPlatformFailures(t *testing.T) {
	env := newMachineTestEnv(t)
	routes := &fakeRoutes{}
	env.offline.Routes = routes
	env.offline.Config.SelfPodAddr = "10.0.0.1:8080"
	records := installForwarders(env.offline)
	surfaces := newMarkedSurfaces(t, env.offline)

	surfaces.checkNoTunnelAnswers(t, "no route", map[string]string{}, true)
	routes.owner = "10.0.0.1:8080"
	surfaces.checkNoTunnelAnswers(t, "stale route to this pod", map[string]string{}, true)
	routes.owner = "10.0.0.2:8080"
	surfaces.checkNoTunnelAnswers(t, "forwarded here by the route owner", map[string]string{proxy.ForwardHeader: "1"}, true)
	env.offline.Routes = nil
	surfaces.checkNoTunnelAnswers(t, "no route store", map[string]string{}, true)
	if len(*records) != 0 {
		t.Fatalf("unexpected forwards: %+v", *records)
	}
}

func TestRouteStoreFailureStaysAPlatformFailure(t *testing.T) {
	env := newMachineTestEnv(t)
	env.offline.Routes = &fakeRoutes{owner: "10.0.0.2:8080", err: store.ErrUnavailable}
	env.offline.Config.SelfPodAddr = "10.0.0.1:8080"
	records := installForwarders(env.offline)
	newMarkedSurfaces(t, env.offline).checkNoTunnelAnswers(t, "route read failed", map[string]string{}, false)
	if len(*records) != 0 {
		t.Fatalf("forwarded despite the failed route read: %+v", *records)
	}
}

func TestFailedForwardToOwnerPodStaysAPlatformFailure(t *testing.T) {
	env := newMachineTestEnv(t)
	env.offline.Routes = &fakeRoutes{owner: "127.0.0.1:1"}
	env.offline.Config.SelfPodAddr = "10.0.0.1:8080"
	surfaces := newMarkedSurfaces(t, env.offline)

	for _, target := range []struct {
		url   string
		marks <-chan int
	}{{surfaces.dashboard + "/webhook/a/b", surfaces.dashboardMarks}, {surfaces.terminal + "/s/x", surfaces.terminalMarks}} {
		got := machineGet(t, target.url)
		if got.Status != http.StatusBadGateway || !strings.HasPrefix(got.Body, "跨 pod 转发失败") {
			t.Fatalf("%s = %d %q", target.url, got.Status, got.Body)
		}
		if mark := nextMark(t, target.marks); mark != 0 {
			t.Errorf("%s: failed forward marked %d", target.url, mark)
		}
	}
}

func TestProxyFailureToOnlineMachineStaysAPlatformFailure(t *testing.T) {
	t.Setenv("DASHBOARD_DIRECT", "0")
	env := newMachineTestEnv(t)
	// The fake daemon's dashboard address (127.0.0.1:1) refuses connections.
	dashboardProxy := proxy.NewDashboard(env.daemon.Registry)
	t.Cleanup(func() { _ = dashboardProxy.Close() })
	env.online.Dashboard = dashboardProxy
	dashboard, marks := markedServer(t, env.online, proxy.SurfaceDashboard)

	got := machineGet(t, dashboard+"/webhook/a/b")
	if got.Status != http.StatusBadGateway || !strings.Contains(got.Body, "反代失败") {
		t.Fatalf("webhook = %d %q", got.Status, got.Body)
	}
	if mark := nextMark(t, marks); mark != 0 {
		t.Errorf("proxy failure marked %d", mark)
	}
}
