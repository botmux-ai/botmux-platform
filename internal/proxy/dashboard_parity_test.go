package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/tunnel/tunneltest"
)

// Ports of test/proxy-dashboard-body.test.ts, proxy-forwarded-host.test.ts,
// proxy-host.test.ts and proxy-upstream-abort.test.ts. The fake daemon
// bridges real tunnel data streams to a local upstream, the Go equivalent
// of the Node tests' fake requestStream.

type capturedRequest struct {
	Method, URL, Body, Cookie, Host, XForwardedHost string
	Header                                          http.Header
}

type captureUpstream struct {
	mu       sync.Mutex
	requests []capturedRequest
	server   *httptest.Server
}

func newCaptureUpstream(t *testing.T) *captureUpstream {
	t.Helper()
	upstream := &captureUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstream.mu.Lock()
		upstream.requests = append(upstream.requests, capturedRequest{
			Method: r.Method, URL: r.URL.RequestURI(), Body: string(body), Cookie: r.Header.Get("Cookie"),
			Host: r.Host, XForwardedHost: r.Header.Get("X-Forwarded-Host"), Header: r.Header.Clone(),
		})
		upstream.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *captureUpstream) addr() string { return strings.TrimPrefix(u.server.URL, "http://") }

func (u *captureUpstream) captured() []capturedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]capturedRequest(nil), u.requests...)
}

// tunnelFront starts a platform front whose handler proxies through the
// fake daemon's tunnel with a fresh Dashboard.
func tunnelFront(t *testing.T, upstreamAddr string, machineID string, platform PlatformHeaders) (*httptest.Server, *tunneltest.Daemon) {
	t.Helper()
	t.Setenv("DASHBOARD_DIRECT", "0")
	daemon := tunneltest.Start(t, upstreamAddr, tunneltest.Options{MachineID: machineID})
	dashboard := NewDashboard(daemon.Registry)
	t.Cleanup(func() { _ = dashboard.Close() })
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dashboard.ProxyHTTP(w, r, daemon.Machine, platform)
	}))
	t.Cleanup(front.Close)
	return front, daemon
}

func TestProxyHTTPForwardsDeleteRequestBody(t *testing.T) {
	upstream := newCaptureUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedfacedeadbeef", PlatformHeaders{})

	payload := `{"names":["some-skill"],"force":false}`
	request, _ := http.NewRequest(http.MethodDelete, front.URL+"/api/skills", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || string(body) != `{"ok":true}` {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	got := upstream.captured()
	if len(got) != 1 || got[0].Method != http.MethodDelete || got[0].URL != "/api/skills" || got[0].Body != payload {
		t.Fatalf("upstream saw %+v", got)
	}
	if got[0].Cookie != "botmux_dashboard_token=tok-123" {
		t.Fatalf("cookie = %q", got[0].Cookie)
	}
}

func TestProxyHTTPProxiesBodylessGetThroughTunnel(t *testing.T) {
	upstream := newCaptureUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedface00000001", PlatformHeaders{})
	response, err := http.Get(front.URL + "/api/skills")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	got := upstream.captured()
	if response.StatusCode != 200 || len(got) != 1 || got[0].Method != http.MethodGet || got[0].Body != "" {
		t.Fatalf("status=%d upstream=%+v", response.StatusCode, got)
	}
}

func TestProxyHTTPForwardsBrowserHostAsXForwardedHost(t *testing.T) {
	for name, spoof := range map[string]string{"plain": "", "client spoof dropped": "attacker.evil.example"} {
		t.Run(name, func(t *testing.T) {
			upstream := newCaptureUpstream(t)
			front, _ := tunnelFront(t, upstream.addr(), "feedface00000002", PlatformHeaders{})
			request, _ := http.NewRequest(http.MethodGet, front.URL+"/s/sid", nil)
			request.Host = "t-feedface00000002.botmux.example.net"
			if spoof != "" {
				request.Header.Set("X-Forwarded-Host", spoof)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			got := upstream.captured()
			if response.StatusCode != 200 || len(got) != 1 {
				t.Fatalf("status=%d upstream=%+v", response.StatusCode, got)
			}
			if got[0].Host != upstream.addrWithLoopback() {
				t.Fatalf("upstream Host = %q, want %q", got[0].Host, upstream.addrWithLoopback())
			}
			if got[0].XForwardedHost != "t-feedface00000002.botmux.example.net" {
				t.Fatalf("X-Forwarded-Host = %q", got[0].XForwardedHost)
			}
		})
	}
}

func (u *captureUpstream) addrWithLoopback() string {
	_, port, _ := net.SplitHostPort(u.addr())
	return "127.0.0.1:" + port
}

func TestProxyHTTPInjectsOnlyPlatformDecidedHeaders(t *testing.T) {
	upstream := newCaptureUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedface00000003", PlatformHeaders{Role: "owner", Actor: "u-owner", LoginURL: "https://platform/open/x"})
	request, _ := http.NewRequest(http.MethodGet, front.URL+"/s/x", nil)
	request.Header.Set("X-Botmux-Role", "guest")
	request.Header.Set("X-Botmux-Scopes", "evil")
	request.Header.Set("X-Botmux-Terminal-Control", "1")
	request.Header.Set("X-Botmux-Webhook-Chat", "chat-1")
	request.Header.Set("Authorization", "Bearer platform-secret")
	request.Header.Set("Cookie", "botmux_proxy_session=secret; other=1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	got := upstream.captured()[0].Header
	if got.Get("X-Botmux-Role") != "owner" || got.Get("X-Botmux-Actor") != "u-owner" || got.Get("X-Botmux-Login-Url") != "https://platform/open/x" {
		t.Fatalf("platform headers = %v", got)
	}
	if values := got.Values("X-Botmux-Role"); len(values) != 1 {
		t.Fatalf("role values = %q", values)
	}
	if got.Get("X-Botmux-Scopes") != "" || got.Get("X-Botmux-Terminal-Control") != "" {
		t.Fatalf("client authority header leaked: %v", got)
	}
	// Protocol headers outside the reserved set pass through.
	if got.Get("X-Botmux-Webhook-Chat") != "chat-1" {
		t.Fatalf("webhook protocol header dropped: %v", got)
	}
	if got.Get("Authorization") != "" || got.Get("Cookie") != "botmux_dashboard_token=tok-123" {
		t.Fatalf("credentials leaked: auth=%q cookie=%q", got.Get("Authorization"), got.Get("Cookie"))
	}
}

func TestProxyHTTPPreservesWebhookAuthorization(t *testing.T) {
	upstream := newCaptureUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedface00000004", PlatformHeaders{})
	request, _ := http.NewRequest(http.MethodPost, front.URL+"/webhook/abc", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer third-party")
	request.Header.Set("X-Botmux-Role", "owner")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	got := upstream.captured()[0].Header
	if got.Get("Authorization") != "Bearer third-party" || got.Get("X-Botmux-Role") != "" {
		t.Fatalf("webhook headers = %v", got)
	}
}

// dyingSSEUpstream pushes two frames, then destroys the connection on kill.
type dyingSSEUpstream struct {
	server        *httptest.Server
	mu            sync.Mutex
	conn          net.Conn
	requestClosed chan struct{}
	closeOnce     sync.Once
}

func newDyingSSEUpstream(t *testing.T) *dyingSSEUpstream {
	t.Helper()
	upstream := &dyingSSEUpstream{requestClosed: make(chan struct{})}
	upstream.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "retry: 5000\n\n")
		_, _ = io.WriteString(w, "event: heartbeat\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		upstream.closeOnce.Do(func() { close(upstream.requestClosed) })
	}))
	upstream.server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateActive {
			upstream.mu.Lock()
			upstream.conn = conn
			upstream.mu.Unlock()
		}
	}
	upstream.server.Start()
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *dyingSSEUpstream) kill() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		_ = u.conn.Close()
	}
}

func (u *dyingSSEUpstream) addr() string { return strings.TrimPrefix(u.server.URL, "http://") }

type browserOutcome string

// openStream reads the first frame, runs trigger, then reports whether the
// response ended cleanly, was aborted, or kept hanging (a zombie).
func openStream(t *testing.T, url string, trigger func()) browserOutcome {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(url)
	if err != nil {
		return "aborted"
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	trigger()
	result := make(chan browserOutcome, 1)
	go func() {
		_, err := io.Copy(io.Discard, reader)
		if err == nil {
			result <- "ended"
			return
		}
		result <- "aborted"
	}()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(1500 * time.Millisecond):
		return "hung"
	}
}

func TestProxyHTTPAbortsBrowserWhenTunnelUpstreamDiesMidStream(t *testing.T) {
	upstream := newDyingSSEUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedface00000005", PlatformHeaders{})
	// A truncated response must not look like a clean end.
	if outcome := openStream(t, front.URL+"/events", upstream.kill); outcome != "aborted" {
		t.Fatalf("outcome = %s, want aborted", outcome)
	}
}

func TestProxyHTTPReleasesUpstreamWhenBrowserGoesAway(t *testing.T) {
	upstream := newDyingSSEUpstream(t)
	front, _ := tunnelFront(t, upstream.addr(), "feedface00000006", PlatformHeaders{})
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+"/events", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(response.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = response.Body.Close()
	select {
	case <-upstream.requestClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request still open after the browser left")
	}
}

func TestForwardHTTPPassesOwnerPodAbortThrough(t *testing.T) {
	peer := newDyingSSEUpstream(t)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = ForwardHTTP(peer.addr(), w, r)
	}))
	defer front.Close()
	if outcome := openStream(t, front.URL+"/events", peer.kill); outcome != "aborted" {
		t.Fatalf("outcome = %s, want aborted", outcome)
	}
}

func TestCallAPIRejectsWhenUpstreamDiesMidBody(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{\"ok\":")
				time.Sleep(20 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()
	t.Setenv("DASHBOARD_DIRECT", "0")
	daemon := tunneltest.Start(t, listener.Addr().String(), tunneltest.Options{MachineID: "feedface00000007"})
	dashboard := NewDashboard(daemon.Registry)
	defer dashboard.Close()

	result := make(chan error, 1)
	go func() {
		_, _, err := dashboard.CallAPI(context.Background(), daemon.Machine, http.MethodGet, "/api/bots", nil)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrUpstreamAborted) || err.Error() == "" || !strings.HasPrefix(err.Error(), "upstream_aborted") {
			t.Fatalf("CallAPI error = %v, want upstream_aborted", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CallAPI hung on a truncated upstream body")
	}
}

func TestProxyHTTPEndsCloseDelimitedResponsesNormally(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nhello ")
				time.Sleep(20 * time.Millisecond)
				_, _ = io.WriteString(conn, "world")
				_ = conn.Close()
			}()
		}
	}()
	front, _ := tunnelFront(t, listener.Addr().String(), "feedface00000008", PlatformHeaders{})
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(front.URL + "/download")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "hello world" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

func TestMachineHostRoutingIsolatesDashboardAndTerminalOrigins(t *testing.T) {
	cfg := config.Config{
		PublicBaseURL: "https://botmux.example.test:8443", RootHost: "botmux.example.test",
		MachineSubdomainPrefix: "m-", TerminalSubdomainPrefix: "t-",
	}
	for host, want := range map[string]MachineSubdomainRoute{
		"m-feedfacefeedface.botmux.example.test:8443": {MachineID: "feedfacefeedface", Surface: SurfaceDashboard},
		"t-feedfacefeedface.botmux.example.test:8443": {MachineID: "feedfacefeedface", Surface: SurfaceTerminal},
		"T-FEEDFACEFEEDFACE.Botmux.Example.Test":      {MachineID: "feedfacefeedface", Surface: SurfaceTerminal},
	} {
		if got, ok := MatchMachineSubdomainRoute(cfg, host); !ok || got != want {
			t.Fatalf("%s => %+v %v", host, got, ok)
		}
	}
	for _, host := range []string{"x-feedfacefeedface.botmux.example.test", "m-feedface.other.test", "m-xyz.botmux.example.test", "botmux.example.test", ""} {
		if got, ok := MatchMachineSubdomainRoute(cfg, host); ok {
			t.Fatalf("%q matched %+v", host, got)
		}
	}
	if got := MachineBaseURL(cfg, "feedfacefeedface", SurfaceDashboard); got != "https://m-feedfacefeedface.botmux.example.test:8443" {
		t.Fatalf("dashboard base = %q", got)
	}
	if got := MachineBaseURL(cfg, "feedfacefeedface", SurfaceTerminal); got != "https://t-feedfacefeedface.botmux.example.test:8443" {
		t.Fatalf("terminal base = %q", got)
	}
	cfg.PublicBaseURL = "https://botmux.example.test:443"
	cfg.TerminalSubdomainPrefix = ""
	if got := MachineBaseURL(cfg, "feedfacefeedface", SurfaceTerminal); got != "https://t-feedfacefeedface.botmux.example.test" {
		t.Fatalf("default port/prefix base = %q", got)
	}
}
