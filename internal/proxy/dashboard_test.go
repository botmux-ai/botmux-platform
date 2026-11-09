package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

func TestDashboardTransportPoolConfigurationAndReuse(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		t.Setenv("DASHBOARD_CONN_POOL", "1")
		dashboard := NewDashboard(nil)
		defer dashboard.Close()

		first := dashboard.transportFor("machine-1")
		if again := dashboard.transportFor("machine-1"); again != first {
			t.Fatal("transport was not reused for the same machine")
		}
		if other := dashboard.transportFor("machine-2"); other == first {
			t.Fatal("different machines unexpectedly share a tunnel transport")
		}
		if first.Proxy != nil || first.ForceAttemptHTTP2 || first.DisableKeepAlives {
			t.Fatalf("unexpected transport flags: %+v", first)
		}
		if first.MaxConnsPerHost != 24 || first.MaxIdleConnsPerHost != 24 || first.IdleConnTimeout != time.Minute {
			t.Fatalf("pool limits = conns:%d idle:%d timeout:%s", first.MaxConnsPerHost, first.MaxIdleConnsPerHost, first.IdleConnTimeout)
		}
		if first.DialContext == nil {
			t.Fatal("tunnel transport has no DialContext")
		}

		dashboard.DropMachine("machine-1")
		if replacement := dashboard.transportFor("machine-1"); replacement == first {
			t.Fatal("DropMachine retained the old transport")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		t.Setenv("DASHBOARD_CONN_POOL", "0")
		dashboard := NewDashboard(nil)
		defer dashboard.Close()

		transport := dashboard.transportFor("machine-1")
		if !transport.DisableKeepAlives || transport.MaxIdleConnsPerHost != 0 {
			t.Fatalf("disabled pool still keeps idle connections: %+v", transport)
		}
		if again := dashboard.transportFor("machine-1"); again != transport {
			t.Fatal("transport configuration was recreated within one machine request path")
		}
	})
}

func TestDashboardRoundTripRetryPolicy(t *testing.T) {
	machine := tunnel.MachineConn{MachineID: "machine-1", DashboardPort: 7891, DashboardToken: "dashboard-secret"}

	t.Run("bodyless retries before response", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://platform.example/api/bots?q=1", nil)
		request.Header.Set("Cookie", "platform=secret")
		request.Header.Set("Connection", "keep-alive, X-Client-Hop")
		request.Header.Set("X-Client-Hop", "must-not-cross-the-proxy")
		attempts := 0
		transport := roundTripFunc(func(outgoing *http.Request) (*http.Response, error) {
			attempts++
			if outgoing.URL.String() != "http://127.0.0.1:7891/api/bots?q=1" || outgoing.Host != "127.0.0.1:7891" {
				t.Errorf("outgoing target = %s host=%q", outgoing.URL, outgoing.Host)
			}
			if got := outgoing.Header.Get("Cookie"); got != dashboardCookie+"=dashboard-secret" {
				t.Errorf("dashboard cookie = %q", got)
			}
			if outgoing.Header.Get("Connection") != "" {
				t.Errorf("hop-by-hop request header leaked: %#v", outgoing.Header)
			}
			if outgoing.Header.Get("X-Client-Hop") != "" {
				t.Errorf("Connection-nominated request header leaked: %#v", outgoing.Header)
			}
			if attempts < 3 {
				return nil, errors.New("stale pooled connection")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		})

		response, err := (&Dashboard{}).roundTrip(request, upstreamHeaders(request.Header, request.Host, machine, false, false, PlatformHeaders{}), transport, "http://127.0.0.1:7891", 3, false)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3", attempts)
		}
	})

	t.Run("body is never replayed", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "http://platform.example/api/update", strings.NewReader("payload"))
		attempts := 0
		var received string
		transport := roundTripFunc(func(outgoing *http.Request) (*http.Response, error) {
			attempts++
			body, err := io.ReadAll(outgoing.Body)
			if err != nil {
				t.Fatal(err)
			}
			received = string(body)
			return nil, errors.New("connection failed after consuming request body")
		})

		response, err := (&Dashboard{}).roundTrip(request, upstreamHeaders(request.Header, request.Host, machine, false, false, PlatformHeaders{}), transport, "http://127.0.0.1:7891", 3, true)
		if err == nil || response != nil {
			t.Fatalf("roundTrip = (%v, %v), want failure", response, err)
		}
		if attempts != 1 || received != "payload" {
			t.Fatalf("body attempts=%d received=%q", attempts, received)
		}
	})
}

func TestDashboardResponseStripsCookiesAndHopByHopHeaders(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type":          {"text/plain"},
			"Set-Cookie":            {"dashboard=must-not-leak"},
			"Connection":            {"keep-alive, X-Connection-Only"},
			"X-Connection-Only":     {"drop-me"},
			"Keep-Alive":            {"timeout=5"},
			"Proxy-Connection":      {"keep-alive"},
			"Proxy-Authenticate":    {"Basic"},
			"Proxy-Authorization":   {"Basic secret"},
			"Te":                    {"trailers"},
			"Trailer":               {"X-Trailer"},
			"Transfer-Encoding":     {"chunked"},
			"Upgrade":               {"websocket"},
			"X-End-To-End-Response": {"preserved"},
		},
		Body: io.NopCloser(strings.NewReader("response-body")),
	}
	recorder := httptest.NewRecorder()
	(&Dashboard{}).writeResponse(recorder, response)

	if recorder.Code != http.StatusCreated || recorder.Body.String() != "response-body" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	for _, name := range []string{
		"Set-Cookie", "Connection", "X-Connection-Only", "Keep-Alive", "Proxy-Connection",
		"Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		if got := recorder.Header().Values(name); len(got) != 0 {
			t.Errorf("%s leaked: %#v", name, got)
		}
	}
	if got := recorder.Header().Get("X-End-To-End-Response"); got != "preserved" {
		t.Fatalf("end-to-end header = %q", got)
	}
}

func TestDashboardCloseCancelsActiveDirectHTTP(t *testing.T) {
	for _, test := range []struct {
		name      string
		streaming bool
	}{
		{name: "waiting for response headers"},
		{name: "streaming response body", streaming: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requestStarted := make(chan struct{})
			requestCanceled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.streaming {
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, "stream-prefix")
					w.(http.Flusher).Flush()
				}
				close(requestStarted)
				<-r.Context().Done()
				close(requestCanceled)
			}))
			defer server.Close()

			t.Setenv("DASHBOARD_DIRECT", "1")
			registry := tunnel.NewRegistry(time.Minute, "", nil)
			defer registry.Close()
			dashboard := NewDashboard(registry)
			defer dashboard.Close()
			machine := tunnel.MachineConn{
				MachineID:      "machine-direct-close",
				DashboardPort:  7891,
				DashboardToken: "dashboard-secret",
				DirectHosts:    []string{strings.TrimPrefix(server.URL, "http://")},
			}
			dashboard.mu.Lock()
			dashboard.directState[machine.MachineID] = directStatus{
				host:    machine.DirectHosts[0],
				checked: time.Now(),
			}
			dashboard.mu.Unlock()

			request := httptest.NewRequest(http.MethodGet, "http://platform.example/active", nil)
			recorder := httptest.NewRecorder()
			proxyDone := make(chan struct{})
			go func() {
				dashboard.ProxyHTTP(recorder, request, machine, PlatformHeaders{})
				close(proxyDone)
			}()

			waitForSignal(t, requestStarted, "direct request did not reach upstream")
			if err := dashboard.Close(); err != nil {
				t.Fatal(err)
			}
			waitForSignal(t, requestCanceled, "Dashboard.Close did not cancel direct upstream request")
			waitForSignal(t, proxyDone, "Dashboard.Close did not unblock proxy handler")

			dashboard.mu.Lock()
			stateCount, transportCount := len(dashboard.directState), len(dashboard.transports)
			dashboard.mu.Unlock()
			if stateCount != 0 || transportCount != 0 {
				t.Fatalf("state recreated after close: direct=%d transports=%d", stateCount, transportCount)
			}
		})
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
