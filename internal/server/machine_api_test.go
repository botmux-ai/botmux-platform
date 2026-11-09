package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
)

func TestCheckDashboardHealthUsesAuthenticatedProxyPathAndDrainsBody(t *testing.T) {
	api := newMachineTestAPI()
	body := &trackedMachineBody{reader: strings.NewReader("healthy")}
	api.client.Transport = machineRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://m-deadbeef.botmux.example/__health" {
			t.Fatalf("health request = %s %s", request.Method, request.URL)
		}
		assertMachineRequestIdentity(t, api.cfg, request, "deadbeef", "owner")
		assertRequestBudget(t, request, dashboardHealthTimeout)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	})

	if !api.CheckDashboardHealth(context.Background(), "deadbeef", "owner") {
		t.Fatal("healthy dashboard reported unavailable")
	}
	if !body.closed || body.bytesRead != len("healthy") {
		t.Fatalf("health body closed=%v bytesRead=%d", body.closed, body.bytesRead)
	}
}

func TestMachineAPIDefaultOperationsKeepSixSecondBudget(t *testing.T) {
	api := newMachineTestAPI()
	if api.client.Timeout != 0 {
		t.Fatalf("global client timeout = %s, want zero", api.client.Timeout)
	}
	transport, ok := api.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("machine API transport = %#v, want direct transport", api.client.Transport)
	}
	api.client.Transport = machineRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		assertRequestBudget(t, request, machineAPITimeout)
		return machineResponse(http.StatusOK, `{"ok":true}`), nil
	})

	status, body := api.SetWorkingDir(context.Background(), "deadbeef", "owner", "cli_app", "off", "")
	if encoded, _ := body.MarshalJSON(); status != http.StatusOK || string(encoded) != `{"ok":true}` {
		t.Fatalf("SetWorkingDir() = %d %s", status, encoded)
	}
}

func TestUpgradeMachineUsesLongUpdateBudgetThenRestarts(t *testing.T) {
	api := newMachineTestAPI()
	calls := 0
	var restartBody []byte
	api.client.Transport = machineRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		assertMachineRequestIdentity(t, api.cfg, request, "deadbeef", "owner")
		switch calls {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/api/update/run" {
				t.Fatalf("update request = %s %s", request.Method, request.URL.Path)
			}
			assertRequestBudget(t, request, machineUpgradeRunTimeout)
			if request.Header.Get("Content-Type") != "" {
				t.Fatalf("bodyless update Content-Type = %q", request.Header.Get("Content-Type"))
			}
			return machineResponse(http.StatusOK, `{"ok":true,"oldVersion":"1.0.0","newVersion":"2.0.0","detail":"installed"}`), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/api/update/restart" {
				t.Fatalf("restart request = %s %s", request.Method, request.URL.Path)
			}
			assertRequestBudget(t, request, machineAPITimeout)
			if request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("restart Content-Type = %q", request.Header.Get("Content-Type"))
			}
			var err error
			if restartBody, err = io.ReadAll(request.Body); err != nil {
				t.Fatal(err)
			}
			return machineResponse(http.StatusNoContent, "restart ignored"), nil
		default:
			t.Fatalf("unexpected request %d: %s", calls, request.URL)
			return nil, errors.New("unexpected request")
		}
	})

	status, body := api.UpgradeMachine(context.Background(), "deadbeef", "owner")
	// `{ ...update, restarting: true }` keeps the daemon's key order.
	if got := mustMarshalJS(t, body); status != http.StatusOK || got != `{"ok":true,"oldVersion":"1.0.0","newVersion":"2.0.0","detail":"installed","restarting":true}` {
		t.Fatalf("UpgradeMachine() = %d %s", status, got)
	}
	if got := string(restartBody); got != `{"update":{"oldVersion":"1.0.0","newVersion":"2.0.0"}}` {
		t.Fatalf("restart body = %s", got)
	}
	if calls != 2 {
		t.Fatalf("requests = %d", calls)
	}
}

func TestUpgradeMachineNormalizesUpdateFailures(t *testing.T) {
	wantUnreachable := `{"ok":false,"error":"machine_unreachable"}`
	tests := []struct {
		name       string
		status     int
		response   string
		requestErr error
		wantStatus int
		wantBody   string
	}{
		{name: "legacy dashboard 404", status: http.StatusNotFound, response: "not found", wantStatus: http.StatusBadRequest, wantBody: `{"ok":false,"error":"upgrade_not_supported"}`},
		{name: "successful non JSON", status: http.StatusOK, response: "installed", wantStatus: http.StatusBadRequest, wantBody: `{"ok":false,"error":"upgrade_not_supported"}`},
		{name: "successful empty body", status: http.StatusOK, response: "", wantStatus: http.StatusBadRequest, wantBody: `{"ok":false,"error":"upgrade_not_supported"}`},
		{name: "failed non JSON", status: http.StatusServiceUnavailable, response: "reconnecting", wantStatus: http.StatusBadGateway, wantBody: wantUnreachable},
		{name: "transport error", requestErr: errors.New("dial failed"), wantStatus: http.StatusBadGateway, wantBody: wantUnreachable},
		{name: "HTTP JSON error", status: http.StatusConflict, response: `{"ok":false,"error":"busy","retryAfter":7}`, wantStatus: http.StatusConflict, wantBody: `{"ok":false,"error":"busy","retryAfter":7}`},
		{name: "update reports failure", status: http.StatusOK, response: `{"error":"install_failed","ok":false}`, wantStatus: http.StatusOK, wantBody: `{"error":"install_failed","ok":false}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := newMachineTestAPI()
			calls := 0
			api.client.Transport = machineRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Path != "/api/update/run" {
					t.Fatalf("unexpected request path %q", request.URL.Path)
				}
				if tc.requestErr != nil {
					return nil, tc.requestErr
				}
				return machineResponse(tc.status, tc.response), nil
			})

			status, body := api.UpgradeMachine(context.Background(), "deadbeef", "owner")
			if got := mustMarshalJS(t, body); status != tc.wantStatus || got != tc.wantBody {
				t.Fatalf("UpgradeMachine() = %d %s, want %d %s", status, got, tc.wantStatus, tc.wantBody)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want update only", calls)
			}
		})
	}
}

func TestUpgradeMachinePreservesInstalledUpdateWhenRestartFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		requestErr error
	}{
		{name: "restart HTTP error", status: http.StatusServiceUnavailable},
		{name: "restart transport error", requestErr: errors.New("connection closed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newMachineTestAPI()
			calls := 0
			api.client.Transport = machineRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return machineResponse(http.StatusOK, `{"ok":true,"oldVersion":"1.0.0","newVersion":"2.0.0","detail":"installed"}`), nil
				}
				if tc.requestErr != nil {
					return nil, tc.requestErr
				}
				return machineResponse(tc.status, "restart failed"), nil
			})

			status, body := api.UpgradeMachine(context.Background(), "deadbeef", "owner")
			// `{ ...update, ok: false, error, updateInstalled }`: ok keeps its
			// position, the new keys are appended.
			want := `{"ok":false,"oldVersion":"1.0.0","newVersion":"2.0.0","detail":"installed","error":"restart_failed","updateInstalled":true}`
			if got := mustMarshalJS(t, body); status != http.StatusBadGateway || got != want {
				t.Fatalf("UpgradeMachine() = %d %s, want 502 %s", status, got, want)
			}
			if calls != 2 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}

func newMachineTestAPI() *MachineAPI {
	return NewMachineAPI(config.Config{
		PublicBaseURL: "https://botmux.example", RootHost: "botmux.example", MachineSubdomainPrefix: "m-",
		SigningSecret: "machine-api-test-secret", SessionTTL: time.Hour,
	})
}

func assertMachineRequestIdentity(t *testing.T, cfg config.Config, request *http.Request, machineID, ownerID string) {
	t.Helper()
	if !strings.HasPrefix(request.Header.Get("Cookie"), auth.ProxyCookieName+"=") {
		t.Fatalf("proxy cookie = %q", request.Header.Get("Cookie"))
	}
	payload, err := auth.ReadProxySession(cfg, request)
	if err != nil || payload.MachineID != machineID || payload.UnionID != ownerID {
		t.Fatalf("proxy identity = %#v, err=%v", payload, err)
	}
}

func assertRequestBudget(t *testing.T, request *http.Request, want time.Duration) {
	t.Helper()
	deadline, ok := request.Context().Deadline()
	if !ok {
		t.Fatalf("request %s has no deadline", request.URL.Path)
	}
	remaining := time.Until(deadline)
	if remaining < want-time.Second || remaining > want+100*time.Millisecond {
		t.Fatalf("request %s budget = %s, want about %s", request.URL.Path, remaining, want)
	}
}

func machineResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type machineRoundTripFunc func(*http.Request) (*http.Response, error)

func (f machineRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type trackedMachineBody struct {
	reader    io.Reader
	bytesRead int
	closed    bool
}

func (b *trackedMachineBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.bytesRead += n
	return n, err
}

func (b *trackedMachineBody) Close() error {
	b.closed = true
	return nil
}

func mustMarshalJS(t *testing.T, value JSValue) string {
	t.Helper()
	encoded, err := value.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
