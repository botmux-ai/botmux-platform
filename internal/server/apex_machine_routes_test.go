package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

const machineRouteTestID = "deadbeef00000001"

func TestOpenMachineChecksDashboardBeforeIssuingTicket(t *testing.T) {
	for _, tc := range []struct {
		name       string
		healthCode int
		wantCode   int
	}{
		{name: "reachable", healthCode: http.StatusOK, wantCode: http.StatusOK},
		{name: "unreachable", healthCode: http.StatusServiceUnavailable, wantCode: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := machineRouteTestConfig()
			registry := tunnel.NewRegistry(time.Minute, "pod-a:8080", nil)
			defer registry.Close()
			registry.Upsert(&tunnel.MachineConn{
				MachineID: machineRouteTestID,
				UnionID:   "owner",
				Name:      "machine",
				LastSeen:  time.Now(),
			})
			api := NewMachineAPI(cfg)
			calls := 0
			api.client.Transport = machineRouteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodGet || request.URL.Path != "/__health" {
					t.Fatalf("health request = %s %s", request.Method, request.URL.Path)
				}
				return machineRouteResponse(tc.healthCode, "health"), nil
			})
			a := Apex{
				Config: cfg, Registry: registry,
				Repository: newMemoryRepository(), MachineAPI: api,
			}
			recorder := httptest.NewRecorder()
			a.ServeHTTP(recorder, machineRouteRequest(cfg, http.MethodPost, "/api/machines/"+machineRouteTestID+"/open", ""))

			if recorder.Code != tc.wantCode || calls != 1 {
				t.Fatalf("response=%d %q health calls=%d", recorder.Code, recorder.Body.String(), calls)
			}
			if tc.wantCode != http.StatusOK {
				if got := recorder.Body.String(); got != `{"error":"dashboard_unreachable"}` {
					t.Fatalf("body = %q", got)
				}
				return
			}
			var body struct {
				OpenURL string `json:"openUrl"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			opened, err := url.Parse(body.OpenURL)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := auth.VerifyProxyTicket(cfg, opened.Query().Get("ticket"))
			if err != nil || claims.MachineID != machineRouteTestID || claims.UnionID != "owner" {
				t.Fatalf("proxy ticket = %#v, err=%v", claims, err)
			}
		})
	}
}

func TestOpenMachineRejectsOfflineRemoteBeforeHealthCheck(t *testing.T) {
	cfg := machineRouteTestConfig()
	repository := newMemoryRepository()
	if err := seedMachine(repository, store.RegisterMachine{
		MachineID: machineRouteTestID, UnionID: "owner", Name: "machine", LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	registry := tunnel.NewRegistry(time.Minute, "pod-a:8080", nil)
	defer registry.Close()
	api := NewMachineAPI(cfg)
	api.client.Transport = machineRouteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("offline machine unexpectedly probed at %s", request.URL)
		return nil, nil
	})
	a := Apex{Config: cfg, Registry: registry, Repository: repository, Routes: &machineRouteLookup{}, MachineAPI: api}
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, machineRouteRequest(cfg, http.MethodPost, "/api/machines/"+machineRouteTestID+"/open", ""))

	if recorder.Code != http.StatusConflict || recorder.Body.String() != `{"error":"machine_offline"}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestOpenMachineFailsClosedOnStoreError(t *testing.T) {
	cfg := machineRouteTestConfig()
	registry := tunnel.NewRegistry(time.Minute, "pod-a:8080", nil)
	defer registry.Close()
	a := Apex{
		Config: cfg, Registry: registry,
		Repository: machineRouteGetErrorRepository{Repository: newMemoryRepository()},
	}
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, machineRouteRequest(cfg, http.MethodPost, "/api/machines/"+machineRouteTestID+"/open", ""))

	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != `{"error":"store_unavailable"}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestUpgradeMachineRouteRequiresSessionAndJSON(t *testing.T) {
	cfg := machineRouteTestConfig()
	path := "/api/machines/" + machineRouteTestID + "/upgrade"
	a := Apex{Config: cfg}

	unauthenticated := httptest.NewRecorder()
	a.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "http://localhost"+path, nil))
	if unauthenticated.Code != http.StatusUnauthorized || unauthenticated.Body.String() != `{"error":"unauthenticated"}` {
		t.Fatalf("unauthenticated response = %d %q", unauthenticated.Code, unauthenticated.Body.String())
	}

	notJSON := httptest.NewRecorder()
	a.ServeHTTP(notJSON, machineRouteRequest(cfg, http.MethodPost, path, "text/plain"))
	if notJSON.Code != http.StatusUnsupportedMediaType || notJSON.Body.String() != `{"error":"json_required"}` {
		t.Fatalf("non-JSON response = %d %q", notJSON.Code, notJSON.Body.String())
	}
}

func TestUpgradeMachineRoutePreservesMachineAPIResponse(t *testing.T) {
	cfg := machineRouteTestConfig()
	repository := newMemoryRepository()
	if err := seedMachine(repository, store.RegisterMachine{
		MachineID: machineRouteTestID, UnionID: "owner", Name: "machine", LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	api := NewMachineAPI(cfg)
	calls := 0
	api.client.Transport = machineRouteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.Path != "/api/update/run" {
			t.Fatalf("upgrade request = %s %s", request.Method, request.URL.Path)
		}
		return machineRouteResponse(http.StatusConflict, `{"ok":false,"error":"upgrade_busy","retryAfter":7}`), nil
	})
	a := Apex{
		Config: cfg, Registry: tunnel.NewRegistry(time.Minute, "pod-a:8080", nil),
		Repository: repository, MachineAPI: api,
	}
	defer a.Registry.Close()
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, machineRouteRequest(
		cfg, http.MethodPost, "/api/machines/"+machineRouteTestID+"/upgrade", "Application/JSON; charset=utf-8",
	))

	if recorder.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("response=%d %q calls=%d", recorder.Code, recorder.Body.String(), calls)
	}
	if got := recorder.Body.String(); got != `{"ok":false,"error":"upgrade_busy","retryAfter":7}` {
		t.Fatalf("body = %q", got)
	}
}

func TestUpgradeMachineRouteRejectsWrongOwnerAndStoreFailure(t *testing.T) {
	cfg := machineRouteTestConfig()
	path := "/api/machines/" + machineRouteTestID + "/upgrade"
	for _, tc := range []struct {
		name       string
		repository store.Repository
		wantCode   int
		wantBody   string
	}{
		{
			name:       "wrong owner",
			repository: machineRouteRepository(t, "someone-else"),
			wantCode:   http.StatusNotFound,
			wantBody:   `{"error":"machine_not_found"}`,
		},
		{
			name:       "store unavailable",
			repository: machineRouteGetErrorRepository{Repository: newMemoryRepository()},
			wantCode:   http.StatusServiceUnavailable,
			wantBody:   `{"error":"store_unavailable"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			a := Apex{Config: cfg, Registry: tunnel.NewRegistry(time.Minute, "pod-a:8080", nil), Repository: tc.repository}
			defer a.Registry.Close()
			a.ServeHTTP(recorder, machineRouteRequest(cfg, http.MethodPost, path, "application/json"))
			if recorder.Code != tc.wantCode || recorder.Body.String() != tc.wantBody {
				t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func machineRouteTestConfig() config.Config {
	return config.Config{
		PublicBaseURL:          "https://botmux.example",
		RootHost:               "botmux.example",
		MachineSubdomainPrefix: "m-",
		SigningSecret:          "route-test-secret",
		SessionTTL:             time.Hour,
		StaleAfter:             time.Minute,
	}
}

func machineRouteRequest(cfg config.Config, method, path, contentType string) *http.Request {
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "owner", Name: "Owner"})
	request := httptest.NewRequest(method, "http://localhost"+path, nil)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	// Machine writes sit behind the fresh-SSO gate, which requires the
	// platform's exact Origin.
	request.Header.Set("Origin", cfg.PublicBaseURL)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return request
}

func machineRouteRepository(t *testing.T, owner string) store.Repository {
	t.Helper()
	repository := newMemoryRepository()
	if err := seedMachine(repository, store.RegisterMachine{
		MachineID: machineRouteTestID, UnionID: owner, Name: "machine", LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	return repository
}

func machineRouteResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type machineRouteLookup struct {
	address string
	err     error
}

func (r *machineRouteLookup) GetMachineRoute(context.Context, string) (string, error) {
	return r.address, r.err
}

func (*machineRouteLookup) DeleteMachineRoute(context.Context, string, string) error { return nil }

type machineRouteGetErrorRepository struct{ store.Repository }

func (machineRouteGetErrorRepository) GetMachine(context.Context, string) (store.MachineDoc, error) {
	return store.MachineDoc{}, store.ErrUnavailable
}

func (machineRouteGetErrorRepository) LookupMachine(context.Context, string, store.AuthorityCacheOptions) (store.MachineDoc, error) {
	return store.MachineDoc{}, store.ErrUnavailable
}

type machineRouteRoundTripFunc func(*http.Request) (*http.Response, error)

func (f machineRouteRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
