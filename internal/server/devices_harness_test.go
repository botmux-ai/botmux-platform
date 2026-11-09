package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Shared harness for the B1 route tests: an Apex on the in-memory document
// (the TS tests' memoryMode), Feishu unconfigured (DMs are no-ops) and Redis
// unconfigured (machine revocation reads as not revoked).

const deviceTestOrigin = "http://localhost"

type deviceHarness struct {
	t    *testing.T
	a    *Apex
	db   store.DocumentDatabase
	repo *store.DocumentRepository
}

func deviceTestConfig() config.Config {
	return config.Config{
		PublicBaseURL:          "http://localhost",
		RootHost:               "localhost",
		MachineSubdomainPrefix: "m-",
		SigningSecret:          "test-secret",
		SessionTTL:             7 * 24 * time.Hour,
		MachineTokenTTL:        180 * 24 * time.Hour,
		StaleAfter:             time.Minute,
	}
}

func newDeviceHarness(t *testing.T) *deviceHarness {
	t.Helper()
	provider := store.NewMemoryDatabaseProvider()
	repo := store.NewDocumentRepository(provider)
	states := auth.NewDeviceStateCache(repo)
	cfg := deviceTestConfig()
	return &deviceHarness{
		t:    t,
		db:   provider.DB,
		repo: repo,
		a: &Apex{
			Config:          cfg,
			Registry:        tunnel.NewRegistry(cfg.StaleAfter, "", nil),
			Repository:      repo,
			DeviceRepo:      repo,
			DesktopSessions: repo,
			DeviceStates:    states,
			DeviceSockets:   NewDeviceSocketWatcher(states),
			Devices:         DevicesDeps{EnrollThrottle: NewEnrollThrottle()},
		},
	}
}

type harnessResponse struct {
	status int
	header http.Header
	raw    []byte
	body   map[string]any
}

func (r harnessResponse) str(key string) string {
	s, _ := r.body[key].(string)
	return s
}

func (r harnessResponse) num(key string) float64 {
	n, _ := r.body[key].(float64)
	return n
}

// call drives the request through Apex.ServeHTTP. A nil body on POST sends
// "{}" like the TS test helper; a string body is sent verbatim.
func (h *deviceHarness) call(method, path string, body any, headers map[string]string) harnessResponse {
	h.t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
		if method != http.MethodGet {
			reader = strings.NewReader("{}")
		}
	case string:
		reader = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, "http://localhost"+path, reader)
	request.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder := httptest.NewRecorder()
	h.a.ServeHTTP(recorder, request)
	out := harnessResponse{status: recorder.Code, header: recorder.Header(), raw: recorder.Body.Bytes()}
	_ = json.Unmarshal(out.raw, &out.body)
	return out
}

func (h *deviceHarness) ssoHeaders(unionID, name string) map[string]string {
	token := auth.MintSession(h.a.Config, auth.SessionUser{UnionID: unionID, Name: name})
	return map[string]string{"Cookie": auth.SessionCookieName + "=" + token, "Origin": deviceTestOrigin}
}

// staleSSOHeaders signs a cookie whose authTime is outside the 600s fresh
// window (MintSession always stamps now).
func (h *deviceHarness) staleSSOHeaders(unionID string) map[string]string {
	token := auth.MintSessionAt(h.a.Config, auth.SessionUser{UnionID: unionID, Name: "Alice"}, time.Now().Add(-700*time.Second))
	return map[string]string{"Cookie": auth.SessionCookieName + "=" + token, "Origin": deviceTestOrigin}
}

func (h *deviceHarness) machineAuth(machineID, unionID, ownerName string) map[string]string {
	token := auth.MintMachineToken(h.a.Config, auth.MachineIdentity{UnionID: unionID, OwnerName: ownerName, MachineID: machineID})
	return map[string]string{"Authorization": "Bearer " + token}
}

func (h *deviceHarness) seedMachine(machineID, unionID, ownerName, name string) {
	h.t.Helper()
	if err := seedMachine(h.repo, store.RegisterMachine{
		MachineID: machineID, UnionID: unionID, OwnerName: ownerName, Name: name,
		BotmuxVersion: "1.0.0", DashboardPort: 8800, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		h.t.Fatal(err)
	}
}

// setMachineOwner rewrites the machine document in place (__setMachineDocMemory).
func (h *deviceHarness) setMachineOwner(machineID, unionID, ownerName string) {
	h.t.Helper()
	if _, err := h.db.Collection("machines").UpdateOne(context.Background(), store.Document{"_id": machineID},
		store.Document{"$set": store.Document{"unionId": unionID, "ownerName": ownerName}}, false); err != nil {
		h.t.Fatal(err)
	}
}

func (h *deviceHarness) device(deviceID string) (store.DeviceDoc, bool) {
	h.t.Helper()
	doc, err := h.repo.GetDevice(context.Background(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return store.DeviceDoc{}, false
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return doc, true
}

func (h *deviceHarness) grant(grantID string) store.DeviceGrantDoc {
	h.t.Helper()
	doc, err := h.repo.GetDeviceGrant(context.Background(), grantID)
	if err != nil {
		h.t.Fatal(err)
	}
	return doc
}

func (h *deviceHarness) createDevice(doc store.DeviceDoc) {
	h.t.Helper()
	if err := h.repo.CreateDevice(context.Background(), doc); err != nil {
		h.t.Fatal(err)
	}
}

// resetDevices drops every device document (__resetDeviceMemoryStores).
func (h *deviceHarness) resetDevices() {
	h.t.Helper()
	if _, err := h.db.Collection("devices").DeleteMany(context.Background(), store.Document{}); err != nil {
		h.t.Fatal(err)
	}
	h.a.DeviceStates.Reset()
}

func expectStatus(t *testing.T, got harnessResponse, status int, errorCode string) {
	t.Helper()
	if got.status != status {
		t.Fatalf("status = %d, want %d (%s)", got.status, status, got.raw)
	}
	if errorCode != "" && got.str("error") != errorCode {
		t.Fatalf("error = %q, want %q (%s)", got.str("error"), errorCode, got.raw)
	}
	if got.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q (%s)", got.header.Get("Cache-Control"), got.raw)
	}
}

// jsonKeys returns the top-level key order of a JSON object (wire order
// matters: the TS object literal order is the contract).
func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := decoder.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	for decoder.More() {
		tok, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := decoder.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func expectKeys(t *testing.T, raw []byte, want ...string) {
	t.Helper()
	if got := jsonKeys(t, raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v (%s)", got, want, raw)
	}
}

func newDeviceRequest(method, path string) *http.Request {
	return httptest.NewRequest(method, "http://localhost"+path, nil)
}

// nopResponseWriter discards everything (for handled/not-handled probes).
type nopResponseWriter struct{}

func (nopResponseWriter) Header() http.Header         { return http.Header{} }
func (nopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopResponseWriter) WriteHeader(int)             {}
