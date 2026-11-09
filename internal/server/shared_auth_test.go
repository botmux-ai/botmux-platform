package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

func machineAuthRequest(t *testing.T, a *Apex, token string) (*MachineAuth, *httptest.ResponseRecorder) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/v1/machine/teams", nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	got, ok := a.RequireMachineAuth(recorder, request)
	if ok != (got != nil) {
		t.Fatalf("ok=%v but auth=%v", ok, got)
	}
	return got, recorder
}

func assertJSONError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status || !strings.Contains(recorder.Body.String(), `"error":"`+code+`"`) {
		t.Fatalf("got %d %s, want %d %s", recorder.Code, recorder.Body.String(), status, code)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
}

func TestRequireMachineAuth(t *testing.T) {
	repository := newMemoryRepository()
	cfg := machineRouteTestConfig()
	cfg.MachineTokenTTL = time.Hour
	a := &Apex{Config: cfg, Repository: repository}
	ctx := context.Background()
	if _, err := repository.BindMachineCAS(ctx, "a1a1a1a1a1a1a1a1", "u-alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	mint := func(machineID, unionID string, at time.Time) string {
		return auth.MintMachineTokenAt(a.Config, auth.MachineIdentity{UnionID: unionID, OwnerName: "Alice", MachineID: machineID}, at)
	}

	_, recorder := machineAuthRequest(t, a, "")
	assertJSONError(t, recorder, http.StatusUnauthorized, "invalid_machine_token")
	_, recorder = machineAuthRequest(t, a, "not-a-token")
	assertJSONError(t, recorder, http.StatusUnauthorized, "invalid_machine_token")

	got, recorder := machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-alice", time.Now()))
	if got == nil || got.UnionID != "u-alice" || got.Name != "Alice" || got.MachineID != "a1a1a1a1a1a1a1a1" {
		t.Fatalf("auth = %+v (%d %s)", got, recorder.Code, recorder.Body.String())
	}

	// Signed for a user who no longer owns the machine / a machine never bound.
	_, recorder = machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-bob", time.Now()))
	assertJSONError(t, recorder, http.StatusForbidden, "machine_ownership_mismatch")
	_, recorder = machineAuthRequest(t, a, mint("b2b2b2b2b2b2b2b2", "u-alice", time.Now()))
	assertJSONError(t, recorder, http.StatusForbidden, "machine_ownership_mismatch")

	// Revocation cutoff: tokens issued before the cutoff are rejected first.
	a.KV = store.NewKVStore(store.NewMemoryKV(), "t", time.Minute, time.Minute)
	if err := a.KV.RevokeMachineToken(ctx, "a1a1a1a1a1a1a1a1", time.Now().UnixMilli(), time.Hour); err != nil {
		t.Fatal(err)
	}
	_, recorder = machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-alice", time.Now().Add(-time.Minute)))
	assertJSONError(t, recorder, http.StatusUnauthorized, "machine_revoked")
	a.KV = nil

	// A RETIRED tombstone is no longer an owned machine.
	if err := repository.RetireMachine(ctx, "a1a1a1a1a1a1a1a1"); err != nil {
		t.Fatal(err)
	}
	_, recorder = machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-alice", time.Now()))
	assertJSONError(t, recorder, http.StatusForbidden, "machine_ownership_mismatch")

	// Store degraded: fail closed, never treat as owned.
	a.Repository = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	_, recorder = machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-alice", time.Now()))
	assertJSONError(t, recorder, http.StatusServiceUnavailable, "store_unavailable")
	a.Repository = nil
	_, recorder = machineAuthRequest(t, a, mint("a1a1a1a1a1a1a1a1", "u-alice", time.Now()))
	assertJSONError(t, recorder, http.StatusServiceUnavailable, "store_unavailable")
}

func TestRequireActiveDesktopAccess(t *testing.T) {
	repository := newMemoryRepository()
	a := &Apex{Config: machineRouteTestConfig(), DesktopSessions: repository}
	session := auth.MintDesktopSession(a.Config, auth.DesktopSessionInput{UnionID: "u-alice", Name: "Alice", LocalProfileID: "profile-1"})
	check := func(authorization string) (*auth.DesktopAccessPayload, *httptest.ResponseRecorder) {
		request := httptest.NewRequest(http.MethodGet, "http://localhost/v1/desktop/machines", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		got, ok := a.RequireActiveDesktopAccess(recorder, request)
		if ok != (got != nil) {
			t.Fatalf("ok=%v but access=%v", ok, got)
		}
		return got, recorder
	}

	_, recorder := check("")
	assertJSONError(t, recorder, http.StatusUnauthorized, "unauthenticated")
	_, recorder = check("Bearer " + session.RefreshToken)
	assertJSONError(t, recorder, http.StatusUnauthorized, "unauthenticated")

	access, recorder := check("Bearer " + session.AccessToken)
	if access == nil || access.SID == "" {
		t.Fatalf("access = %+v (%d %s)", access, recorder.Code, recorder.Body.String())
	}

	if err := repository.RevokeDesktopSessionFamily(context.Background(), access.SID, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	_, recorder = check("Bearer " + session.AccessToken)
	assertJSONError(t, recorder, http.StatusUnauthorized, "session_revoked")

	a.DesktopSessions = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	_, recorder = check("Bearer " + session.AccessToken)
	assertJSONError(t, recorder, http.StatusServiceUnavailable, "store_unavailable")
	a.DesktopSessions = nil
	_, recorder = check("Bearer " + session.AccessToken)
	assertJSONError(t, recorder, http.StatusServiceUnavailable, "store_unavailable")
}
