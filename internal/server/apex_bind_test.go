package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Handler-level counterparts of test/server-machines-bind.test.ts: the bind
// CAS runs before a machine token is minted.

func bindRequest(t *testing.T, a *Apex, unionID, machineID string) *httptest.ResponseRecorder {
	t.Helper()
	code := auth.IssueBindToken(a.Config, auth.BindIdentity{UnionID: unionID, OwnerName: unionID + "-name"})
	body, _ := json.Marshal(map[string]string{"code": code, "machineId": machineID})
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/bind", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, request)
	return recorder
}

func bindTestApex(t *testing.T, repository store.Repository) *Apex {
	t.Helper()
	cfg := machineRouteTestConfig()
	cfg.BindCodeTTL = time.Minute
	cfg.MachineTokenTTL = time.Hour
	registry := tunnel.NewRegistry(time.Minute, "pod-a:8080", nil)
	t.Cleanup(func() { _ = registry.Close() })
	return &Apex{Config: cfg, Registry: registry, Repository: repository}
}

func TestBindGivesFreshIDWhenMachineOwnedByAnotherUser(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	a := bindTestApex(t, repository)
	if rec := bindRequest(t, a, "owner", machineRouteTestID); rec.Code != http.StatusOK {
		t.Fatalf("first bind = %d %s", rec.Code, rec.Body.String())
	}
	// Another user presenting the same id (copied ~/.botmux, shared HOME,
	// machine image) is bound as a new machine; the owner's record is kept.
	rec := bindRequest(t, a, "intruder", machineRouteTestID)
	var other struct {
		MachineID    string `json:"machineId"`
		MachineToken string `json:"machineToken"`
		Reassigned   bool   `json:"reassigned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &other); err != nil || rec.Code != http.StatusOK || !other.Reassigned {
		t.Fatalf("conflicting bind = %d %s", rec.Code, rec.Body.String())
	}
	if other.MachineID == machineRouteTestID || !machineIDPattern.MatchString(other.MachineID) {
		t.Fatalf("conflicting bind reused the owned id: %q", other.MachineID)
	}
	claims, err := auth.VerifyMachineToken(a.Config, other.MachineToken)
	if err != nil || claims.MachineID != other.MachineID || claims.UnionID != "intruder" {
		t.Fatalf("token = %+v err = %v", claims, err)
	}
	doc, err := repository.GetMachine(context.Background(), machineRouteTestID)
	if err != nil || doc.UnionID != "owner" {
		t.Fatalf("owner doc = %+v err = %v", doc, err)
	}
	fresh, err := repository.GetMachine(context.Background(), other.MachineID)
	if err != nil || fresh.UnionID != "intruder" {
		t.Fatalf("fresh doc = %+v err = %v", fresh, err)
	}
	// The same owner re-binding (reinstall) keeps the id.
	rec = bindRequest(t, a, "owner", machineRouteTestID)
	var body struct {
		MachineID    string `json:"machineId"`
		MachineToken string `json:"machineToken"`
		Reassigned   bool   `json:"reassigned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body.MachineID != machineRouteTestID || body.MachineToken == "" || body.Reassigned {
		t.Fatalf("rebind = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBindNeverReusesRetiredMachineID(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	ctx := context.Background()
	if _, err := repository.BindMachineCAS(ctx, machineRouteTestID, "owner", "Owner"); err != nil {
		t.Fatal(err)
	}
	if err := repository.RetireMachine(ctx, machineRouteTestID); err != nil {
		t.Fatal(err)
	}
	a := bindTestApex(t, repository)
	rec := bindRequest(t, a, "owner", machineRouteTestID)
	var body struct {
		MachineID    string `json:"machineId"`
		MachineToken string `json:"machineToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("bind = %d %s", rec.Code, rec.Body.String())
	}
	if body.MachineID == machineRouteTestID || !machineIDPattern.MatchString(body.MachineID) {
		t.Fatalf("retired id was reused: %q", body.MachineID)
	}
	claims, err := auth.VerifyMachineToken(a.Config, body.MachineToken)
	if err != nil || claims.MachineID != body.MachineID {
		t.Fatalf("machine token = %+v err = %v", claims, err)
	}
	fresh, err := repository.GetMachine(ctx, body.MachineID)
	if err != nil || fresh.Retired() || fresh.UnionID != "owner" {
		t.Fatalf("fresh doc = %+v err = %v", fresh, err)
	}
	if old, _ := repository.GetMachine(ctx, machineRouteTestID); !old.Retired() {
		t.Fatalf("tombstone revived: %+v", old)
	}
}

type unavailableBindRepository struct{ store.Repository }

func (unavailableBindRepository) BindMachineCAS(context.Context, string, string, string) (store.BindResult, error) {
	return "", store.ErrUnavailable
}

func TestBindFailsClosedWhenStoreUnavailable(t *testing.T) {
	t.Parallel()
	a := bindTestApex(t, unavailableBindRepository{Repository: newMemoryRepository()})
	rec := bindRequest(t, a, "owner", machineRouteTestID)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != `{"error":"store_unavailable"}` {
		t.Fatalf("bind = %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnbindRetiresAndIsIdempotent(t *testing.T) {
	t.Parallel()
	repository := machineRouteRepository(t, "owner")
	a := bindTestApex(t, repository)
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		a.ServeHTTP(recorder, machineRouteRequest(a.Config, http.MethodPost, "/api/machines/"+machineRouteTestID+"/unbind", ""))
		if recorder.Code != http.StatusOK || recorder.Body.String() != `{"ok":true}` {
			t.Fatalf("unbind #%d = %d %s", i+1, recorder.Code, recorder.Body.String())
		}
		doc, err := repository.GetMachine(context.Background(), machineRouteTestID)
		if err != nil || !doc.Retired() {
			t.Fatalf("unbind #%d doc = %+v err = %v", i+1, doc, err)
		}
	}
	machines, err := repository.ListMachinesForUser(context.Background(), "owner")
	if err != nil || len(machines) != 0 {
		t.Fatalf("retired machine still listed: %+v err = %v", machines, err)
	}
}
