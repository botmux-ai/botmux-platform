package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/auth"
)

// The rest of test/server-machines-bind.test.ts at the handler level: first
// bind and same-owner rebind, a junk code, unbind authorization and RETIRED
// machines on business routes.

func TestBindNewMachineThenSameOwnerRebindIsIdempotent(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	a := bindTestApex(t, repository)
	first := bindRequest(t, a, "u-alice", "")
	var bound struct {
		MachineID    string `json:"machineId"`
		MachineToken string `json:"machineToken"`
		TunnelURL    string `json:"tunnelUrl"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &bound); err != nil || first.Code != http.StatusOK {
		t.Fatalf("bind = %d %s", first.Code, first.Body.String())
	}
	if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(bound.MachineID) || bound.MachineToken == "" || !strings.HasPrefix(bound.TunnelURL, "ws") {
		t.Fatalf("bind body = %s", first.Body.String())
	}
	doc, err := repository.GetMachine(context.Background(), bound.MachineID)
	if err != nil || doc.Retired() {
		t.Fatalf("bound doc = %+v err=%v", doc, err)
	}

	code := auth.IssueBindToken(a.Config, auth.BindIdentity{UnionID: "u-alice", OwnerName: "Alice Chan"})
	body, _ := json.Marshal(map[string]string{"code": code, "machineId": bound.MachineID})
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/bind", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	again := httptest.NewRecorder()
	a.ServeHTTP(again, request)
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"machineId":"`+bound.MachineID+`"`) {
		t.Fatalf("rebind = %d %s", again.Code, again.Body.String())
	}
	if doc, err := repository.GetMachine(context.Background(), bound.MachineID); err != nil || doc.OwnerName != "Alice Chan" {
		t.Fatalf("owner name after rebind = %+v err=%v", doc, err)
	}
}

func TestBindRejectsJunkCode(t *testing.T) {
	t.Parallel()
	a := bindTestApex(t, newMemoryRepository())
	result := serveApex(a, http.MethodPost, "/api/bind", "", "", `{"code":"junk"}`)
	if result.status != http.StatusBadRequest || result.raw != `{"error":"invalid_or_expired"}` {
		t.Fatalf("junk code = %d %s", result.status, result.raw)
	}
}

func TestUnbindRequiresLoginAndOwnership(t *testing.T) {
	t.Parallel()
	repository := machineRouteRepository(t, "owner")
	a := bindTestApex(t, repository)
	path := "/api/machines/" + machineRouteTestID + "/unbind"
	if result := serveApex(a, http.MethodPost, path, "", a.Config.PublicBaseURL, ""); result.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d %s", result.status, result.raw)
	}
	mallory := auth.SessionCookieName + "=" + auth.MintSession(a.Config, auth.SessionUser{UnionID: "u-mallory", Name: "Mallory"})
	if result := serveApex(a, http.MethodPost, path, mallory, a.Config.PublicBaseURL, ""); result.status != http.StatusNotFound || result.raw != `{"error":"machine_not_found"}` {
		t.Fatalf("non-owner = %d %s", result.status, result.raw)
	}
	if doc, err := repository.GetMachine(context.Background(), machineRouteTestID); err != nil || doc.Retired() {
		t.Fatalf("non-owner unbind changed the record: %+v err=%v", doc, err)
	}
}

func TestRetiredMachineIsGoneForBusinessRoutes(t *testing.T) {
	t.Parallel()
	repository := machineRouteRepository(t, "owner")
	if err := repository.RetireMachine(context.Background(), machineRouteTestID); err != nil {
		t.Fatal(err)
	}
	a := bindTestApex(t, repository)
	cookie := auth.SessionCookieName + "=" + auth.MintSession(a.Config, auth.SessionUser{UnionID: "owner", Name: "Owner"})
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/machines/" + machineRouteTestID + "/open", "{}"},
		{http.MethodPost, "/api/machines/" + machineRouteTestID + "/rename", `{"name":"x"}`},
		{http.MethodGet, "/api/machines/" + machineRouteTestID + "/sessions", ""},
		{http.MethodPut, "/api/machines/" + machineRouteTestID + "/bots/cli_x/working-dir-mode", `{"mode":"off"}`},
	} {
		result := serveApex(a, route.method, route.path, cookie, a.Config.PublicBaseURL, route.body)
		if result.status != http.StatusNotFound || result.errorCode() != "machine_not_found" {
			t.Fatalf("%s %s = %d %s", route.method, route.path, result.status, result.raw)
		}
	}
}

func TestRenameMachineTrimsAndTruncates(t *testing.T) {
	t.Parallel()
	repository := machineRouteRepository(t, "owner")
	a := bindTestApex(t, repository)
	cookie := auth.SessionCookieName + "=" + auth.MintSession(a.Config, auth.SessionUser{UnionID: "owner", Name: "Owner"})
	path := "/api/machines/" + machineRouteTestID + "/rename"
	if result := serveApex(a, http.MethodPost, path, cookie, "", `{"name":"　 "}`); result.status != http.StatusBadRequest || result.raw != `{"error":"name_required"}` {
		t.Fatalf("blank = %d %s", result.status, result.raw)
	}
	long := strings.Repeat("机", 70)
	result := serveApex(a, http.MethodPost, path, cookie, "", `{"name":" `+long+` "}`)
	want := `{"ok":true,"name":"` + strings.Repeat("机", 64) + `"}`
	if result.status != http.StatusOK || result.raw != want {
		t.Fatalf("rename = %d %s", result.status, result.raw)
	}
}
