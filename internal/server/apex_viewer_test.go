package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Read-only viewer role on the co-manager grant API, the machine list and
// the OpenAPI.

type viewerEntry struct {
	UnionID   string   `json:"unionId"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	GrantedAt int64    `json:"grantedAt"`
	ViaTeamID string   `json:"viaTeamId"`
}

func viewerEntries(t *testing.T, raw string) map[string]viewerEntry {
	t.Helper()
	var body struct {
		CoManagers []viewerEntry `json:"coManagers"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	out := map[string]viewerEntry{}
	for _, entry := range body.CoManagers {
		out[entry.UnionID] = entry
	}
	return out
}

func TestGrantViewerRole(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmMate2+`"],"canManage":true,"roles":{"`+cmMate+`":"viewer"}}`)
	if r.status != http.StatusOK {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
	got := viewerEntries(t, r.raw)
	// canManage never leaks into a viewer grant.
	if v := got[cmMate]; v.Role != "viewer" || !slices.Equal(v.Scopes, auth.ViewerScopes()) || v.ViaTeamID != cmTeam {
		t.Fatalf("viewer = %+v", v)
	}
	// Unlisted newcomer: today's co-manager grant, legacy (empty) role.
	if c := got[cmMate2]; c.Role != "" || !containsString(c.Scopes, store.DeviceScopeTerminalControl) || !containsString(c.Scopes, store.DeviceScopeDashboardManage) {
		t.Fatalf("co-manager = %+v", c)
	}
	persisted := f.coManagers(t, cmMachine)
	if len(persisted) != 2 || persisted[0].Role != store.CoManagerRoleViewer || persisted[1].Role != "" {
		t.Fatalf("persisted = %+v", persisted)
	}
}

func TestSwitchRoleBothWaysKeepsGrantOrigin(t *testing.T) {
	f := newCoManagerFixture(t)
	manage := defaultCoManager(cmMate, 1000, cmTeam)
	manage.Scopes = auth.ComanagerGrantableScopes()
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{manage, defaultCoManager(cmMate2, 2000, cmTeam)})

	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmMate2+`"],"roles":{"`+cmMate+`":"viewer"}}`)
	got := viewerEntries(t, r.raw)
	if r.status != http.StatusOK || got[cmMate].Role != "viewer" || !slices.Equal(got[cmMate].Scopes, auth.ViewerScopes()) || got[cmMate].GrantedAt != 1000 {
		t.Fatalf("demote = %d %s", r.status, r.raw)
	}
	// The other, unlisted co-manager is untouched.
	if got[cmMate2].Role != "" || !slices.Equal(got[cmMate2].Scopes, auth.ComanagerDefaultScopes()) || got[cmMate2].GrantedAt != 2000 {
		t.Fatalf("bystander = %+v", got[cmMate2])
	}

	r = f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmMate2+`"],"roles":{"`+cmMate+`":"co-manager"}}`)
	got = viewerEntries(t, r.raw)
	// Promoted back to the default grant (no silent dashboard:manage).
	if got[cmMate].Role != "" || !slices.Equal(got[cmMate].Scopes, auth.ComanagerDefaultScopes()) || got[cmMate].GrantedAt != 1000 {
		t.Fatalf("promote = %s", r.raw)
	}
	// Listing a co-manager as co-manager is a no-op, not a scope reset.
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{manage})
	r = f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`"],"roles":{"`+cmMate+`":"co-manager"}}`)
	if got := viewerEntries(t, r.raw)[cmMate]; !slices.Equal(got.Scopes, auth.ComanagerGrantableScopes()) {
		t.Fatalf("same-role no-op = %s", r.raw)
	}
}

func TestOldClientsKeepExistingRoles(t *testing.T) {
	f := newCoManagerFixture(t)
	viewer := store.MachineCoManager{UnionID: cmMate, Name: cmMate, Role: store.CoManagerRoleViewer, Scopes: auth.ViewerScopes(), GrantedAt: 1, GrantedBy: cmOwner}
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{viewer})
	// A client that predates roles adds someone with canManage: the viewer
	// must not be turned into a co-manager or gain dashboard:manage.
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmMate2+`"],"canManage":true}`)
	got := viewerEntries(t, r.raw)
	if r.status != http.StatusOK || got[cmMate].Role != "viewer" || !slices.Equal(got[cmMate].Scopes, auth.ViewerScopes()) {
		t.Fatalf("old client = %d %s", r.status, r.raw)
	}
	if got[cmMate2].Role != "" || !containsString(got[cmMate2].Scopes, store.DeviceScopeDashboardManage) {
		t.Fatalf("old client newcomer = %+v", got[cmMate2])
	}
}

func TestInvalidRolesRejectWholeRequest(t *testing.T) {
	f := newCoManagerFixture(t)
	for _, body := range []string{
		`{"unionIds":["` + cmMate + `"],"roles":{"` + cmMate + `":"admin"}}`,
		`{"unionIds":["` + cmMate + `"],"roles":{"` + cmMate + `":"owner"}}`,
		`{"unionIds":["` + cmMate + `"],"roles":{"` + cmMate + `":""}}`,
		`{"unionIds":["` + cmMate + `"],"roles":{"` + cmMate + `":1}}`,
		`{"unionIds":["` + cmMate + `"],"roles":["viewer"]}`,
		`{"unionIds":["` + cmMate + `"],"roles":"viewer"}`,
	} {
		if r := f.call(http.MethodPut, cmPath, cmOwner, body); r.status != http.StatusBadRequest || r.body.Error != "invalid_roles" {
			t.Fatalf("%s = %d %s", body, r.status, r.raw)
		}
	}
	if got := f.coManagers(t, cmMachine); len(got) != 0 {
		t.Fatalf("partial write: %+v", got)
	}
	// Role changes stay owner-only and strict like every other grant write.
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, cmTeam)})
	if r := f.call(http.MethodPut, cmPath, cmMate, `{"unionIds":["`+cmMate+`"],"roles":{"`+cmMate+`":"co-manager"}}`); r.status != http.StatusForbidden {
		t.Fatalf("co-manager self-edit = %d %s", r.status, r.raw)
	}
	stale := agedCookie(t, f.cfg, 601)
	result := serveApex(f.apex, http.MethodPut, cmPath, stale, "http://localhost", `{"unionIds":["`+cmMate+`"],"roles":{"`+cmMate+`":"viewer"}}`)
	if result.status != http.StatusUnauthorized || result.errorCode() != "stale_session" {
		t.Fatalf("stale role change = %d %s", result.status, result.raw)
	}
}

func TestViewerSeesOwnEntryAndCanLeave(t *testing.T) {
	f := newCoManagerFixture(t)
	viewer := store.MachineCoManager{UnionID: cmMate, Name: cmMate, Role: store.CoManagerRoleViewer, Scopes: auth.ViewerScopes(), GrantedAt: 1, GrantedBy: cmOwner}
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{viewer, defaultCoManager(cmMate2, 1, cmTeam)})
	r := f.call(http.MethodGet, cmPath, cmMate, "")
	if got := viewerEntries(t, r.raw); r.status != http.StatusOK || len(got) != 1 || got[cmMate].Role != "viewer" {
		t.Fatalf("viewer GET = %d %s", r.status, r.raw)
	}
	if r := f.call(http.MethodDelete, cmPath+"/"+cmMate2, cmMate, ""); r.status != http.StatusForbidden {
		t.Fatalf("viewer removes someone else = %d", r.status)
	}
	if r := f.call(http.MethodDelete, cmPath+"/"+cmMate, cmMate, ""); r.status != http.StatusOK {
		t.Fatalf("viewer leaves = %d %s", r.status, r.raw)
	}
	if got := f.coManagers(t, cmMachine); len(got) != 1 || got[0].UnionID != cmMate2 {
		t.Fatalf("after leave = %+v", got)
	}
}

func TestManagedMachinesCarryRole(t *testing.T) {
	f := newCoManagerFixture(t)
	viewer := store.MachineCoManager{UnionID: cmMate, Name: cmMate, Role: store.CoManagerRoleViewer, Scopes: auth.ComanagerGrantableScopes(), GrantedAt: 1, GrantedBy: cmOwner}
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{viewer, defaultCoManager(cmMate2, 1, cmTeam)})
	for unionID, want := range map[string]struct {
		role   string
		scopes []string
	}{
		cmMate:  {"viewer", auth.ViewerScopes()},
		cmMate2: {"co-manager", auth.ComanagerDefaultScopes()},
	} {
		result := serveApex(f.apex, http.MethodGet, "/api/machines", f.fresh(unionID), "http://localhost", "")
		var body struct {
			Managed []struct {
				MachineID string   `json:"machineId"`
				MyRole    string   `json:"myRole"`
				MyScopes  []string `json:"myScopes"`
			} `json:"managedMachines"`
		}
		if err := json.Unmarshal([]byte(result.raw), &body); err != nil || result.status != http.StatusOK || len(body.Managed) != 1 {
			t.Fatalf("%s list = %d %s", unionID, result.status, result.raw)
		}
		if got := body.Managed[0]; got.MyRole != want.role || !slices.Equal(got.MyScopes, want.scopes) {
			t.Fatalf("%s managed = %+v", unionID, got)
		}
	}
}

func TestOpenAPIExcludesViewers(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.seedBobCoManagedByAlice(auth.ComanagerDefaultScopes())
	if err := h.repository.SetMachineCoManagers(context.Background(), openAPIMIDBob, "u-bob", []store.MachineCoManager{
		{UnionID: "u-alice", Name: "Alice", Role: store.CoManagerRoleViewer, Scopes: auth.ComanagerGrantableScopes(), GrantedAt: time.Now().UnixMilli(), GrantedBy: "u-bob"},
	}); err != nil {
		t.Fatal(err)
	}
	if ids := machineIDs(h.call(http.MethodGet, "/openapi/machines", "")); !slices.Equal(ids, []string{openAPIMIDAlice}) {
		t.Fatalf("ids = %v", ids)
	}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDBob+"/proxy/api/sessions", ""), http.StatusForbidden, "machine_not_owned")
	expectOpenAPIError(t, h.call(http.MethodPost, "/openapi/machines/"+openAPIMIDBob+"/proxy/api/sessions", `{}`), http.StatusForbidden, "machine_not_owned")
	if len(h.proxyCalls()) != 0 {
		t.Fatal("daemon called for a viewer")
	}
}

func TestViewerCanOpenMachine(t *testing.T) {
	f := newCoManagerFixture(t)
	viewer := store.MachineCoManager{UnionID: cmMate, Name: cmMate, Role: store.CoManagerRoleViewer, Scopes: auth.ViewerScopes(), GrantedAt: 1, GrantedBy: cmOwner}
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{viewer})
	result := serveApex(f.apex, http.MethodGet, "/open/"+cmMachine+"?next=%2F", f.fresh(cmMate), "http://localhost", "")
	if result.status != http.StatusFound {
		t.Fatalf("viewer open = %d %s", result.status, result.raw)
	}
	// An outsider still cannot.
	if result := serveApex(f.apex, http.MethodGet, "/open/"+cmMachine+"?next=%2F", f.fresh(cmOutsider), "http://localhost", ""); result.status != http.StatusForbidden {
		t.Fatalf("outsider open = %d", result.status)
	}
}
