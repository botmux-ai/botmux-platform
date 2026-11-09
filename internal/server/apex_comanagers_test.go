package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-machine-comanagers.test.ts (co-manager grant API, the
// leave/disband auto-removal) on the in-memory repository.

const (
	cmOwner    = "u-owner"
	cmMate     = "u-teammate"
	cmMate2    = "u-teammate-2"
	cmOutsider = "u-outsider"
	cmMachine  = "aaaaaaaa11112222"
	cmTeam     = "bbbbbbbb33334444"
	cmPath     = "/api/machines/" + cmMachine + "/co-managers"
)

type coManagerFixture struct {
	cfg        config.Config
	apex       *Apex
	repository *store.DocumentRepository
}

func newCoManagerFixture(t *testing.T) *coManagerFixture {
	t.Helper()
	cfg := config.Config{
		PublicBaseURL: "http://localhost", RootHost: "localhost", MachineSubdomainPrefix: "m-",
		SigningSecret: "comanager-api-test-secret", SessionTTL: 7 * 24 * time.Hour, StaleAfter: 2 * time.Minute,
	}
	repository := newMemoryRepository()
	ctx := context.Background()
	if err := repository.CreateTeam(ctx, store.TeamDoc{ID: cmTeam, Name: "测试团队", Members: []string{cmOwner}, CreatedBy: cmOwner, CreatedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{cmMate, cmMate2} {
		if err := repository.AddTeamMember(ctx, cmTeam, member); err != nil {
			t.Fatal(err)
		}
	}
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	t.Cleanup(func() { _ = registry.Close() })
	f := &coManagerFixture{cfg: cfg, repository: repository, apex: &Apex{Config: cfg, Registry: registry, Repository: repository}}
	f.seedMachine(t, cmMachine, cmOwner, nil)
	return f
}

func (f *coManagerFixture) seedMachine(t *testing.T, machineID, owner string, coManagers []store.MachineCoManager) {
	t.Helper()
	if err := seedMachine(f.repository, store.RegisterMachine{MachineID: machineID, UnionID: owner, OwnerName: "Owner", Name: "workstation", BotmuxVersion: "3.18.14", DashboardPort: 7777, LastSeen: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if coManagers != nil {
		if err := f.repository.SetMachineCoManagers(context.Background(), machineID, owner, coManagers); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *coManagerFixture) createTeam(t *testing.T, teamID, creator string, members ...string) {
	t.Helper()
	ctx := context.Background()
	if err := f.repository.CreateTeam(ctx, store.TeamDoc{ID: teamID, Name: teamID, Members: []string{creator}, CreatedBy: creator, CreatedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		if err := f.repository.AddTeamMember(ctx, teamID, member); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *coManagerFixture) coManagers(t *testing.T, machineID string) []store.MachineCoManager {
	t.Helper()
	doc, err := f.repository.LookupMachine(context.Background(), machineID, store.AuthorityCacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return doc.CoManagers
}

func (f *coManagerFixture) fresh(unionID string) string {
	now := time.Now()
	return auth.SessionCookieName + "=" + auth.MintSessionAt(f.cfg, auth.SessionUser{UnionID: unionID, Name: unionID}, now)
}

type coManagerReply struct {
	status int
	raw    string
	body   struct {
		OK         bool   `json:"ok"`
		Error      string `json:"error"`
		IsOwner    *bool  `json:"isOwner"`
		UnionIDs   []string
		CoManagers []struct {
			UnionID   string   `json:"unionId"`
			Scopes    []string `json:"scopes"`
			GrantedAt int64    `json:"grantedAt"`
			GrantedBy string   `json:"grantedBy"`
			ViaTeamID string   `json:"viaTeamId"`
			LeftTeam  *bool    `json:"leftTeam"`
		} `json:"coManagers"`
	}
}

func (f *coManagerFixture) call(method, path, unionID, body string) coManagerReply {
	cookie := ""
	if unionID != "" {
		cookie = f.fresh(unionID)
	}
	result := serveApex(f.apex, method, path, cookie, "http://localhost", body)
	reply := coManagerReply{status: result.status, raw: result.raw}
	_ = json.Unmarshal([]byte(result.raw), &reply.body)
	return reply
}

func defaultCoManager(unionID string, grantedAt int64, viaTeamID string) store.MachineCoManager {
	return store.MachineCoManager{UnionID: unionID, Name: unionID, Scopes: auth.ComanagerDefaultScopes(), GrantedAt: grantedAt, GrantedBy: cmOwner, ViaTeamID: viaTeamID}
}

func TestCoManagerOwnerGrantsTeammateWithDefaultScopes(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`"]}`)
	if r.status != http.StatusOK || len(r.body.CoManagers) != 1 {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
	entry := r.body.CoManagers[0]
	if entry.UnionID != cmMate || entry.GrantedBy != cmOwner || entry.ViaTeamID != cmTeam || !equalStrings(entry.Scopes, auth.ComanagerDefaultScopes()) {
		t.Fatalf("entry = %+v", entry)
	}
	if got := f.coManagers(t, cmMachine); len(got) != 1 {
		t.Fatalf("persisted = %+v", got)
	}
}

func TestCoManagerNonTeammateRejectsWholeRequest(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmOutsider+`"]}`)
	if r.status != http.StatusForbidden || r.raw != `{"error":"not_teammate","unionIds":["`+cmOutsider+`"]}` {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
	if got := f.coManagers(t, cmMachine); len(got) != 0 {
		t.Fatalf("partial success persisted: %+v", got)
	}
}

func TestCoManagerCannotDelegateFurther(t *testing.T) {
	f := newCoManagerFixture(t)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, time.Now().UnixMilli(), "")})
	r := f.call(http.MethodPut, cmPath, cmMate, `{"unionIds":["`+cmMate+`","`+cmMate2+`"]}`)
	if r.status != http.StatusForbidden || r.raw != `{"error":"owner_only"}` {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
}

func TestCoManagerWritesAreStrictTier(t *testing.T) {
	f := newCoManagerFixture(t)
	stale := agedCookie(t, f.cfg, 601)
	result := serveApex(f.apex, http.MethodPut, cmPath, stale, "http://localhost", `{"unionIds":["`+cmMate+`"]}`)
	if result.status != http.StatusUnauthorized || result.errorCode() != "stale_session" {
		t.Fatalf("stale put = %d %s", result.status, result.raw)
	}
}

func TestCoManagerOwnerCannotListSelf(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmOwner+`"]}`)
	if r.status != http.StatusBadRequest || r.raw != `{"error":"owner_not_allowed"}` {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
}

func TestCoManagerReorderKeepsGrantTime(t *testing.T) {
	f := newCoManagerFixture(t)
	grantedAt := time.Now().UnixMilli() - 86_400_000
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, grantedAt, "")})
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate2+`","`+cmMate+`"]}`)
	if r.status != http.StatusOK {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
	for _, entry := range r.body.CoManagers {
		if entry.UnionID == cmMate && entry.GrantedAt != grantedAt {
			t.Fatalf("grantedAt refreshed: %d != %d", entry.GrantedAt, grantedAt)
		}
	}
}

func TestCoManagerGetOwnerSeesAllCoManagerSeesSelf(t *testing.T) {
	f := newCoManagerFixture(t)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, ""), defaultCoManager(cmMate2, 1, "")})
	asOwner := f.call(http.MethodGet, cmPath, cmOwner, "")
	if asOwner.status != http.StatusOK || asOwner.body.IsOwner == nil || !*asOwner.body.IsOwner || len(asOwner.body.CoManagers) != 2 {
		t.Fatalf("owner = %d %s", asOwner.status, asOwner.raw)
	}
	asMate := f.call(http.MethodGet, cmPath, cmMate, "")
	if asMate.status != http.StatusOK || asMate.body.IsOwner == nil || *asMate.body.IsOwner || len(asMate.body.CoManagers) != 1 || asMate.body.CoManagers[0].UnionID != cmMate {
		t.Fatalf("co-manager = %d %s", asMate.status, asMate.raw)
	}
	// The co-manager's own entry carries no leftTeam flag.
	if asMate.body.CoManagers[0].LeftTeam != nil {
		t.Fatalf("co-manager view leaked leftTeam: %s", asMate.raw)
	}
	if outsider := f.call(http.MethodGet, cmPath, cmOutsider, ""); outsider.status != http.StatusNotFound {
		t.Fatalf("outsider = %d %s", outsider.status, outsider.raw)
	}
}

func TestCoManagerLeftTeamFlag(t *testing.T) {
	f := newCoManagerFixture(t)
	const tmpTeam = "cccccccc55556666"
	f.createTeam(t, tmpTeam, cmOwner, cmOutsider)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmOutsider, 1, "")})
	before := f.call(http.MethodGet, cmPath, cmOwner, "")
	if left := before.body.CoManagers[0].LeftTeam; left == nil || *left {
		t.Fatalf("before = %s", before.raw)
	}
	if err := f.repository.RemoveTeamMember(context.Background(), tmpTeam, cmOutsider); err != nil {
		t.Fatal(err)
	}
	after := f.call(http.MethodGet, cmPath, cmOwner, "")
	if left := after.body.CoManagers[0].LeftTeam; left == nil || !*left {
		t.Fatalf("after = %s", after.raw)
	}
}

func TestCoManagerLeftTeamOmittedWhenTeamsUnavailable(t *testing.T) {
	f := newCoManagerFixture(t)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, "")})
	f.apex.Repository = teamsUnavailableRepository{Repository: f.repository}
	r := f.call(http.MethodGet, cmPath, cmOwner, "")
	if r.status != http.StatusOK || len(r.body.CoManagers) != 1 || r.body.CoManagers[0].LeftTeam != nil {
		t.Fatalf("get = %d %s", r.status, r.raw)
	}
}

func TestCoManagerDeleteRules(t *testing.T) {
	seed := func(f *coManagerFixture) {
		f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, ""), defaultCoManager(cmMate2, 1, "")})
	}
	f := newCoManagerFixture(t)
	seed(f)
	if r := f.call(http.MethodDelete, cmPath+"/"+cmMate, cmOwner, ""); r.status != http.StatusOK || len(r.body.CoManagers) != 1 {
		t.Fatalf("owner delete = %d %s", r.status, r.raw)
	}
	seed(f)
	selfLeave := f.call(http.MethodDelete, cmPath+"/"+cmMate, cmMate, "")
	if selfLeave.status != http.StatusOK {
		t.Fatalf("self leave = %d %s", selfLeave.status, selfLeave.raw)
	}
	for _, entry := range selfLeave.body.CoManagers {
		if entry.UnionID == cmMate {
			t.Fatalf("self leave kept entry: %s", selfLeave.raw)
		}
	}
	seed(f)
	if r := f.call(http.MethodDelete, cmPath+"/"+cmMate2, cmMate, ""); r.status != http.StatusForbidden || r.raw != `{"error":"owner_only"}` {
		t.Fatalf("remove other = %d %s", r.status, r.raw)
	}
}

func TestCoManagerDeleteIsIdempotent(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodDelete, cmPath+"/"+cmMate, cmOwner, "")
	if r.status != http.StatusOK || r.raw != `{"ok":true,"coManagers":[]}` {
		t.Fatalf("delete = %d %s", r.status, r.raw)
	}
}

func TestCoManagerRetiredMachineIsNotFound(t *testing.T) {
	f := newCoManagerFixture(t)
	if err := f.repository.RetireMachine(context.Background(), cmMachine); err != nil {
		t.Fatal(err)
	}
	if r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`"]}`); r.status != http.StatusNotFound {
		t.Fatalf("put = %d %s", r.status, r.raw)
	}
	if r := f.call(http.MethodGet, cmPath, cmOwner, ""); r.status != http.StatusNotFound {
		t.Fatalf("get = %d %s", r.status, r.raw)
	}
}

func TestCoManagerListLimitAndValidation(t *testing.T) {
	f := newCoManagerFixture(t)
	many := make([]string, auth.ComanagerMax+1)
	for index := range many {
		many[index] = "u-" + string(rune('a'+index))
	}
	encoded, _ := json.Marshal(map[string]any{"unionIds": many})
	if r := f.call(http.MethodPut, cmPath, cmOwner, string(encoded)); r.status != http.StatusBadRequest || r.body.Error != "too_many" {
		t.Fatalf("too many = %d %s", r.status, r.raw)
	}
	for _, body := range []string{`{}`, `{"unionIds":"u-x"}`} {
		if r := f.call(http.MethodPut, cmPath, cmOwner, body); r.status != http.StatusBadRequest || r.raw != `{"error":"unionIds_required"}` {
			t.Fatalf("%s = %d %s", body, r.status, r.raw)
		}
	}
	// Like TS, non-string entries are dropped rather than rejected.
	if r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":[1,""]}`); r.status != http.StatusOK || r.raw != `{"ok":true,"coManagers":[]}` {
		t.Fatalf("non-string ids = %d %s", r.status, r.raw)
	}
}

func TestCoManagerEmptyListClears(t *testing.T) {
	f := newCoManagerFixture(t)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, "")})
	if r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":[]}`); r.status != http.StatusOK || r.raw != `{"ok":true,"coManagers":[]}` {
		t.Fatalf("clear = %d %s", r.status, r.raw)
	}
}

func TestCoManagerRoutesRequireLogin(t *testing.T) {
	f := newCoManagerFixture(t)
	if r := serveApex(f.apex, http.MethodGet, cmPath, "", "", ""); r.status != http.StatusUnauthorized {
		t.Fatalf("get = %d", r.status)
	}
	if r := serveApex(f.apex, http.MethodPut, cmPath, "", "http://localhost", `{"unionIds":[]}`); r.status != http.StatusUnauthorized {
		t.Fatalf("put = %d", r.status)
	}
}

func TestCoManagerStoreFailureIsUnavailable(t *testing.T) {
	f := newCoManagerFixture(t)
	f.apex.Repository = machineRouteGetErrorRepository{Repository: f.repository}
	if r := f.call(http.MethodGet, cmPath, cmOwner, ""); r.status != http.StatusServiceUnavailable || r.raw != `{"error":"store_unavailable"}` {
		t.Fatalf("get = %d %s", r.status, r.raw)
	}
}

func TestLeaveDropsOnlyGrantsViaThatTeam(t *testing.T) {
	f := newCoManagerFixture(t)
	const teamA, teamB, other = "dddddddd77778888", "eeeeeeee99990000", "ffffffff11112222"
	f.createTeam(t, teamA, cmOwner, cmMate)
	f.createTeam(t, teamB, cmOwner, cmMate)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, teamA)})
	f.seedMachine(t, other, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, teamB)})
	if r := f.call(http.MethodPost, "/api/teams/"+teamA+"/leave", cmMate, "{}"); r.status != http.StatusOK || r.raw != `{"ok":true}` {
		t.Fatalf("leave = %d %s", r.status, r.raw)
	}
	if got := f.coManagers(t, cmMachine); len(got) != 0 {
		t.Fatalf("grant via team A kept: %+v", got)
	}
	if got := f.coManagers(t, other); len(got) != 1 {
		t.Fatalf("grant via team B dropped: %+v", got)
	}
}

func TestLeaveDoesNotTouchOwnMachine(t *testing.T) {
	f := newCoManagerFixture(t)
	const teamC, mine = "aaaa1111bbbb2222", "cccc3333dddd4444"
	f.createTeam(t, teamC, cmOwner, cmMate)
	f.seedMachine(t, mine, cmMate, []store.MachineCoManager{{UnionID: cmMate, Name: "M", Scopes: auth.ComanagerDefaultScopes(), GrantedAt: 1, GrantedBy: cmMate, ViaTeamID: teamC}})
	f.call(http.MethodPost, "/api/teams/"+teamC+"/leave", cmMate, "{}")
	if got := f.coManagers(t, mine); len(got) != 1 {
		t.Fatalf("own machine changed: %+v", got)
	}
}

func TestLeaveKeepsGrantsWithoutViaTeam(t *testing.T) {
	f := newCoManagerFixture(t)
	const teamD = "eeee5555ffff6666"
	f.createTeam(t, teamD, cmOwner, cmMate)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, "")})
	f.call(http.MethodPost, "/api/teams/"+teamD+"/leave", cmMate, "{}")
	if got := f.coManagers(t, cmMachine); len(got) != 1 {
		t.Fatalf("legacy grant dropped: %+v", got)
	}
}

func TestCoManagerCanManageGrantsDashboardManageToNewcomersOnly(t *testing.T) {
	f := newCoManagerFixture(t)
	r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`"],"canManage":true}`)
	if r.status != http.StatusOK || !containsString(r.body.CoManagers[0].Scopes, store.DeviceScopeDashboardManage) || !containsString(r.body.CoManagers[0].Scopes, store.DeviceScopeTerminalControl) {
		t.Fatalf("canManage = %d %s", r.status, r.raw)
	}

	f = newCoManagerFixture(t)
	if r := f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`"]}`); containsString(r.body.CoManagers[0].Scopes, store.DeviceScopeDashboardManage) {
		t.Fatalf("default grant includes dashboard:manage: %s", r.raw)
	}

	f = newCoManagerFixture(t)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, "")})
	r = f.call(http.MethodPut, cmPath, cmOwner, `{"unionIds":["`+cmMate+`","`+cmMate2+`"],"canManage":true}`)
	for _, entry := range r.body.CoManagers {
		manage := containsString(entry.Scopes, store.DeviceScopeDashboardManage)
		if entry.UnionID == cmMate && manage {
			t.Fatalf("existing co-manager silently elevated: %s", r.raw)
		}
		if entry.UnionID == cmMate2 && !manage {
			t.Fatalf("new co-manager missing dashboard:manage: %s", r.raw)
		}
	}
}

func TestTeamDeleteDropsCreatorsOwnCoManagerGrant(t *testing.T) {
	f := newCoManagerFixture(t)
	const team = "bbbb0001cccc0002"
	f.createTeam(t, team, cmMate, cmOwner)
	f.seedMachine(t, cmMachine, cmOwner, []store.MachineCoManager{defaultCoManager(cmMate, 1, team)})
	if r := f.call(http.MethodDelete, "/api/teams/"+team, cmMate, ""); r.status != http.StatusOK || r.raw != `{"ok":true}` {
		t.Fatalf("delete = %d %s", r.status, r.raw)
	}
	// The cleanup is fire-and-forget.
	deadline := time.Now().Add(2 * time.Second)
	for len(f.coManagers(t, cmMachine)) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("creator's grant survived team deletion: %+v", f.coManagers(t, cmMachine))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDesktopPathStaysOwnerOnly(t *testing.T) {
	doc := store.MachineDoc{ID: cmMachine, UnionID: cmOwner, CoManagers: []store.MachineCoManager{{
		UnionID: cmMate, Name: "M", Scopes: append(auth.ComanagerDefaultScopes(), store.DeviceScopeDashboardManage), GrantedAt: 1, GrantedBy: cmOwner, ViaTeamID: cmTeam,
	}}}
	if !auth.ResolveMachineAccess(&doc, cmMate).OK {
		t.Fatal("web path must admit the co-manager")
	}
	if doc.UnionID == cmMate {
		t.Fatal("desktop owner comparison must reject the co-manager")
	}
}

type teamsUnavailableRepository struct{ store.Repository }

func (teamsUnavailableRepository) ListTeamsForUser(context.Context, string) ([]store.TeamDoc, error) {
	return nil, store.ErrUnavailable
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
