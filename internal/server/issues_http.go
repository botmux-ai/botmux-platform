package server

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Issue Board HTTP (src/server/issues-http.ts, issues-core.ts,
// machine-issues-http.ts; DESIGN-issue-board.md). Owned by Phase 2 agent B2.
//
// Three entries share issues_core.go:
//   - web /api/issues* (SSO cookie; regular writes need a same-origin Origin,
//     high-sensitivity writes additionally a fresh SSO login),
//   - desktop /v1/desktop/teams and /v1/desktop/issues* (desktop bearer),
//   - machine /v1/machine/teams and /v1/machine/issues* (machine token; only
//     the five endpoints the daemon needs, every response no-store).
//
// Request bodies are read with JSON.parse semantics (issues_json.go). Where
// TS would persist a value of a foreign JSON type into a string field
// (claimId, localTaskRef, status, attentionReason, desktop machineId,
// suggestedAssigneeUnionId, patch title/body/labels/targetRepoLabel arrays)
// the Go entries answer 400 {"error":"invalid"} instead; real clients always
// send strings there.

// IssuesDeps holds issue-module seams that are not shared Apex authorities.
type IssuesDeps struct {
	// LookupMachine replaces the machine ownership lookup used by claim, bind
	// and status (the TS MachineLookupReader injection point). Nil reads
	// a.Repository.LookupMachine without the positive cache, like
	// getMachineLookup's defaults.
	LookupMachine func(ctx context.Context, machineID string) (store.MachineDoc, error)
	// Now is the clock for the fresh-SSO check; nil is time.Now.
	Now func() time.Time
}

func (a *Apex) issuesNow() time.Time {
	if a.Issues.Now != nil {
		return a.Issues.Now()
	}
	return time.Now()
}

var (
	issuesWebPathPattern     = regexp.MustCompile(`^/api/issues/([A-Za-z0-9_]+)(?:/(claim|bind|status|cancel|force-detach|events))?$`)
	issuesDesktopPathPattern = regexp.MustCompile(`^/v1/desktop/issues/([A-Za-z0-9_]+)(?:/(claim|bind|status))?$`)
	issuesMachinePathPattern = regexp.MustCompile(`^/v1/machine/issues/([A-Za-z0-9_]+)(?:/(claim|bind|status))?$`)
	issuesTeamSettingsPath   = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/issue-settings$`)
	issuesTeamAdminsPath     = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/admins$`)
)

// issuesSend writes a core response; noStore adds the machine entry's
// cache-control. A TS throw becomes the top-level 500 "internal error".
func issuesSend(w http.ResponseWriter, resp issuesResponse, noStore bool) {
	if resp.internalError {
		text(w, http.StatusInternalServerError, "internal error")
		return
	}
	if noStore {
		writeJSONNoStore(w, resp.status, resp.body)
		return
	}
	writeJSON(w, resp.status, resp.body)
}

func issuesWriteError(w http.ResponseWriter, status int, code string, noStore bool) {
	issuesSend(w, issuesErr(status, code), noStore)
}

// ---- team issue settings + admins ----

// handleTeamIssueSettingsAPI serves /api/teams/:id/issue-settings and
// /api/teams/:id/admins (handleTeamIssueSettingsApi). It runs after the
// fresh-SSO gate, like TS.
func (a *Apex) handleTeamIssueSettingsAPI(w http.ResponseWriter, r *http.Request) bool {
	pathname, _ := issuesRequestTarget(r)
	session, err := auth.ReadSession(a.Config, r)
	if err != nil {
		if issuesTeamSettingsPath.MatchString(pathname) || issuesTeamAdminsPath.MatchString(pathname) {
			writeJSON(w, http.StatusUnauthorized, issuesErrorBody{Error: "unauthenticated"})
			return true
		}
		return false
	}
	principal := issuesPrincipal{UnionID: session.UnionID, Name: session.Name}

	if m := issuesTeamAdminsPath.FindStringSubmatch(pathname); m != nil {
		if r.Method != http.MethodPut {
			writeJSON(w, http.StatusMethodNotAllowed, issuesErrorBody{Error: "method_not_allowed"})
			return true
		}
		if !issuesOriginOK(a.Config, r) {
			writeJSON(w, http.StatusForbidden, issuesErrorBody{Error: "bad_origin"})
			return true
		}
		list, ok := issuesProp(issuesReadJSON(r), "admins").value.([]any)
		if !ok {
			writeJSON(w, http.StatusBadRequest, issuesErrorBody{Error: "invalid"})
			return true
		}
		admins := make([]string, len(list))
		for i, item := range list {
			admins[i] = issuesJSString(item) // body.admins.map(String)
		}
		issuesSend(w, a.issuesCorePutTeamAdmins(r.Context(), m[1], principal, admins), false)
		return true
	}

	m := issuesTeamSettingsPath.FindStringSubmatch(pathname)
	if m == nil {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		issuesSend(w, a.issuesCoreGetTeamSettings(r.Context(), m[1], principal), false)
	case http.MethodPut:
		if !issuesOriginOK(a.Config, r) {
			writeJSON(w, http.StatusForbidden, issuesErrorBody{Error: "bad_origin"})
			return true
		}
		body := issuesReadJSON(r)
		presets, form := issuesProp(body, "repoPresets"), issuesProp(body, "issueForm")
		patch := store.TeamIssueSettingsPatch{SetRepoPresets: presets.defined, SetIssueForm: form.defined}
		if presets.defined {
			patch.RepoPresets = issuesPlain(presets.value)
		}
		if form.defined {
			patch.IssueForm = issuesPlain(form.value)
		}
		issuesSend(w, a.issuesCorePutTeamSettings(r.Context(), m[1], principal, patch), false)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, issuesErrorBody{Error: "method_not_allowed"})
	}
	return true
}

// ---- web (SSO cookie) ----

type issuesStaleSessionBody struct {
	Error    string `json:"error"`
	LoginURL string `json:"loginUrl"`
}

type issuesNotImplementedBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// handleWebIssuesAPI serves /api/issues and /api/issues/* (handleWebIssuesApi).
func (a *Apex) handleWebIssuesAPI(w http.ResponseWriter, r *http.Request) bool {
	pathname, rawQuery := issuesRequestTarget(r)
	if pathname != "/api/issues" && !strings.HasPrefix(pathname, "/api/issues/") {
		return false
	}
	session, err := auth.ReadSession(a.Config, r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, issuesErrorBody{Error: "unauthenticated"})
		return true
	}
	principal := issuesPrincipal{UnionID: session.UnionID, Name: session.Name}
	ctx := r.Context()

	if pathname == "/api/issues" && r.Method == http.MethodGet {
		teamID, _ := issuesSearchParam(rawQuery, "teamId")
		if teamID == "" {
			writeJSON(w, http.StatusBadRequest, issuesErrorBody{Error: "missing_teamId"})
			return true
		}
		issuesSend(w, a.issuesCoreList(ctx, teamID, principal), false)
		return true
	}

	if pathname == "/api/issues" && r.Method == http.MethodPost {
		if !issuesOriginOK(a.Config, r) {
			writeJSON(w, http.StatusForbidden, issuesErrorBody{Error: "bad_origin"})
			return true
		}
		issuesSend(w, a.issuesWebCreate(ctx, principal, issuesReadJSON(r)), false)
		return true
	}

	m := issuesWebPathPattern.FindStringSubmatch(pathname)
	if m == nil {
		writeJSON(w, http.StatusNotFound, issuesErrorBody{Error: "not_found"})
		return true
	}
	issueID, sub := m[1], m[2]

	if sub == "events" && r.Method == http.MethodGet {
		after, _ := issuesSearchParam(rawQuery, "after")
		if after == "" {
			after = "0"
		}
		afterSeq := issuesJSNumber(after)
		if !issuesTruthy(afterSeq) {
			afterSeq = 0 // Number(...) || 0: NaN and -0 become 0
		}
		issuesSend(w, a.issuesCoreEvents(ctx, issueID, afterSeq, principal), false)
		return true
	}

	if sub == "" && r.Method == http.MethodPatch {
		if !issuesOriginOK(a.Config, r) {
			writeJSON(w, http.StatusForbidden, issuesErrorBody{Error: "bad_origin"})
			return true
		}
		body := issuesReadJSON(r)
		rev, ok := issuesProp(body, "rev").number()
		if !ok {
			writeJSON(w, http.StatusBadRequest, issuesErrorBody{Error: "missing_rev"})
			return true
		}
		issuesSend(w, a.issuesCorePatch(ctx, issueID, principal, issuesPatchArgs{
			Rev:                      rev,
			Title:                    issuesProp(body, "title"),
			Body:                     issuesProp(body, "body"),
			Labels:                   issuesProp(body, "labels"),
			TargetRepoID:             issuesProp(body, "targetRepoId"),
			TargetRepoLabel:          issuesProp(body, "targetRepoLabel"),
			SuggestedAssigneeUnionID: issuesProp(body, "suggestedAssigneeUnionId"),
		}), false)
		return true
	}

	// High-sensitivity writes: cancel (501 until the P2 command channel),
	// force-detach and DELETE need fresh SSO + Origin.
	highSensitive := (sub == "force-detach" && r.Method == http.MethodPost) ||
		(sub == "cancel" && r.Method == http.MethodPost) ||
		(sub == "" && r.Method == http.MethodDelete)
	if highSensitive {
		if auth.RequireFreshSSO(&auth.Principal{Kind: auth.PrincipalSSO, Session: session}, a.issuesNow()) == nil {
			writeJSON(w, http.StatusUnauthorized, issuesStaleSessionBody{Error: "stale_session", LoginURL: "/auth/login"})
			return true
		}
		if !issuesOriginOK(a.Config, r) {
			writeJSON(w, http.StatusForbidden, issuesErrorBody{Error: "bad_origin"})
			return true
		}
		switch sub {
		case "cancel":
			writeJSON(w, http.StatusNotImplemented, issuesNotImplementedBody{Error: "not_implemented", Detail: "web cancel ships in P2"})
		case "force-detach":
			expected, ok := issuesProp(issuesReadJSON(r), "expectedStateRev").number()
			if !ok {
				writeJSON(w, http.StatusBadRequest, issuesErrorBody{Error: "missing_expectedStateRev"})
				return true
			}
			issuesSend(w, a.issuesCoreForceDetach(ctx, issueID, principal, expected), false)
		default:
			issuesSend(w, a.issuesCoreArchive(ctx, issueID, principal), false)
		}
		return true
	}

	writeJSON(w, http.StatusMethodNotAllowed, issuesErrorBody{Error: "method_not_allowed"})
	return true
}

// issuesWebCreate is the POST /api/issues body handling before
// coreCreateIssue.
func (a *Apex) issuesWebCreate(ctx context.Context, p issuesPrincipal, body any) issuesResponse {
	invalid := issuesErr(http.StatusBadRequest, "invalid")
	teamProp := issuesProp(body, "teamId")
	if !teamProp.truthy() {
		return invalid
	}
	values, title := issuesProp(body, "values"), issuesProp(body, "title")
	// New clients send values{}; old ones at least a title.
	if !values.truthy() && !title.truthy() {
		return invalid
	}
	teamID, ok := teamProp.str()
	if !ok {
		// getTeamDoc never finds a non-string _id.
		return issuesNotFound
	}
	args := issuesCreateArgs{TeamID: teamID, Title: title, Body: issuesProp(body, "body")}
	if values.truthy() {
		args.Values, _ = values.value.(*issueJSONObject)
	}
	for _, field := range []struct {
		name string
		dst  *issueJS
	}{{"labels", &args.Labels}, {"targetRepoId", &args.TargetRepoID}, {"targetRepoLabel", &args.TargetRepoLabel}} {
		if prop := issuesProp(body, field.name); prop.truthy() {
			*field.dst = prop
		}
	}
	if custom := issuesProp(body, "customFields"); custom.truthy() {
		args.CustomFields, _ = custom.value.(*issueJSONObject)
	}
	if assignee := issuesProp(body, "suggestedAssigneeUnionId"); assignee.truthy() {
		text, ok := assignee.str()
		if !ok {
			return invalid
		}
		args.SuggestedAssigneeUnionID = text
	}
	return a.issuesCoreCreate(ctx, p, args)
}

// ---- desktop (bearer access token) ----

type issuesTeamItem struct {
	TeamID   string `json:"teamId"`
	TeamName string `json:"teamName"`
}

type issuesTeamsBody struct {
	Teams []issuesTeamItem `json:"teams"`
}

func (a *Apex) issuesTeamsFor(ctx context.Context, unionID string) (issuesTeamsBody, bool) {
	if a.Repository == nil {
		return issuesTeamsBody{}, false
	}
	docs, err := a.Repository.ListTeamsForUser(ctx, unionID)
	if err != nil {
		return issuesTeamsBody{}, false
	}
	body := issuesTeamsBody{Teams: make([]issuesTeamItem, 0, len(docs))}
	for _, team := range docs {
		body.Teams = append(body.Teams, issuesTeamItem{TeamID: team.ID, TeamName: team.Name})
	}
	return body, true
}

// handleDesktopIssuesAPI serves /v1/desktop/teams, /v1/desktop/issues and
// /v1/desktop/issues/* (handleDesktopIssuesApi).
func (a *Apex) handleDesktopIssuesAPI(w http.ResponseWriter, r *http.Request) bool {
	pathname, rawQuery := issuesRequestTarget(r)
	if pathname != "/v1/desktop/teams" && pathname != "/v1/desktop/issues" && !strings.HasPrefix(pathname, "/v1/desktop/issues/") {
		return false
	}
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return true
	}
	principal := issuesPrincipal{UnionID: access.UnionID, Name: access.Name}
	ctx := r.Context()

	if pathname == "/v1/desktop/teams" && r.Method == http.MethodGet {
		body, ok := a.issuesTeamsFor(ctx, access.UnionID)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, issuesErrorBody{Error: "store_unavailable"})
			return true
		}
		writeJSON(w, http.StatusOK, body)
		return true
	}
	if pathname == "/v1/desktop/issues" && r.Method == http.MethodGet {
		teamID, _ := issuesSearchParam(rawQuery, "teamId")
		if teamID == "" {
			writeJSON(w, http.StatusBadRequest, issuesErrorBody{Error: "missing_teamId"})
			return true
		}
		issuesSend(w, a.issuesCoreList(ctx, teamID, principal), false)
		return true
	}

	m := issuesDesktopPathPattern.FindStringSubmatch(pathname)
	if m == nil {
		writeJSON(w, http.StatusNotFound, issuesErrorBody{Error: "not_found"})
		return true
	}
	issueID, sub := m[1], m[2]
	if r.Method != http.MethodPost || sub == "" {
		writeJSON(w, http.StatusMethodNotAllowed, issuesErrorBody{Error: "method_not_allowed"})
		return true
	}
	body := issuesReadJSON(r)
	var resp issuesResponse
	switch sub {
	case "claim":
		resp = a.issuesClaimRequest(ctx, issueID, principal, body, "")
	case "bind":
		resp = a.issuesBindRequest(ctx, issueID, principal, body, "")
	default:
		resp = a.issuesStatusRequest(ctx, issueID, principal, body, "")
	}
	issuesSend(w, resp, false)
	return true
}

// issuesClaimRequest validates a desktop (machineToken == "") or machine
// claim body and runs coreClaimIssue. The machine entry takes the machine id
// from its token and refuses a different one named in the body.
func (a *Apex) issuesClaimRequest(ctx context.Context, issueID string, p issuesPrincipal, body any, machineToken string) issuesResponse {
	invalid := issuesErr(http.StatusBadRequest, "invalid")
	claimProp, machineProp := issuesProp(body, "claimId"), issuesProp(body, "machineId")
	expected, hasExpected := issuesProp(body, "expectedStateRev").number()
	machineID := machineToken
	if machineToken == "" {
		if !claimProp.truthy() || !machineProp.truthy() || !hasExpected {
			return invalid
		}
		text, ok := machineProp.str()
		if !ok {
			return invalid
		}
		machineID = text
	} else {
		if !claimProp.truthy() || !hasExpected {
			return invalid
		}
		// The body's machineId, when given, must be the token's: a wrong
		// machine is an explicit error, not silently replaced.
		if machineProp.truthy() {
			if text, ok := machineProp.str(); !ok || text != machineToken {
				return issuesErr(http.StatusForbidden, "machine_mismatch")
			}
		}
	}
	claimID, ok := claimProp.str()
	if !ok {
		return invalid
	}
	args := issuesClaimArgs{ClaimID: claimID, MachineID: machineID, ExpectedStateRev: expected}
	if agent := issuesProp(body, "agent"); agent.truthy() {
		args.Agent = issuesBSONValue(agent.value)
	}
	if repoLabel := issuesProp(body, "repoLabel"); repoLabel.truthy() {
		args.RepoLabel = issuesBSONValue(repoLabel.value)
	}
	return a.issuesCoreClaim(ctx, issueID, p, args)
}

func (a *Apex) issuesBindRequest(ctx context.Context, issueID string, p issuesPrincipal, body any, machineFence string) issuesResponse {
	invalid := issuesErr(http.StatusBadRequest, "invalid")
	claimProp, refProp := issuesProp(body, "claimId"), issuesProp(body, "localTaskRef")
	expected, hasExpected := issuesProp(body, "expectedStateRev").number()
	if !claimProp.truthy() || !refProp.truthy() || !hasExpected {
		return invalid
	}
	claimID, ok1 := claimProp.str()
	ref, ok2 := refProp.str()
	if !ok1 || !ok2 {
		return invalid
	}
	return a.issuesCoreBind(ctx, issueID, p, issuesBindArgs{
		ClaimID: claimID, LocalTaskRef: ref, ExpectedStateRev: expected, MachineFence: machineFence,
		// Display-only and optional; sanitized in the core.
		LocalTaskLabel: issuesProp(body, "localTaskLabel"),
		LocalTaskURL:   issuesProp(body, "localTaskUrl"),
	})
}

func (a *Apex) issuesStatusRequest(ctx context.Context, issueID string, p issuesPrincipal, body any, machineFence string) issuesResponse {
	invalid := issuesErr(http.StatusBadRequest, "invalid")
	claimProp, statusProp := issuesProp(body, "claimId"), issuesProp(body, "status")
	claimEpoch, ok1 := issuesProp(body, "claimEpoch").number()
	sourceSeq, ok2 := issuesProp(body, "sourceSeq").number()
	expected, ok3 := issuesProp(body, "expectedStateRev").number()
	if !claimProp.truthy() || !ok1 || !ok2 || !statusProp.truthy() || !ok3 {
		return invalid
	}
	claimID, ok1 := claimProp.str()
	status, ok2 := statusProp.str()
	if !ok1 || !ok2 {
		return invalid
	}
	args := issuesStatusArgs{
		ClaimID: claimID, ClaimEpoch: claimEpoch, SourceSeq: sourceSeq, Status: store.IssueStatus(status),
		ExpectedStateRev: expected, MachineFence: machineFence,
	}
	if reasonProp := issuesProp(body, "attentionReason"); reasonProp.truthy() {
		reason, ok := reasonProp.str()
		if !ok {
			return invalid
		}
		args.AttentionReason = store.AttentionReason(reason)
	}
	return a.issuesCoreStatus(ctx, issueID, p, args)
}

// ---- machine (machine token) ----

// handleMachineIssuesAPI serves /v1/machine/teams, /v1/machine/issues and
// /v1/machine/issues/* (handleMachineIssuesApi). The daemon only has its
// machine token; the token's machine id is authoritative and bind/status are
// fenced to the machine that claimed.
func (a *Apex) handleMachineIssuesAPI(w http.ResponseWriter, r *http.Request) bool {
	pathname, rawQuery := issuesRequestTarget(r)
	if pathname != "/v1/machine/teams" && pathname != "/v1/machine/issues" && !strings.HasPrefix(pathname, "/v1/machine/issues/") {
		return false
	}
	machine, ok := a.RequireMachineAuth(w, r)
	if !ok {
		return true
	}
	principal := issuesPrincipal{UnionID: machine.UnionID, Name: machine.Name}
	ctx := r.Context()

	if pathname == "/v1/machine/teams" && r.Method == http.MethodGet {
		body, ok := a.issuesTeamsFor(ctx, principal.UnionID)
		if !ok {
			issuesWriteError(w, http.StatusServiceUnavailable, "store_unavailable", true)
			return true
		}
		writeJSONNoStore(w, http.StatusOK, body)
		return true
	}
	if pathname == "/v1/machine/issues" && r.Method == http.MethodGet {
		teamID, _ := issuesSearchParam(rawQuery, "teamId")
		if teamID == "" {
			issuesWriteError(w, http.StatusBadRequest, "missing_teamId", true)
			return true
		}
		issuesSend(w, a.issuesCoreList(ctx, teamID, principal), true)
		return true
	}

	m := issuesMachinePathPattern.FindStringSubmatch(pathname)
	if m == nil {
		issuesWriteError(w, http.StatusNotFound, "not_found", true)
		return true
	}
	issueID, sub := m[1], m[2]
	if r.Method != http.MethodPost || sub == "" {
		issuesWriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", true)
		return true
	}
	body := issuesReadJSON(r)
	var resp issuesResponse
	switch sub {
	case "claim":
		resp = a.issuesClaimRequest(ctx, issueID, principal, body, machine.MachineID)
	case "bind":
		resp = a.issuesBindRequest(ctx, issueID, principal, body, machine.MachineID)
	default:
		resp = a.issuesStatusRequest(ctx, issueID, principal, body, machine.MachineID)
	}
	issuesSend(w, resp, true)
	return true
}
