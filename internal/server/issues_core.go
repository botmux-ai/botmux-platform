package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Issue Board authorization + orchestration (src/server/issues-core.ts,
// DESIGN-issue-board.md §三). Route-agnostic: the web (SSO), desktop (bearer)
// and machine (machine token) entries resolve a principal and share this
// layer. Routes authenticate, the core authorizes: every operation re-checks
// team membership here (a client-supplied teamId is never trusted) and
// high-sensitivity operations additionally require issue creator or team
// admin. A degraded store answers 503.
//
// TS issues-core.ts sends no Feishu notifications, so nothing here is behind
// FeishuWritesDisabled.

type issuesPrincipal struct {
	UnionID string
	Name    string
}

// issuesResponse is CoreResponse. internalError reproduces a TS handler that
// throws (TypeError on a malformed body): the top-level catch answers 500
// text/plain "internal error".
type issuesResponse struct {
	status        int
	body          any
	internalError bool
}

type issuesErrorBody struct {
	Error string `json:"error"`
}

type issuesFieldErrorBody struct {
	Error string `json:"error"`
	Field string `json:"field"`
}

type issuesIssueBody struct {
	Issue store.IssueDoc `json:"issue"`
}

type issuesClaimBody struct {
	Claim *store.IssueClaim `json:"claim,omitempty"`
	Issue store.IssueDoc    `json:"issue"`
}

type issuesEventsBody struct {
	Events []store.IssueEventDoc `json:"events"`
}

// issuesSections is the board split (§十): four columns plus the attention
// strip on top.
type issuesSections struct {
	NeedsAttention []store.IssueDoc `json:"needsAttention"`
	Todo           []store.IssueDoc `json:"todo"`
	InProgress     []store.IssueDoc `json:"inProgress"`
	InReview       []store.IssueDoc `json:"inReview"`
	Done           []store.IssueDoc `json:"done"`
}

type issuesSectionsBody struct {
	Sections issuesSections `json:"sections"`
}

type issuesTeamSettingsBody struct {
	TeamID      string                 `json:"teamId"`
	RepoPresets []store.TeamRepoPreset `json:"repoPresets"`
	IssueForm   store.IssueFormConfig  `json:"issueForm"`
	Admins      []string               `json:"admins"`
	CreatedBy   string                 `json:"createdBy"`
	CanEdit     bool                   `json:"canEdit"`
}

type issuesTeamAdminsBody struct {
	TeamID    string   `json:"teamId"`
	CreatedBy string   `json:"createdBy"`
	Admins    []string `json:"admins"`
}

func issuesOK(body any) issuesResponse { return issuesResponse{status: http.StatusOK, body: body} }

func issuesErr(status int, code string) issuesResponse {
	return issuesResponse{status: status, body: issuesErrorBody{Error: code}}
}

func issuesInternalError() issuesResponse {
	return issuesResponse{status: http.StatusInternalServerError, internalError: true}
}

var (
	issuesNotFound         = issuesErr(http.StatusNotFound, "not_found")
	issuesForbidden        = issuesErr(http.StatusForbidden, "forbidden")
	issuesStoreUnavailable = issuesErr(http.StatusServiceUnavailable, "store_unavailable")
)

// issuesFromStoreError is fromStoreError: unavailable 503, not_found 404,
// invalid 400, forbidden 403, every other reason 409 with the reason as the
// error code.
func issuesFromStoreError(err error) issuesResponse {
	switch reason := store.StoreReason(err); reason {
	case "unavailable":
		return issuesStoreUnavailable
	case "not_found":
		return issuesNotFound
	case "invalid":
		return issuesErr(http.StatusBadRequest, "invalid")
	case "forbidden":
		return issuesForbidden
	default:
		return issuesErr(http.StatusConflict, reason)
	}
}

// issuesGetTeam is getTeamDoc: an unavailable store and a missing team are
// both "no team" (callers answer 404 so non-members cannot probe teams).
func (a *Apex) issuesGetTeam(ctx context.Context, teamID string) (store.TeamDoc, bool) {
	if a.Repository == nil {
		return store.TeamDoc{}, false
	}
	team, err := a.Repository.GetTeam(ctx, teamID)
	if err != nil {
		return store.TeamDoc{}, false
	}
	return team, true
}

// issuesRequireMember is requireMember.
func (a *Apex) issuesRequireMember(ctx context.Context, teamID string, p issuesPrincipal) (store.TeamDoc, *issuesResponse) {
	team, ok := a.issuesGetTeam(ctx, teamID)
	if !ok || !contains(team.Members, p.UnionID) {
		resp := issuesNotFound
		return store.TeamDoc{}, &resp
	}
	return team, nil
}

// issuesCanManage: issue creator or team admin (creator included).
func issuesCanManage(issue store.IssueDoc, team store.TeamDoc, p issuesPrincipal) bool {
	return p.UnionID == issue.CreatedBy || store.IsTeamAdmin(team, p.UnionID)
}

func (a *Apex) issuesLookupMachine(ctx context.Context, machineID string) (store.MachineDoc, error) {
	if a.Issues.LookupMachine != nil {
		return a.Issues.LookupMachine(ctx, machineID)
	}
	if a.Repository == nil {
		return store.MachineDoc{}, store.ErrUnavailable
	}
	return a.Repository.LookupMachine(ctx, machineID, store.AuthorityCacheOptions{})
}

// issuesRequireOwnedActiveMachine is requireOwnedActiveMachine (P1#9): a
// client-named machine must exist, be ACTIVE and belong to the principal.
// Missing / retired / foreign are all 403 (no existence oracle); a failed
// lookup is 503 fail-closed.
func (a *Apex) issuesRequireOwnedActiveMachine(ctx context.Context, machineID string, p issuesPrincipal) *issuesResponse {
	doc, err := a.issuesLookupMachine(ctx, machineID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		resp := issuesStoreUnavailable
		return &resp
	}
	if err != nil || (doc.Status != "" && doc.Status != store.MachineStatusActive) || doc.UnionID != p.UnionID {
		resp := issuesForbidden
		return &resp
	}
	return nil
}

// issuesMachineFenceError is machineFenceError: on the machine-token entry
// the issue's claim must have been taken by the calling machine. An empty
// fence (web / desktop) disables the check.
func issuesMachineFenceError(issue store.IssueDoc, fence string) *issuesResponse {
	if fence == "" {
		return nil
	}
	if issue.Claim == nil || issue.Claim.MachineID != fence {
		resp := issuesErr(http.StatusForbidden, "machine_mismatch")
		return &resp
	}
	return nil
}

func issuesSectionize(issues []store.IssueDoc) issuesSections {
	s := issuesSections{
		NeedsAttention: []store.IssueDoc{}, Todo: []store.IssueDoc{}, InProgress: []store.IssueDoc{},
		InReview: []store.IssueDoc{}, Done: []store.IssueDoc{},
	}
	for _, issue := range issues {
		attentioned := issue.AttentionSince != 0
		switch {
		case issue.Status == store.IssueNeedsAttention || (issue.Status == store.IssueCancelling && attentioned):
			s.NeedsAttention = append(s.NeedsAttention, issue)
		case issue.Status == store.IssueOpen || issue.Status == store.IssueReopened:
			s.Todo = append(s.Todo, issue)
		case issue.Status == store.IssueClaimed || issue.Status == store.IssueInProgress || issue.Status == store.IssueCancelling:
			s.InProgress = append(s.InProgress, issue)
		case issue.Status == store.IssueInReview:
			s.InReview = append(s.InReview, issue)
		case issue.Status == store.IssueDone:
			s.Done = append(s.Done, issue)
		}
	}
	return s
}

// ---- reads ----

func (a *Apex) issuesCoreList(ctx context.Context, teamID string, p issuesPrincipal) issuesResponse {
	if _, resp := a.issuesRequireMember(ctx, teamID, p); resp != nil {
		return *resp
	}
	issues, err := a.IssueStore.ListForTeam(ctx, teamID, false)
	if err != nil {
		return issuesFromStoreError(err)
	}
	return issuesOK(issuesSectionsBody{Sections: issuesSectionize(issues)})
}

func (a *Apex) issuesCoreEvents(ctx context.Context, issueID string, afterSeq float64, p issuesPrincipal) issuesResponse {
	issue, err := a.IssueStore.Get(ctx, issueID)
	if err != nil {
		return issuesFromStoreError(err)
	}
	if _, resp := a.issuesRequireMember(ctx, issue.TeamID, p); resp != nil {
		return *resp
	}
	events, err := a.IssueStore.ListEvents(ctx, issueID, afterSeq)
	if err != nil {
		return issuesFromStoreError(err)
	}
	return issuesOK(issuesEventsBody{Events: events})
}

// ---- create ----

// issuesCreateArgs are coreCreateIssue's args; each field is set only when
// the TS handler would have put it in the args literal.
type issuesCreateArgs struct {
	TeamID                   string
	Values                   *issueJSONObject // only when body.values is a JSON object
	Title                    issueJS
	Body                     issueJS
	Labels                   issueJS
	TargetRepoID             issueJS
	TargetRepoLabel          issueJS
	CustomFields             *issueJSONObject
	SuggestedAssigneeUnionID string
}

// issuesObjectFunctionString is String(Object): what `values.constructor`
// (inherited from Object.prototype) coerces to when a team form has a field
// with the otherwise legal id "constructor" and the submission omits it.
const issuesObjectFunctionString = "function Object() { [native code] }"

func (a *Apex) issuesCoreCreate(ctx context.Context, p issuesPrincipal, args issuesCreateArgs) issuesResponse {
	team, ok := a.issuesGetTeam(ctx, args.TeamID)
	if !ok || !contains(team.Members, p.UnionID) {
		return issuesNotFound
	}
	presets, form := store.ResolveTeamIssueSettings(team)

	// Old clients send title/body/labels (and flat repo / customFields); new
	// ones send values{} keyed by field id. Own properties only: a key is
	// "undefined" exactly when the object lacks it.
	values := map[string]any{}
	if args.Values != nil {
		for _, key := range args.Values.keys {
			values[key] = issuesPlain(args.Values.values[key])
		}
	}
	setIfUndefined := func(key string, value issueJS) {
		if _, present := values[key]; !present && value.defined {
			values[key] = issuesPlain(value.value)
		}
	}
	setIfUndefined("title", args.Title)
	setIfUndefined("body", args.Body)
	setIfUndefined("labels", args.Labels)
	if _, present := values["repo"]; !present && (args.TargetRepoID.truthy() || args.TargetRepoLabel.truthy()) {
		repo := map[string]any{}
		if args.TargetRepoID.defined {
			repo["id"] = issuesPlain(args.TargetRepoID.value)
		}
		if args.TargetRepoLabel.defined {
			repo["label"] = issuesPlain(args.TargetRepoLabel.value)
		}
		values["repo"] = repo
	}
	if args.CustomFields != nil {
		for _, key := range args.CustomFields.keys {
			// values.constructor is inherited (never undefined), so a
			// customFields.constructor entry is never merged.
			if key == "constructor" {
				continue
			}
			if _, present := values[key]; !present {
				values[key] = issuesPlain(args.CustomFields.values[key])
			}
		}
	}
	if _, present := values["constructor"]; !present {
		for _, field := range form.Fields {
			if field.ID == "constructor" && field.Type != store.IssueFieldMultiselect && field.Type != store.IssueFieldRepo {
				values["constructor"] = issuesObjectFunctionString
			}
		}
	}

	submission, formErr := store.ValidateIssueFormSubmission(form, presets, values)
	if formErr != nil {
		return issuesResponse{status: http.StatusBadRequest, body: issuesFieldErrorBody{Error: formErr.Reason, Field: formErr.Field}}
	}
	var customFields store.IssueCustomFields
	for _, field := range submission.CustomFields {
		customFields = append(customFields, store.IssueCustomField{ID: field.ID, Value: field.Value})
	}
	doc, err := a.IssueStore.Create(ctx, store.CreateIssueInput{
		TeamID: args.TeamID, Title: submission.Title, Body: submission.Body, Labels: submission.Labels,
		TargetRepoID: submission.TargetRepoID, TargetRepoLabel: submission.TargetRepoLabel,
		CustomFields: customFields, SuggestedAssigneeUnionID: args.SuggestedAssigneeUnionID,
		CreatedBy: p.UnionID, CreatedByName: p.Name,
	})
	if err != nil {
		return issuesFromStoreError(err)
	}
	return issuesResponse{status: http.StatusCreated, body: issuesIssueBody{Issue: doc}}
}

// ---- team settings ----

func issuesNonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func issuesNonNilPresets(values []store.TeamRepoPreset) []store.TeamRepoPreset {
	if values == nil {
		return []store.TeamRepoPreset{}
	}
	return values
}

func (a *Apex) issuesCoreGetTeamSettings(ctx context.Context, teamID string, p issuesPrincipal) issuesResponse {
	if _, resp := a.issuesRequireMember(ctx, teamID, p); resp != nil {
		return *resp
	}
	// TS reads the team a second time here.
	team, ok := a.issuesGetTeam(ctx, teamID)
	if !ok {
		return issuesNotFound
	}
	presets, form := store.ResolveTeamIssueSettings(team)
	return issuesOK(issuesTeamSettingsBody{
		TeamID: teamID, RepoPresets: issuesNonNilPresets(presets), IssueForm: form,
		Admins: issuesNonNilStrings(team.Admins), CreatedBy: team.CreatedBy,
		CanEdit: store.IsTeamAdmin(team, p.UnionID),
	})
}

func (a *Apex) issuesCorePutTeamSettings(ctx context.Context, teamID string, p issuesPrincipal, patch store.TeamIssueSettingsPatch) issuesResponse {
	team, ok := a.issuesGetTeam(ctx, teamID)
	if !ok || !contains(team.Members, p.UnionID) {
		return issuesNotFound
	}
	if !store.IsTeamAdmin(team, p.UnionID) {
		return issuesErr(http.StatusForbidden, "not_admin")
	}
	if err := a.Repository.UpdateTeamIssueSettings(ctx, teamID, patch); err != nil {
		return issuesStoreUnavailable
	}
	fresh, ok := a.issuesGetTeam(ctx, teamID)
	if !ok {
		// TS: resolveTeamIssueSettings(null) throws.
		return issuesInternalError()
	}
	presets, form := store.ResolveTeamIssueSettings(fresh)
	return issuesOK(issuesTeamSettingsBody{
		TeamID: teamID, RepoPresets: issuesNonNilPresets(presets), IssueForm: form,
		Admins: issuesNonNilStrings(fresh.Admins), CreatedBy: fresh.CreatedBy, CanEdit: true,
	})
}

func (a *Apex) issuesCorePutTeamAdmins(ctx context.Context, teamID string, p issuesPrincipal, admins []string) issuesResponse {
	team, ok := a.issuesGetTeam(ctx, teamID)
	if !ok || !contains(team.Members, p.UnionID) {
		return issuesNotFound
	}
	if team.CreatedBy != p.UnionID {
		return issuesErr(http.StatusForbidden, "not_creator")
	}
	written, err := a.Repository.UpdateTeamAdmins(ctx, teamID, admins, &team)
	if err != nil {
		return issuesStoreUnavailable
	}
	return issuesOK(issuesTeamAdminsBody{TeamID: teamID, CreatedBy: team.CreatedBy, Admins: issuesNonNilStrings(written)})
}

// ---- issue writes ----

// issuesWithIssue is withIssue: load the issue (503/404), check membership of
// its team (404), then run op with the issue and team.
func (a *Apex) issuesWithIssue(ctx context.Context, issueID string, p issuesPrincipal, op func(store.IssueDoc, store.TeamDoc) issuesResponse) issuesResponse {
	issue, err := a.IssueStore.Get(ctx, issueID)
	if err != nil {
		return issuesFromStoreError(err)
	}
	team, resp := a.issuesRequireMember(ctx, issue.TeamID, p)
	if resp != nil {
		return *resp
	}
	return op(issue, team)
}

// issuesPatchArgs are corePatchIssue's args as raw body properties (only
// defined ones reach patchIssue).
type issuesPatchArgs struct {
	Rev                      float64
	Title                    issueJS
	Body                     issueJS
	Labels                   issueJS
	TargetRepoID             issueJS
	TargetRepoLabel          issueJS
	SuggestedAssigneeUnionID issueJS
}

// issuesSliceable reports whether `v.slice(0, n)` works on a JSON value
// (strings and arrays); anything else makes TS patchIssue throw.
func issuesSliceable(v any) bool {
	switch v.(type) {
	case string, []any:
		return true
	}
	return false
}

// issuesBuildPatch maps the body onto store.IssuePatch. TS patchIssue throws
// (500) on `.slice` of a non-string/non-array title, body or non-empty
// targetRepoLabel; values it would persist with a foreign JSON type (array
// title, non-string-array labels, non-string assignee) are rejected as
// invalid instead of being written into string fields.
func issuesBuildPatch(args issuesPatchArgs) (store.IssuePatch, *issuesResponse) {
	crash := func(j issueJS) bool { return j.defined && !issuesSliceable(j.value) }
	repoLabelCrash := args.TargetRepoLabel.defined && args.TargetRepoLabel.value != nil &&
		args.TargetRepoLabel.value != "" && !issuesSliceable(args.TargetRepoLabel.value)
	if crash(args.Title) || crash(args.Body) || repoLabelCrash {
		resp := issuesInternalError()
		return store.IssuePatch{}, &resp
	}
	invalid := issuesErr(http.StatusBadRequest, "invalid")
	var patch store.IssuePatch
	if args.Title.defined {
		title, ok := args.Title.str()
		if !ok {
			return store.IssuePatch{}, &invalid
		}
		patch.Title = &title
	}
	if args.Body.defined {
		body, ok := args.Body.str()
		if !ok {
			return store.IssuePatch{}, &invalid
		}
		patch.Body = &body
	}
	if args.Labels.defined {
		items, ok := args.Labels.value.([]any)
		if !ok {
			return store.IssuePatch{}, &invalid
		}
		labels := make([]string, 0, len(items))
		for _, item := range items {
			label, ok := item.(string)
			if !ok {
				return store.IssuePatch{}, &invalid
			}
			labels = append(labels, label)
		}
		patch.Labels = &labels
	}
	if args.TargetRepoLabel.defined {
		label := ""
		if args.TargetRepoLabel.value != nil {
			text, ok := args.TargetRepoLabel.str()
			if !ok {
				return store.IssuePatch{}, &invalid
			}
			label = text
		}
		patch.TargetRepoLabel = &label
	}
	if args.TargetRepoID.defined {
		id := "" // null / "" unset the field
		if args.TargetRepoID.value != nil {
			id = issuesJSString(args.TargetRepoID.value) // String(x).slice(0, 40)
		}
		patch.TargetRepoID = &id
	}
	if args.SuggestedAssigneeUnionID.defined {
		assignee, ok := args.SuggestedAssigneeUnionID.str()
		if !ok {
			return store.IssuePatch{}, &invalid
		}
		patch.SuggestedAssigneeUnionID = &assignee
	}
	return patch, nil
}

func (a *Apex) issuesCorePatch(ctx context.Context, issueID string, p issuesPrincipal, args issuesPatchArgs) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(store.IssueDoc, store.TeamDoc) issuesResponse {
		patch, resp := issuesBuildPatch(args)
		if resp != nil {
			return *resp
		}
		doc, err := a.IssueStore.Patch(ctx, issueID, args.Rev, patch)
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesIssueBody{Issue: doc})
	})
}

type issuesClaimArgs struct {
	ClaimID          string
	MachineID        string
	Agent            any // BSON-shaped; nil when the request had no truthy agent
	RepoLabel        any
	ExpectedStateRev float64
}

func (a *Apex) issuesCoreClaim(ctx context.Context, issueID string, p issuesPrincipal, args issuesClaimArgs) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(store.IssueDoc, store.TeamDoc) issuesResponse {
		// P1#9: verify the named machine (ACTIVE + owned) before writing.
		if resp := a.issuesRequireOwnedActiveMachine(ctx, args.MachineID, p); resp != nil {
			return *resp
		}
		doc, err := a.IssueStore.Claim(ctx, issueID, store.ClaimIssueInput{
			ClaimID: args.ClaimID, UnionID: p.UnionID, Name: p.Name, MachineID: args.MachineID,
			Agent: args.Agent, RepoLabel: args.RepoLabel, ExpectedStateRev: args.ExpectedStateRev,
		})
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesClaimBody{Claim: doc.Claim, Issue: doc})
	})
}

type issuesBindArgs struct {
	ClaimID          string
	LocalTaskRef     string
	ExpectedStateRev float64
	MachineFence     string
	LocalTaskLabel   issueJS // passed through only when a string
	LocalTaskURL     issueJS
}

func (a *Apex) issuesCoreBind(ctx context.Context, issueID string, p issuesPrincipal, args issuesBindArgs) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(issue store.IssueDoc, _ store.TeamDoc) issuesResponse {
		// Only the claimant binds.
		if issue.Claim == nil || issue.Claim.UnionID != p.UnionID {
			return issuesForbidden
		}
		// Machine-token entry: the claim must be this machine's.
		if resp := issuesMachineFenceError(issue, args.MachineFence); resp != nil {
			return *resp
		}
		// The machine valid at claim time may since have been retired or
		// re-owned; bind is a real side effect, so re-check it.
		if resp := a.issuesRequireOwnedActiveMachine(ctx, issue.Claim.MachineID, p); resp != nil {
			return *resp
		}
		// Display fields come from the machine and are rendered verbatim on
		// the detail page: sanitize each one explicitly.
		var label, link string
		if text, ok := args.LocalTaskLabel.str(); ok {
			label, _ = issuesSanitizeLocalTaskLabel(text)
		}
		if text, ok := args.LocalTaskURL.str(); ok {
			link, _ = issuesSanitizeLocalTaskURL(text)
		}
		doc, err := a.IssueStore.Bind(ctx, issueID, store.BindIssueInput{
			ClaimID: args.ClaimID, LocalTaskRef: args.LocalTaskRef, ExpectedStateRev: args.ExpectedStateRev,
			LocalTaskLabel: label, LocalTaskURL: link,
		})
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesIssueBody{Issue: doc})
	})
}

type issuesStatusArgs struct {
	ClaimID          string
	ClaimEpoch       float64
	SourceSeq        float64
	Status           store.IssueStatus
	AttentionReason  store.AttentionReason
	ExpectedStateRev float64
	MachineFence     string
}

func (a *Apex) issuesCoreStatus(ctx context.Context, issueID string, p issuesPrincipal, args issuesStatusArgs) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(issue store.IssueDoc, _ store.TeamDoc) issuesResponse {
		// Machine checks only while a claim exists (a real side effect is
		// possible); the terminal-idempotent retry after the claim was cleared
		// must still answer 200.
		if issue.Claim != nil && issue.Claim.MachineID != "" {
			if resp := issuesMachineFenceError(issue, args.MachineFence); resp != nil {
				return *resp
			}
			if resp := a.issuesRequireOwnedActiveMachine(ctx, issue.Claim.MachineID, p); resp != nil {
				return *resp
			}
		}
		doc, err := a.IssueStore.StatusWriteback(ctx, issueID, store.StatusWritebackInput{
			UnionID: p.UnionID, ClaimID: args.ClaimID, ClaimEpoch: args.ClaimEpoch, SourceSeq: args.SourceSeq,
			Target: args.Status, AttentionReason: args.AttentionReason, ExpectedStateRev: args.ExpectedStateRev,
		})
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesIssueBody{Issue: doc})
	})
}

func (a *Apex) issuesCoreForceDetach(ctx context.Context, issueID string, p issuesPrincipal, expectedStateRev float64) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(issue store.IssueDoc, team store.TeamDoc) issuesResponse {
		if !issuesCanManage(issue, team, p) {
			return issuesForbidden
		}
		doc, err := a.IssueStore.ForceDetach(ctx, issueID, p.UnionID, expectedStateRev)
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesIssueBody{Issue: doc})
	})
}

func (a *Apex) issuesCoreArchive(ctx context.Context, issueID string, p issuesPrincipal) issuesResponse {
	return a.issuesWithIssue(ctx, issueID, p, func(issue store.IssueDoc, team store.TeamDoc) issuesResponse {
		if !issuesCanManage(issue, team, p) {
			return issuesForbidden
		}
		doc, err := a.IssueStore.Archive(ctx, issueID, p.UnionID)
		if err != nil {
			return issuesFromStoreError(err)
		}
		return issuesOK(issuesIssueBody{Issue: doc})
	})
}
