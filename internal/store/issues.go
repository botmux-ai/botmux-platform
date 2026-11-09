package store

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// IssueStore is the Issue Board repository (src/store/issues.ts). Every state
// transition is a CAS: FindOneAndUpdate with the exact TS precondition. When
// MongoDB is unavailable every operation fails closed with ErrUnavailable;
// callers answer 503 and never fall back to an in-memory authority.
//
// rev guards body/label edits and stateRev guards state transitions, so status
// write-back never conflicts with an edit. claimEpochCounter and eventSeq are
// independent monotonic counters.
//
// Numeric inputs that arrive in client JSON (rev, expectedStateRev, claimEpoch,
// sourceSeq, afterSeq) are float64: they are JS numbers in TS, and filtering
// on them unchanged keeps "1.5 never matches stateRev 1" semantics instead of
// letting a handler's integer conversion turn a conflict into a write.
type IssueStore struct {
	provider DatabaseProvider
	now      func() time.Time
}

func NewIssueStore(provider DatabaseProvider) *IssueStore {
	return NewIssueStoreWithClock(provider, time.Now)
}

func NewIssueStoreWithClock(provider DatabaseProvider, now func() time.Time) *IssueStore {
	if now == nil {
		now = time.Now
	}
	return &IssueStore{provider: provider, now: now}
}

const (
	issuesCollection      = "issues"
	issueEventsCollection = "issue_events"

	issueTitleMax       = 200
	issueBodyMax        = 16 * 1024
	issueRepoLabelMax   = 64
	issueRepoIDPatchMax = 40
)

// issueStatusCatchup is the §七 catch-up whitelist: /status is a projection of
// one claim/epoch, so any forward A2A jump, release, review rework and
// blocked/unblocked are allowed; only backward or cross-semantic moves are
// rejected.
var issueStatusCatchup = map[IssueStatus][]IssueStatus{
	IssueClaimed:    {IssueInProgress, IssueInReview, IssueDone, IssueNeedsAttention, IssueOpen, IssueReopened},
	IssueInProgress: {IssueInReview, IssueDone, IssueNeedsAttention, IssueOpen, IssueReopened},
	IssueInReview:   {IssueInProgress, IssueDone, IssueNeedsAttention, IssueOpen, IssueReopened},
	// needs_attention -> in_progress is further limited to task_blocked.
	IssueNeedsAttention: {IssueInProgress, IssueOpen, IssueReopened},
	IssueCancelling:     {IssueOpen, IssueReopened},
	IssueOpen:           {},
	IssueReopened:       {},
	IssueDone:           {},
}

// issueActiveStatuses may not be archived.
var issueActiveStatuses = []IssueStatus{IssueClaimed, IssueInProgress, IssueInReview, IssueCancelling, IssueNeedsAttention}

func (s *IssueStore) nowMS() int64 { return s.now().UnixMilli() }

func (s *IssueStore) issues(ctx context.Context) (DocumentCollection, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	return providerCollection(ctx, s.provider, issuesCollection)
}

// PersistenceAvailable mirrors issuesPersistenceAvailable: false in memory
// mode, where TS has no issue authority at all and skips the lease sweeper.
func (s *IssueStore) PersistenceAvailable() bool {
	return s != nil && s.provider != nil && !isMemoryProvider(s.provider)
}

// EnsureIndexes creates the issues/issue_events indexes from the TS
// ensureIndexes block. Like the rest of that block it is best-effort for the
// caller: missing create-index permission must not stop serving.
func (s *IssueStore) EnsureIndexes(ctx context.Context) error {
	issues, err := s.issues(ctx)
	if err != nil {
		return err
	}
	events, err := providerCollection(ctx, s.provider, issueEventsCollection)
	if err != nil {
		return err
	}
	specs := []struct {
		c    DocumentCollection
		spec IndexSpec
	}{
		{issues, IndexSpec{Keys: []IndexKey{{Field: "teamId", Order: 1}, {Field: "status", Order: 1}}}},
		// Sweeper and lazy takeover candidate scans use this compound index.
		{issues, IndexSpec{Keys: []IndexKey{{Field: "status", Order: 1}, {Field: "claim.bound", Order: 1}, {Field: "claim.leaseExpiresAt", Order: 1}}}},
		// The timeline's per-issue seq is the cross-collection idempotency key.
		{events, IndexSpec{Keys: []IndexKey{{Field: "issueId", Order: 1}, {Field: "seq", Order: 1}}, Unique: true}},
	}
	for _, item := range specs {
		if err := item.c.CreateIndexSpec(ctx, item.spec); err != nil {
			return failClosed(err)
		}
	}
	return nil
}

// appendEvent is best-effort (§审计写策略: P0 append, failures only logged).
// seq is the issue's eventSeq, already incremented by the caller's CAS, which
// keeps UNIQUE(issueId, seq).
func (s *IssueStore) appendEvent(ctx context.Context, issue IssueDoc, ev issueEventRecord) {
	events, err := providerCollection(ctx, s.provider, issueEventsCollection)
	if err != nil {
		return
	}
	ev.ID = randomDocumentID("iev")
	ev.IssueID = issue.ID
	ev.TeamID = issue.TeamID
	ev.Seq = jsNumber(float64(issue.EventSeq))
	ev.At = float64(s.nowMS())
	if err := events.InsertOne(ctx, ev); err != nil {
		slog.Warn("issue_events append failed (P0 best-effort)", "issueId", issue.ID, "error", err)
	}
}

func (s *IssueStore) findIssue(ctx context.Context, c DocumentCollection, issueID string) (IssueDoc, error) {
	var doc IssueDoc
	if err := c.FindOne(ctx, Document{"_id": issueID}, &doc); err != nil {
		if errors.Is(err, ErrNotFound) {
			return IssueDoc{}, ErrNotFound
		}
		return IssueDoc{}, failClosed(err)
	}
	return doc, nil
}

// casIssue runs one CAS transition. found=false means the precondition did
// not match.
func casIssue(ctx context.Context, c DocumentCollection, filter, update Document) (IssueDoc, bool, error) {
	var doc IssueDoc
	err := c.FindOneAndUpdate(ctx, filter, update, FindOneAndUpdateOptions{ReturnAfter: true}, &doc)
	if errors.Is(err, ErrNotFound) {
		return IssueDoc{}, false, nil
	}
	if err != nil {
		return IssueDoc{}, false, failClosed(err)
	}
	return doc, true, nil
}

// ---- reads ----

// ListForTeam returns a team's issues in natural order; archived issues are
// excluded unless includeArchived.
func (s *IssueStore) ListForTeam(ctx context.Context, teamID string, includeArchived bool) ([]IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return nil, err
	}
	query := Document{"teamId": teamID}
	if !includeArchived {
		query["archivedAt"] = Document{"$exists": false}
	}
	var docs []IssueDoc
	if err := c.FindMany(ctx, query, &docs); err != nil {
		return nil, failClosed(err)
	}
	if docs == nil {
		docs = []IssueDoc{}
	}
	return docs, nil
}

// Get returns ErrNotFound when the issue does not exist.
func (s *IssueStore) Get(ctx context.Context, issueID string) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	return s.findIssue(ctx, c, issueID)
}

// ListEvents returns the timeline entries with seq > afterSeq, ascending.
func (s *IssueStore) ListEvents(ctx context.Context, issueID string, afterSeq float64) ([]IssueEventDoc, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	c, err := providerCollection(ctx, s.provider, issueEventsCollection)
	if err != nil {
		return nil, err
	}
	var docs []IssueEventDoc
	filter := Document{"issueId": issueID, "seq": Document{"$gt": afterSeq}}
	if err := c.FindManyOptions(ctx, filter, FindOptions{Sort: []IndexKey{{Field: "seq", Order: 1}}}, &docs); err != nil {
		return nil, failClosed(err)
	}
	if docs == nil {
		docs = []IssueEventDoc{}
	}
	return docs, nil
}

// ---- writes ----

// CreateIssueInput mirrors createIssue's args. Empty strings and empty
// CustomFields mean "not provided"; Labels distinguishes nil (absent) from an
// empty slice (persisted as []), like the TS truthiness checks.
type CreateIssueInput struct {
	TeamID                   string
	Title                    string
	Body                     string
	Labels                   []string
	TargetRepoID             string
	TargetRepoLabel          string
	CustomFields             IssueCustomFields
	SuggestedAssigneeUnionID string
	CreatedBy                string
	CreatedByName            string
}

// Create inserts an open issue. A blank title (after JS trim) is ErrInvalid.
func (s *IssueStore) Create(ctx context.Context, in CreateIssueInput) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	title := truncateUTF16(in.Title, issueTitleMax)
	body := truncateUTF16(in.Body, issueBodyMax)
	if isJSBlank(title) {
		return IssueDoc{}, ErrInvalid
	}
	now := s.nowMS()
	record := issueRecord{
		ID: randomDocumentID("iss"), TeamID: in.TeamID, Title: title, Body: body, Status: IssueOpen,
		TargetRepoID: in.TargetRepoID, SuggestedAssigneeUnionID: in.SuggestedAssigneeUnionID,
		CreatedBy: in.CreatedBy, CreatedByName: in.CreatedByName,
		CreatedAt: float64(now), UpdatedAt: float64(now),
		Rev: 1, StateRev: 1, ClaimEpochCounter: 0, EventSeq: 1,
	}
	doc := IssueDoc{
		ID: record.ID, TeamID: in.TeamID, Title: title, Body: body, Status: IssueOpen,
		TargetRepoID: in.TargetRepoID, CreatedBy: in.CreatedBy, CreatedByName: in.CreatedByName,
		CreatedAt: now, UpdatedAt: now, Rev: 1, StateRev: 1, ClaimEpochCounter: 0, EventSeq: 1,
	}
	if in.Labels != nil {
		labels := append([]string{}, in.Labels...)
		record.Labels, doc.Labels = &labels, &labels
	}
	if in.TargetRepoLabel != "" {
		record.TargetRepoLabel = truncateUTF16(in.TargetRepoLabel, issueRepoLabelMax)
		doc.TargetRepoLabel = record.TargetRepoLabel
	}
	if len(in.CustomFields) > 0 {
		record.CustomFields = append(IssueCustomFields(nil), in.CustomFields...)
		doc.CustomFields = record.CustomFields
	}
	if in.SuggestedAssigneeUnionID != "" {
		assignee := in.SuggestedAssigneeUnionID
		doc.SuggestedAssigneeUnionID = &assignee
	}
	if err := c.InsertOne(ctx, record); err != nil {
		return IssueDoc{}, failClosed(err)
	}
	s.appendEvent(ctx, doc, issueEventRecord{Kind: IssueEventCreated, ToStatus: IssueOpen, ActorUnionID: in.CreatedBy})
	return doc, nil
}

// IssuePatch mirrors patchIssue's patch; nil fields are not touched. For
// TargetRepoID/TargetRepoLabel a pointer to "" clears the field (TS null or
// empty string). CustomFields are intentionally not patchable: they are only
// written through create-time form validation.
type IssuePatch struct {
	Title                    *string
	Body                     *string
	Labels                   *[]string
	TargetRepoID             *string
	TargetRepoLabel          *string
	SuggestedAssigneeUnionID *string
}

// Patch edits body/labels/assignee under the rev lock. Only open/reopened
// issues are editable (active issues are locked against requirement drift).
// Failures: ErrNotFound, ErrRevConflict, ErrIssueLocked.
func (s *IssueStore) Patch(ctx context.Context, issueID string, rev float64, patch IssuePatch) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	set := Document{"updatedAt": float64(s.nowMS())}
	unset := Document{}
	if patch.Title != nil {
		set["title"] = truncateUTF16(*patch.Title, issueTitleMax)
	}
	if patch.Body != nil {
		set["body"] = truncateUTF16(*patch.Body, issueBodyMax)
	}
	if patch.Labels != nil {
		labels := append([]string{}, (*patch.Labels)...)
		set["labels"] = labels
	}
	if patch.TargetRepoLabel != nil {
		if *patch.TargetRepoLabel == "" {
			unset["targetRepoLabel"] = ""
		} else {
			set["targetRepoLabel"] = truncateUTF16(*patch.TargetRepoLabel, issueRepoLabelMax)
		}
	}
	if patch.TargetRepoID != nil {
		if *patch.TargetRepoID == "" {
			unset["targetRepoId"] = ""
		} else {
			set["targetRepoId"] = truncateUTF16(*patch.TargetRepoID, issueRepoIDPatchMax)
		}
	}
	if patch.SuggestedAssigneeUnionID != nil {
		set["suggestedAssigneeUnionId"] = *patch.SuggestedAssigneeUnionID
	}
	update := Document{"$set": set, "$inc": Document{"rev": int32(1)}}
	if len(unset) > 0 {
		update["$unset"] = unset
	}
	filter := Document{"_id": issueID, "rev": rev, "status": Document{"$in": []IssueStatus{IssueOpen, IssueReopened}}}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if ok {
		return doc, nil
	}
	// Tell a rev conflict apart from an active-state lock.
	cur, err := s.findIssue(ctx, c, issueID)
	if err != nil {
		return IssueDoc{}, err
	}
	if float64(cur.Rev) != rev {
		return IssueDoc{}, ErrRevConflict
	}
	return IssueDoc{}, ErrIssueLocked
}

// ClaimIssueInput mirrors claimIssue's args. Agent/RepoLabel are persisted
// verbatim when JS-truthy and omitted otherwise. They carry the client's JSON
// value already shaped for BSON the way the Node driver would write it
// (string, bool, int32/float64 numbers, bson.D objects in JS property order,
// bson.A arrays).
type ClaimIssueInput struct {
	ClaimID          string
	UnionID          string
	Name             string
	MachineID        string
	Agent            any
	RepoLabel        any
	ExpectedStateRev float64
}

// Claim reserves an issue (§六 step 1). Legal prior states: open, reopened,
// or claimed with an unbound, expired reservation. claimEpochCounter++ and the
// claim snapshots it. Retrying the same claimId by the same machine+person
// inside the lease returns the existing claim (before any stateRev check).
// Failures: ErrNotFound, ErrAlreadyClaimed, ErrClaimExpired,
// ErrNeedsForceDetach, ErrStateRevConflict.
func (s *IssueStore) Claim(ctx context.Context, issueID string, in ClaimIssueInput) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	now := s.nowMS()
	cur, err := s.findIssue(ctx, c, issueID)
	if err != nil {
		return IssueDoc{}, err
	}
	// Idempotent hit requires the same claimId *and* the same actor. claimId is
	// a client-generated 128-bit key; if two machines ever share one (copied
	// key, or a client deriving it from issueId) comparing only the key would
	// hand someone else's claim back as "your retry". A different actor is
	// already_claimed, and the lease is deliberately ignored: falling through to
	// stale takeover would keep the shared claimId on the new claim, letting the
	// original machine's late bind hijack it. Taking over an expired unbound
	// reservation requires a fresh random claimId (§六 step 1).
	if cur.Claim != nil && cur.Claim.ClaimID == in.ClaimID {
		if cur.Claim.MachineID != in.MachineID || cur.Claim.UnionID != in.UnionID {
			return IssueDoc{}, ErrAlreadyClaimed
		}
		if cur.Claim.LeaseExpiresAt > now {
			return cur, nil
		}
		return IssueDoc{}, ErrClaimExpired
	}
	if cur.Status == IssueNeedsAttention {
		return IssueDoc{}, ErrNeedsForceDetach
	}
	freshEligible := cur.Status == IssueOpen || cur.Status == IssueReopened
	staleTakeover := cur.Status == IssueClaimed && cur.Claim != nil && !cur.Claim.Bound && cur.Claim.LeaseExpiresAt <= now
	if !freshEligible && !staleTakeover {
		return IssueDoc{}, ErrAlreadyClaimed
	}

	claim := issueClaimRecord{
		ClaimID: in.ClaimID, ClaimEpoch: jsNumber(float64(cur.ClaimEpochCounter + 1)),
		UnionID: in.UnionID, Name: in.Name, MachineID: in.MachineID,
		ClaimedAt: float64(now), LeaseExpiresAt: float64(now + ClaimLeaseMS),
		Bound: false, LastSourceSeq: 0,
	}
	if jsTruthy(in.Agent) {
		claim.Agent = in.Agent
	}
	if jsTruthy(in.RepoLabel) {
		claim.RepoLabel = in.RepoLabel
	}
	// CAS on prior state + exact stateRev; the lease/unbound conditions make the
	// two branches mutually exclusive.
	filter := Document{"_id": issueID, "stateRev": in.ExpectedStateRev}
	if freshEligible {
		filter["status"] = Document{"$in": []IssueStatus{IssueOpen, IssueReopened}}
	} else {
		filter["status"] = IssueClaimed
		filter["claim.bound"] = false
		filter["claim.leaseExpiresAt"] = Document{"$lte": float64(now)}
	}
	update := Document{
		"$set": Document{"status": IssueClaimed, "claim": claim, "updatedAt": float64(now)},
		"$inc": Document{"stateRev": int32(1), "claimEpochCounter": int32(1), "eventSeq": int32(1)},
	}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if !ok {
		return IssueDoc{}, ErrStateRevConflict
	}
	s.appendEvent(ctx, doc, issueEventRecord{Kind: IssueEventClaimed, FromStatus: cur.Status, ToStatus: IssueClaimed, ActorUnionID: in.UnionID})
	return doc, nil
}

// BindIssueInput mirrors bindIssue's args. LocalTaskLabel/LocalTaskURL are
// display fields written only when non-empty; the caller sanitizes them
// (https-only URL) before they reach the store.
type BindIssueInput struct {
	ClaimID          string
	LocalTaskRef     string
	ExpectedStateRev float64
	LocalTaskLabel   string
	LocalTaskURL     string
}

// Bind attaches the local task (§六 step 3): claimId matches, unbound and
// lease alive -> bound=true and the lease resets to the activation window.
// Re-binding the same localTaskRef while still claimed and leased returns the
// current issue. Failures: ErrNotFound, ErrClaimMismatch, ErrClaimExpired,
// ErrStateRevConflict.
func (s *IssueStore) Bind(ctx context.Context, issueID string, in BindIssueInput) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	now := s.nowMS()
	cur, err := s.findIssue(ctx, c, issueID)
	if err != nil {
		return IssueDoc{}, err
	}
	if cur.Claim == nil || cur.Claim.ClaimID != in.ClaimID {
		return IssueDoc{}, ErrClaimMismatch
	}
	if cur.Claim.Bound {
		if cur.Status == IssueClaimed && cur.Claim.LeaseExpiresAt > now && cur.Claim.LocalTaskRef == in.LocalTaskRef {
			return cur, nil
		}
		if cur.Claim.LeaseExpiresAt <= now || cur.Status != IssueClaimed {
			return IssueDoc{}, ErrClaimExpired
		}
		return IssueDoc{}, ErrClaimMismatch
	}
	if cur.Claim.LeaseExpiresAt <= now {
		return IssueDoc{}, ErrClaimExpired
	}
	set := Document{
		"claim.localTaskRef":   in.LocalTaskRef,
		"claim.bound":          true,
		"claim.leaseExpiresAt": float64(now + ActivationLeaseMS),
		"updatedAt":            float64(now),
	}
	// Display fields only when given: an empty string would render as
	// "present but blank" on the detail page.
	if in.LocalTaskLabel != "" {
		set["claim.localTaskLabel"] = in.LocalTaskLabel
	}
	if in.LocalTaskURL != "" {
		set["claim.localTaskUrl"] = in.LocalTaskURL
	}
	filter := Document{
		"_id":                  issueID,
		"stateRev":             in.ExpectedStateRev,
		"status":               IssueClaimed,
		"claim.claimId":        in.ClaimID,
		"claim.bound":          false,
		"claim.leaseExpiresAt": Document{"$gt": float64(now)},
	}
	update := Document{"$set": set, "$inc": Document{"stateRev": int32(1), "eventSeq": int32(1)}}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if !ok {
		return IssueDoc{}, ErrStateRevConflict
	}
	s.appendEvent(ctx, doc, issueEventRecord{Kind: IssueEventBound, ActorUnionID: cur.Claim.UnionID})
	return doc, nil
}

// StatusWritebackInput mirrors statusWriteback's args. An empty
// AttentionReason means "not provided" (defaults to run_timeout).
type StatusWritebackInput struct {
	UnionID          string
	ClaimID          string
	ClaimEpoch       float64
	SourceSeq        float64
	Target           IssueStatus
	AttentionReason  AttentionReason
	ExpectedStateRev float64
}

// StatusWriteback applies a status projection (§七): terminal idempotency,
// epoch fence, claimant check, sourceSeq monotonic idempotency, catch-up
// whitelist and stateRev CAS; open/reopened/done clear the claim. The
// two-step authorization lives in the caller. Failures: ErrNotFound,
// ErrStaleEpoch, ErrIssueForbidden, ErrInvalidTransition,
// ErrStateRevConflict.
func (s *IssueStore) StatusWriteback(ctx context.Context, issueID string, in StatusWritebackInput) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	now := s.nowMS()
	cur, err := s.findIssue(ctx, c, issueID)
	if err != nil {
		return IssueDoc{}, err
	}
	// Terminal idempotency (§七 P1#3/#2): claim already cleared, epoch counter
	// matches and the status already reached the target -> no-op success.
	if cur.Claim == nil && float64(cur.ClaimEpochCounter) == in.ClaimEpoch && cur.Status == in.Target {
		return cur, nil
	}
	if cur.Claim == nil {
		return IssueDoc{}, ErrStaleEpoch
	}
	if float64(cur.Claim.ClaimEpoch) != in.ClaimEpoch || cur.Claim.ClaimID != in.ClaimID {
		return IssueDoc{}, ErrStaleEpoch
	}
	// The caller guarantees principal == claim.unionId owns the machine.
	if cur.Claim.UnionID != in.UnionID {
		return IssueDoc{}, ErrIssueForbidden
	}
	// sourceSeq at or below the applied one is a duplicate/late retry: return
	// the current issue without side effects.
	if in.SourceSeq <= cur.Claim.LastSourceSeq {
		return cur, nil
	}
	if !issueStatusAllowed(cur.Status, in.Target) {
		return IssueDoc{}, ErrInvalidTransition
	}
	// needs_attention -> in_progress only unblocks task_blocked (§七 v12).
	if cur.Status == IssueNeedsAttention && in.Target == IssueInProgress && cur.AttentionReason != AttentionTaskBlocked {
		return IssueDoc{}, ErrInvalidTransition
	}

	clearsClaim := in.Target == IssueOpen || in.Target == IssueReopened || in.Target == IssueDone
	set := Document{"status": in.Target, "updatedAt": float64(now)}
	// Never $set claim.lastSourceSeq when the same update $unsets claim: Mongo
	// rejects the pair ("Updating the path 'claim.lastSourceSeq' would create a
	// conflict at 'claim'") and the error used to surface as a permanent 503
	// for done/open/reopened (TS commit 4e52262). Terminal idempotency does not
	// rely on lastSourceSeq.
	if !clearsClaim {
		set["claim.lastSourceSeq"] = jsNumber(in.SourceSeq)
	}
	unset := Document{}
	if in.Target == IssueNeedsAttention {
		reason := in.AttentionReason
		if reason == "" {
			reason = AttentionRunTimeout
		}
		set["attentionSince"] = float64(now)
		set["attentionReason"] = reason
	} else {
		unset["attentionSince"] = ""
		unset["attentionReason"] = ""
	}
	if clearsClaim {
		unset["claim"] = ""
	}
	update := Document{"$set": set, "$inc": Document{"stateRev": int32(1), "eventSeq": int32(1)}}
	if len(unset) > 0 {
		update["$unset"] = unset
	}
	filter := Document{"_id": issueID, "stateRev": in.ExpectedStateRev, "claim.claimId": in.ClaimID}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if !ok {
		return IssueDoc{}, ErrStateRevConflict
	}
	kind := IssueEventStatus
	if clearsClaim {
		kind = IssueEventReleased
	}
	s.appendEvent(ctx, doc, issueEventRecord{Kind: kind, FromStatus: cur.Status, ToStatus: in.Target, ActorUnionID: in.UnionID})
	return doc, nil
}

func issueStatusAllowed(from, to IssueStatus) bool {
	for _, allowed := range issueStatusCatchup[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// ForceDetach moves needs_attention / long-stuck cancelling to reopened
// (§五): claimEpochCounter++ and the claim is cleared. Failures: ErrNotFound,
// ErrInvalidTransition, ErrStateRevConflict.
func (s *IssueStore) ForceDetach(ctx context.Context, issueID, actorUnionID string, expectedStateRev float64) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	now := s.nowMS()
	filter := Document{
		"_id":      issueID,
		"stateRev": expectedStateRev,
		"status":   Document{"$in": []IssueStatus{IssueNeedsAttention, IssueCancelling}},
	}
	update := Document{
		"$set":   Document{"status": IssueReopened, "updatedAt": float64(now)},
		"$unset": Document{"claim": "", "attentionSince": "", "attentionReason": "", "cancelCommandId": ""},
		"$inc":   Document{"stateRev": int32(1), "claimEpochCounter": int32(1), "eventSeq": int32(1)},
	}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if !ok {
		cur, err := s.findIssue(ctx, c, issueID)
		if err != nil {
			return IssueDoc{}, err
		}
		if cur.Status != IssueNeedsAttention && cur.Status != IssueCancelling {
			return IssueDoc{}, ErrInvalidTransition
		}
		return IssueDoc{}, ErrStateRevConflict
	}
	s.appendEvent(ctx, doc, issueEventRecord{
		Kind: IssueEventForceDetached, ToStatus: IssueReopened, ActorUnionID: actorUnionID,
		Detail: "强制脱离：旧执行可能仍在运行",
	})
	return doc, nil
}

// Archive soft-deletes (§五) by setting archivedAt; active issues are
// refused and an already archived issue is returned unchanged. Failures:
// ErrNotFound, ErrIssueActive, ErrConflict (lost the CAS to a claim).
func (s *IssueStore) Archive(ctx context.Context, issueID, actorUnionID string) (IssueDoc, error) {
	c, err := s.issues(ctx)
	if err != nil {
		return IssueDoc{}, err
	}
	now := s.nowMS()
	cur, err := s.findIssue(ctx, c, issueID)
	if err != nil {
		return IssueDoc{}, err
	}
	if cur.ArchivedAt != 0 {
		return cur, nil
	}
	for _, active := range issueActiveStatuses {
		if cur.Status == active {
			return IssueDoc{}, ErrIssueActive
		}
	}
	filter := Document{"_id": issueID, "status": Document{"$nin": issueActiveStatuses}}
	update := Document{
		"$set": Document{"archivedAt": float64(now), "updatedAt": float64(now)},
		"$inc": Document{"stateRev": int32(1), "eventSeq": int32(1)},
	}
	doc, ok, err := casIssue(ctx, c, filter, update)
	if err != nil {
		return IssueDoc{}, err
	}
	if !ok {
		return IssueDoc{}, ErrConflict
	}
	s.appendEvent(ctx, doc, issueEventRecord{Kind: IssueEventArchived, ActorUnionID: actorUnionID})
	return doc, nil
}

// IssueSweepResult counts the reservations the sweeper moved.
type IssueSweepResult struct {
	ToOpen      int
	ToAttention int
}

// SweepExpiredLeases is the lease sweeper (§五 path 2): expired unbound
// reservations go back to open, expired bound ones to
// needs_attention(claim_activate_timeout). The CAS preconditions make
// concurrent replicas and repeated sweeps succeed at most once per issue. The
// counts are valid even when an error interrupts the sweep (TS logs and
// returns the partial counts).
func (s *IssueStore) SweepExpiredLeases(ctx context.Context) (IssueSweepResult, error) {
	var result IssueSweepResult
	c, err := s.issues(ctx)
	if err != nil {
		return result, err
	}
	now := float64(s.nowMS())
	for _, bound := range []bool{false, true} {
		candidates := Document{"status": IssueClaimed, "claim.bound": bound, "claim.leaseExpiresAt": Document{"$lte": now}}
		var expired []IssueDoc
		if err := c.FindMany(ctx, candidates, &expired); err != nil {
			slog.Warn("sweepExpiredLeases failed", "error", err)
			return result, failClosed(err)
		}
		for _, issue := range expired {
			filter := Document{"_id": issue.ID, "status": IssueClaimed, "claim.bound": bound, "claim.leaseExpiresAt": Document{"$lte": now}}
			var update Document
			var event issueEventRecord
			if !bound {
				update = Document{
					"$set":   Document{"status": IssueOpen, "updatedAt": now},
					"$unset": Document{"claim": ""},
					"$inc":   Document{"stateRev": int32(1), "eventSeq": int32(1)},
				}
				event = issueEventRecord{Kind: IssueEventLeaseExpired, ToStatus: IssueOpen, ActorUnionID: "system", Detail: "unbound claim lease expired"}
			} else {
				update = Document{
					"$set": Document{
						"status": IssueNeedsAttention, "attentionSince": now,
						"attentionReason": AttentionClaimActivateTimeout, "updatedAt": now,
					},
					"$inc": Document{"stateRev": int32(1), "eventSeq": int32(1)},
				}
				event = issueEventRecord{Kind: IssueEventLeaseExpired, ToStatus: IssueNeedsAttention, ActorUnionID: "system", Detail: "bound claim activation lease expired"}
			}
			doc, ok, err := casIssue(ctx, c, filter, update)
			if err != nil {
				slog.Warn("sweepExpiredLeases failed", "issueId", issue.ID, "error", err)
				return result, err
			}
			if !ok {
				continue
			}
			if bound {
				result.ToAttention++
			} else {
				result.ToOpen++
			}
			s.appendEvent(ctx, doc, event)
		}
	}
	return result, nil
}
