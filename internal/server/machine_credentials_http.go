package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// POST /v1/machine/credential-grant (machine-credentials-http.ts, DESIGN
// §3.2): the daemon, holding this machine's token, asks for a short-lived
// credential of one tool on behalf of the turn's sender (a unionId the daemon
// resolved from the Feishu event; the CLI cannot change it).
//
// Every check refuses outright, never degrades:
//  1. machine token valid, machine ACTIVE, ownership current (RequireMachineAuth);
//  2. well-formed body; per-machine rate limit;
//  3. sender is the machine owner, shares at least one team with them, or allowed this machine
//     (403 not_teammate; a daemon that sends machineConsent:true gets 403 consent_missing instead);
//  4. sender authorized this platform (404 credential_not_found) and it is not marked for re-authorization (409);
//  5. sender's consent covers this use: self use, consent for a shared team, or the machine allowance
//     given while the machine had this owner (403 consent_missing);
//  6. the provider turns the refresh credential into a short-lived one (refresh rejected → mark reauth + 409; transient → 502).
//
// The platform cannot independently verify that this person triggered the
// turn — it trusts the daemon. The team boundary, the person's consent, the
// per-grant audit and the first-use notification are the compensation; none
// of them may be relaxed here.

var (
	credentialGrantUnionID = regexp.MustCompile(`^[A-Za-z0-9_-]{4,128}$`)
	credentialGrantID      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)
)

// credentialsPageURL is where a refused grant sends the person to (re)authorize.
func (a *Apex) credentialsPageURL() string {
	return a.Config.PublicBaseURL + credentialsPagePath
}

// credentialFieldTrue is `body[name] === true`.
func credentialFieldTrue(fields map[string]json.RawMessage, name string) bool {
	return string(bytes.TrimSpace(fields[name])) == "true"
}

// credentialAllowance is how a person may use a machine's grants before their
// consent is looked at: they are the owner, share teams with the owner, or
// allowed the machine for this platform (only read when no team is shared).
type credentialAllowance struct {
	self          bool
	sharedTeamIDs []string
	machineOK     bool
}

func (a *Apex) credentialAllowance(ctx context.Context, machine *MachineAuth, unionID string, platform store.CredentialPlatform) (credentialAllowance, error) {
	al := credentialAllowance{self: unionID == machine.UnionID}
	if al.self {
		return al, nil
	}
	if a.Repository == nil {
		return al, store.ErrUnavailable
	}
	teams, err := a.Repository.ListTeamsForUser(ctx, machine.UnionID)
	if err != nil {
		return al, err
	}
	for _, team := range teams {
		if credentialContains(team.Members, unionID) {
			al.sharedTeamIDs = append(al.sharedTeamIDs, team.ID)
		}
	}
	if len(al.sharedTeamIDs) == 0 {
		al.machineOK, err = a.machineConsentCovers(ctx, machine, unionID, platform)
	}
	return al, err
}

// machineConsentCovers reports whether the person allowed this machine for
// platform while it belonged to its current owner.
func (a *Apex) machineConsentCovers(ctx context.Context, machine *MachineAuth, unionID string, platform store.CredentialPlatform) (bool, error) {
	consent, err := a.CredentialStore.GetMachineConsent(ctx, unionID, machine.MachineID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return consent.OwnerUnionID == machine.UnionID && credentialContains(consent.Platforms, string(platform)), nil
}

// credentialBasis is what lets the person's credential be used on the machine:
// "self", "team" (consent for a shared team) or "machine"; "" when none.
func (a *Apex) credentialBasis(ctx context.Context, machine *MachineAuth, unionID string, platform store.CredentialPlatform, al credentialAllowance, consent store.ConsentTeams) (string, error) {
	if al.self {
		return "self", nil
	}
	if len(al.sharedTeamIDs) > 0 {
		teamOK := consent.All
		for _, id := range al.sharedTeamIDs {
			teamOK = teamOK || credentialContains(consent.Teams, id)
		}
		if teamOK {
			return "team", nil
		}
	}
	machineOK := al.machineOK
	if !machineOK && len(al.sharedTeamIDs) > 0 {
		var err error
		if machineOK, err = a.machineConsentCovers(ctx, machine, unionID, platform); err != nil {
			return "", err
		}
	}
	if machineOK {
		return "machine", nil
	}
	return "", nil
}

type credentialGrantRefusal struct {
	Error        string `json:"error"`
	AuthorizeURL string `json:"authorizeUrl,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type credentialRateLimitedBody struct {
	Error        string `json:"error"`
	RetryAfterMS int64  `json:"retryAfterMs"`
}

type credentialGrantedBody struct {
	OK        bool                     `json:"ok"`
	Tool      store.CredentialPlatform `json:"tool"`
	UnionID   string                   `json:"unionId"`
	Variables credential.Variables     `json:"variables"`
	ExpiresAt int64                    `json:"expiresAt"`
	// CloudJWTRegions answers a request that named regions: the ones this
	// platform tried. Absent otherwise, as from a platform without regions.
	CloudJWTRegions *[]string `json:"cloudJwtRegions,omitempty"`
}

// credentialGrantRegionsMax bounds the regions one request may name.
const credentialGrantRegionsMax = 16

// regionalWaitBudget bounds how long a grant waits for its regional mints,
// counted from when they start (alongside the default one). It stays under the
// daemon's first-attempt budget with room for the rest of the grant: a slow
// regional login must never cost the person the default ticket. A mint that
// misses it finishes in the background, writes back and warms the cache, so
// the next grant has it.
const regionalWaitBudget = 5 * time.Second

// regionalMinRemaining: a regional ticket closer to its end than this is left
// out. The grant lasts as long as its first token, and a daemon refuses a
// grant that has already expired — a dying regional ticket would take the
// default one down with it.
const regionalMinRemaining = time.Minute

// credentialGrantRegions reads the optional `cloudJwtRegions` member: the
// token partitions a daemon can use besides the default one. requested=false
// when it is absent or not an array of strings — an older daemon sends none,
// and a regional variable it did not ask for would make it reject the whole
// grant, so anything unreadable is treated as not asked.
func credentialGrantRegions(body map[string]json.RawMessage) (regions []string, requested bool) {
	raw, present := body["cloudJwtRegions"]
	if !present {
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil || len(items) > credentialGrantRegionsMax {
		return nil, false
	}
	regions = make([]string, 0, len(items))
	for _, item := range items {
		// json.Unmarshal reads a null into a string as "", so check the type.
		var region string
		if trimmed := bytes.TrimSpace(item); len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(trimmed, &region) != nil {
			return nil, false
		}
		regions = append(regions, region)
	}
	return regions, true
}

// regionalGrant is one regional record's mint for a grant.
type regionalGrant struct {
	login  credential.RegionalLogin
	doc    store.CredentialDoc
	minted credential.MintResult
	done   chan struct{}
}

// regionalGrants are the regional mints one grant started.
type regionalGrants struct {
	// tried answers the request: the regions it named that this platform has.
	tried    []string
	deadline time.Time
	mints    []*regionalGrant
}

// startRegionalGrants starts minting, in parallel, the regional records this
// person holds for the requested regions (in the provider's order). Only
// records the person authorized and that are not marked for
// re-authorization are minted.
func (a *Apex) startRegionalGrants(ctx context.Context, unionID string, platform store.CredentialPlatform, requested []string) *regionalGrants {
	g := &regionalGrants{tried: []string{}, deadline: a.credentialNow().Add(a.regionalWaitBudget())}
	var logins []credential.RegionalLogin
	for _, login := range a.Credentials.Providers.Regions(string(platform)) {
		if credentialContains(requested, login.Region) {
			g.tried = append(g.tried, login.Region)
			logins = append(logins, login)
		}
	}
	if len(logins) == 0 {
		return g
	}
	// One read for all of them: most people hold no regional login, and every
	// grant from a daemon that names regions comes through here.
	docs, err := a.CredentialStore.ListForUser(ctx, unionID)
	if err != nil {
		slog.Warn("credential grant: regional logins unreadable, granting without them", "unionId", unionID, "platform", string(platform))
		return g
	}
	for _, login := range logins {
		for _, doc := range docs {
			if string(doc.Platform) == login.Platform && doc.Status == store.CredentialActive {
				r := &regionalGrant{login: login, doc: doc, done: make(chan struct{})}
				g.mints = append(g.mints, r)
				go func() {
					defer close(r.done)
					r.minted = a.mintCredential(ctx, r.doc)
				}()
			}
		}
	}
	return g
}

func (a *Apex) regionalWaitBudget() time.Duration {
	if a.Credentials.RegionalWait > 0 {
		return a.Credentials.RegionalWait
	}
	return regionalWaitBudget
}

// collect settles every regional mint — write-back, re-authorization marks —
// whether or not its token is used, and returns the tokens that may go out:
// when use is set, those finished by the deadline and with life left. A mint
// still running then is settled in the background when it finishes.
func (a *Apex) collectRegionalGrants(ctx context.Context, g *regionalGrants, unionID, machineID string, use bool) (variables credential.Variables, expiresAt int64) {
	if g == nil {
		return nil, 0
	}
	var timeout <-chan time.Time
	if use {
		if wait := g.deadline.Sub(a.credentialNow()); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			timeout = timer.C
		}
	}
	for _, r := range g.mints {
		finished := false
		if timeout != nil {
			select {
			case <-r.done:
				finished = true
			case <-timeout:
				timeout = nil
			}
		} else {
			select {
			case <-r.done:
				finished = true
			default:
			}
		}
		if !finished {
			slog.Warn("credential grant: regional login still minting, granting without it", "unionId", unionID, "platform", r.login.Platform)
			go func(r *regionalGrant) {
				<-r.done
				a.settleRegionalGrant(ctx, unionID, machineID, r, false)
			}(r)
			continue
		}
		if regional := a.settleRegionalGrant(ctx, unionID, machineID, r, use); len(regional) > 0 {
			variables = append(variables, regional...)
			if expiresAt == 0 || r.minted.ExpiresAt < expiresAt {
				expiresAt = r.minted.ExpiresAt
			}
		}
	}
	return variables, expiresAt
}

// settleRegionalGrant writes back what one regional mint changed and, when
// use is set and the token has life left, returns its variables. A regional
// login that needs re-authorization costs only its own region: it is marked
// like any other credential and the grant goes on.
func (a *Apex) settleRegionalGrant(ctx context.Context, unionID, machineID string, r *regionalGrant, use bool) credential.Variables {
	if !r.minted.OK {
		if r.minted.Reason == credential.MintReauthRequired {
			version := r.doc.Version
			a.CredentialStore.MarkReauthRequired(ctx, r.doc.ID, r.minted.Detail, &version)
		}
		slog.Warn("credential grant: regional login not minted", "unionId", unionID, "platform", r.login.Platform, "reason", string(r.minted.Reason), "detail", r.minted.Detail)
		return nil
	}
	if r.minted.UpdatedSealed != nil {
		if err := a.CredentialStore.UpdateSealed(ctx, r.doc.ID, r.doc.Version, *r.minted.UpdatedSealed, store.CredentialSealedPatch{RefreshExpiresAt: r.minted.RefreshExpiresAt}); err != nil {
			slog.Warn("credential grant: regional write-back skipped", "unionId", unionID, "platform", r.login.Platform)
		}
	}
	if !use {
		return nil
	}
	if r.minted.ExpiresAt-a.credentialNow().UnixMilli() < regionalMinRemaining.Milliseconds() {
		slog.Warn("credential grant: regional token about to expire, granting without it", "unionId", unionID, "platform", r.login.Platform)
		return nil
	}
	a.CredentialStore.TouchUse(ctx, r.doc.ID, machineID)
	return r.minted.Variables
}

func (a *Apex) handleMachineCredentialsAPI(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/v1/machine/credential-grant" {
		return false
	}
	if r.Method != http.MethodPost {
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return true
	}
	timer := newStageTimer(nil)
	outcome, timedMachine, timedPlatform := "rejected", "", ""
	defer func() { logCredentialGrantTiming(timer, outcome, timedMachine, timedPlatform) }()
	machine, ok := a.RequireMachineAuth(w, r)
	timer.mark("auth")
	if !ok {
		return true
	}
	timedMachine = machine.MachineID
	if !a.credentialVaultEnabled() {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "credential_vault_disabled"})
		return true
	}
	body := readCredentialJSONFields(r)
	unionID, unionOK := credentialFieldString(body, "unionId")
	tool, toolOK := credentialFieldString(body, "tool")
	appID, appOK := credentialFieldString(body, "appId")
	sessionID, sessionOK := credentialFieldString(body, "sessionId")
	turnID, turnOK := credentialFieldString(body, "turnId")
	_, turnPresent := body["turnId"]
	if body == nil || !unionOK || !credentialGrantUnionID.MatchString(unionID) ||
		!toolOK || !a.Credentials.Providers.Known(tool) ||
		!appOK || !credentialGrantID.MatchString(appID) ||
		!sessionOK || !credentialGrantID.MatchString(sessionID) ||
		(turnPresent && (!turnOK || !credentialGrantID.MatchString(turnID))) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return true
	}
	if _, present := body["machineId"]; present {
		// `body.machineId !== machineId`: anything but the authenticated id
		// (including null or a number) is a mismatch.
		claimed, isString := credentialFieldString(body, "machineId")
		if !isString || claimed != machine.MachineID {
			writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "machine_mismatch"})
			return true
		}
	}
	platform := store.CredentialPlatform(tool)
	timedPlatform = tool
	authorizeURL := a.credentialsPageURL()

	limiter := a.Credentials.GrantLimiter
	if limiter == nil {
		limiter = defaultCredentialGrantLimiter
	}
	if retryAfter, limited := limiter.take(machine.MachineID, a.credentialNow().UnixMilli()); limited {
		writeJSONNoStore(w, http.StatusTooManyRequests, credentialRateLimitedBody{Error: "rate_limited", RetryAfterMS: retryAfter})
		return true
	}

	// The grant may rotate a one-time refresh token: once minting starts it
	// must finish (write-back, audit) even if the daemon disconnects.
	ctx := context.WithoutCancel(r.Context())
	audit := func(outcome store.CredentialGrantOutcome, reason, machineName, basis string) {
		a.CredentialStore.AppendGrant(ctx, store.CredentialGrantInput{
			UnionID: unionID, Platform: platform, MachineID: machine.MachineID, MachineName: machineName,
			OwnerUnionID: machine.UnionID, AppID: appID, SessionID: sessionID, TurnID: turnID,
			Outcome: outcome, Reason: reason, Basis: basis,
		})
	}
	refuse := func(status int, refusal credentialGrantRefusal) bool {
		audit(store.CredentialRefused, refusal.Error, "", "")
		writeJSONNoStore(w, status, refusal)
		return true
	}

	// 3. Who may ask: self use, a teammate of the owner, or a person who
	// allowed this machine.
	al, err := a.credentialAllowance(ctx, machine, unionID, platform)
	timer.mark("teams")
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}
	if !al.self && len(al.sharedTeamIDs) == 0 && !al.machineOK {
		if credentialFieldTrue(body, "machineConsent") {
			return refuse(http.StatusForbidden, credentialGrantRefusal{Error: "consent_missing", AuthorizeURL: authorizeURL})
		}
		return refuse(http.StatusForbidden, credentialGrantRefusal{Error: "not_teammate"})
	}

	// 4. The credential exists and is usable.
	doc, err := a.CredentialStore.Get(ctx, unionID, platform)
	timer.mark("get")
	if errors.Is(err, store.ErrNotFound) {
		return refuse(http.StatusNotFound, credentialGrantRefusal{Error: "credential_not_found", AuthorizeURL: authorizeURL})
	}
	if err != nil {
		// An unreadable stored document needs a fresh authorization; a store
		// outage is transient. Neither is audited (the audit would fail too).
		if errors.Is(err, store.ErrInvalid) {
			writeJSONNoStore(w, http.StatusConflict, credentialGrantRefusal{Error: "credential_reauth_required", AuthorizeURL: authorizeURL})
		} else {
			writeJSONNoStore(w, http.StatusServiceUnavailable, credentialGrantRefusal{Error: "store_unavailable", AuthorizeURL: authorizeURL})
		}
		return true
	}
	if doc.Status == store.CredentialReauthRequired {
		return refuse(http.StatusConflict, credentialGrantRefusal{Error: "credential_reauth_required", AuthorizeURL: authorizeURL, Detail: doc.StatusReason})
	}

	// 5. Consent (self use is always allowed).
	basis, err := a.credentialBasis(ctx, machine, unionID, platform, al, doc.ConsentTeams)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}
	if basis == "" {
		return refuse(http.StatusForbidden, credentialGrantRefusal{Error: "consent_missing", AuthorizeURL: authorizeURL})
	}

	// 6. Mint the short-lived credential. The regional logins a request names
	// are minted alongside, not after: on a cache miss each takes seconds, and
	// the daemon's first attempt has a budget of its own.
	regions, regionsRequested := credentialGrantRegions(body)
	_, regionalProvider := a.Credentials.Providers.DeviceLogin(tool).(credential.RegionalDeviceLogin)
	regionsAnswered := regionsRequested && regionalProvider
	var regional *regionalGrants
	if regionsAnswered {
		regional = a.startRegionalGrants(ctx, unionID, platform, regions)
	}
	minted := a.mintCredential(ctx, doc)
	timer.mark("mint")
	if !minted.OK && minted.Reason == credential.MintReauthRequired {
		// Refresh tokens are single-use: the loser of a concurrent refresh is
		// told invalid_grant. Re-read first — a changed version means another
		// request just refreshed and wrote back, so retry once with the new
		// record (usually reusing its fresh access token) instead of voiding
		// the credential.
		again, err := a.CredentialStore.Get(ctx, unionID, platform)
		if err == nil && again.Version != doc.Version && again.Status == store.CredentialActive {
			doc = again
			minted = a.mintCredential(ctx, doc)
		}
		timer.mark("remint")
	}
	if !minted.OK {
		// No regional token goes out, but what the regional mints changed is
		// still written back.
		a.collectRegionalGrants(ctx, regional, unionID, machine.MachineID, false)
		if minted.Reason == credential.MintReauthRequired {
			version := doc.Version
			a.CredentialStore.MarkReauthRequired(ctx, doc.ID, minted.Detail, &version)
			slog.Warn("credential grant: reauth required", "unionId", unionID, "platform", tool, "machineId", machine.MachineID, "detail", minted.Detail)
			return refuse(http.StatusConflict, credentialGrantRefusal{Error: "credential_reauth_required", AuthorizeURL: authorizeURL, Detail: minted.Detail})
		}
		slog.Warn("credential grant: provider unavailable", "unionId", unionID, "platform", tool, "machineId", machine.MachineID, "detail", minted.Detail)
		audit(store.CredentialRefused, "provider_unavailable: "+minted.Detail, "", "")
		writeJSONNoStore(w, http.StatusBadGateway, credentialErrorBody{Error: "provider_unavailable", Detail: minted.Detail})
		return true
	}
	if minted.UpdatedSealed != nil {
		// CAS write-back: a conflict means another pod just refreshed and our
		// token may already be superseded. Still hand out this result (Feishu's
		// previous access token normally stays valid until it expires) but never
		// overwrite the other pod's newer refresh token.
		err := a.CredentialStore.UpdateSealed(ctx, doc.ID, doc.Version, *minted.UpdatedSealed, store.CredentialSealedPatch{RefreshExpiresAt: minted.RefreshExpiresAt})
		if err != nil {
			reason := "unavailable"
			if errors.Is(err, store.ErrConflict) {
				reason = "conflict"
			}
			slog.Warn("credential grant: refresh write-back skipped", "unionId", unionID, "platform", tool, "reason", reason)
		}
		timer.mark("writeback")
	}

	// Audit + last use + first-use notification.
	machineName := machine.MachineID
	if a.Repository != nil {
		if found, err := a.Repository.LookupMachine(ctx, machine.MachineID, store.AuthorityCacheOptions{}); err == nil {
			machineName = found.Name
		}
	}
	timer.mark("machine")
	// Checked before this grant's own audit row exists.
	firstOK, granted := true, false
	if !al.self {
		var err error
		granted, err = a.CredentialStore.HasGrantedOnMachine(ctx, unionID, machine.MachineID)
		firstOK = err == nil
	}
	timer.mark("history")
	audit(store.CredentialGranted, "", machineName, basis)
	timer.mark("audit")
	a.CredentialStore.TouchUse(ctx, doc.ID, machine.MachineID)
	timer.mark("touch")
	outcome = "granted"
	if !al.self && firstOK && !granted {
		ownerName := machine.Name
		if ownerName == "" {
			ownerName = machine.UnionID
		}
		info := feishu.CredentialFirstUseMessage{
			Platform: tool, MachineName: machineName, MachineID: machine.MachineID, OwnerName: ownerName,
			AppID: appID, ManageURL: authorizeURL,
		}
		notify := a.Credentials.Notify
		if notify == nil && a.Feishu != nil {
			notify = a.Feishu.SendCredentialFirstUseDM
		}
		if notify != nil {
			// Best-effort, like `void notify(...).catch(() => undefined)`.
			go func() { _ = notify(ctx, unionID, info) }()
		}
	}
	variables, expiresAt := minted.Variables, minted.ExpiresAt
	response := credentialGrantedBody{OK: true, Tool: platform, UnionID: unionID}
	if regionsAnswered {
		regionalVariables, regionalExpiresAt := a.collectRegionalGrants(ctx, regional, unionID, machine.MachineID, true)
		variables = append(append(credential.Variables(nil), minted.Variables...), regionalVariables...)
		// The grant lasts as long as the first token in it.
		if regionalExpiresAt != 0 && regionalExpiresAt < expiresAt {
			expiresAt = regionalExpiresAt
		}
		response.CloudJWTRegions = &regional.tried
	}
	timer.mark("regions")
	slog.Info("credential granted", "unionId", unionID, "platform", tool, "machineId", machine.MachineID,
		"ownerUnionId", machine.UnionID, "appId", appID, "sessionId", sessionID, "turnId", turnID, "keys", variables.Keys())
	response.Variables, response.ExpiresAt = variables, expiresAt
	writeJSONNoStore(w, http.StatusOK, response)
	return true
}

// mintCredential is mintFor(cfg, doc): the provider of the doc's platform.
func (a *Apex) mintCredential(ctx context.Context, doc store.CredentialDoc) credential.MintResult {
	if a.Credentials.Mint != nil {
		return a.Credentials.Mint(ctx, doc)
	}
	return a.credentialProviders().Mint(ctx, credential.Record{
		UnionID: doc.UnionID, Platform: string(doc.Platform), Sealed: doc.Sealed,
		AppID: doc.Meta.AppID, RefreshExpiresAt: doc.RefreshExpiresAt,
	})
}
