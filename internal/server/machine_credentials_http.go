package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

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
//  3. sender is the machine owner, or shares at least one team with them (403 not_teammate);
//  4. sender authorized this platform (404 credential_not_found) and it is not marked for re-authorization (409);
//  5. sender consented for a shared team (self use always allowed; 403 consent_missing);
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
	audit := func(outcome store.CredentialGrantOutcome, reason, machineName string) {
		a.CredentialStore.AppendGrant(ctx, store.CredentialGrantInput{
			UnionID: unionID, Platform: platform, MachineID: machine.MachineID, MachineName: machineName,
			OwnerUnionID: machine.UnionID, AppID: appID, SessionID: sessionID, TurnID: turnID,
			Outcome: outcome, Reason: reason,
		})
	}
	refuse := func(status int, refusal credentialGrantRefusal) bool {
		audit(store.CredentialRefused, refusal.Error, "")
		writeJSONNoStore(w, status, refusal)
		return true
	}

	// 3. Team boundary: self use, or at least one team shared with the owner.
	self := unionID == machine.UnionID
	var sharedTeamIDs []string
	if !self {
		var teams []store.TeamDoc
		err := store.ErrUnavailable
		if a.Repository != nil {
			teams, err = a.Repository.ListTeamsForUser(ctx, machine.UnionID)
		}
		timer.mark("teams")
		if err != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return true
		}
		for _, team := range teams {
			if credentialContains(team.Members, unionID) {
				sharedTeamIDs = append(sharedTeamIDs, team.ID)
			}
		}
		if len(sharedTeamIDs) == 0 {
			return refuse(http.StatusForbidden, credentialGrantRefusal{Error: "not_teammate"})
		}
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
	if !self {
		consented := doc.ConsentTeams.All
		for _, id := range sharedTeamIDs {
			if !consented && credentialContains(doc.ConsentTeams.Teams, id) {
				consented = true
			}
		}
		if !consented {
			return refuse(http.StatusForbidden, credentialGrantRefusal{Error: "consent_missing", AuthorizeURL: authorizeURL})
		}
	}

	// 6. Mint the short-lived credential.
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
		if minted.Reason == credential.MintReauthRequired {
			version := doc.Version
			a.CredentialStore.MarkReauthRequired(ctx, doc.ID, minted.Detail, &version)
			slog.Warn("credential grant: reauth required", "unionId", unionID, "platform", tool, "machineId", machine.MachineID, "detail", minted.Detail)
			return refuse(http.StatusConflict, credentialGrantRefusal{Error: "credential_reauth_required", AuthorizeURL: authorizeURL, Detail: minted.Detail})
		}
		slog.Warn("credential grant: provider unavailable", "unionId", unionID, "platform", tool, "machineId", machine.MachineID, "detail", minted.Detail)
		audit(store.CredentialRefused, "provider_unavailable: "+minted.Detail, "")
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
	if !self {
		var err error
		granted, err = a.CredentialStore.HasGrantedOnMachine(ctx, unionID, machine.MachineID)
		firstOK = err == nil
	}
	timer.mark("history")
	audit(store.CredentialGranted, "", machineName)
	timer.mark("audit")
	a.CredentialStore.TouchUse(ctx, doc.ID, machine.MachineID)
	timer.mark("touch")
	outcome = "granted"
	if !self && firstOK && !granted {
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
	slog.Info("credential granted", "unionId", unionID, "platform", tool, "machineId", machine.MachineID,
		"ownerUnionId", machine.UnionID, "appId", appID, "sessionId", sessionID, "turnId", turnID, "keys", minted.Variables.Keys())
	writeJSONNoStore(w, http.StatusOK, credentialGrantedBody{
		OK: true, Tool: platform, UnionID: unionID, Variables: minted.Variables, ExpiresAt: minted.ExpiresAt,
	})
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
