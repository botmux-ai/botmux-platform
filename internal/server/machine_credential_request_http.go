package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// POST /v1/machine/credential-request: a daemon whose governed command was
// refused asks the platform to get the person authorized. The platform works
// out per service what this person still lacks on this machine (authorize,
// reauthorize, add_scopes, or allow the machine) and, when something is
// missing, stores a request and DMs the person one card whose button opens
// /credentials?request=<id>. The endpoint mints nothing and never answers 404
// (a daemon reads 404 as "this platform has no such endpoint").
//
// Limits: 30 requests per machine per ten minutes (per pod); a request already
// sent for the same missing set within ten minutes is reused instead of
// messaging again; 6 requests per day per person and machine, 20 per day per
// person (counted from the stored requests).

const (
	credentialRequestDedupeMS   = 10 * 60_000
	credentialRequestDayMS      = 24 * 3600 * 1000
	credentialRequestMachineDay = 6
	credentialRequestPersonDay  = 20
	credentialRequestDMTimeout  = 5 * time.Second
	credentialRequestNameMax    = 64
)

type credentialRequestBody struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	RequestID string `json:"requestId,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	Deduped   bool   `json:"deduped,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func (a *Apex) credentialRequestNotifier() func(ctx context.Context, unionID string, info feishu.CredentialRequestMessage) error {
	if a.Credentials.NotifyRequest != nil {
		return a.Credentials.NotifyRequest
	}
	if a.Feishu.Configured() {
		return a.Feishu.SendCredentialRequestDM
	}
	return nil
}

func (a *Apex) handleMachineCredentialRequestAPI(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/v1/machine/credential-request" {
		return false
	}
	if r.Method != http.MethodPost {
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return true
	}
	machine, ok := a.RequireMachineAuth(w, r)
	if !ok {
		return true
	}
	if !a.credentialVaultEnabled() {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "credential_vault_disabled"})
		return true
	}
	notify := a.credentialRequestNotifier()
	if notify == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "notify_unavailable"})
		return true
	}
	body := readCredentialJSONFields(r)
	unionID, unionOK := credentialFieldString(body, "unionId")
	appID, appOK := credentialFieldString(body, "appId")
	scopes, scopesOK := incrementalScopesOf(body)
	var requestedTools []string
	toolsOK := json.Unmarshal(body["tools"], &requestedTools) == nil
	if body == nil || !unionOK || !credentialGrantUnionID.MatchString(unionID) ||
		!appOK || !credentialGrantID.MatchString(appID) ||
		!scopesOK || !toolsOK {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return true
	}
	var tools []string
	seen := map[string]bool{}
	for _, tool := range requestedTools {
		if a.Credentials.Providers.Known(tool) && !seen[tool] {
			seen[tool] = true
			tools = append(tools, tool)
		}
	}
	if len(tools) == 0 {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return true
	}
	if _, present := body["machineId"]; present {
		claimed, isString := credentialFieldString(body, "machineId")
		if !isString || claimed != machine.MachineID {
			writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "machine_mismatch"})
			return true
		}
	}

	now := a.credentialNow().UnixMilli()
	limiter := a.Credentials.RequestLimiter
	if limiter == nil {
		limiter = defaultCredentialRequestLimiter
	}
	if retryAfter, limited := limiter.take(machine.MachineID, now); limited {
		writeJSONNoStore(w, http.StatusTooManyRequests, credentialRateLimitedBody{Error: "rate_limited", RetryAfterMS: retryAfter})
		return true
	}
	unavailable := func() bool {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}

	ctx := r.Context()
	var machineDoc store.MachineDoc
	err := store.ErrUnavailable
	if a.Repository != nil {
		machineDoc, err = a.Repository.LookupMachine(ctx, machine.MachineID, store.AuthorityCacheOptions{})
	}
	if err != nil {
		return unavailable()
	}

	var missing, platforms []string
	for _, platform := range tools {
		state, err := a.credentialRequestState(ctx, machine, unionID, store.CredentialPlatform(platform), scopes)
		if err != nil {
			return unavailable()
		}
		if state != "" {
			missing = append(missing, platform+":"+state)
			platforms = append(platforms, platform)
		}
	}
	if len(missing) == 0 {
		writeJSONNoStore(w, http.StatusOK, credentialRequestBody{OK: true, Status: "ready"})
		return true
	}

	recent, err := a.CredentialStore.RecentRequests(ctx, unionID, machine.MachineID, now-credentialRequestDayMS, credentialRequestMachineDay)
	if err != nil {
		return unavailable()
	}
	var request store.CredentialRequestDoc
	reused := false
	for _, earlier := range recent {
		if now-earlier.CreatedAt < credentialRequestDedupeMS && containsAll(earlier.Missing, missing) {
			request, reused = earlier, true
			break
		}
	}
	if reused {
		if len(scopes) > 0 {
			if err := a.CredentialStore.MergeRequest(ctx, request.ID, scopes); err != nil {
				return unavailable()
			}
		}
		if request.NotifiedAt != 0 {
			writeJSONNoStore(w, http.StatusOK, credentialRequestBody{OK: true, Status: "sent", RequestID: request.ID, ExpiresAt: request.ExpiresAt, Deduped: true})
			return true
		}
	} else {
		if len(recent) >= credentialRequestMachineDay {
			return a.credentialRequestCapped(w, recent[len(recent)-1], now)
		}
		person, err := a.CredentialStore.RecentRequests(ctx, unionID, "", now-credentialRequestDayMS, credentialRequestPersonDay)
		if err != nil {
			return unavailable()
		}
		if len(person) >= credentialRequestPersonDay {
			return a.credentialRequestCapped(w, person[len(person)-1], now)
		}
		request, err = a.CredentialStore.CreateRequest(ctx, store.CredentialRequestDoc{
			UnionID: unionID, MachineID: machine.MachineID, OwnerUnionID: machine.UnionID,
			OwnerName:   cardText(first(machineDoc.OwnerName, machine.Name)),
			MachineName: cardText(first(machineDoc.DisplayName, machineDoc.Name)),
			AppID:       appID, BotName: a.requestBotName(machine.MachineID, appID, machineDoc),
			Platforms: platforms, Scopes: scopes, Missing: missing,
		})
		if err != nil {
			return unavailable()
		}
	}

	titles := map[string]string{}
	for _, card := range a.credentialPlatforms() {
		titles[card.Platform] = card.Title
	}
	services := make([]string, 0, len(request.Platforms))
	for _, platform := range request.Platforms {
		services = append(services, first(titles[platform], platform))
	}
	dmCtx, cancel := context.WithTimeout(ctx, credentialRequestDMTimeout)
	defer cancel()
	err = notify(dmCtx, unionID, feishu.CredentialRequestMessage{
		BotName: request.BotName, OwnerName: request.OwnerName, MachineName: request.MachineName,
		Services: services, AuthorizeURL: a.credentialsPageURL() + "?request=" + request.ID,
	})
	if err != nil {
		slog.Warn("credential request card not delivered", "unionId", unionID, "machineId", machine.MachineID, "requestId", request.ID, "error", err)
		writeJSONNoStore(w, http.StatusOK, credentialRequestBody{OK: true, Status: "undeliverable", RequestID: request.ID, Detail: inviteDMErrorText(err)})
		return true
	}
	if err := a.CredentialStore.MarkRequestNotified(ctx, request.ID); err != nil {
		slog.Warn("credential request notified mark failed", "requestId", request.ID, "error", err)
	}
	slog.Info("credential request sent", "unionId", unionID, "machineId", machine.MachineID, "requestId", request.ID, "missing", missing)
	writeJSONNoStore(w, http.StatusOK, credentialRequestBody{OK: true, Status: "sent", RequestID: request.ID, ExpiresAt: request.ExpiresAt})
	return true
}

// credentialRequestState is what the person still lacks for platform on this
// machine: "authorize", "reauthorize", "add_scopes", "allow", or "" when a
// grant would succeed. Whether the machine is allowed is only reported once the
// credential itself is usable, so the answer never depends on credentials the
// machine could not use anyway.
func (a *Apex) credentialRequestState(ctx context.Context, machine *MachineAuth, unionID string, platform store.CredentialPlatform, scopes []string) (string, error) {
	al, err := a.credentialAllowance(ctx, machine, unionID, platform)
	if err != nil {
		return "", err
	}
	doc, err := a.CredentialStore.Get(ctx, unionID, platform)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "authorize", nil
	case errors.Is(err, store.ErrInvalid):
		return "reauthorize", nil
	case err != nil:
		return "", err
	case doc.Status == store.CredentialReauthRequired:
		return "reauthorize", nil
	}
	if platform == store.CredentialPlatformLarkCLI {
		granted := strings.FieldsFunc(doc.Meta.Scope, isCredentialJSSpace)
		for _, scope := range scopes {
			if !credentialContains(granted, scope) {
				return "add_scopes", nil
			}
		}
	}
	basis, err := a.credentialBasis(ctx, machine, unionID, platform, al, doc.ConsentTeams)
	if err != nil {
		return "", err
	}
	if basis == "" {
		return "allow", nil
	}
	return "", nil
}

func (a *Apex) credentialRequestCapped(w http.ResponseWriter, oldest store.CredentialRequestDoc, now int64) bool {
	writeJSONNoStore(w, http.StatusTooManyRequests, credentialRateLimitedBody{Error: "request_cap", RetryAfterMS: oldest.CreatedAt + credentialRequestDayMS - now})
	return true
}

// requestBotName is the name the machine reports for appID (live connection
// first, then the stored machine) as card text; empty when none is known.
func (a *Apex) requestBotName(machineID, appID string, doc store.MachineDoc) string {
	name := ""
	if a.Registry != nil {
		if live, ok := a.Registry.Get(machineID); ok {
			for _, bot := range live.Bots {
				if bot.AppID == appID {
					name = bot.Name
				}
			}
		}
	}
	if name == "" {
		for _, bot := range doc.Bots {
			if bot.AppID == appID {
				name = bot.Name
			}
		}
	}
	return cardText(name)
}

// cardText makes a daemon-reported name safe to show in the card and the page:
// control and format characters (zero-width, bidi overrides, line separators)
// and angle brackets are dropped and the result is capped at
// credentialRequestNameMax UTF-16 units without a cut-off surrogate.
func cardText(value string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' || r == '<' || r == '>' {
			return -1
		}
		return r
	}, value)
	cut := truncate(clean, credentialRequestNameMax)
	if !strings.HasSuffix(clean, "�") {
		cut = strings.TrimSuffix(cut, "�")
	}
	return strings.TrimSpace(cut)
}

// containsAll reports whether every want is in values.
func containsAll(values, want []string) bool {
	for _, item := range want {
		if !credentialContains(values, item) {
			return false
		}
	}
	return true
}
