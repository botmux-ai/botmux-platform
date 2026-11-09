package server

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// writeJSONNoStore is sendJson(res, status, body, { 'cache-control': 'no-store' }):
// every machine / desktop / device API response carries it.
func writeJSONNoStore(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, value)
}

// MachineAuth is the daemon behind a machine-token request.
type MachineAuth struct {
	UnionID   string
	Name      string
	MachineID string
}

var machineBearerPattern = regexp.MustCompile(`(?i)^Bearer\s+(.+)$`)

// RequireMachineAuth ports requireMachineAuth (machine-issues-http.ts), the
// single gate of every /v1/machine/* API: signature, cutoff revocation, then a
// live ownership re-check — the signature only proves the platform minted the
// token, not that the machine still belongs to the person it was minted for.
// On failure the response has been written and ok is false.
func (a *Apex) RequireMachineAuth(w http.ResponseWriter, r *http.Request) (*MachineAuth, bool) {
	token := ""
	if m := machineBearerPattern.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		token = strings.TrimSpace(m[1])
	}
	var payload *auth.MachineTokenPayload
	if token != "" {
		payload, _ = auth.VerifyMachineToken(a.Config, token)
	}
	if payload == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_machine_token"})
		return nil, false
	}
	// isMachineTokenRevoked treats an unconfigured or failing Redis as "not
	// revoked"; the ownership re-check below is the fail-closed backstop.
	if a.KV != nil {
		if revoked, err := a.KV.IsMachineTokenRevoked(r.Context(), payload.MachineID, payload.IAT); err == nil && revoked {
			writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "machine_revoked"})
			return nil, false
		}
	}
	if a.Repository == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return nil, false
	}
	doc, err := a.Repository.LookupMachine(r.Context(), payload.MachineID, store.AuthorityCacheOptions{})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return nil, false
	}
	// TS: `doc.status !== undefined && doc.status !== 'ACTIVE'` — any explicit
	// non-ACTIVE status (not only RETIRED) is a mismatch.
	if err != nil || (doc.Status != "" && doc.Status != store.MachineStatusActive) || doc.UnionID != payload.UnionID {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "machine_ownership_mismatch"})
		return nil, false
	}
	return &MachineAuth{UnionID: payload.UnionID, Name: payload.OwnerName, MachineID: payload.MachineID}, true
}

// RequireActiveDesktopAccess ports requireActiveDesktopAccess (desktop-auth.ts):
// a valid desktop access token whose session family has not been revoked.
// On failure the response has been written and ok is false.
func (a *Apex) RequireActiveDesktopAccess(w http.ResponseWriter, r *http.Request) (*auth.DesktopAccessPayload, bool) {
	access, err := auth.VerifyDesktopAccessToken(a.Config, auth.ParseBearer(r.Header.Get("Authorization")))
	if err != nil || access == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return nil, false
	}
	if a.DesktopSessions == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return nil, false
	}
	status, err := a.DesktopSessions.GetDesktopSessionFamilyStatus(r.Context(), access.SID, store.AuthorityCacheOptions{})
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return nil, false
	}
	if status == store.DesktopFamilyRevoked {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "session_revoked"})
		return nil, false
	}
	return access, true
}

// ReadPrincipal resolves the request principal (SSO cookie or device bearer)
// against this pod's device-state cache. See auth.ReadPrincipal for errors.
func (a *Apex) ReadPrincipal(r *http.Request) (*auth.Principal, error) {
	return auth.ReadPrincipal(r.Context(), a.Config, r, a.DeviceStates)
}
