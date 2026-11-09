package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// deviceSessionChainMaxSec is the absolute device proxy session chain cap
// (DESIGN-device-pairing §5.2 S1): sessionMaxExp = min(deviceExp, first issue
// + 12h). A renewal reuses the chain's cap and can never push it out.
const deviceSessionChainMaxSec = 12 * 3600

// deviceOpenResponse is the device open wire contract. Clients never decode
// the ticket, so lease clocks are given explicitly (Unix milliseconds).
type deviceOpenResponse struct {
	OpenURL             string `json:"openUrl"`
	SID                 string `json:"sid"`
	RenewalChain        string `json:"renewalChain"`
	AuthExpiresAt       int64  `json:"authExpiresAt"`
	SessionMaxExpiresAt int64  `json:"sessionMaxExpiresAt"`
}

// handleDeviceMachineOpen is the device-principal branch of
// POST /api/machines/:id/open and of the mobile session open (TS
// device-open.ts): it issues a device proxy ticket instead of the SSO proxy
// ticket. The purpose is always chosen by the route, never by the client, and
// nextPath (when set) is the server-derived terminal landing path that wins
// over the body's `next`.
func (a *Apex) handleDeviceMachineOpen(w http.ResponseWriter, r *http.Request, machineID string, access *auth.DeviceAccessPayload, purpose auth.DeviceProxyPurpose, nextPath *string) {
	ctx := r.Context()
	// Machine ownership, fail-closed three states; RETIRED equals missing.
	if a.Repository == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	machine, err := a.Repository.LookupMachine(ctx, machineID, store.AuthorityCacheOptions{})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	if err != nil || machine.Retired() || machine.UnionID != access.UnionID {
		writeJSONNoStore(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
		return
	}

	// Authoritative device read (issuing derives a credential, so it never
	// goes through the positive cache): active, same credentialVersion, and
	// not past deviceExp.
	if a.DeviceRepo == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	device, err := a.DeviceRepo.GetDevice(ctx, access.DeviceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "device_gone"})
		return
	}
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	if device.Status != store.DeviceStatusActive || device.CredentialVersion != access.CredentialVersion {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "device_revoked"})
		return
	}
	requiredScope := store.DeviceScopeSessionsOpen
	if purpose == auth.DeviceProxyPurposeDashboardMobile {
		requiredScope = store.DeviceScopeDashboardManage
	}
	if !contains(device.Scopes, requiredScope) || !access.HasScope(requiredScope) {
		// dashboard:manage is an explicit owner grant added later. An older
		// mobile enrollment lacks it and must re-enroll under fresh SSO;
		// recovery_required routes the native client into that flow.
		if purpose == auth.DeviceProxyPurposeDashboardMobile && device.DeviceKind == store.DeviceKindMobile {
			writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "recovery_required"})
			return
		}
		writeJSONNoStore(w, http.StatusForbidden, apexError{Error: "insufficient_scope"})
		return
	}
	deviceExpSec := floorDiv(device.DeviceExp, 1000)
	if time.Now().Unix() >= deviceExpSec {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "device_expired"})
		return
	}

	// Online check and liveness probe, same rules as the SSO branch.
	if live, ok := a.Registry.Get(machineID); !ok || live.UnionID != access.UnionID {
		if !a.machineRouted(ctx, machineID) {
			writeJSONNoStore(w, http.StatusConflict, apexError{Error: "machine_offline"})
			return
		}
	}
	if a.MachineAPI == nil || !a.MachineAPI.CheckDashboardHealth(ctx, machineID, access.UnionID) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, apexError{Error: "dashboard_unreachable"})
		return
	}

	// The clock is read after the (up to 9s) health probe, like the TS
	// handler, so the issued lease is never already partly spent.
	nowSec := time.Now().Unix()
	sid := randomID(8)
	sessionMaxExp := min(deviceExpSec, nowSec+deviceSessionChainMaxSec)
	effectiveScopes := append([]string{}, device.Scopes...)
	// Read the body exactly once: a caller may send both a renewal chain and a
	// client-shell landing path.
	body := readJSONObject(r)
	if raw, ok := body["chain"].(string); ok && raw != "" {
		chain, err := auth.VerifyDeviceProxySessionToken(a.Config, raw)
		if err == nil && chain != nil &&
			chain.DeviceID == device.ID &&
			chain.MachineID == machineID &&
			chain.CredentialVersion == device.CredentialVersion &&
			chain.Purpose == purpose &&
			nowSec < chain.SessionMaxExp {
			sid = chain.SID
			sessionMaxExp = chain.SessionMaxExp
			// Renewal only narrows: authoritative scopes ∩ chain scopes.
			effectiveScopes = make([]string, 0, len(device.Scopes))
			for _, scope := range device.Scopes {
				if contains(chain.EffectiveScopes, scope) {
					effectiveScopes = append(effectiveScopes, scope)
				}
			}
		}
	}
	authExp := min(access.Exp, deviceExpSec, sessionMaxExp)
	// Strict boundary: a ticket whose lease ends now could never be redeemed.
	// Reject here so the client refreshes instead of hitting /__open with a
	// dead ticket.
	if authExp <= nowSec {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "access_expired"})
		return
	}
	claims := auth.DeviceProxyClaims{
		UnionID:           access.UnionID,
		MachineID:         machineID,
		DeviceID:          device.ID,
		CredentialVersion: device.CredentialVersion,
		EffectiveScopes:   effectiveScopes,
		SID:               sid,
		SessionMaxExp:     sessionMaxExp,
		AuthExp:           authExp,
		Purpose:           purpose,
	}
	ticket := auth.IssueDeviceProxyTicket(a.Config, claims)
	// Opaque native-only renewal handle with the same signed chain claims as
	// the HttpOnly cookie /__open will mint. It never enters openUrl or page
	// JavaScript; returning it keeps sid and the first 12h cap fixed.
	renewalChain := auth.MintDeviceProxySession(a.Config, claims)
	requestedNext := ""
	if nextPath != nil {
		requestedNext = *nextPath
	} else if raw, ok := body["next"].(string); ok {
		requestedNext = raw
	}
	// new URL('/__open', base) + searchParams.set: form-urlencoded values.
	openURL := machineSurfaceBaseURL(a.Config, machineID, purpose == auth.DeviceProxyPurposeTerminal) + "/__open?ticket=" + formEncodeJS(ticket)
	if next, ok := auth.SafeProxyNextPath(requestedNext); ok {
		openURL += "&next=" + formEncodeJS(next)
	}
	writeJSONNoStore(w, http.StatusOK, deviceOpenResponse{
		OpenURL:             openURL,
		SID:                 sid,
		RenewalChain:        renewalChain,
		AuthExpiresAt:       authExp * 1000,
		SessionMaxExpiresAt: sessionMaxExp * 1000,
	})
}

// machineRouted reports whether the machine is online on some pod (Redis
// route). A route read failure counts as offline, as getMachineRoute's null.
func (a *Apex) machineRouted(ctx context.Context, machineID string) bool {
	if a.Routes == nil {
		return false
	}
	route, err := a.Routes.GetMachineRoute(ctx, machineID)
	return err == nil && route != ""
}

// machineSurfaceBaseURL is machineBaseUrl(cfg, id, surface). The terminal
// surface has its own origin (TerminalSubdomainPrefix) so a device terminal
// cookie can never ride along to the dashboard origin, and vice versa.
func machineSurfaceBaseURL(cfg config.Config, machineID string, terminal bool) string {
	if terminal {
		cfg.MachineSubdomainPrefix = first(cfg.TerminalSubdomainPrefix, "t-")
	}
	return MachineBaseURL(cfg, machineID)
}

func floorDiv(value, divisor int64) int64 {
	quotient := value / divisor
	if (value%divisor != 0) && ((value < 0) != (divisor < 0)) {
		quotient--
	}
	return quotient
}

// encodeURIComponentJS percent-encodes everything outside
// A-Z a-z 0-9 - _ . ! ~ * ' ( ), as encodeURIComponent does (url.QueryEscape
// differs on space and on ! * ' ( )).
func encodeURIComponentJS(value string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&15])
	}
	return b.String()
}

// formEncodeJS is the WHATWG application/x-www-form-urlencoded serializer
// used by URLSearchParams (space is '+', '~' is escaped, '*' is not).
func formEncodeJS(value string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c == '*' || c == '-' || c == '.' || c == '_' ||
			'0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&15])
		}
	}
	return b.String()
}

// decodeURIComponentJS mirrors decodeURIComponent including its URIError
// cases (malformed escapes, invalid UTF-8 such as %ff, encoded surrogates),
// which url.PathUnescape would silently accept or reject differently.
func decodeURIComponentJS(value string) (string, bool) {
	if !strings.Contains(value, "%") {
		return value, true
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); {
		if value[i] != '%' {
			out = append(out, value[i])
			i++
			continue
		}
		lead, ok := percentByte(value, i)
		if !ok {
			return "", false
		}
		i += 3
		if lead < 0x80 {
			out = append(out, lead)
			continue
		}
		width := 0
		switch {
		case lead&0xE0 == 0xC0:
			width = 2
		case lead&0xF0 == 0xE0:
			width = 3
		case lead&0xF8 == 0xF0:
			width = 4
		default:
			return "", false
		}
		seq := []byte{lead}
		for k := 1; k < width; k++ {
			next, ok := percentByte(value, i)
			if !ok || next&0xC0 != 0x80 {
				return "", false
			}
			seq = append(seq, next)
			i += 3
		}
		if !validUTF8Sequence(seq) {
			return "", false // overlong, surrogate or out-of-range code point
		}
		out = append(out, seq...)
	}
	return string(out), true
}

func validUTF8Sequence(seq []byte) bool {
	r, size := utf8.DecodeRune(seq)
	return size == len(seq) && !(r == utf8.RuneError && size == 1)
}

func percentByte(value string, i int) (byte, bool) {
	if i+2 >= len(value) || value[i] != '%' {
		return 0, false
	}
	hi, ok1 := hexNibble(value[i+1])
	lo, ok2 := hexNibble(value[i+2])
	return hi<<4 | lo, ok1 && ok2
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
