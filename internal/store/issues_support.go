package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
)

// ReasonError is a TS StoreResult failure reason that has no generic store
// sentinel. Handlers map StoreReason(err) to HTTP exactly like the TS
// issues-core fromStoreError / credentials-http branches do, so the reason
// strings are wire-visible error codes and must not change.
type ReasonError struct{ Reason string }

func (e *ReasonError) Error() string { return "store: " + e.Reason }

var (
	// ErrInvalid is TS reason 'invalid': rejected input (blank issue title) or a
	// stored document whose shape fails validation (credentials).
	ErrInvalid           = &ReasonError{Reason: "invalid"}
	ErrRevConflict       = &ReasonError{Reason: "rev_conflict"}
	ErrStateRevConflict  = &ReasonError{Reason: "state_rev_conflict"}
	ErrIssueLocked       = &ReasonError{Reason: "issue_locked"}
	ErrIssueActive       = &ReasonError{Reason: "issue_active"}
	ErrAlreadyClaimed    = &ReasonError{Reason: "already_claimed"}
	ErrNeedsForceDetach  = &ReasonError{Reason: "needs_force_detach"}
	ErrClaimExpired      = &ReasonError{Reason: "claim_expired"}
	ErrClaimMismatch     = &ReasonError{Reason: "claim_mismatch"}
	ErrStaleEpoch        = &ReasonError{Reason: "stale_epoch"}
	ErrInvalidTransition = &ReasonError{Reason: "invalid_transition"}
	// ErrIssueForbidden is the store-level claimant check in statusWriteback.
	ErrIssueForbidden = &ReasonError{Reason: "forbidden"}
)

// StoreReason returns the TS StoreResult reason for an error returned by
// IssueStore or CredentialStore: "" for nil, "unavailable" for anything
// failClosed wrapped (even when the driver error underneath was a duplicate
// key), a ReasonError's reason, "not_found", "conflict", and "unavailable"
// for everything else (the TS stores' catch-all).
func StoreReason(err error) string {
	var reason *ReasonError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.As(err, &reason):
		return reason.Reason
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrConflict):
		return "conflict"
	default:
		return "unavailable"
	}
}

// failClosed turns any storage failure into ErrUnavailable. The TS issue and
// credential stores catch every driver exception (including duplicate keys
// and "would create a conflict" update errors) as reason 'unavailable', and
// callers answer 503 instead of trusting a partial result.
func failClosed(err error) error {
	if err == nil || errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func providerCollection(ctx context.Context, provider DatabaseProvider, name string) (DocumentCollection, error) {
	if provider == nil {
		return nil, ErrUnavailable
	}
	db, err := provider.Database(ctx)
	if err != nil {
		return nil, failClosed(err)
	}
	if db == nil {
		return nil, ErrUnavailable
	}
	c := db.Collection(name)
	if c == nil {
		return nil, ErrUnavailable
	}
	return c, nil
}

// UnavailableDatabaseProvider is the memory-mode provider for IssueStore and
// CredentialStore. Without MONGODB_URI issues and credentials have no
// in-memory fallback, so every operation answers 'unavailable' -> 503
// store_unavailable, while machines/teams/devices
// keep working in memory. Wiring mounts these two stores on this provider
// instead of NewMemoryDatabaseProvider.
type UnavailableDatabaseProvider struct{}

func (UnavailableDatabaseProvider) Database(context.Context) (DocumentDatabase, error) {
	return nil, ErrUnavailable
}

// isMemoryProvider reports the Go equivalent of TS memory mode (no MongoDB
// configured): UnavailableDatabaseProvider in production wiring, or a store
// mounted on NewMemoryDatabaseProvider (tests, local experiments).
func isMemoryProvider(provider DatabaseProvider) bool {
	var db DocumentDatabase
	switch p := provider.(type) {
	case UnavailableDatabaseProvider, *UnavailableDatabaseProvider:
		return true
	case StaticDatabaseProvider:
		db = p.DB
	case *StaticDatabaseProvider:
		if p != nil {
			db = p.DB
		}
	default:
		return false
	}
	_, memory := db.(*MemoryDatabase)
	return memory
}

// randomDocumentID matches `${prefix}_${crypto.randomBytes(12).toString('hex')}`.
func randomDocumentID(prefix string) string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("store: crypto/rand failed: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(raw[:])
}

// jsNumber returns the BSON value the Node driver writes for a JS number:
// int32 for integers in int32 range, double for everything else. Values that
// come from client JSON (sourceSeq) keep whatever physical type Node would
// have produced, so mixed-version writers never split a field's BSON type.
func jsNumber(value float64) any {
	if value == math.Trunc(value) && value >= math.MinInt32 && value <= math.MaxInt32 && !(value == 0 && math.Signbit(value)) {
		return int32(value)
	}
	return value
}

// truncateUTF16 mirrors String.prototype.slice(0, limit), whose limit counts
// UTF-16 code units. Cutting a surrogate pair leaves a lone high surrogate in
// JS, which the Node BSON serializer persists as U+FFFD.
func truncateUTF16(value string, limit int) string {
	units := 0
	for i, r := range value {
		width := 1
		if r >= 0x10000 {
			width = 2
		}
		if units+width > limit {
			if width == 2 && units+1 == limit {
				return value[:i] + "\uFFFD"
			}
			return value[:i]
		}
		units += width
	}
	return value
}

// isJSBlank reports whether String.prototype.trim() would yield "". JS trims
// WhiteSpace + LineTerminator, which differs from unicode.IsSpace (U+FEFF is
// trimmed by JS, U+0085 is not).
func isJSBlank(value string) bool {
	return strings.TrimFunc(value, isJSWhitespace) == ""
}

func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}
