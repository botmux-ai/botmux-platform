package store

import (
	"context"
	"errors"
	"time"
)

// DesktopRefreshTTLSec is the desktop refresh-token lifetime (30 days). It
// MUST equal the auth layer's desktop refresh TTL (TS: DESKTOP_REFRESH_TTL_SEC
// in auth/desktop-pkce.ts); it is duplicated here because internal/store must
// not import internal/auth. The revocation fence covers at least one full
// refresh TTL after the revoke instant.
const DesktopRefreshTTLSec int64 = 30 * 24 * 60 * 60

// proxyTicketFenceMinMS keeps a consumed proxy-ticket tombstone for at least
// this long: signed tokens still verify during the second in which exp ==
// floor(now/1000), and pods' clocks/in-flight requests need slack.
const proxyTicketFenceMinMS int64 = 60_000

// desktopRevocationSlackMS is added on top of one refresh TTL to absorb
// cross-pod clock skew and in-flight refreshes.
const desktopRevocationSlackMS int64 = 60_000

// DesktopFamilyStatus is the state of a desktop session family (sid).
type DesktopFamilyStatus string

const (
	DesktopFamilyActive  DesktopFamilyStatus = "active"
	DesktopFamilyRevoked DesktopFamilyStatus = "revoked"
)

// oneTimeUseDocument is the tombstone written by the single-use fences.
type oneTimeUseDocument struct {
	ID         string    `bson:"_id"`
	ConsumedAt float64   `bson:"consumedAt"`
	ExpiresAt  any       `bson:"expiresAt"`
	ExpireAt   time.Time `bson:"expireAt"`
}

func (s *DocumentRepository) consumeOnce(ctx context.Context, collection, id string, fenceExpiresAtMS int64) error {
	c, err := s.collection(ctx, collection)
	if err != nil {
		return err
	}
	err = normalizeDBError(c.InsertOne(ctx, oneTimeUseDocument{
		ID: id, ConsumedAt: bsonNumber(s.nowMS()), ExpiresAt: jsNumberBSON(fenceExpiresAtMS), ExpireAt: msTime(fenceExpiresAtMS),
	}))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrConflict):
		return ErrReplayed
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrUnavailable):
		return err
	default:
		return ErrUnavailable
	}
}

// ConsumeProxyTicket records a proxy ticket id (jti) as used. nil means this
// call consumed it; ErrReplayed means it was already used; ErrUnavailable
// means the fence could not be written and the ticket must be rejected. The
// tombstone lives until max(expiresAtMS, now+60s).
func (s *DocumentRepository) ConsumeProxyTicket(ctx context.Context, ticketID string, expiresAtMS int64) error {
	fence := expiresAtMS
	if min := s.nowMS() + proxyTicketFenceMinMS; fence < min {
		fence = min
	}
	return s.consumeOnce(ctx, collectionProxyTicketUses, ticketID, fence)
}

// ConsumeDesktopAuthCode records a desktop auth code id as used (same result
// contract as ConsumeProxyTicket). The tombstone lives until expiresAtMS.
func (s *DocumentRepository) ConsumeDesktopAuthCode(ctx context.Context, codeID string, expiresAtMS int64) error {
	return s.consumeOnce(ctx, collectionDesktopAuthCodeUses, codeID, expiresAtMS)
}

func (s *DocumentRepository) invalidateFamily(sessionID string) {
	if s != nil && s.familyCache != nil {
		s.familyCache.invalidate(sessionID)
	}
}

// RevokeDesktopSessionFamily writes the cross-pod revocation tombstone for a
// desktop session family (logout). Access and refresh tokens share one sid,
// so verification stays stateless apart from this fence. The tombstone
// expires no earlier than now + one refresh TTL + 60s (a refresh racing the
// logout may have issued a token outliving expiresAtMS), and an existing
// later expiry is kept ($max). ErrUnavailable means the fence was not
// recorded and logout must not be acknowledged.
func (s *DocumentRepository) RevokeDesktopSessionFamily(ctx context.Context, sessionID string, expiresAtMS int64) error {
	// Drop the positive entry before writing and again afterwards so an
	// authority read racing the write cannot backfill a stale "active".
	s.invalidateFamily(sessionID)
	now := s.nowMS()
	effective := expiresAtMS
	if min := now + DesktopRefreshTTLSec*1000 + desktopRevocationSlackMS; effective < min {
		effective = min
	}
	c, err := s.collection(ctx, collectionDesktopSessionRevocations)
	if err != nil {
		return err
	}
	_, err = c.UpdateOne(ctx, Document{"_id": sessionID}, Document{
		"$set": Document{"revokedAt": bsonNumber(now)},
		"$max": Document{"expiresAt": jsNumberBSON(effective), "expireAt": msTime(effective)},
	}, true)
	if err != nil {
		err = normalizeDBError(err)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			err = ErrUnavailable
		}
		return err
	}
	s.invalidateFamily(sessionID)
	return nil
}

// GetDesktopSessionFamilyStatus reports whether sessionID has an unexpired
// revocation tombstone. ErrUnavailable must be treated as "reject" by
// callers. With opts.PositiveTTL > 0 only DesktopFamilyActive results are
// cached (see AuthorityCacheOptions).
func (s *DocumentRepository) GetDesktopSessionFamilyStatus(ctx context.Context, sessionID string, opts AuthorityCacheOptions) (DesktopFamilyStatus, error) {
	read := func(ctx context.Context) (DesktopFamilyStatus, error) {
		s.familyReads.Add(1)
		return s.readDesktopSessionFamilyStatus(ctx, sessionID)
	}
	ttl := opts.ttl(desktopDashboardAuthCacheHardMax)
	if ttl <= 0 {
		return read(ctx)
	}
	return s.familyCache.get(ctx, sessionID, ttl, s.now, read, func(status DesktopFamilyStatus, err error) bool {
		return err == nil && status == DesktopFamilyActive
	})
}

func (s *DocumentRepository) readDesktopSessionFamilyStatus(ctx context.Context, sessionID string) (DesktopFamilyStatus, error) {
	c, err := s.collection(ctx, collectionDesktopSessionRevocations)
	if err != nil {
		return "", err
	}
	var doc struct {
		ID string `bson:"_id"`
	}
	err = c.FindOne(ctx, Document{"_id": sessionID, "expiresAt": Document{"$gt": bsonNumber(s.nowMS())}}, &doc)
	switch {
	case err == nil:
		return DesktopFamilyRevoked, nil
	case errors.Is(err, ErrNotFound):
		return DesktopFamilyActive, nil
	default:
		return "", normalizeDBError(err)
	}
}
