package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestDesktopRefreshTTLMatchesTypeScript(t *testing.T) {
	t.Parallel()
	if DesktopRefreshTTLSec != 2_592_000 {
		t.Fatalf("DesktopRefreshTTLSec = %d", DesktopRefreshTTLSec)
	}
}

func TestConsumeProxyTicketIsSingleUseWithMinimumFence(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	if err := s.ConsumeProxyTicket(ctx, "jti-1", now+30_000); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeProxyTicket(ctx, "jti-1", now+30_000); !errors.Is(err, ErrReplayed) || !errors.Is(err, ErrConflict) {
		t.Fatalf("replay = %v", err)
	}
	raw := s.db.MemoryCollection(collectionProxyTicketUses).Documents()[0]
	// The fence outlives the ticket's own exp by at least 60s.
	if raw["expiresAt"] != float64(now+60_000) || raw["consumedAt"] != float64(now) {
		t.Fatalf("fence = %#v", raw)
	}
	if at, ok := raw["expireAt"].(primitive.DateTime); !ok || at.Time().UnixMilli() != now+60_000 {
		t.Fatalf("expireAt = %#v", raw["expireAt"])
	}
	if err := s.ConsumeProxyTicket(ctx, "jti-2", now+120_000); err != nil {
		t.Fatal(err)
	}
	if got := s.db.MemoryCollection(collectionProxyTicketUses).Documents()[1]["expiresAt"]; got != float64(now+120_000) {
		t.Fatalf("later exp must be kept: %#v", got)
	}
}

func TestConsumeDesktopAuthCodeIsSingleUse(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	if err := s.ConsumeDesktopAuthCode(ctx, "code-1", now+1000); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeDesktopAuthCode(ctx, "code-1", now+1000); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay = %v", err)
	}
	// No 60s floor for auth codes.
	if got := s.db.MemoryCollection(collectionDesktopAuthCodeUses).Documents()[0]["expiresAt"]; got != float64(now+1000) {
		t.Fatalf("expiresAt = %#v", got)
	}
	// Proxy tickets and auth codes are separate namespaces.
	if err := s.ConsumeProxyTicket(ctx, "code-1", now); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSessionFamilyRevocationFence(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	if status, err := s.GetDesktopSessionFamilyStatus(ctx, "sid", AuthorityCacheOptions{}); err != nil || status != DesktopFamilyActive {
		t.Fatalf("fresh = %v %v", status, err)
	}
	if err := s.RevokeDesktopSessionFamily(ctx, "sid", now+1000); err != nil {
		t.Fatal(err)
	}
	minimum := now + DesktopRefreshTTLSec*1000 + 60_000
	raw := s.db.MemoryCollection(collectionDesktopSessionRevocations).Documents()[0]
	if raw["expiresAt"] != float64(minimum) || raw["revokedAt"] != float64(now) {
		t.Fatalf("fence = %#v", raw)
	}
	// A later explicit expiry raises the fence; an earlier one never lowers it.
	s.clock.Advance(time.Second)
	if err := s.RevokeDesktopSessionFamily(ctx, "sid", minimum+5_000_000); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDesktopSessionFamily(ctx, "sid", 1); err != nil {
		t.Fatal(err)
	}
	raw = s.db.MemoryCollection(collectionDesktopSessionRevocations).Documents()[0]
	if raw["expiresAt"] != float64(minimum+5_000_000) {
		t.Fatalf("$max lost: %#v", raw["expiresAt"])
	}
	if at := raw["expireAt"].(primitive.DateTime); at.Time().UnixMilli() != minimum+5_000_000 {
		t.Fatalf("expireAt = %v", at)
	}
	if status, _ := s.GetDesktopSessionFamilyStatus(ctx, "sid", AuthorityCacheOptions{}); status != DesktopFamilyRevoked {
		t.Fatalf("revoked = %v", status)
	}
	// Once the fence expires the family reads as active again.
	s.clock.Advance(time.Duration(minimum+5_000_000-s.nowMS()) * time.Millisecond)
	if status, _ := s.GetDesktopSessionFamilyStatus(ctx, "sid", AuthorityCacheOptions{}); status != DesktopFamilyActive {
		t.Fatalf("expired fence = %v", status)
	}
}
