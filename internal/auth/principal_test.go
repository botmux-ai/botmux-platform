package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Ports of test/auth-principal.test.ts plus the epoch/fail-closed paths.

func principalRequest(headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://botmux.example/api/x", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func principalFixture(t *testing.T, edit func(*store.DeviceDoc)) (*store.DocumentRepository, *DeviceStateCache, string) {
	t.Helper()
	cfg := deviceTestConfig()
	repo := store.NewDocumentRepository(store.NewMemoryDatabaseProvider())
	now := time.Now().UnixMilli()
	doc := makeTestDevice(now, edit)
	if err := repo.CreateDevice(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	return repo, NewDeviceStateCache(repo), MintDeviceAccessToken(cfg, doc, now)
}

func TestReadPrincipalRejectsCookieAndBearerTogether(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	_, cache, access := principalFixture(t, nil)
	session := MintSession(cfg, SessionUser{UnionID: "u-alice", Name: "Alice"})
	p, err := ReadPrincipal(context.Background(), cfg, principalRequest(map[string]string{
		"Cookie": SessionCookieName + "=" + session, "Authorization": "Bearer " + access,
	}), cache)
	if p != nil || !errors.Is(err, ErrConflictingCredentials) || ErrConflictingCredentials.HTTPStatus() != http.StatusBadRequest {
		t.Fatalf("principal = %+v err = %v", p, err)
	}
}

func TestReadPrincipalDeviceForgedAndAnonymous(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	_, cache, access := principalFixture(t, nil)
	ctx := context.Background()
	p, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "Bearer " + access}), cache)
	if err != nil || p == nil || p.Kind != PrincipalDevice || p.Device.DeviceID != "dev-1" {
		t.Fatalf("device principal = %+v err = %v", p, err)
	}
	// Case-insensitive scheme, extra whitespace trimmed.
	p, err = ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "bearer \t " + access + "  "}), cache)
	if err != nil || p == nil || p.Kind != PrincipalDevice {
		t.Fatalf("lower-case bearer = %+v err = %v", p, err)
	}
	for _, header := range []string{"Bearer not-a-token", "Bearer    ", "Basic abc", "Bearer"} {
		if p, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": header}), cache); p != nil || err != nil {
			t.Fatalf("%q = %+v err = %v", header, p, err)
		}
	}
	if p, err := ReadPrincipal(ctx, cfg, principalRequest(nil), cache); p != nil || err != nil {
		t.Fatalf("anonymous = %+v err = %v", p, err)
	}
}

func TestReadPrincipalRevokedAndGoneDevices(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	repo, cache, access := principalFixture(t, nil)
	ctx := context.Background()
	if _, err := repo.ForceRevokeDevice(ctx, "dev-1"); err != nil {
		t.Fatal(err)
	}
	cache.Reset() // as if the 5s positive cache had expired
	if p, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "Bearer " + access}), cache); p != nil || !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("revoked = %+v err = %v", p, err)
	}
	now := time.Now().UnixMilli()
	ghost := MintDeviceAccessToken(cfg, makeTestDevice(now, func(d *store.DeviceDoc) { d.ID = "dev-ghost" }), now)
	if p, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "Bearer " + ghost}), cache); p != nil || !errors.Is(err, ErrDeviceGone) {
		t.Fatalf("ghost = %+v err = %v", p, err)
	}
	if ErrDeviceRevoked.HTTPStatus() != http.StatusUnauthorized || ErrDeviceGone.HTTPStatus() != http.StatusUnauthorized {
		t.Fatal("revoked/gone must be 401")
	}
}

func TestReadPrincipalCredentialVersionMismatchIsRevoked(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	_, cache, _ := principalFixture(t, func(d *store.DeviceDoc) { d.CredentialVersion = 2 })
	now := time.Now().UnixMilli()
	stale := MintDeviceAccessToken(cfg, makeTestDevice(now, nil), now) // credentialVersion 1
	if _, err := ReadPrincipal(context.Background(), cfg, principalRequest(map[string]string{"Authorization": "Bearer " + stale}), cache); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("stale credentialVersion = %v", err)
	}
}

func TestDeviceStateCacheTTLAndBypass(t *testing.T) {
	t.Parallel()
	repo, cache, _ := principalFixture(t, nil)
	ctx := context.Background()
	t0 := time.Now()
	if s, err := cache.Get(ctx, "dev-1", DeviceStateOptions{Now: t0}); err != nil || s.Status != store.DeviceStatusActive {
		t.Fatalf("first = %+v err = %v", s, err)
	}
	if _, err := repo.ForceRevokeDevice(ctx, "dev-1"); err != nil {
		t.Fatal(err)
	}
	// Within the TTL the cached "active" is served (revocation lags <= 5s).
	if s, _ := cache.Get(ctx, "dev-1", DeviceStateOptions{Now: t0.Add(time.Second)}); s.Status != store.DeviceStatusActive {
		t.Fatalf("cached = %+v", s)
	}
	// Watcher path: bypass sees the truth immediately.
	if s, _ := cache.Get(ctx, "dev-1", DeviceStateOptions{Now: t0.Add(time.Second), BypassCache: true}); s.Status != store.DeviceStatusRevoked {
		t.Fatalf("bypass = %+v", s)
	}
	if s, _ := cache.Get(ctx, "dev-1", DeviceStateOptions{Now: t0.Add(6 * time.Second)}); s.Status != store.DeviceStatusRevoked {
		t.Fatalf("after ttl = %+v", s)
	}
}

func TestDeviceStateCacheTTLHardCap(t *testing.T) {
	t.Parallel()
	reader := &scriptedDeviceReader{doc: store.DeviceDoc{ID: "d", Status: store.DeviceStatusActive, CredentialVersion: 1}}
	cache := NewDeviceStateCache(reader)
	t0 := time.Now()
	_, _ = cache.Get(context.Background(), "d", DeviceStateOptions{Now: t0, TTL: time.Hour})
	_, _ = cache.Get(context.Background(), "d", DeviceStateOptions{Now: t0.Add(10 * time.Second), TTL: time.Hour})
	_, _ = cache.Get(context.Background(), "d", DeviceStateOptions{Now: t0.Add(10*time.Second + time.Millisecond), TTL: time.Hour})
	if got := reader.reads.Load(); got != 2 {
		t.Fatalf("reads = %d, want 2 (TTL capped at 10s)", got)
	}
}

type scriptedDeviceReader struct {
	doc   store.DeviceDoc
	err   error
	reads atomic.Int64
	// during runs inside GetDevice, after the read and before returning.
	during func(n int64)
}

func (r *scriptedDeviceReader) GetDevice(context.Context, string) (store.DeviceDoc, error) {
	n := r.reads.Add(1)
	if r.during != nil {
		r.during(n)
	}
	return r.doc, r.err
}

func TestDeviceStateCacheFailsClosedWhenUnavailable(t *testing.T) {
	t.Parallel()
	reader := &scriptedDeviceReader{doc: store.DeviceDoc{ID: "d", Status: store.DeviceStatusActive, CredentialVersion: 1}}
	cache := NewDeviceStateCache(reader)
	t0 := time.Now()
	if _, err := cache.Get(context.Background(), "d", DeviceStateOptions{Now: t0}); err != nil {
		t.Fatal(err)
	}
	reader.err = errors.New("connection reset")
	// An expired entry is never used as a fallback.
	if s, err := cache.Get(context.Background(), "d", DeviceStateOptions{Now: t0.Add(6 * time.Second)}); s != nil || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("unavailable = %+v err = %v", s, err)
	}
	cache.Reset() // the still-fresh (real clock) entry must not mask the outage
	cfg := deviceTestConfig()
	token := MintDeviceAccessToken(cfg, store.DeviceDoc{ID: "d", UnionID: "u", CredentialVersion: 1, DeviceExp: time.Now().Add(time.Hour).UnixMilli()}, time.Now().UnixMilli())
	if _, err := ReadPrincipal(context.Background(), cfg, principalRequest(map[string]string{"Authorization": "Bearer " + token}), cache); !errors.Is(err, ErrDeviceUnavailable) || ErrDeviceUnavailable.HTTPStatus() != http.StatusServiceUnavailable {
		t.Fatalf("principal err = %v", err)
	}
	if _, err := ReadPrincipal(context.Background(), cfg, principalRequest(map[string]string{"Authorization": "Bearer " + token}), nil); !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("nil cache err = %v", err)
	}
}

func TestDeviceStateCacheEpochDiscardsRacingRead(t *testing.T) {
	t.Parallel()
	reader := &scriptedDeviceReader{doc: store.DeviceDoc{ID: "d", Status: store.DeviceStatusActive, CredentialVersion: 1}}
	cache := NewDeviceStateCache(reader)
	// The first read races a same-pod revoke: it must not backfill "active";
	// the retry reads the authority again.
	reader.during = func(n int64) {
		if n == 1 {
			cache.Invalidate("d")
			reader.doc.Status = store.DeviceStatusRevoked
		}
	}
	s, err := cache.Get(context.Background(), "d", DeviceStateOptions{})
	if err != nil || s.Status != store.DeviceStatusRevoked || reader.reads.Load() != 2 {
		t.Fatalf("state = %+v err = %v reads = %d", s, err, reader.reads.Load())
	}
	// A revocation storm (every read races) fails closed.
	storm := &scriptedDeviceReader{doc: store.DeviceDoc{ID: "d", Status: store.DeviceStatusActive}}
	stormCache := NewDeviceStateCache(storm)
	storm.during = func(int64) { stormCache.Invalidate("d") }
	if s, err := stormCache.Get(context.Background(), "d", DeviceStateOptions{}); s != nil || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("storm = %+v err = %v", s, err)
	}
	if stormCache.Epoch("d") != 2 {
		t.Fatalf("epoch = %d", stormCache.Epoch("d"))
	}
}

func TestRequireSSOAndFreshness(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	_, cache, access := principalFixture(t, nil)
	ctx := context.Background()
	dev, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "Bearer " + access}), cache)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if RequireSSO(dev) != nil || RequireFreshSSO(dev, now) != nil || RequireRoutineSSO(dev, now) != nil {
		t.Fatal("device principal satisfied an SSO requirement")
	}
	session := MintSessionAt(cfg, SessionUser{UnionID: "u-alice", Name: "Alice"}, now)
	sso, err := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Cookie": SessionCookieName + "=" + session}), cache)
	if err != nil || sso == nil || sso.Kind != PrincipalSSO || RequireSSO(sso) == nil {
		t.Fatalf("sso = %+v err = %v", sso, err)
	}
	if RequireFreshSSO(sso, now) == nil || RequireFreshSSO(sso, now.Add(600*time.Second)) == nil {
		t.Fatal("fresh session within the strict window rejected")
	}
	if RequireFreshSSO(sso, now.Add(601*time.Second)) != nil {
		t.Fatal("stale session accepted by the strict window")
	}
	if RequireRoutineSSO(sso, now.Add(601*time.Second)) == nil || RequireRoutineSSO(sso, now.Add(12*time.Hour+time.Second)) != nil {
		t.Fatal("routine window mismatch")
	}
	legacy := &Principal{Kind: PrincipalSSO, Session: &SessionPayload{Kind: "session", UnionID: "u", Exp: now.Unix() + 60}}
	if RequireSSO(legacy) == nil || RequireFreshSSO(legacy, now) != nil || RequireRoutineSSO(legacy, now) != nil {
		t.Fatal("legacy cookie without authTime must be valid but never fresh")
	}
	if RequireSSO(nil) != nil || RequireFreshSSO(nil, now) != nil {
		t.Fatal("nil principal satisfied SSO")
	}
}

func TestRequireDeviceScope(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	_, cache, access := principalFixture(t, func(d *store.DeviceDoc) { d.Scopes = []string{"machines:read"} })
	ctx := context.Background()
	dev, _ := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Authorization": "Bearer " + access}), cache)
	if u, ok := RequireDeviceScope(dev, "machines:read"); !ok || u != "u-alice" {
		t.Fatalf("device scope = %q %v", u, ok)
	}
	if _, ok := RequireDeviceScope(dev, "terminal:control"); ok {
		t.Fatal("missing scope accepted")
	}
	session := MintSession(cfg, SessionUser{UnionID: "u-bob", Name: "Bob"})
	sso, _ := ReadPrincipal(ctx, cfg, principalRequest(map[string]string{"Cookie": SessionCookieName + "=" + session}), cache)
	if u, ok := RequireDeviceScope(sso, "terminal:control"); !ok || u != "u-bob" {
		t.Fatalf("sso scope = %q %v", u, ok)
	}
	if _, ok := RequireDeviceScope(nil, "machines:read"); ok {
		t.Fatal("nil principal accepted")
	}
}

// The store keeps its own copy of the desktop refresh TTL (internal/store must
// not import internal/auth) to size the session-family revocation fence.
func TestStoreDesktopRefreshTTLMatchesAuth(t *testing.T) {
	t.Parallel()
	if store.DesktopRefreshTTLSec != DesktopRefreshTTLSec {
		t.Fatalf("store.DesktopRefreshTTLSec = %d, auth.DesktopRefreshTTLSec = %d", store.DesktopRefreshTTLSec, DesktopRefreshTTLSec)
	}
}
