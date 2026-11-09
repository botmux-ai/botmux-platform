package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of test/server-devices-refresh.test.ts (the §3.4 decision order).

func (h *deviceHarness) refreshToken(generation int64, jti string, deviceExpMS int64, familyID string) string {
	return auth.BuildDeviceRefreshToken(h.a.Config, auth.DeviceRefreshClaims{
		DeviceID: "dev-1", FamilyID: familyID, Generation: generation, JTI: jti, CredentialVersion: 1, DeviceExpMS: deviceExpMS,
	})
}

// seedRefreshDevice creates dev-1 at generation 1 and returns its R1.
func (h *deviceHarness) seedRefreshDevice(mutate func(*store.DeviceDoc)) (r1 string, deviceExp int64) {
	h.t.Helper()
	now := time.Now().UnixMilli()
	doc := store.DeviceDoc{
		ID: "dev-1", UnionID: "u-alice", OwnerName: "Alice", DeviceKind: store.DeviceKindDesktopIDE, DeviceName: "my-macbook",
		Scopes: store.DeviceMVPScopes(), CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "fam-1", RefreshGeneration: 1, RefreshCurrentJTI: "jti-r1", RefreshRetryKeyHash: "",
		ReplayUntil: 0, RefreshRotatedAt: now, EnrolledAt: now, DeviceExp: now + 90*deviceDay, LastSeenAt: now,
		ApprovedVia: store.DeviceApprovedViaFeishuConfirm,
	}
	if mutate != nil {
		mutate(&doc)
	}
	r1 = h.refreshToken(1, "jti-r1", doc.DeviceExp, "fam-1")
	if doc.RefreshTokenHash == "" {
		doc.RefreshTokenHash = auth.SHA256Hex(r1)
	}
	h.createDevice(doc)
	return r1, doc.DeviceExp
}

func (h *deviceHarness) postRefresh(refreshToken any, idempotencyKey string) harnessResponse {
	h.t.Helper()
	headers := map[string]string{}
	if idempotencyKey != "" {
		headers["Idempotency-Key"] = idempotencyKey
	}
	body := map[string]any{}
	if refreshToken != nil {
		body["refreshToken"] = refreshToken
	}
	return h.call(http.MethodPost, "/api/devices/refresh", body, headers)
}

func TestDeviceRefreshRequiresKeyAndToken(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedRefreshDevice(nil)
	expectStatus(t, h.postRefresh("x", ""), http.StatusBadRequest, "bad_request")
	expectStatus(t, h.postRefresh(nil, "k1"), http.StatusBadRequest, "bad_request")
	expectStatus(t, h.postRefresh(12345, "k1"), http.StatusBadRequest, "bad_request")
	expectStatus(t, h.postRefresh("x", strings.Repeat("k", 257)), http.StatusBadRequest, "bad_request")
}

func TestDeviceRefreshForgedTokenChangesNothing(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedRefreshDevice(nil)
	expectStatus(t, h.postRefresh("AAAA.BBBB", "k1"), http.StatusUnauthorized, "invalid_refresh")
	if doc, _ := h.device("dev-1"); doc.RefreshGeneration != 1 {
		t.Fatalf("generation = %d", doc.RefreshGeneration)
	}
}

func TestDeviceRefreshMainChain(t *testing.T) {
	h := newDeviceHarness(t)
	r1, _ := h.seedRefreshDevice(nil)

	first := h.postRefresh(r1, "key-1")
	expectStatus(t, first, http.StatusOK, "")
	expectKeys(t, first.raw, "accessToken", "refreshToken", "deviceExp", "accessExpiresAt")
	if int64(first.num("accessExpiresAt"))%1000 != 0 {
		t.Fatalf("accessExpiresAt = %v", first.body["accessExpiresAt"])
	}
	r2 := first.str("refreshToken")
	if claims, err := auth.ParseDeviceRefreshToken(h.a.Config, r2); err != nil || claims.Generation != 2 {
		t.Fatalf("claims = %+v %v", claims, err)
	}

	// The current ticket inside the window: zero writes, same refresh bytes.
	again := h.postRefresh(r2, "key-2")
	expectStatus(t, again, http.StatusOK, "")
	if again.str("refreshToken") != r2 {
		t.Fatal("in-window refresh changed the refresh token")
	}
	if doc, _ := h.device("dev-1"); doc.RefreshGeneration != 2 {
		t.Fatalf("generation = %d", doc.RefreshGeneration)
	}

	// Lost response: R1 + the same key replays exactly R2.
	replay := h.postRefresh(r1, "key-1")
	expectStatus(t, replay, http.StatusOK, "")
	if replay.str("refreshToken") != r2 {
		t.Fatal("exact replay returned different bytes")
	}

	// R1 with another key inside the window: 409, no revocation.
	expectStatus(t, h.postRefresh(r1, "key-other"), http.StatusConflict, "refresh_in_progress")
	if doc, _ := h.device("dev-1"); doc.Status != store.DeviceStatusActive || doc.RefreshGeneration != 2 {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestDeviceRefreshAccessCappedAtDeviceExp(t *testing.T) {
	h := newDeviceHarness(t)
	deviceExp := time.Now().UnixMilli() + 5*60_000 + 789
	r1, _ := h.seedRefreshDevice(func(d *store.DeviceDoc) { d.DeviceExp = deviceExp })
	got := h.postRefresh(r1, "near-device-exp")
	expectStatus(t, got, http.StatusOK, "")
	if int64(got.num("deviceExp")) != deviceExp || int64(got.num("accessExpiresAt")) != deviceExp/1000*1000 {
		t.Fatalf("got = %s", got.raw)
	}
	access, err := auth.VerifyDeviceAccessToken(h.a.Config, got.str("accessToken"))
	if err != nil || access.Exp != deviceExp/1000 {
		t.Fatalf("access = %+v %v", access, err)
	}
}

func TestDeviceRefreshExpiredRecoveryWindowRevokes(t *testing.T) {
	h := newDeviceHarness(t)
	now := time.Now().UnixMilli()
	deviceExp := now + 90*deviceDay
	r1 := h.refreshToken(1, "jti-r1", deviceExp, "fam-1")
	r2 := h.refreshToken(2, "jti-r2", deviceExp, "fam-1")
	h.seedRefreshDevice(func(d *store.DeviceDoc) {
		d.RefreshGeneration = 2
		d.RefreshTokenHash = auth.SHA256Hex(r2)
		d.RefreshCurrentJTI = "jti-r2"
		d.PrevRefreshTokenHash = auth.SHA256Hex(r1)
		d.RefreshRetryKeyHash = auth.SHA256Hex("key-1")
		d.ReplayUntil = now - 1000
		d.DeviceExp = deviceExp
	})
	epochBefore := h.a.DeviceStates.Epoch("dev-1")
	expectStatus(t, h.postRefresh(r1, "key-1"), http.StatusUnauthorized, "recovery_required")
	doc, _ := h.device("dev-1")
	if doc.Status != store.DeviceStatusRevoked || doc.CredentialVersion != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	if h.a.DeviceStates.Epoch("dev-1") == epochBefore {
		t.Fatal("revocation did not invalidate the device state cache")
	}
}

func TestDeviceRefreshStaleGenerationRevokes(t *testing.T) {
	h := newDeviceHarness(t)
	now := time.Now().UnixMilli()
	deviceExp := now + 90*deviceDay
	r0 := h.refreshToken(1, "jti-r1", deviceExp, "fam-1")
	r3 := h.refreshToken(3, "jti-r3", deviceExp, "fam-1")
	h.seedRefreshDevice(func(d *store.DeviceDoc) {
		d.RefreshGeneration = 3
		d.RefreshTokenHash = auth.SHA256Hex(r3)
		d.RefreshCurrentJTI = "jti-r3"
		d.PrevRefreshTokenHash = auth.SHA256Hex(h.refreshToken(2, "jti-r2", deviceExp, "fam-1"))
		d.RefreshRetryKeyHash = auth.SHA256Hex("key-2")
		d.ReplayUntil = now + 60_000
		d.DeviceExp = deviceExp
	})
	closed := 0
	release, _ := h.a.DeviceSockets.Register(DeviceSocketClaims{DeviceID: "dev-1", CredentialVersion: 1, AuthExp: time.Now().Add(time.Hour).Unix()},
		func() { closed++ }, nil)
	defer release()
	expectStatus(t, h.postRefresh(r0, "key-x"), http.StatusUnauthorized, "device_revoked")
	if doc, _ := h.device("dev-1"); doc.Status != store.DeviceStatusRevoked {
		t.Fatalf("status = %s", doc.Status)
	}
	if closed != 1 {
		t.Fatalf("closed sockets = %d", closed)
	}
	// A replay storm after the revocation is a plain 401 (no second alarm).
	expectStatus(t, h.postRefresh(r0, "key-y"), http.StatusUnauthorized, "device_revoked")
	if closed != 1 {
		t.Fatalf("closed sockets = %d", closed)
	}
}

func TestDeviceRefreshOldFamilyNeverRevokesNewFamily(t *testing.T) {
	h := newDeviceHarness(t)
	_, deviceExp := h.seedRefreshDevice(func(d *store.DeviceDoc) { d.RefreshFamilyID = "fam-2" })
	oldFamily := h.refreshToken(1, "jti-old", deviceExp, "fam-1")
	expectStatus(t, h.postRefresh(oldFamily, "k"), http.StatusUnauthorized, "invalid_refresh")
	if doc, _ := h.device("dev-1"); doc.Status != store.DeviceStatusActive {
		t.Fatalf("status = %s", doc.Status)
	}
}

func TestDeviceRefreshRevokedAndFutureGeneration(t *testing.T) {
	h := newDeviceHarness(t)
	r1, _ := h.seedRefreshDevice(func(d *store.DeviceDoc) { d.Status = store.DeviceStatusRevoked })
	expectStatus(t, h.postRefresh(r1, "k"), http.StatusUnauthorized, "device_revoked")

	h.resetDevices()
	_, deviceExp := h.seedRefreshDevice(nil)
	future := h.refreshToken(9, "jti-9", deviceExp, "fam-1")
	expectStatus(t, h.postRefresh(future, "k"), http.StatusUnauthorized, "invalid_refresh")
	if doc, _ := h.device("dev-1"); doc.RefreshGeneration != 1 {
		t.Fatalf("generation = %d", doc.RefreshGeneration)
	}
}

func TestDeviceRefreshGoneExpiredAndUnavailable(t *testing.T) {
	h := newDeviceHarness(t)
	r1, deviceExp := h.seedRefreshDevice(nil)
	h.a.Devices.Now = func() time.Time { return time.UnixMilli(deviceExp + 1) }
	expectStatus(t, h.postRefresh(r1, "k"), http.StatusUnauthorized, "device_expired")
	h.a.Devices.Now = nil

	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.postRefresh(r1, "k"), http.StatusServiceUnavailable, "store_unavailable")
	h.a.DeviceRepo = h.repo

	h.resetDevices()
	expectStatus(t, h.postRefresh(r1, "k"), http.StatusUnauthorized, "device_gone")
}

// failingRevokeRepo makes ForceRevokeDevice unavailable.
type failingRevokeRepo struct{ store.DeviceRepository }

func (failingRevokeRepo) ForceRevokeDevice(context.Context, string) (bool, error) {
	return false, store.ErrUnavailable
}

func TestDeviceRefreshRevocationUnavailableIs503(t *testing.T) {
	h := newDeviceHarness(t)
	now := time.Now().UnixMilli()
	deviceExp := now + 90*deviceDay
	r0 := h.refreshToken(1, "jti-r1", deviceExp, "fam-1")
	h.seedRefreshDevice(func(d *store.DeviceDoc) {
		d.RefreshGeneration = 3
		d.RefreshTokenHash = auth.SHA256Hex(h.refreshToken(3, "jti-r3", deviceExp, "fam-1"))
		d.RefreshCurrentJTI = "jti-r3"
		d.ReplayUntil = now + 60_000
	})
	h.a.DeviceRepo = failingRevokeRepo{h.repo}
	expectStatus(t, h.postRefresh(r0, "k"), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDeviceRefreshLatin1IdempotencyKey(t *testing.T) {
	// Node decodes header bytes as latin1 and hashes the string as UTF-8, so
	// a raw 0xE9 byte is the key "é" for both the retry hash and the jti.
	h := newDeviceHarness(t)
	r1, _ := h.seedRefreshDevice(nil)
	got := h.postRefresh(r1, "k\xe9")
	expectStatus(t, got, http.StatusOK, "")
	doc, _ := h.device("dev-1")
	if doc.RefreshRetryKeyHash != auth.SHA256Hex("ké") {
		t.Fatalf("retry key hash = %s", doc.RefreshRetryKeyHash)
	}
	if doc.RefreshCurrentJTI != auth.DeriveRefreshJTI(h.a.Config, auth.SHA256Hex(r1), "ké", 2) {
		t.Fatal("jti not derived from the latin1-decoded key")
	}
}
