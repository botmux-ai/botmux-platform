package server

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of test/server-devices-manage.test.ts (device management is SSO-only
// with a fresh session; a device ticket can never manage devices — D2).

const deviceDay = int64(24 * 3600 * 1000)

type manageHarness struct {
	*deviceHarness
	seq int
}

func (h *manageHarness) seedDevice(mutate func(*store.DeviceDoc)) store.DeviceDoc {
	h.t.Helper()
	h.seq++
	now := time.Now().UnixMilli()
	doc := store.DeviceDoc{
		ID: fmt.Sprintf("d-%02x112233aabbccdd", h.seq), UnionID: "u-alice", OwnerName: "Alice",
		DeviceKind: store.DeviceKindDesktopIDE, DeviceName: "my-ide", Scopes: store.DeviceMVPScopes(),
		CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "fam-1", RefreshGeneration: 1, RefreshTokenHash: "hash-r1", RefreshCurrentJTI: "jti-r1",
		RefreshRetryKeyHash: "", ReplayUntil: 0, RefreshRotatedAt: now, EnrolledAt: now,
		DeviceExp: now + 90*deviceDay, LastSeenAt: now, ApprovedVia: store.DeviceApprovedViaFeishuConfirm,
	}
	if mutate != nil {
		mutate(&doc)
	}
	h.createDevice(doc)
	return doc
}

func TestDeviceListOwnDevicesNewestFirstWithoutRefreshInternals(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	now := time.Now().UnixMilli()
	older := h.seedDevice(func(d *store.DeviceDoc) { d.EnrolledAt = now - 60_000; d.DeviceName = "older-ide" })
	newer := h.seedDevice(func(d *store.DeviceDoc) { d.EnrolledAt = now; d.DeviceName = "newer-ide" })
	h.seedDevice(func(d *store.DeviceDoc) { d.UnionID = "u-bob"; d.OwnerName = "Bob" })

	got := h.call(http.MethodGet, "/api/devices", nil, h.ssoHeaders("u-alice", "Alice"))
	expectStatus(t, got, http.StatusOK, "")
	devices, _ := got.body["devices"].([]any)
	if len(devices) != 2 {
		t.Fatalf("devices = %s", got.raw)
	}
	first := devices[0].(map[string]any)
	if first["deviceId"] != newer.ID || devices[1].(map[string]any)["deviceId"] != older.ID {
		t.Fatalf("order = %s", got.raw)
	}
	if first["deviceName"] != "newer-ide" || first["status"] != "active" {
		t.Fatalf("dto = %v", first)
	}
	scopes := []any{}
	for _, s := range store.DeviceMVPScopes() {
		scopes = append(scopes, s)
	}
	if !reflect.DeepEqual(first["scopes"], scopes) {
		t.Fatalf("scopes = %v", first["scopes"])
	}
	for _, key := range []string{"refreshTokenHash", "refreshCurrentJti", "refreshFamilyId", "refreshRetryKeyHash"} {
		if _, leaked := first[key]; leaked {
			t.Fatalf("DTO leaks %s", key)
		}
	}
	want := fmt.Sprintf(`{"deviceId":%q,"deviceKind":"desktop-ide","deviceName":"newer-ide","status":"active","scopes":["machines:read","sessions:open","terminal:control","self:refresh"],"enrolledAt":%d,"lastSeenAt":%d,"deviceExp":%d}`,
		newer.ID, newer.EnrolledAt, newer.LastSeenAt, newer.DeviceExp)
	if raw := string(got.raw); raw[len(`{"devices":[`):len(`{"devices":[`)+len(want)] != want {
		t.Fatalf("wire = %s\nwant prefix %s", raw, want)
	}
}

func TestDeviceManagementRequiresFreshSSO(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, nil), http.StatusUnauthorized, "stale_session")
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, h.staleSSOHeaders("u-alice")), http.StatusUnauthorized, "stale_session")

	bearer := map[string]string{"Authorization": "Bearer " + auth.MintDeviceAccessToken(h.a.Config, dev, time.Now().UnixMilli())}
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, bearer), http.StatusUnauthorized, "stale_session")
	bearer["Origin"] = deviceTestOrigin
	expectStatus(t, h.call(http.MethodPost, "/api/devices/"+dev.ID+"/revoke", nil, bearer), http.StatusUnauthorized, "stale_session")
	if after, _ := h.device(dev.ID); after.Status != store.DeviceStatusActive {
		t.Fatalf("status = %s", after.Status)
	}
}

func TestDeviceCookieAndBearerConflict(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	headers := h.ssoHeaders("u-alice", "Alice")
	headers["Authorization"] = "Bearer " + auth.MintDeviceAccessToken(h.a.Config, dev, time.Now().UnixMilli())
	got := h.call(http.MethodGet, "/api/devices", nil, headers)
	expectStatus(t, got, http.StatusBadRequest, "conflicting_credentials")
}

func TestDevicePrincipalErrorsMapToWire(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	bearer := map[string]string{"Authorization": "Bearer " + auth.MintDeviceAccessToken(h.a.Config, dev, time.Now().UnixMilli())}

	// A revoked device bearer is a 401 device_revoked, not a stale session.
	if _, err := h.repo.ForceRevokeDevice(context.Background(), dev.ID); err != nil {
		t.Fatal(err)
	}
	h.a.DeviceStates.Invalidate(dev.ID)
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, bearer), http.StatusUnauthorized, "device_revoked")

	h.resetDevices()
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, bearer), http.StatusUnauthorized, "device_gone")

	// The device authority is unreachable: 503 store_unavailable.
	h.a.DeviceStates = auth.NewDeviceStateCache(store.NewDocumentRepository(store.UnavailableDatabaseProvider{}))
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, bearer), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDeviceRevokeOriginOwnerAndIdempotency(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	path := "/api/devices/" + dev.ID + "/revoke"
	sso := h.ssoHeaders("u-alice", "Alice")
	expectStatus(t, h.call(http.MethodPost, path, nil, map[string]string{"Cookie": sso["Cookie"]}), http.StatusForbidden, "bad_origin")
	expectStatus(t, h.call(http.MethodPost, path, nil, map[string]string{"Cookie": sso["Cookie"], "Origin": "https://evil.example.test"}),
		http.StatusForbidden, "bad_origin")

	// Revocation drops the positive cache (epoch bump) before closing this
	// pod's device sockets with reason owner_revoked.
	epochBefore := h.a.DeviceStates.Epoch(dev.ID)
	closedAfterInvalidate := make(chan bool, 1)
	release, ok := h.a.DeviceSockets.Register(DeviceSocketClaims{DeviceID: dev.ID, CredentialVersion: 1, AuthExp: time.Now().Add(time.Hour).Unix()}, func() {
		closedAfterInvalidate <- h.a.DeviceStates.Epoch(dev.ID) > epochBefore
	}, nil)
	if !ok {
		t.Fatal("register failed")
	}
	defer release()

	got := h.call(http.MethodPost, path, nil, sso)
	expectStatus(t, got, http.StatusOK, "")
	if string(got.raw) != `{"ok":true}` {
		t.Fatalf("revoke = %s", got.raw)
	}
	select {
	case afterInvalidate := <-closedAfterInvalidate:
		if !afterInvalidate {
			t.Fatal("socket closed before the state cache was invalidated")
		}
	default:
		t.Fatal("device socket was not closed")
	}
	after, _ := h.device(dev.ID)
	if after.Status != store.DeviceStatusRevoked || after.CredentialVersion != 2 {
		t.Fatalf("after = %+v", after)
	}

	expectStatus(t, h.call(http.MethodPost, path, nil, sso), http.StatusOK, "")
	if final, _ := h.device(dev.ID); final.CredentialVersion != 2 {
		t.Fatalf("idempotent revoke bumped credentialVersion to %d", final.CredentialVersion)
	}
}

func TestDeviceRevokeForeignOrMissing(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/"+dev.ID+"/revoke", nil, h.ssoHeaders("u-mallory", "Mallory")),
		http.StatusNotFound, "device_not_found")
	if after, _ := h.device(dev.ID); after.Status != store.DeviceStatusActive {
		t.Fatalf("status = %s", after.Status)
	}
	expectStatus(t, h.call(http.MethodPost, "/api/devices/d-0000000000000000/revoke", nil, h.ssoHeaders("u-alice", "Alice")),
		http.StatusNotFound, "device_not_found")
}

func TestDeviceManagementStoreDegraded(t *testing.T) {
	h := &manageHarness{deviceHarness: newDeviceHarness(t)}
	dev := h.seedDevice(nil)
	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodGet, "/api/devices", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusServiceUnavailable, "store_unavailable")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/"+dev.ID+"/revoke", nil, h.ssoHeaders("u-alice", "Alice")),
		http.StatusServiceUnavailable, "store_unavailable")
}

func TestDeviceRoutesFallThrough(t *testing.T) {
	h := newDeviceHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/devices"},
		{http.MethodGet, "/api/devices/refresh"},
		{http.MethodGet, "/api/devices/d-0000000000000000/revoke"},
		{http.MethodPost, "/api/devices/d-00/revoke"},
		{http.MethodPost, "/api/devices/grants/ABC0000000000000/approve"},
	} {
		request := newDeviceRequest(tc.method, tc.path)
		if h.a.handleDevicesAPI(nopResponseWriter{}, request) {
			t.Fatalf("%s %s was handled", tc.method, tc.path)
		}
	}
}
