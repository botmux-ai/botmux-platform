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

// Port of test/server-devices-enroll.test.ts plus the branches it does not
// reach (grant GET, poll body gates, store degradation, wire key order).

const enrollMachineID = "01aabbccdd112233"

func (h *deviceHarness) enrollOK(machineID string) (grantID, pollSecret string) {
	h.t.Helper()
	got := h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "My IDE"},
		h.machineAuth(machineID, "u-alice", "Alice"))
	expectStatus(h.t, got, http.StatusOK, "")
	expectKeys(h.t, got.raw, "grantId", "pollSecret", "expiresAt", "pollIntervalMs")
	if got.str("grantId") == "" || got.str("pollSecret") == "" || got.num("pollIntervalMs") != 2000 {
		h.t.Fatalf("enroll = %s", got.raw)
	}
	return got.str("grantId"), got.str("pollSecret")
}

func (h *deviceHarness) poll(grantID, pollSecret string) harnessResponse {
	h.t.Helper()
	return h.call(http.MethodPost, "/api/devices/enroll/poll", map[string]any{"grantId": grantID, "pollSecret": pollSecret}, nil)
}

func TestDeviceEnrollF1FullChain(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)

	pending := h.poll(grantID, pollSecret)
	expectStatus(t, pending, http.StatusOK, "")
	if pending.str("status") != "pending" || pending.num("pollIntervalMs") != 2000 {
		t.Fatalf("pending = %s", pending.raw)
	}

	info := h.call(http.MethodGet, "/api/devices/grants/"+grantID, nil, h.ssoHeaders("u-alice", "Alice"))
	expectStatus(t, info, http.StatusOK, "")
	expectKeys(t, info.raw, "grantId", "deviceKind", "deviceName", "machineId", "machineName", "scopes", "status", "createdAt", "expiresAt")
	if info.str("deviceName") != "My IDE" || info.str("machineName") != "alice-macbook" || info.str("status") != "pending" {
		t.Fatalf("grant info = %s", info.raw)
	}

	approved := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice"))
	expectStatus(t, approved, http.StatusOK, "")
	if string(approved.raw) != `{"status":"approved"}` {
		t.Fatalf("approve = %s", approved.raw)
	}

	issued := h.poll(grantID, pollSecret)
	expectStatus(t, issued, http.StatusOK, "")
	expectKeys(t, issued.raw, "status", "deviceId", "accessToken", "refreshToken", "deviceExp", "accessExpiresAt")
	deviceID := issued.str("deviceId")
	if issued.str("status") != "issued" || !strings.HasPrefix(deviceID, "d-") || issued.str("accessToken") == "" {
		t.Fatalf("issued = %s", issued.raw)
	}
	if want := "d-" + auth.SHA256Hex("device:" + grantID)[:16]; deviceID != want {
		t.Fatalf("deviceId = %s, want %s", deviceID, want)
	}
	claims, err := auth.ParseDeviceRefreshToken(h.a.Config, issued.str("refreshToken"))
	if err != nil || claims.Generation != 1 {
		t.Fatalf("refresh claims = %+v %v", claims, err)
	}
	dev, ok := h.device(deviceID)
	if !ok || dev.OwnerName != "Alice" || dev.ApprovedVia != store.DeviceApprovedViaFeishuConfirm || dev.DeviceKind != store.DeviceKindDesktopIDE {
		t.Fatalf("device = %+v", dev)
	}
	grant := h.grant(grantID)
	if dev.DeviceExp != grant.DecidedAt+deviceLifetimeMS || grant.Status != store.DeviceGrantConsumed {
		t.Fatalf("deviceExp = %d decidedAt = %d status = %s", dev.DeviceExp, grant.DecidedAt, grant.Status)
	}

	// Lost response: polling again re-issues the very same refresh bytes.
	again := h.poll(grantID, pollSecret)
	if again.str("status") != "issued" || again.str("refreshToken") != issued.str("refreshToken") {
		t.Fatalf("again = %s", again.raw)
	}

	// The issued refresh token rotates directly (enroll → refresh integration).
	rotated := h.call(http.MethodPost, "/api/devices/refresh", map[string]any{"refreshToken": issued.str("refreshToken")},
		map[string]string{"Idempotency-Key": "key-1"})
	expectStatus(t, rotated, http.StatusOK, "")
	claims, err = auth.ParseDeviceRefreshToken(h.a.Config, rotated.str("refreshToken"))
	if err != nil || claims.Generation != 2 {
		t.Fatalf("rotated claims = %+v %v", claims, err)
	}
}

func TestDeviceEnrollInputAndAuth(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	machine := h.machineAuth(enrollMachineID, "u-alice", "Alice")

	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"},
		map[string]string{"Authorization": "Bearer junk"}), http.StatusUnauthorized, "invalid_machine_token")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"}, nil),
		http.StatusUnauthorized, "invalid_machine_token")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "mobile", "deviceName": "x"}, machine),
		http.StatusBadRequest, "unsupported_device_kind")
	// The kind check is strict equality on the JSON value: no coercion.
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": []string{"desktop-ide"}, "deviceName": "x"}, machine),
		http.StatusBadRequest, "unsupported_device_kind")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "  "}, machine),
		http.StatusBadRequest, "device_name_required")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", "not json", machine),
		http.StatusBadRequest, "unsupported_device_kind")

	h.enrollOK(enrollMachineID)
	limited := h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "again"}, machine)
	expectStatus(t, limited, http.StatusTooManyRequests, "too_many_requests")

	// After the 10s gap the same machine may enroll again.
	h.a.Devices.Now = func() time.Time { return time.Now().Add(11 * time.Second) }
	h.enrollOK(enrollMachineID)
}

func TestDeviceEnrollTrimsAndCapsDeviceName(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	name := strings.Repeat("😀", 40) // 80 UTF-16 units: the 64-unit cap splits nothing
	got := h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "  " + name + "  "},
		h.machineAuth(enrollMachineID, "u-alice", "Alice"))
	expectStatus(t, got, http.StatusOK, "")
	if grant := h.grant(got.str("grantId")); grant.DeviceName != strings.Repeat("😀", 32) {
		t.Fatalf("deviceName = %q", grant.DeviceName)
	}
	h.a.Devices.Now = func() time.Time { return time.Now().Add(11 * time.Second) }
	got = h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": 12345},
		h.machineAuth(enrollMachineID, "u-alice", "Alice"))
	expectStatus(t, got, http.StatusOK, "")
	if grant := h.grant(got.str("grantId")); grant.DeviceName != "12345" {
		t.Fatalf("numeric deviceName = %q", grant.DeviceName)
	}
}

func TestDeviceEnrollFirstOwnershipCheck(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	// The token claims u-bob but MongoDB says u-alice (old token after /api/bind).
	got := h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"},
		h.machineAuth(enrollMachineID, "u-bob", "Bob"))
	expectStatus(t, got, http.StatusForbidden, "machine_ownership_mismatch")

	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"},
		h.machineAuth("02aabbccdd112233", "u-alice", "Alice")), http.StatusForbidden, "machine_ownership_mismatch")

	const retired = "03aabbccdd112233"
	h.seedMachine(retired, "u-alice", "Alice", "old")
	if err := h.repo.RetireMachine(context.Background(), retired); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"},
		h.machineAuth(retired, "u-alice", "Alice")), http.StatusForbidden, "machine_ownership_mismatch")
}

func TestDeviceEnrollRevokedMachineTokenAndDegradedStore(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	token := h.machineAuth(enrollMachineID, "u-alice", "Alice")
	h.a.KV = store.NewKVStore(store.NewMemoryKV(), "t", time.Minute, time.Minute)
	if err := h.a.KV.RevokeMachineToken(context.Background(), enrollMachineID, time.Now().Add(time.Second).UnixMilli(), time.Hour); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"}, token),
		http.StatusUnauthorized, "machine_revoked")
	h.a.KV = nil

	// Ownership lookup degraded: 503, never treated as owned or missing.
	h.a.Repository = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"}, token),
		http.StatusServiceUnavailable, "store_unavailable")
	h.a.Repository = h.repo

	// Grant cannot be stored: 503 and the throttle is not consumed.
	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll", map[string]any{"deviceKind": "desktop-ide", "deviceName": "x"}, token),
		http.StatusServiceUnavailable, "store_unavailable")
	h.a.DeviceRepo = h.repo
	h.enrollOK(enrollMachineID)
}

func TestDeviceGrantGet(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, _ := h.enrollOK(enrollMachineID)
	path := "/api/devices/grants/" + grantID

	expectStatus(t, h.call(http.MethodGet, path, nil, nil), http.StatusUnauthorized, "unauthenticated")
	// Freshness is not required to view the confirmation page.
	expectStatus(t, h.call(http.MethodGet, path, nil, h.staleSSOHeaders("u-alice")), http.StatusOK, "")
	expectStatus(t, h.call(http.MethodGet, path, nil, h.ssoHeaders("u-mallory", "Mallory")), http.StatusNotFound, "grant_not_found")
	expectStatus(t, h.call(http.MethodGet, "/api/devices/grants/deadbeefdeadbeef", nil, h.ssoHeaders("u-alice", "Alice")),
		http.StatusNotFound, "grant_not_found")

	// A lapsed pending grant reads as expired; a missing machine falls back
	// to the id prefix.
	h.a.Devices.Now = func() time.Time { return time.UnixMilli(h.grant(grantID).ExpiresAt + 1) }
	if err := h.repo.RetireMachine(context.Background(), enrollMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Collection("machines").DeleteOne(context.Background(), store.Document{"_id": enrollMachineID}); err != nil {
		t.Fatal(err)
	}
	got := h.call(http.MethodGet, path, nil, h.ssoHeaders("u-alice", "Alice"))
	expectStatus(t, got, http.StatusOK, "")
	if got.str("status") != "expired" || got.str("machineName") != enrollMachineID[:8] {
		t.Fatalf("grant = %s", got.raw)
	}

	// Wrong method / unknown action are not device routes.
	if got := h.call(http.MethodPost, path, nil, h.ssoHeaders("u-alice", "Alice")); got.status == http.StatusOK {
		t.Fatalf("POST grant = %d", got.status)
	}

	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.call(http.MethodGet, path, nil, h.ssoHeaders("u-alice", "Alice")), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDeviceGrantDecisionGates(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	approve := "/api/devices/grants/" + grantID + "/approve"

	sso := h.ssoHeaders("u-alice", "Alice")
	expectStatus(t, h.call(http.MethodPost, approve, nil, map[string]string{"Cookie": sso["Cookie"]}), http.StatusForbidden, "bad_origin")
	expectStatus(t, h.call(http.MethodPost, approve, nil, map[string]string{"Cookie": sso["Cookie"], "Origin": "https://evil.example.test"}),
		http.StatusForbidden, "bad_origin")
	stale := h.call(http.MethodPost, approve, nil, h.staleSSOHeaders("u-alice"))
	expectStatus(t, stale, http.StatusUnauthorized, "stale_session")
	if string(stale.raw) != `{"error":"stale_session","loginUrl":"/auth/login"}` {
		t.Fatalf("stale = %s", stale.raw)
	}
	expectStatus(t, h.call(http.MethodPost, approve, nil, h.ssoHeaders("u-mallory", "Mallory")), http.StatusNotFound, "grant_not_found")

	deny := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/deny", nil, sso)
	expectStatus(t, deny, http.StatusOK, "")
	if string(deny.raw) != `{"status":"denied"}` {
		t.Fatalf("deny = %s", deny.raw)
	}
	// A repeated deny succeeds only because the authority already says denied.
	denyAgain := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/deny", nil, sso)
	expectStatus(t, denyAgain, http.StatusOK, "")
	if denyAgain.str("status") != "denied" {
		t.Fatalf("deny again = %s", denyAgain.raw)
	}
	if polled := h.poll(grantID, pollSecret); string(polled.raw) != `{"status":"denied"}` {
		t.Fatalf("poll after deny = %s", polled.raw)
	}
	// Approving a denied grant: 409 with the authoritative status.
	conflict := h.call(http.MethodPost, approve, nil, sso)
	expectStatus(t, conflict, http.StatusConflict, "grant_not_pending")
	if string(conflict.raw) != `{"error":"grant_not_pending","status":"denied"}` {
		t.Fatalf("approve denied = %s", conflict.raw)
	}
}

func TestDeviceGrantApproveDenyRace(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	sso := h.ssoHeaders("u-alice", "Alice")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, sso), http.StatusOK, "")
	// A repeated approve click is idempotent.
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, sso), http.StatusOK, "")

	denyAfterApprove := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/deny", nil, sso)
	expectStatus(t, denyAfterApprove, http.StatusConflict, "grant_not_pending")
	if denyAfterApprove.str("status") != "approved" {
		t.Fatalf("deny after approve = %s", denyAfterApprove.raw)
	}

	if issued := h.poll(grantID, pollSecret); issued.str("status") != "issued" {
		t.Fatalf("issued = %s", issued.raw)
	}
	denyAfterConsumed := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/deny", nil, sso)
	expectStatus(t, denyAfterConsumed, http.StatusConflict, "grant_not_pending")
	if denyAfterConsumed.str("status") != "consumed" {
		t.Fatalf("deny after consumed = %s", denyAfterConsumed.raw)
	}
	approveAfterConsumed := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, sso)
	if string(approveAfterConsumed.raw) != `{"status":"approved"}` {
		t.Fatalf("approve after consumed = %s", approveAfterConsumed.raw)
	}

	// Past expiresAt a losing deny reports expired.
	h.a.Devices.Now = func() time.Time { return time.UnixMilli(h.grant(grantID).ExpiresAt) }
	late := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/deny", nil, sso)
	expectStatus(t, late, http.StatusConflict, "grant_not_pending")
	if late.str("status") != "expired" {
		t.Fatalf("late deny = %s", late.raw)
	}
}

func TestDeviceApproveSecondOwnershipCheck(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	// The machine was re-bound to someone else after enroll.
	h.setMachineOwner(enrollMachineID, "u-mallory", "Mallory")
	approved := h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice"))
	expectStatus(t, approved, http.StatusConflict, "machine_ownership_changed")
	if polled := h.poll(grantID, pollSecret); polled.str("status") != "denied" {
		t.Fatalf("poll = %s", polled.raw)
	}
}

func TestDevicePollThirdOwnershipCheck(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusOK, "")
	h.setMachineOwner(enrollMachineID, "u-mallory", "Mallory")
	polled := h.poll(grantID, pollSecret)
	expectStatus(t, polled, http.StatusOK, "")
	if string(polled.raw) != `{"status":"denied","reason":"machine_ownership_changed"}` {
		t.Fatalf("poll = %s", polled.raw)
	}
	if grant := h.grant(grantID); grant.Status != store.DeviceGrantDenied {
		t.Fatalf("grant status = %s", grant.Status)
	}
}

func TestDevicePollSecretGate(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, _ := h.enrollOK(enrollMachineID)
	expectStatus(t, h.poll(grantID, "wrong"), http.StatusNotFound, "grant_not_found")
	expectStatus(t, h.poll("deadbeefdeadbeef", "x"), http.StatusNotFound, "grant_not_found")
	expectStatus(t, h.poll("not-hex", "x"), http.StatusBadRequest, "bad_request")
	expectStatus(t, h.poll(grantID, ""), http.StatusBadRequest, "bad_request")
	expectStatus(t, h.call(http.MethodPost, "/api/devices/enroll/poll", "", nil), http.StatusBadRequest, "bad_request")

	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.poll(grantID, "x"), http.StatusServiceUnavailable, "store_unavailable")
}

func TestDevicePollLogicalTTLAppliesToConsumed(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusOK, "")
	if issued := h.poll(grantID, pollSecret); issued.str("status") != "issued" {
		t.Fatalf("issued = %s", issued.raw)
	}
	h.a.Devices.Now = func() time.Time { return time.UnixMilli(h.grant(grantID).ExpiresAt + 1) }
	expired := h.poll(grantID, pollSecret)
	expectStatus(t, expired, http.StatusOK, "")
	if string(expired.raw) != `{"status":"expired"}` {
		t.Fatalf("expired = %s", expired.raw)
	}
}

func TestDevicePollRecoversConsumeBeforeCreateCrash(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusOK, "")
	grant := h.grant(grantID)

	// The server crashed after the consume CAS and before creating the device.
	if err := h.repo.ConsumeDeviceGrant(context.Background(), grantID, grant.PollSecretHash, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	deviceID := "d-" + auth.SHA256Hex("device:" + grantID)[:16]
	if _, ok := h.device(deviceID); ok {
		t.Fatal("device exists before recovery")
	}
	recovered := h.poll(grantID, pollSecret)
	expectStatus(t, recovered, http.StatusOK, "")
	if recovered.str("status") != "issued" || recovered.str("deviceId") != deviceID {
		t.Fatalf("recovered = %s", recovered.raw)
	}
	if dev, ok := h.device(deviceID); !ok || dev.Status != store.DeviceStatusActive {
		t.Fatalf("device = %+v", dev)
	}
}

func TestDevicePollConsumedDeviceStates(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusOK, "")
	issued := h.poll(grantID, pollSecret)
	deviceID := issued.str("deviceId")

	// A revoked device is never re-issued from the grant.
	if _, err := h.repo.ForceRevokeDevice(context.Background(), deviceID); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, h.poll(grantID, pollSecret), http.StatusUnauthorized, "device_revoked")

	// A record owned by someone else under the derived id: 409.
	h.resetDevices()
	dev := mobileTestDevice(deviceID, "u-mallory")
	dev.ApprovedVia = store.DeviceApprovedViaFeishuConfirm
	h.createDevice(dev)
	expectStatus(t, h.poll(grantID, pollSecret), http.StatusConflict, "grant_already_consumed")
}

func TestDevicePollConflictingDeviceRecord(t *testing.T) {
	h := newDeviceHarness(t)
	h.seedMachine(enrollMachineID, "u-alice", "Alice", "alice-macbook")
	grantID, pollSecret := h.enrollOK(enrollMachineID)
	expectStatus(t, h.call(http.MethodPost, "/api/devices/grants/"+grantID+"/approve", nil, h.ssoHeaders("u-alice", "Alice")), http.StatusOK, "")
	// Something else already occupies the derived id with a different
	// provenance: the poll must not adopt it.
	deviceID := "d-" + auth.SHA256Hex("device:" + grantID)[:16]
	h.createDevice(mobileTestDevice(deviceID, "u-alice"))
	conflict := h.poll(grantID, pollSecret)
	if conflict.status != http.StatusInternalServerError || conflict.str("error") != "device_conflict" {
		t.Fatalf("conflict = %d %s", conflict.status, conflict.raw)
	}
}

// mobileTestDevice is a minimal active mobile record for conflict tests.
func mobileTestDevice(deviceID, unionID string) store.DeviceDoc {
	now := time.Now().UnixMilli()
	return store.DeviceDoc{
		ID: deviceID, UnionID: unionID, OwnerName: "Someone", DeviceKind: store.DeviceKindMobile, DeviceName: "phone",
		Scopes: store.MobileDeviceScopes(), CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "f-test", RefreshGeneration: 1, RefreshTokenHash: "h", RefreshCurrentJTI: "j",
		RefreshRotatedAt: now, EnrolledAt: now, DeviceExp: now + deviceLifetimeMS, LastSeenAt: now,
		ApprovedVia: store.DeviceApprovedViaSSOMobile,
	}
}
