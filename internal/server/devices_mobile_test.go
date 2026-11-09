package server

import (
	"context"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of test/server-devices-mobile-bind.test.ts.

var mobileEnrollmentID = strings.Repeat("A", 43)

func (h *deviceHarness) mobileBind(headers map[string]string, body any) harnessResponse {
	h.t.Helper()
	if body == nil {
		body = map[string]any{"enrollmentId": mobileEnrollmentID, "deviceName": "Alice iPhone"}
	}
	return h.call(http.MethodPost, "/api/devices/mobile-bind", body, headers)
}

func TestMobileBindIssuesScopedRefreshableCredentials(t *testing.T) {
	h := newDeviceHarness(t)
	got := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, got, http.StatusOK, "")
	expectKeys(t, got.raw, "status", "deviceId", "accessToken", "refreshToken", "deviceExp", "accessExpiresAt")
	deviceID := got.str("deviceId")
	if got.str("status") != "issued" || !regexp.MustCompile(`^d-[a-f0-9]{16}$`).MatchString(deviceID) {
		t.Fatalf("bind = %s", got.raw)
	}
	if want := "d-" + auth.SHA256Hex("mobile-device:u-alice:" + mobileEnrollmentID)[:16]; deviceID != want {
		t.Fatalf("deviceId = %s, want %s", deviceID, want)
	}
	claims, err := auth.ParseDeviceRefreshToken(h.a.Config, got.str("refreshToken"))
	if err != nil || claims.Generation != 1 || claims.FamilyID != "f-"+auth.SHA256Hex("mobile-family:u-alice:" + mobileEnrollmentID)[:24] {
		t.Fatalf("claims = %+v %v", claims, err)
	}
	dev, ok := h.device(deviceID)
	if !ok || dev.DeviceKind != store.DeviceKindMobile || dev.DeviceName != "Alice iPhone" ||
		dev.ApprovedVia != store.DeviceApprovedViaSSOMobile || !reflect.DeepEqual(dev.Scopes, store.MobileDeviceScopes()) ||
		dev.OwnerName != "Alice" || dev.DeviceExp != dev.EnrolledAt+deviceLifetimeMS {
		t.Fatalf("device = %+v", dev)
	}
	if int64(got.num("accessExpiresAt"))%1000 != 0 || int64(got.num("deviceExp")) != dev.DeviceExp {
		t.Fatalf("times = %s", got.raw)
	}
}

func TestMobileBindRetryIsIdempotentPerAccount(t *testing.T) {
	h := newDeviceHarness(t)
	first := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	retry := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, retry, http.StatusOK, "")
	if retry.str("deviceId") != first.str("deviceId") || retry.str("refreshToken") != first.str("refreshToken") {
		t.Fatalf("retry = %s first = %s", retry.raw, first.raw)
	}
	bob := h.mobileBind(h.ssoHeaders("u-bob", "Bob"), nil)
	expectStatus(t, bob, http.StatusOK, "")
	if bob.str("deviceId") == first.str("deviceId") {
		t.Fatal("accounts collided")
	}
}

func TestMobileBindGates(t *testing.T) {
	h := newDeviceHarness(t)
	sso := h.ssoHeaders("u-alice", "Alice")
	expectStatus(t, h.mobileBind(map[string]string{"Cookie": sso["Cookie"]}, nil), http.StatusForbidden, "bad_origin")
	expectStatus(t, h.mobileBind(map[string]string{"Origin": deviceTestOrigin}, nil), http.StatusUnauthorized, "stale_session")
	expectStatus(t, h.mobileBind(h.staleSSOHeaders("u-alice"), nil), http.StatusUnauthorized, "stale_session")
	expectStatus(t, h.mobileBind(sso, map[string]any{"enrollmentId": "short", "deviceName": "x"}), http.StatusBadRequest, "invalid_enrollment_id")
	expectStatus(t, h.mobileBind(sso, map[string]any{"enrollmentId": mobileEnrollmentID, "deviceName": "  \ufeff\u3000 "}),
		http.StatusBadRequest, "device_name_required")

	issued := h.mobileBind(sso, nil)
	dev, _ := h.device(issued.str("deviceId"))
	bearer := auth.MintDeviceAccessToken(h.a.Config, dev, time.Now().UnixMilli())
	attempt := h.mobileBind(map[string]string{"Authorization": "Bearer " + bearer, "Origin": deviceTestOrigin}, nil)
	expectStatus(t, attempt, http.StatusForbidden, "sso_required")

	h.a.DeviceRepo = store.NewDocumentRepository(store.UnavailableDatabaseProvider{})
	expectStatus(t, h.mobileBind(sso, nil), http.StatusServiceUnavailable, "store_unavailable")
}

func TestMobileBindNeverRevivesRevokedInstall(t *testing.T) {
	h := newDeviceHarness(t)
	first := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	if revokedNow, err := h.repo.ForceRevokeDevice(context.Background(), first.str("deviceId")); err != nil || !revokedNow {
		t.Fatalf("force revoke = %v %v", revokedNow, err)
	}
	retry := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, retry, http.StatusConflict, "device_revoked")
	if string(retry.raw) != `{"error":"device_revoked"}` {
		t.Fatalf("retry = %s", retry.raw)
	}
}

func TestMobileBindOldDeviceWithoutDashboardManageNeedsRecovery(t *testing.T) {
	h := newDeviceHarness(t)
	first := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	dev, _ := h.device(first.str("deviceId"))
	h.resetDevices()
	dev.Scopes = store.DeviceMVPScopes()
	h.createDevice(dev)
	retry := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, retry, http.StatusConflict, "recovery_required")
	if _, leaked := retry.body["accessToken"]; leaked {
		t.Fatalf("retry = %s", retry.raw)
	}
}

func TestMobileBindExpiredInstallReturnsDeviceExpired(t *testing.T) {
	h := newDeviceHarness(t)
	first := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	dev, _ := h.device(first.str("deviceId"))
	h.resetDevices()
	dev.DeviceExp = time.Now().UnixMilli() - 1
	h.createDevice(dev)
	retry := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, retry, http.StatusConflict, "device_expired")
	if _, leaked := retry.body["refreshToken"]; leaked {
		t.Fatalf("retry = %s", retry.raw)
	}
}

func TestMobileBindForeignRecordUnderDerivedIDConflicts(t *testing.T) {
	h := newDeviceHarness(t)
	deviceID := "d-" + auth.SHA256Hex("mobile-device:u-alice:" + mobileEnrollmentID)[:16]
	foreign := mobileTestDevice(deviceID, "u-alice")
	foreign.ApprovedVia = store.DeviceApprovedViaFeishuConfirm
	h.createDevice(foreign)
	expectStatus(t, h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil), http.StatusConflict, "device_conflict")
}

// racingDeviceRepo lets a test interleave a concurrent writer with the
// handler's CreateDevice (the TS test monkey-patches createDeviceDoc).
type racingDeviceRepo struct {
	store.DeviceRepository
	create func(ctx context.Context, doc store.DeviceDoc) error
}

func (r racingDeviceRepo) CreateDevice(ctx context.Context, doc store.DeviceDoc) error {
	return r.create(ctx, doc)
}

func TestMobileBindCreateRevokeRaceReturnsDeviceRevoked(t *testing.T) {
	h := newDeviceHarness(t)
	h.a.DeviceRepo = racingDeviceRepo{DeviceRepository: h.repo, create: func(ctx context.Context, doc store.DeviceDoc) error {
		if err := h.repo.CreateDevice(ctx, doc); err != nil {
			t.Fatal(err)
		}
		if revokedNow, err := h.repo.ForceRevokeDevice(ctx, doc.ID); err != nil || !revokedNow {
			t.Fatalf("force revoke = %v %v", revokedNow, err)
		}
		// Another request created the same record: this one takes the
		// duplicate-race branch.
		return store.ErrConflict
	}}
	raced := h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil)
	expectStatus(t, raced, http.StatusConflict, "device_revoked")
	if _, leaked := raced.body["accessToken"]; leaked {
		t.Fatalf("raced = %s", raced.raw)
	}
}

func TestMobileBindCreateFailureWithoutRecord(t *testing.T) {
	h := newDeviceHarness(t)
	h.a.DeviceRepo = racingDeviceRepo{DeviceRepository: h.repo, create: func(context.Context, store.DeviceDoc) error {
		return store.ErrConflict
	}}
	expectStatus(t, h.mobileBind(h.ssoHeaders("u-alice", "Alice"), nil), http.StatusConflict, "device_conflict")
}
