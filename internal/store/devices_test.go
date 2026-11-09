package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Ports of test/store-devices.test.ts.

const dayMS int64 = 24 * 3600 * 1000

func makeDevice(now int64, mutate ...func(*DeviceDoc)) DeviceDoc {
	d := DeviceDoc{
		ID: "dev-1", UnionID: "u-alice", OwnerName: "Alice", DeviceKind: DeviceKindDesktopIDE, DeviceName: "my-macbook",
		Scopes: DeviceMVPScopes(), CredentialVersion: 1, Status: DeviceStatusActive, RefreshFamilyID: "fam-1",
		RefreshGeneration: 1, RefreshTokenHash: "hash-r1", RefreshCurrentJTI: "jti-r1", RefreshRetryKeyHash: "",
		ReplayUntil: 0, RefreshRotatedAt: now, EnrolledAt: now, DeviceExp: now + 90*dayMS, LastSeenAt: now,
		ApprovedVia: DeviceApprovedViaFeishuConfirm,
	}
	for _, m := range mutate {
		m(&d)
	}
	return d
}

func makeGrant(now int64, mutate ...func(*DeviceGrantDoc)) DeviceGrantDoc {
	g := DeviceGrantDoc{
		ID: "grant-1", Kind: DeviceGrantKindF1MachineEnroll, UnionID: "u-alice", MachineID: "aabbccdd11223344",
		DeviceKind: DeviceKindDesktopIDE, DeviceName: "my-macbook", Scopes: DeviceMVPScopes(), PollSecretHash: "hash-poll",
		Status: DeviceGrantPending, CreatedAt: now, ExpiresAt: now + 5*60_000,
	}
	for _, m := range mutate {
		m(&g)
	}
	return g
}

func rotate(t *testing.T, s memoryRepo, id, presented string, gen int64, key, next, jti string, now int64) RotateRefreshOutcome {
	t.Helper()
	out, err := s.RotateDeviceRefresh(context.Background(), RotateDeviceRefreshInput{
		DeviceID: id, PresentedHash: presented, PresentedGeneration: gen, RetryKeyHash: key, NewHash: next, NewJTI: jti, NowMS: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeviceScopeSets(t *testing.T) {
	t.Parallel()
	mvp := DeviceMVPScopes()
	if len(mvp) != 4 || mvp[3] != DeviceScopeSelfRefresh {
		t.Fatalf("mvp = %v", mvp)
	}
	mvp[0] = "mutated"
	mobile := MobileDeviceScopes()
	if len(mobile) != 5 || mobile[0] != DeviceScopeMachinesRead || mobile[4] != DeviceScopeDashboardManage {
		t.Fatalf("mobile = %v", mobile)
	}
}

func TestCreateDeviceRejectsDuplicateIDs(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	if err := s.CreateDevice(context.Background(), makeDevice(now)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDevice(context.Background(), makeDevice(now)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	raw := s.db.MemoryCollection(collectionDevices).Documents()[0]
	if _, ok := raw["credentialVersion"].(int32); !ok {
		t.Fatalf("credentialVersion = %T", raw["credentialVersion"])
	}
	if _, ok := raw["enrolledAt"].(float64); !ok {
		t.Fatalf("enrolledAt = %T", raw["enrolledAt"])
	}
	if _, ok := raw["prevRefreshTokenHash"]; ok {
		t.Fatal("empty prevRefreshTokenHash must be omitted")
	}
}

func TestGetDeviceDistinguishesMissing(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	if _, err := s.GetDevice(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	want := makeDevice(s.nowMS())
	_ = s.CreateDevice(ctx, want)
	got, err := s.GetDevice(ctx, "dev-1")
	if err != nil || got.UnionID != "u-alice" || got.DeviceExp != want.DeviceExp || got.RefreshGeneration != 1 || len(got.Scopes) != 4 {
		t.Fatalf("device = %+v %v", got, err)
	}
}

func TestListDevicesForUserListsOnlyOwnDevices(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	_ = s.CreateDevice(ctx, makeDevice(now))
	_ = s.CreateDevice(ctx, makeDevice(now, func(d *DeviceDoc) { d.ID, d.UnionID, d.OwnerName = "dev-2", "u-bob", "Bob" }))
	got, err := s.ListDevicesForUser(ctx, "u-alice")
	if err != nil || len(got) != 1 || got[0].ID != "dev-1" {
		t.Fatalf("list = %+v %v", got, err)
	}
}

func TestRevokeDeviceIsOwnerScopedAndIdempotent(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	_ = s.CreateDevice(ctx, makeDevice(s.nowMS()))
	if err := s.RevokeDevice(ctx, "dev-1", "u-mallory"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user revoke = %v", err)
	}
	if err := s.RevokeDevice(ctx, "dev-1", "u-alice"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetDevice(ctx, "dev-1")
	if after.Status != DeviceStatusRevoked || after.CredentialVersion != 2 {
		t.Fatalf("after = %+v", after)
	}
	if err := s.RevokeDevice(ctx, "dev-1", "u-alice"); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetDevice(ctx, "dev-1")
	if again.CredentialVersion != 2 {
		t.Fatalf("idempotent revoke bumped version: %+v", again)
	}
	if err := s.RevokeDevice(ctx, "missing", "u-alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if v, ok := s.db.MemoryCollection(collectionDevices).Documents()[0]["credentialVersion"].(int32); !ok || v != 2 {
		t.Fatalf("$inc must keep int32: %T", s.db.MemoryCollection(collectionDevices).Documents()[0]["credentialVersion"])
	}
}

func TestForceRevokeDeviceReportsTransitionOnce(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	_ = s.CreateDevice(ctx, makeDevice(s.nowMS()))
	if now, err := s.ForceRevokeDevice(ctx, "dev-1"); err != nil || !now {
		t.Fatalf("first = %v %v", now, err)
	}
	if after, _ := s.GetDevice(ctx, "dev-1"); after.Status != DeviceStatusRevoked {
		t.Fatalf("after = %+v", after)
	}
	for _, id := range []string{"dev-1", "nope"} {
		if now, err := s.ForceRevokeDevice(ctx, id); err != nil || now {
			t.Fatalf("%s = %v %v", id, now, err)
		}
	}
}

func TestRotateDeviceRefreshRotatesOnce(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	r := rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now)
	d := r.Device
	if r.Result != RotateRotated || d.RefreshTokenHash != "hash-r2" || d.PrevRefreshTokenHash != "hash-r1" || d.RefreshGeneration != 2 ||
		d.RefreshCurrentJTI != "jti-r2" || d.RefreshRetryKeyHash != "key-1" || d.ReplayUntil != now+60_000 || d.LastSeenAt != now || d.RefreshRotatedAt != now {
		t.Fatalf("rotated = %+v %+v", r, d)
	}
}

func TestRotateCurrentWithinWindowDoesNotAdvance(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now)
	r := rotate(t, s, "dev-1", "hash-r2", 2, "key-2", "hash-r3", "jti-r3", now+5000)
	if r.Result != RotateCurrentWithinWindow || r.Device.RefreshGeneration != 2 || r.Device.RefreshTokenHash != "hash-r2" ||
		r.Device.RefreshCurrentJTI != "jti-r2" || r.Device.ReplayUntil != now+60_000 {
		t.Fatalf("result = %+v %+v", r, r.Device)
	}
}

func TestRotateExactReplayWithSameKey(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	if r := rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now); r.Result != RotateRotated {
		t.Fatal(r.Result)
	}
	for _, at := range []int64{now + 1000, now + 2000} {
		r := rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", at)
		if r.Result != RotateExactReplay || r.Device.RefreshGeneration != 2 || r.Device.RefreshTokenHash != "hash-r2" ||
			r.Device.ReplayUntil != now+60_000 || r.Device.RefreshCurrentJTI != "jti-r2" || r.Device.RefreshRetryKeyHash != "key-1" {
			t.Fatalf("replay = %+v %+v", r, r.Device)
		}
	}
}

func TestRotatePrevWithDifferentKeyIsInProgress(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now)
	if r := rotate(t, s, "dev-1", "hash-r1", 1, "key-EVIL", "hash-x", "jti-x", now+1000); r.Result != RotateRefreshInProgress || r.Device != nil {
		t.Fatalf("result = %+v", r)
	}
	doc, _ := s.GetDevice(context.Background(), "dev-1")
	if doc.Status != DeviceStatusActive || doc.RefreshGeneration != 2 || doc.RefreshTokenHash != "hash-r2" {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestRotatePrevOutsideWindowIsReplayExpired(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now)
	for _, key := range []string{"key-1", "key-9"} {
		if r := rotate(t, s, "dev-1", "hash-r1", 1, key, "hash-x", "jti-x", now+61_000); r.Result != RotateReplayExpired {
			t.Fatalf("%s = %v", key, r.Result)
		}
	}
}

func TestRotateOlderGenerationIsStale(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	now := s.nowMS()
	_ = s.CreateDevice(context.Background(), makeDevice(now))
	rotate(t, s, "dev-1", "hash-r1", 1, "key-1", "hash-r2", "jti-r2", now)
	t2 := now + 61_000
	if r := rotate(t, s, "dev-1", "hash-r2", 2, "key-2", "hash-r3", "jti-r3", t2); r.Result != RotateRotated {
		t.Fatal(r.Result)
	}
	if r := rotate(t, s, "dev-1", "hash-r1", 1, "key-3", "hash-r4", "jti-r4", t2+1); r.Result != RotateStaleGeneration {
		t.Fatal(r.Result)
	}
	// The current token presented after its window is "invalid" (no rotation:
	// rotation requires the window to have passed AND the CAS to match).
	if r := rotate(t, s, "dev-1", "hash-r3", 3, "k", "hash-r5", "jti-r5", t2+61_000); r.Result != RotateRotated {
		t.Fatal(r.Result)
	}
}

func TestRotateInvalidRevokedExpiredNotFound(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	_ = s.CreateDevice(ctx, makeDevice(now))
	if r := rotate(t, s, "dev-1", "hash-unknown", 1, "q", "x", "j", now); r.Result != RotateInvalid {
		t.Fatal(r.Result)
	}
	if r := rotate(t, s, "nope", "h", 1, "q", "x", "j", now); r.Result != RotateNotFound {
		t.Fatal(r.Result)
	}
	_ = s.CreateDevice(ctx, makeDevice(now, func(d *DeviceDoc) { d.ID, d.RefreshTokenHash, d.DeviceExp = "dev-old", "hash-o1", now-1 }))
	if r := rotate(t, s, "dev-old", "hash-o1", 1, "q", "x", "j", now); r.Result != RotateExpired {
		t.Fatal(r.Result)
	}
	_, _ = s.ForceRevokeDevice(ctx, "dev-1")
	if r := rotate(t, s, "dev-1", "hash-r1", 1, "q", "x", "j", now); r.Result != RotateRevoked {
		t.Fatal(r.Result)
	}
	// A future generation with an unknown hash is invalid, not stale.
	_ = s.CreateDevice(ctx, makeDevice(now, func(d *DeviceDoc) { d.ID = "dev-3" }))
	if r := rotate(t, s, "dev-3", "hash-r1", 7, "q", "x", "j", now); r.Result != RotateInvalid {
		t.Fatal(r.Result)
	}
}

func TestTouchDeviceLastSeen(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	_ = s.CreateDevice(ctx, makeDevice(s.nowMS()))
	if err := s.TouchDeviceLastSeen(ctx, "dev-1", 42); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchDeviceLastSeen(ctx, "missing", 42); err != nil {
		t.Fatalf("best-effort touch must not report missing devices: %v", err)
	}
	if d, _ := s.GetDevice(ctx, "dev-1"); d.LastSeenAt != 42 {
		t.Fatalf("lastSeenAt = %d", d.LastSeenAt)
	}
}

func TestDeviceGrantStateMachine(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	if err := s.CreateDeviceGrant(ctx, makeGrant(now)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDeviceGrant(ctx, makeGrant(now)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate grant = %v", err)
	}
	if err := s.ApproveDeviceGrant(ctx, "grant-1", "u-alice", "dev-9", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveDeviceGrant(ctx, "grant-1", "u-alice", "dev-9", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approve = %v", err)
	}
	g, err := s.GetDeviceGrant(ctx, "grant-1")
	if err != nil || g.DeviceID != "dev-9" || g.Status != DeviceGrantApproved || g.DecidedAt != now || !g.ExpireAt.Equal(time.UnixMilli(now+5*60_000)) {
		t.Fatalf("grant = %+v %v", g, err)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-1", "hash-poll", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-1", "hash-poll", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("second consume = %v", err)
	}
	if _, err := s.GetDeviceGrant(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing grant = %v", err)
	}
}

func TestDeviceGrantCASConditions(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	_ = s.CreateDeviceGrant(ctx, makeGrant(now))
	if err := s.ApproveDeviceGrant(ctx, "grant-1", "u-mallory", "dev-9", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign approve = %v", err)
	}
	_ = s.CreateDeviceGrant(ctx, makeGrant(now, func(g *DeviceGrantDoc) { g.ID, g.ExpiresAt = "grant-old", now-1 }))
	if err := s.ApproveDeviceGrant(ctx, "grant-old", "u-alice", "dev-9", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired approve = %v", err)
	}
	if err := s.ApproveDeviceGrant(ctx, "grant-1", "u-alice", "dev-9", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-1", "hash-wrong", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong secret = %v", err)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-1", "hash-poll", now+10*60_000); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired consume = %v", err)
	}
}

func TestDeviceGrantDeniedAndVoided(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	ctx := context.Background()
	now := s.nowMS()
	_ = s.CreateDeviceGrant(ctx, makeGrant(now))
	if err := s.DenyDeviceGrant(ctx, "grant-1", "u-alice", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveDeviceGrant(ctx, "grant-1", "u-alice", "dev-9", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve after deny = %v", err)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-1", "hash-poll", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("consume after deny = %v", err)
	}
	// Void only applies to approved grants (no owner/expiry condition).
	_ = s.CreateDeviceGrant(ctx, makeGrant(now, func(g *DeviceGrantDoc) { g.ID, g.ExpiresAt = "grant-2", now+1 }))
	if err := s.VoidApprovedDeviceGrant(ctx, "grant-2", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("void pending = %v", err)
	}
	_ = s.ApproveDeviceGrant(ctx, "grant-2", "u-alice", "dev-2", now)
	if err := s.VoidApprovedDeviceGrant(ctx, "grant-2", now+10*60_000); err != nil {
		t.Fatalf("void expired approved grant = %v", err)
	}
	if g, _ := s.GetDeviceGrant(ctx, "grant-2"); g.Status != DeviceGrantDenied || g.DecidedAt != now+10*60_000 {
		t.Fatalf("voided = %+v", g)
	}
	if err := s.ConsumeDeviceGrant(ctx, "grant-2", "hash-poll", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("consume after void = %v", err)
	}
}

// insertOne keeps the client's field order, so the inserted document must
// list fields in the src/server/devices.ts object-literal order.
func TestDeviceInsertDocumentFollowsTSFieldOrder(t *testing.T) {
	t.Parallel()
	want := []string{"_id", "unionId", "ownerName", "deviceKind", "deviceName", "scopes", "credentialVersion", "status",
		"refreshFamilyId", "refreshGeneration", "refreshTokenHash", "prevRefreshTokenHash", "refreshCurrentJti",
		"refreshRetryKeyHash", "replayUntil", "refreshRotatedAt", "enrolledAt", "deviceExp", "lastSeenAt", "approvedVia"}
	typ := reflect.TypeOf(deviceInsertDocument{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, strings.Split(typ.Field(i).Tag.Get("bson"), ",")[0])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("field order = %v\nwant %v", got, want)
	}
}
