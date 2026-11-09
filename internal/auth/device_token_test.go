package auth

import (
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Ports of test/auth-device-token.test.ts.

const dayMS = int64(24 * time.Hour / time.Millisecond)

func deviceTestConfig() config.Config {
	return config.Config{SigningSecret: "test-secret", SessionTTL: 7 * 24 * time.Hour}
}

func makeTestDevice(nowMS int64, edit func(*store.DeviceDoc)) store.DeviceDoc {
	doc := store.DeviceDoc{
		ID: "dev-1", UnionID: "u-alice", OwnerName: "Alice", DeviceKind: store.DeviceKindDesktopIDE, DeviceName: "my-macbook",
		Scopes: store.DeviceMVPScopes(), CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "fam-1", RefreshGeneration: 1, RefreshTokenHash: "hash-r1", RefreshCurrentJTI: "jti-r1",
		RefreshRotatedAt: nowMS, EnrolledAt: nowMS, DeviceExp: nowMS + 90*dayMS, LastSeenAt: nowMS,
		ApprovedVia: store.DeviceApprovedViaFeishuConfirm,
	}
	if edit != nil {
		edit(&doc)
	}
	return doc
}

func TestDeviceAccessTokenRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	now := time.Now().UnixMilli()
	p, err := VerifyDeviceAccessToken(cfg, MintDeviceAccessToken(cfg, makeTestDevice(now, nil), now))
	if err != nil {
		t.Fatal(err)
	}
	if p.UnionID != "u-alice" || p.DeviceID != "dev-1" || p.CredentialVersion != 1 || len(p.Scopes) != 4 || p.IAT != now ||
		p.Exp != now/1000+DeviceAccessTTLSec {
		t.Fatalf("payload = %+v", p)
	}
}

func TestDeviceAccessTokenCappedByDeviceExp(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	now := time.Now().UnixMilli()
	deviceExp := now + 5*60_000 + 789
	p, err := VerifyDeviceAccessToken(cfg, MintDeviceAccessToken(cfg, makeTestDevice(now, func(d *store.DeviceDoc) { d.DeviceExp = deviceExp }), now))
	if err != nil {
		t.Fatal(err)
	}
	if p.Exp != deviceExp/1000 || p.Exp >= now/1000+DeviceAccessTTLSec {
		t.Fatalf("exp = %d", p.Exp)
	}
}

func TestDeviceTokensRejectCrossPurposeUse(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	now := time.Now().UnixMilli()
	access := MintDeviceAccessToken(cfg, makeTestDevice(now, nil), now)
	if _, err := ParseDeviceRefreshToken(cfg, access); err == nil {
		t.Fatal("access token parsed as refresh token")
	}
	refresh := BuildDeviceRefreshToken(cfg, DeviceRefreshClaims{DeviceID: "dev-1", FamilyID: "fam-1", Generation: 2, JTI: "j", CredentialVersion: 1, DeviceExpMS: now + dayMS})
	if _, err := VerifyDeviceAccessToken(cfg, refresh); err == nil {
		t.Fatal("refresh token verified as access token")
	}
	// The refresh MAC key is domain-separated from the signing secret.
	if err := VerifyToken(refresh, cfg.SigningSecret, "device-refresh", time.Now(), nil); err == nil {
		t.Fatal("refresh token verifies with the raw signing secret")
	}
}

func TestDeviceRefreshTokenIsByteDeterministic(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	deviceExp := time.Now().UnixMilli() + 90*dayMS
	jti := DeriveRefreshJTI(cfg, SHA256Hex("R0-token-bytes"), "idem-key-128bit", 2)
	claims := DeviceRefreshClaims{DeviceID: "dev-1", FamilyID: "fam-1", Generation: 2, JTI: jti, CredentialVersion: 1, DeviceExpMS: deviceExp}
	first := BuildDeviceRefreshToken(cfg, claims)
	if rebuilt := BuildDeviceRefreshToken(cfg, claims); rebuilt != first {
		t.Fatalf("rebuilt token differs:\n%s\n%s", first, rebuilt)
	}
	p, err := ParseDeviceRefreshToken(cfg, first)
	if err != nil || p.Generation != 2 || p.FamilyID != "fam-1" || p.JTI != jti || p.Exp != deviceExp/1000 {
		t.Fatalf("payload = %+v err = %v", p, err)
	}
}

func TestDeriveRefreshJTIInputs(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	h := SHA256Hex("R0")
	base := DeriveRefreshJTI(cfg, h, "key-1", 2)
	if DeriveRefreshJTI(cfg, h, "key-1", 2) != base {
		t.Fatal("same inputs gave different jti")
	}
	for _, other := range []string{DeriveRefreshJTI(cfg, h, "key-2", 2), DeriveRefreshJTI(cfg, h, "key-1", 3), DeriveRefreshJTI(cfg, SHA256Hex("R1"), "key-1", 2)} {
		if other == base {
			t.Fatal("different inputs gave the same jti")
		}
	}
}

func TestDeviceRefreshTokenRejectsTamperingAndOtherSecret(t *testing.T) {
	t.Parallel()
	cfg := deviceTestConfig()
	token := BuildDeviceRefreshToken(cfg, DeviceRefreshClaims{DeviceID: "dev-1", FamilyID: "fam-1", Generation: 2, JTI: "j", CredentialVersion: 1, DeviceExpMS: time.Now().UnixMilli() + dayMS})
	swap := byte('A')
	if token[10] == 'A' {
		swap = 'B'
	}
	tampered := token[:10] + string(swap) + token[11:]
	if _, err := ParseDeviceRefreshToken(cfg, tampered); err == nil {
		t.Fatal("tampered token accepted")
	}
	other := cfg
	other.SigningSecret = "other-secret"
	if _, err := ParseDeviceRefreshToken(other, token); err == nil {
		t.Fatal("token accepted under another secret")
	}
}
