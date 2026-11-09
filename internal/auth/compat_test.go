package auth

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const compatSecret = "compat-secret-123"

func compatConfig() config.Config {
	return config.Config{
		SigningSecret:   compatSecret,
		SessionTTL:      time.Hour,
		MachineTokenTTL: 180 * 24 * time.Hour,
		BindCodeTTL:     5 * time.Minute,
	}
}

func TestTypeScriptGoldenTokens(t *testing.T) {
	cfg := compatConfig()
	now := time.Unix(1700000000, 0)
	machineNow := time.Unix(1700000000, 123000000)

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "session full",
			got: MintSessionAt(cfg, SessionUser{
				UnionID: "on_abc", OpenID: "ou_def", Name: "王小明", Avatar: "https://example/avatar.png",
				UserToken: &SessionUserToken{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: 1800000000},
			}, now),
			want: "eyJraW5kIjoic2Vzc2lvbiIsInVuaW9uSWQiOiJvbl9hYmMiLCJvcGVuSWQiOiJvdV9kZWYiLCJuYW1lIjoi546L5bCP5piOIiwiYXZhdGFyIjoiaHR0cHM6Ly9leGFtcGxlL2F2YXRhci5wbmciLCJ1dCI6eyJhIjoiYWNjZXNzIiwiciI6InJlZnJlc2giLCJlIjoxODAwMDAwMDAwfSwiYXV0aFRpbWUiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.JHL20EcZcpsSP363rVcohMTpfsi1np_1f3pKTXvPycc",
		},
		{
			name: "session optional fields omitted",
			got:  MintSessionAt(cfg, SessionUser{UnionID: "on_min", Name: "Minimal"}, now),
			want: "eyJraW5kIjoic2Vzc2lvbiIsInVuaW9uSWQiOiJvbl9taW4iLCJuYW1lIjoiTWluaW1hbCIsImF1dGhUaW1lIjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.ckjzs9DyRr_KQp5YBVDwtDqt6jC10QfvOURPze7Gwt4",
		},
		{
			name: "session JSON.stringify Unicode escaping",
			got:  MintSessionAt(cfg, SessionUser{UnionID: "on_escape", Name: "<>&\u2028\u2029"}, now),
			want: "eyJraW5kIjoic2Vzc2lvbiIsInVuaW9uSWQiOiJvbl9lc2NhcGUiLCJuYW1lIjoiPD4m4oCo4oCpIiwiYXV0aFRpbWUiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.7j3M9XaSxZVaAI7yeAj7MPuOAM5D8kjkIKIqFaRgPRE",
		},
		{
			name: "machine",
			got:  MintMachineTokenAt(cfg, MachineIdentity{UnionID: "on_abc", OwnerName: "王小明", MachineID: "deadbeefcafebabe"}, machineNow),
			want: "eyJraW5kIjoibWFjaGluZSIsInVuaW9uSWQiOiJvbl9hYmMiLCJvd25lck5hbWUiOiLnjovlsI_mmI4iLCJtYWNoaW5lSWQiOiJkZWFkYmVlZmNhZmViYWJlIiwiaWF0IjoxNzAwMDAwMDAwMTIzLCJleHAiOjE3MTU1NTIwMDB9.zNSRV-OJto5zhSjPxYsu89HF1XbeQSgB5LSwnpiFcXc",
		},
		{
			name: "bind",
			got:  IssueBindTokenAt(cfg, BindIdentity{UnionID: "on_abc", OwnerName: "王小明"}, now),
			want: "eyJraW5kIjoiYmluZCIsInVuaW9uSWQiOiJvbl9hYmMiLCJvd25lck5hbWUiOiLnjovlsI_mmI4iLCJleHAiOjE3MDAwMDAzMDB9.GfgAwMUz4mpL4RSeA7FpW1sPuZWE-LOIvtJESLUP9ds",
		},
		{
			name: "proxy ticket",
			got:  issueProxyTicket(cfg, ProxyIdentity{UnionID: "on_abc", MachineID: "deadbeefcafebabe"}, now, "00112233445566778899aabbccddeeff"),
			want: "eyJraW5kIjoicHJveHktdGlja2V0IiwianRpIjoiMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJ1bmlvbklkIjoib25fYWJjIiwibWFjaGluZUlkIjoiZGVhZGJlZWZjYWZlYmFiZSIsImV4cCI6MTcwMDAwMDAzMH0.WJ73PkwmGqiSWPSTU1Ce0vtKhZ6YFwy9-vRmgpGfroA",
		},
		{
			name: "proxy session",
			got:  MintProxySessionAt(cfg, ProxyIdentity{UnionID: "on_abc", MachineID: "deadbeefcafebabe"}, now),
			want: "eyJraW5kIjoicHJveHktc2Vzc2lvbiIsInVuaW9uSWQiOiJvbl9hYmMiLCJtYWNoaW5lSWQiOiJkZWFkYmVlZmNhZmViYWJlIiwiZXhwIjoxNzAwNjA0ODAwfQ.b-LGCZBC7860eL92Ak7TLvdcuaQL3QBCyDu2jLq_HrI",
		},
	}
	// The proxy-session fixture uses the production 7-day session TTL.
	cfg.SessionTTL = 7 * 24 * time.Hour
	tests[len(tests)-1].got = MintProxySessionAt(cfg, ProxyIdentity{UnionID: "on_abc", MachineID: "deadbeefcafebabe"}, now)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("token mismatch\n got: %s\nwant: %s", tc.got, tc.want)
			}
		})
	}
}

func TestVerifyTypeScriptTokensAndExpiryBoundary(t *testing.T) {
	cfg := compatConfig()
	const sessionToken = "eyJraW5kIjoic2Vzc2lvbiIsInVuaW9uSWQiOiJvbl9hYmMiLCJvcGVuSWQiOiJvdV9kZWYiLCJuYW1lIjoi546L5bCP5piOIiwiYXZhdGFyIjoiaHR0cHM6Ly9leGFtcGxlL2F2YXRhci5wbmciLCJ1dCI6eyJhIjoiYWNjZXNzIiwiciI6InJlZnJlc2giLCJlIjoxODAwMDAwMDAwfSwiZXhwIjoxNzAwMDAzNjAwfQ.2rLIOZjJ16K3R_ar1GZL6shzl9kxR3IyHbaOERRtOtk"

	payload, err := VerifySessionAt(cfg, sessionToken, time.Unix(1700003600, 0))
	if err != nil {
		t.Fatalf("exp == now must remain valid: %v", err)
	}
	if payload.UnionID != "on_abc" || payload.OpenID != "ou_def" || payload.UserToken == nil || payload.UserToken.RefreshToken != "refresh" {
		t.Fatalf("decoded payload = %#v", payload)
	}
	if _, err := VerifySessionAt(cfg, sessionToken, time.Unix(1700003601, 0)); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired verify error = %v", err)
	}
	if _, err := VerifyMachineTokenAt(cfg, sessionToken, time.Unix(1700000000, 0)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cross-kind verify error = %v", err)
	}
	if _, err := VerifySessionAt(cfg, sessionToken+"x", time.Unix(1700000000, 0)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered verify error = %v", err)
	}
}

func TestLegacyMachineTokenWithoutIAT(t *testing.T) {
	cfg := compatConfig()
	const legacy = "eyJraW5kIjoibWFjaGluZSIsInVuaW9uSWQiOiJvbl9vbGQiLCJvd25lck5hbWUiOiJPbGQiLCJtYWNoaW5lSWQiOiIwMTIzNDU2NyIsImV4cCI6MTcxNTU1MjAwMH0.3NqQWeKt9cNTc-9i2nOBvGvHhkfP0l45wgFyNzUgGPc"
	payload, err := VerifyMachineTokenAt(cfg, legacy, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if payload.IAT != nil || payload.MachineID != "01234567" {
		t.Fatalf("legacy payload = %#v", payload)
	}
}

func TestBindBlobTypeScriptGolden(t *testing.T) {
	const token = "eyJraW5kIjoiYmluZCIsInVuaW9uSWQiOiJvbl9hYmMiLCJvd25lck5hbWUiOiLnjovlsI_mmI4iLCJleHAiOjE3MDAwMDAzMDB9.GfgAwMUz4mpL4RSeA7FpW1sPuZWE-LOIvtJESLUP9ds"
	const want = "eyJ1IjoiaHR0cHM6Ly9ib3RtdXguZXhhbXBsZSIsInQiOiJleUpyYVc1a0lqb2lZbWx1WkNJc0luVnVhVzl1U1dRaU9pSnZibDloWW1NaUxDSnZkMjVsY2s1aGJXVWlPaUxuam92bHNJX21tSTRpTENKbGVIQWlPakUzTURBd01EQXpNREI5LkdmZ0F3TVV6NG1wTDRSU2VBN0ZwVzFzUHVaV0UtTE9JdnRKRVNMVVA5ZHMifQ"
	got := EncodeBindBlob("https://botmux.example", token)
	if got != want {
		t.Fatalf("blob mismatch\n got: %s\nwant: %s", got, want)
	}
	decoded, err := DecodeBindBlob(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, BindBlob{PlatformBaseURL: "https://botmux.example", Token: token}) {
		t.Fatalf("decoded blob = %#v", decoded)
	}
}
