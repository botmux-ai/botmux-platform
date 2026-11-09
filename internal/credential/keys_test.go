package credential

import (
	"bytes"
	"context"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

func TestVaultClosedWithoutKEK(t *testing.T) {
	cfg := config.Config{}
	if VaultConfigured(cfg) {
		t.Fatal("vault must be closed without a KEK")
	}
	if KeysFromConfig(cfg) != nil {
		t.Fatal("key set must be nil without a KEK")
	}
	keys, err := ConfigKeySource(cfg)(context.Background())
	if keys != nil || err != nil {
		t.Fatalf("config source = %v, %v", keys, err)
	}
}

func TestKeysComeFromConfigAndLegacyOnlyExtendsDecryption(t *testing.T) {
	kek, legacy := randomKey(t), randomKey(t)
	cfg := config.Config{CredentialKEK: kek, CredentialKEKLegacy: [][]byte{legacy}}
	if !VaultConfigured(cfg) {
		t.Fatal("vault must be enabled with a KEK")
	}
	keys := KeysFromConfig(cfg)
	if keys == nil || !bytes.Equal(keys.Current, kek) {
		t.Fatalf("current key = %v", keys)
	}
	if len(keys.All) != 2 || !bytes.Equal(keys.All[0], kek) || !bytes.Equal(keys.All[1], legacy) {
		t.Fatal("decryption order must be current, then legacy")
	}
	// Legacy KEKs alone never enable sealing.
	if VaultConfigured(config.Config{CredentialKEKLegacy: [][]byte{legacy}}) {
		t.Fatal("legacy-only configuration must keep the vault closed")
	}
}

func TestInjectedKeySourceReplacesConfig(t *testing.T) {
	legacy := randomKey(t)
	override := &Keys{Current: legacy, All: [][]byte{legacy}}
	got, err := StaticKeySource(override)(context.Background())
	if err != nil || got != override {
		t.Fatalf("static source = %v, %v", got, err)
	}
	kek := randomKey(t)
	fromConfig, _ := ConfigKeySource(config.Config{CredentialKEK: kek})(context.Background())
	if fromConfig == nil || !bytes.Equal(fromConfig.Current, kek) {
		t.Fatal("config source must serve the configured KEK")
	}
}
