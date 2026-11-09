package credential

import (
	"context"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// Keys is the vault's effective key set, taken straight from the
// environment (CREDENTIAL_KEK / CREDENTIAL_KEK_LEGACY, parsed by
// config.ParseKEK).
//
// The KEK is deliberately not split with a share in MongoDB: decryption
// already needs ciphertext (MongoDB) plus KEK (environment), and moving half the KEK
// into MongoDB would add a single point of failure without enlarging the set
// of stores an attacker must compromise.
type Keys struct {
	// Current seals new envelopes.
	Current []byte
	// All is tried in order when opening: Current first, then rotation
	// leftovers.
	All [][]byte
}

// VaultConfigured reports whether the vault is enabled. A missing (or
// malformed, which config treats as missing) KEK closes the capability
// instead of sealing with a wrong key.
func VaultConfigured(cfg config.Config) bool {
	return len(cfg.CredentialKEK) > 0
}

// KeysFromConfig returns nil when the vault is disabled.
func KeysFromConfig(cfg config.Config) *Keys {
	if !VaultConfigured(cfg) {
		return nil
	}
	all := make([][]byte, 0, 1+len(cfg.CredentialKEKLegacy))
	all = append(all, cfg.CredentialKEK)
	all = append(all, cfg.CredentialKEKLegacy...)
	return &Keys{Current: cfg.CredentialKEK, All: all}
}

// KeySource is the asynchronous seam TS keeps in getCredentialKeys so a future
// KMS-backed source only changes here. Handlers depend on a KeySource; tests
// inject fixed keys instead of overriding global state
// (__setCredentialKeysForTests). A nil *Keys means the vault is disabled.
type KeySource func(context.Context) (*Keys, error)

// ConfigKeySource serves KeysFromConfig(cfg).
func ConfigKeySource(cfg config.Config) KeySource {
	keys := KeysFromConfig(cfg)
	return func(context.Context) (*Keys, error) { return keys, nil }
}

// StaticKeySource always serves keys (nil disables the vault).
func StaticKeySource(keys *Keys) KeySource {
	return func(context.Context) (*Keys, error) { return keys, nil }
}
