// Package credential implements the credential vault's envelope encryption
// (src/auth/credential-crypto.ts) and key set (src/auth/credential-keys.ts).
//
// Every credential gets its own random data key (DEK, AES-256-GCM); the DEK is
// wrapped by the KEK injected through the CREDENTIAL_KEK secret. The KEK
// never reaches MongoDB, which only ever holds ciphertext plus the wrapped DEK.
// The sealed format is shared with the Node service byte for byte, so either
// backend can open what the other sealed during a mixed-version rollout.
package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// Version and Algorithm are the only sealed-envelope parameters the Node
	// service understands; anything else must be treated as unreadable.
	Version   = 1
	Algorithm = "A256GCM"

	ivBytes  = 12
	keyBytes = 32
	tagBytes = 16
)

// ErrInvalidKEK reports a KEK that is not exactly 32 bytes. The TS service
// throws in the same situation instead of sealing with a wrong-sized key.
var ErrInvalidKEK = errors.New("credential KEK must be 32 bytes")

// Sealed is the persisted envelope. Field names and order match the TS
// SealedCredential literal; V is an int so the BSON encoder writes int32 like
// the Node driver does for the literal 1.
type Sealed struct {
	V   int    `json:"v" bson:"v"`
	Alg string `json:"alg" bson:"alg"`
	// KEKID locates the wrapping KEK during rotation (first 16 hex chars of
	// sha256(KEK)). It only speeds up the search; the GCM tag is the authority.
	KEKID string `json:"kekId" bson:"kekId"`
	// WrappedDEK and Data are both packed as iv.tag.ciphertext (base64url).
	WrappedDEK string `json:"wrappedDek" bson:"wrappedDek"`
	Data       string `json:"data" bson:"data"`
}

// Valid is the structural check TS performs with isSealedCredential before
// handing a stored envelope to openCredential.
func (s Sealed) Valid() bool {
	return s.V == Version && s.Alg == Algorithm
}

// KEKID returns the identifier recorded in Sealed.KEKID for kek.
func KEKID(kek []byte) string {
	sum := sha256.Sum256(kek)
	return hex.EncodeToString(sum[:])[:16]
}

// AAD binds a ciphertext to the record identity: moving A's sealed credential
// onto B's record (or onto another platform) makes it fail authentication.
func AAD(unionID, platform string) []byte {
	return []byte("botmux-credential-v1|" + unionID + "|" + platform)
}

// Seal encrypts plaintext under a fresh DEK and wraps the DEK with kek.
func Seal(kek, plaintext, aad []byte) (Sealed, error) {
	if len(kek) != keyBytes {
		return Sealed{}, ErrInvalidKEK
	}
	random := make([]byte, keyBytes+2*ivBytes)
	if _, err := rand.Read(random); err != nil {
		return Sealed{}, err
	}
	defer clear(random)
	dek, wrapIV, dataIV := random[:keyBytes], random[keyBytes:keyBytes+ivBytes], random[keyBytes+ivBytes:]
	return sealWith(kek, dek, wrapIV, dataIV, plaintext, aad)
}

// sealWith is Seal with caller-chosen DEK and IVs; tests use it to reproduce
// fixed Node-generated vectors.
func sealWith(kek, dek, wrapIV, dataIV, plaintext, aad []byte) (Sealed, error) {
	if len(kek) != keyBytes {
		return Sealed{}, ErrInvalidKEK
	}
	wrapped, err := gcmEncrypt(kek, wrapIV, dek, aad)
	if err != nil {
		return Sealed{}, err
	}
	data, err := gcmEncrypt(dek, dataIV, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{V: Version, Alg: Algorithm, KEKID: KEKID(kek), WrappedDEK: wrapped, Data: data}, nil
}

// Open decrypts sealed with the first KEK in keks that authenticates it. keks
// is in priority order (current KEK first, rotation leftovers after); KEKs
// whose id matches sealed.KEKID are tried first. ok=false means the record is
// unreadable (wrong key, tampering or corruption) and callers must treat the
// credential as needing re-authorization.
func Open(keks [][]byte, sealed Sealed, aad []byte) (plaintext []byte, ok bool) {
	if !sealed.Valid() {
		return nil, false
	}
	ordered := make([][]byte, 0, len(keks))
	for _, kek := range keks {
		if KEKID(kek) == sealed.KEKID {
			ordered = append(ordered, kek)
		}
	}
	for _, kek := range keks {
		if KEKID(kek) != sealed.KEKID {
			ordered = append(ordered, kek)
		}
	}
	for _, kek := range ordered {
		if len(kek) != keyBytes {
			continue
		}
		dek, ok := gcmDecrypt(kek, sealed.WrappedDEK, aad)
		if !ok || len(dek) != keyBytes {
			continue
		}
		out, ok := gcmDecrypt(dek, sealed.Data, aad)
		clear(dek)
		if ok {
			return out, true
		}
	}
	return nil, false
}

func gcmEncrypt(key, iv, plaintext, aad []byte) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(iv) != ivBytes {
		return "", errors.New("credential: GCM IV must be 12 bytes")
	}
	sealed := aead.Seal(nil, iv, plaintext, aad)
	ct, tag := sealed[:len(sealed)-tagBytes], sealed[len(sealed)-tagBytes:]
	return packGCM(iv, tag, ct), nil
}

func gcmDecrypt(key []byte, packed string, aad []byte) ([]byte, bool) {
	iv, tag, ct, ok := unpackGCM(packed)
	if !ok {
		return nil, false
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, false
	}
	// Go's AEAD expects ciphertext||tag; the packed format stores them apart.
	out, err := aead.Open(nil, iv, append(ct, tag...), aad)
	if err != nil {
		return nil, false
	}
	if out == nil {
		out = []byte{}
	}
	return out, true
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// packGCM matches Node's `${iv}.${tag}.${ct}` with Buffer#toString('base64url')
// (URL alphabet, no padding).
func packGCM(iv, tag, ct []byte) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString(iv) + "." + enc.EncodeToString(tag) + "." + enc.EncodeToString(ct)
}

func unpackGCM(packed string) (iv, tag, ct []byte, ok bool) {
	parts := strings.Split(packed, ".")
	if len(parts) != 3 {
		return nil, nil, nil, false
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		value, ok := decodeBase64URL(part)
		if !ok {
			return nil, nil, nil, false
		}
		decoded[i] = value
	}
	if len(decoded[0]) != ivBytes || len(decoded[1]) != tagBytes {
		return nil, nil, nil, false
	}
	return decoded[0], decoded[1], decoded[2], true
}

// decodeBase64URL accepts what Node's Buffer.from(s, 'base64url') decodes for
// any envelope either service writes: both alphabets, optional padding and a
// dangling final sextet (which Node drops). Node additionally skips stray
// characters; such input can only come from hand-editing a record and is
// rejected here, which callers already treat as "unreadable".
func decodeBase64URL(value string) ([]byte, bool) {
	if index := strings.IndexByte(value, '='); index >= 0 {
		value = value[:index]
	}
	if strings.ContainsAny(value, "+/") {
		value = strings.NewReplacer("+", "-", "/", "_").Replace(value)
	}
	if len(value)%4 == 1 {
		value = value[:len(value)-1]
	}
	out, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	return out, true
}
