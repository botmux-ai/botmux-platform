package credential

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func seq(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// nodeVector was produced by Node's built-in crypto (`node -e`, see
// TestNodeCanOpenGoSealed for the same algorithm) with fixed key material:
// KEK = 00..1f, DEK = 40..5f, wrap IV = a0..ab, data IV = b0..bb,
// AAD = credentialAad('on_user_a', 'lark-cli').
var nodeVector = struct {
	kekID, wrappedDEK, data, emptyData, plaintext string
}{
	kekID:      "630dcd2966c43366",
	wrappedDEK: "oKGio6Slpqeoqaqr.ouxTAg1eZABuI5jOteKmKQ.plk-bgGORPgqLM2YSzeOkSD9C0PG4hQ7xFd83SP2K14",
	data:       "sLGys7S1tre4ubq7.Z-rBiZ3SgvGicXGNB4-taQ.eCLy4Kc4jupTsVOXhpMi6YQq9gV1N_q9nakUXquK0HQ5lmMGBRPD",
	emptyData:  "sLGys7S1tre4ubq7.uGhkxap-W_Jel0XX9Q305g.",
	plaintext:  `{"refresh_token":"r-1","note":"中文"}`,
}

func TestSealMatchesNodeVectorByteForByte(t *testing.T) {
	kek, dek := seq(0x00, 32), seq(0x40, 32)
	sealed, err := sealWith(kek, dek, seq(0xa0, 12), seq(0xb0, 12), []byte(nodeVector.plaintext), AAD("on_user_a", "lark-cli"))
	if err != nil {
		t.Fatal(err)
	}
	want := Sealed{V: 1, Alg: "A256GCM", KEKID: nodeVector.kekID, WrappedDEK: nodeVector.wrappedDEK, Data: nodeVector.data}
	if sealed != want {
		t.Fatalf("Go envelope differs from Node:\n got %+v\nwant %+v", sealed, want)
	}
	empty, err := sealWith(kek, dek, seq(0xa0, 12), seq(0xb0, 12), nil, AAD("on_user_a", "lark-cli"))
	if err != nil || empty.Data != nodeVector.emptyData {
		t.Fatalf("empty plaintext envelope = %q, %v", empty.Data, err)
	}
}

func TestOpenNodeSealedVector(t *testing.T) {
	sealed := Sealed{V: 1, Alg: "A256GCM", KEKID: nodeVector.kekID, WrappedDEK: nodeVector.wrappedDEK, Data: nodeVector.data}
	plain, ok := Open([][]byte{seq(0x00, 32)}, sealed, AAD("on_user_a", "lark-cli"))
	if !ok || string(plain) != nodeVector.plaintext {
		t.Fatalf("open Node vector = %q, %v", plain, ok)
	}
	sealed.Data = nodeVector.emptyData
	plain, ok = Open([][]byte{seq(0x00, 32)}, sealed, AAD("on_user_a", "lark-cli"))
	if !ok || plain == nil || len(plain) != 0 {
		t.Fatalf("empty plaintext must open to an empty, non-nil buffer: %q, %v", plain, ok)
	}
}

// TestNodeCanOpenGoSealed proves the Go -> Node direction with fresh random
// DEK/IVs: Node's built-in crypto (no repository TS involved) opens a Go
// envelope with the TS algorithm.
func TestNodeCanOpenGoSealed(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	kek := randomKey(t)
	plain := `{"refresh_token":"r-2","emoji":"🔑","html":"<a&b>"}`
	sealed, err := Seal(kek, []byte(plain), AAD("on_user_b", "device-cli"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(sealed)
	const script = `
const crypto = require('crypto');
const [kekHex, envelope, unionId, platform] = process.argv.slice(1);
const kek = Buffer.from(kekHex, 'hex');
const sealed = JSON.parse(envelope);
const aad = Buffer.from('botmux-credential-v1|' + unionId + '|' + platform, 'utf8');
function dec(key, packed) {
  const [iv, tag, ct] = packed.split('.').map((p) => Buffer.from(p, 'base64url'));
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(aad); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
if (sealed.v !== 1 || sealed.alg !== 'A256GCM') throw new Error('shape');
if (crypto.createHash('sha256').update(kek).digest('hex').slice(0, 16) !== sealed.kekId) throw new Error('kekId');
process.stdout.write(dec(dec(kek, sealed.wrappedDek), sealed.data).toString('utf8'));
`
	out, err := exec.Command(node, "-e", script, hex.EncodeToString(kek), string(envelope), "on_user_b", "device-cli").CombinedOutput()
	if err != nil {
		t.Fatalf("node failed to open Go envelope: %v\n%s", err, out)
	}
	if string(out) != plain {
		t.Fatalf("node plaintext = %q, want %q", out, plain)
	}
}

func TestSealOpenRoundTripWithFreshCiphertext(t *testing.T) {
	kek := randomKey(t)
	aad := AAD("on_user_a", "lark-cli")
	plain := []byte(`{"refresh_token":"r-1","note":"中文"}`)
	a, err := Seal(kek, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(kek, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if a.Data == b.Data || a.WrappedDEK == b.WrappedDEK {
		t.Fatal("each seal must use a fresh DEK and IV")
	}
	if a.KEKID != KEKID(kek) || !a.Valid() {
		t.Fatalf("envelope metadata: %+v", a)
	}
	got, ok := Open([][]byte{kek}, a, aad)
	if !ok || !bytes.Equal(got, plain) {
		t.Fatalf("open = %q, %v", got, ok)
	}
}

func TestOpenRejectsMovedRecord(t *testing.T) {
	kek := randomKey(t)
	sealed, _ := Seal(kek, []byte("x"), AAD("on_user_a", "lark-cli"))
	if _, ok := Open([][]byte{kek}, sealed, AAD("on_user_b", "lark-cli")); ok {
		t.Fatal("another user's AAD must not open")
	}
	if _, ok := Open([][]byte{kek}, sealed, AAD("on_user_a", "device-cli")); ok {
		t.Fatal("another platform's AAD must not open")
	}
}

func TestOpenRejectsTamperingAndWrongKEK(t *testing.T) {
	kek := randomKey(t)
	aad := AAD("on_user_a", "lark-cli")
	sealed, _ := Seal(kek, []byte("secret"), aad)
	tampered := sealed
	last := tampered.Data[len(tampered.Data)-1]
	replacement := "A"
	if last == 'A' {
		replacement = "B"
	}
	tampered.Data = tampered.Data[:len(tampered.Data)-1] + replacement
	if _, ok := Open([][]byte{kek}, tampered, aad); ok {
		t.Fatal("tampered ciphertext must not open")
	}
	if _, ok := Open([][]byte{randomKey(t)}, sealed, aad); ok {
		t.Fatal("wrong KEK must not open")
	}
}

func TestOpenDuringKEKRotation(t *testing.T) {
	current, old := randomKey(t), randomKey(t)
	aad := AAD("on_user_a", "lark-cli")
	sealed, _ := Seal(old, []byte("legacy"), aad)
	got, ok := Open([][]byte{current, old}, sealed, aad)
	if !ok || string(got) != "legacy" {
		t.Fatalf("legacy KEK in the key list must still open: %q, %v", got, ok)
	}
	if _, ok := Open([][]byte{current}, sealed, aad); ok {
		t.Fatal("without the legacy KEK the record must stay sealed")
	}
	// A stale kekId only reorders the search; the GCM tag decides.
	sealed.KEKID = KEKID(current)
	if got, ok := Open([][]byte{current, old}, sealed, aad); !ok || string(got) != "legacy" {
		t.Fatalf("kekId is a hint, not a trust anchor: %q, %v", got, ok)
	}
}

func TestOpenRejectsMalformedEnvelopes(t *testing.T) {
	kek := randomKey(t)
	aad := AAD("u", "lark-cli")
	good, _ := Seal(kek, []byte("x"), aad)
	parts := strings.Split(good.Data, ".")
	cases := map[string]Sealed{
		"version":      {V: 2, Alg: good.Alg, KEKID: good.KEKID, WrappedDEK: good.WrappedDEK, Data: good.Data},
		"algorithm":    {V: 1, Alg: "A128GCM", KEKID: good.KEKID, WrappedDEK: good.WrappedDEK, Data: good.Data},
		"two parts":    {V: 1, Alg: good.Alg, KEKID: good.KEKID, WrappedDEK: good.WrappedDEK, Data: parts[0] + "." + parts[1]},
		"short iv":     {V: 1, Alg: good.Alg, KEKID: good.KEKID, WrappedDEK: good.WrappedDEK, Data: parts[0][:8] + "." + parts[1] + "." + parts[2]},
		"short tag":    {V: 1, Alg: good.Alg, KEKID: good.KEKID, WrappedDEK: good.WrappedDEK, Data: parts[0] + "." + parts[1][:8] + "." + parts[2]},
		"wrapped junk": {V: 1, Alg: good.Alg, KEKID: good.KEKID, WrappedDEK: "a.b.c", Data: good.Data},
	}
	for name, sealed := range cases {
		if _, ok := Open([][]byte{kek}, sealed, aad); ok {
			t.Errorf("%s: malformed envelope opened", name)
		}
	}
	if (Sealed{}).Valid() || (Sealed{V: 2, Alg: Algorithm}).Valid() {
		t.Fatal("shape check must reject unknown versions")
	}
}

func TestOpenAcceptsPaddedAndStandardAlphabet(t *testing.T) {
	// Node's Buffer.from(_, 'base64url') also accepts padding and the standard
	// alphabet; envelopes re-encoded that way must still open.
	kek := randomKey(t)
	aad := AAD("u", "lark-cli")
	sealed, _ := Seal(kek, bytes.Repeat([]byte{0xfb, 0xff}, 40), aad)
	reencode := func(packed string) string {
		parts := strings.Split(packed, ".")
		for i, part := range parts {
			raw, _ := base64.RawURLEncoding.DecodeString(part)
			parts[i] = base64.StdEncoding.EncodeToString(raw)
		}
		return strings.Join(parts, ".")
	}
	sealed.WrappedDEK, sealed.Data = reencode(sealed.WrappedDEK), reencode(sealed.Data)
	if _, ok := Open([][]byte{kek}, sealed, aad); !ok {
		t.Fatal("padded standard-alphabet envelope must open")
	}
}

func TestSealRejectsWrongSizedKEKAndOpenSkipsIt(t *testing.T) {
	if _, err := Seal(make([]byte, 16), []byte("x"), nil); !errors.Is(err, ErrInvalidKEK) {
		t.Fatalf("Seal with 16-byte KEK err = %v", err)
	}
	kek := randomKey(t)
	sealed, _ := Seal(kek, []byte("x"), nil)
	if got, ok := Open([][]byte{make([]byte, 16), nil, kek}, sealed, nil); !ok || string(got) != "x" {
		t.Fatalf("wrong-sized keys must be skipped: %q, %v", got, ok)
	}
}

func TestParseKEKFormats(t *testing.T) {
	// The vault reuses config.ParseKEK (TS parseKek); keep the TS cases here.
	raw := randomKey(t)
	for name, encoded := range map[string]string{
		"hex":       hex.EncodeToString(raw),
		"base64":    base64.StdEncoding.EncodeToString(raw),
		"base64url": base64.RawURLEncoding.EncodeToString(raw),
	} {
		if got := config.ParseKEK(encoded); !bytes.Equal(got, raw) {
			t.Errorf("%s: ParseKEK = %x", name, got)
		}
	}
	if config.ParseKEK("short") != nil || config.ParseKEK("") != nil {
		t.Fatal("malformed KEKs must be rejected")
	}
}

func TestSealedJSONAndKEKID(t *testing.T) {
	encoded, _ := json.Marshal(Sealed{V: 1, Alg: "A256GCM", KEKID: "k", WrappedDEK: "w", Data: "d"})
	if string(encoded) != `{"v":1,"alg":"A256GCM","kekId":"k","wrappedDek":"w","data":"d"}` {
		t.Fatalf("sealed JSON = %s", encoded)
	}
	if KEKID(seq(0, 32)) != nodeVector.kekID {
		t.Fatalf("KEKID = %s", KEKID(seq(0, 32)))
	}
}
