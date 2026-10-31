package crypto

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, constants.AESKeySize) }

func TestAEADRejectsBadKeyAndSuite(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewAEAD(constants.CipherSuiteAES256GCM, make([]byte, n)); !errors.Is(err, qerrors.ErrInvalidKeySize) {
			t.Errorf("key length %d: got %v, want ErrInvalidKeySize", n, err)
		}
	}
	if _, err := NewAEAD(constants.CipherSuite(0xFFFF), testKey(1)); err == nil {
		t.Error("unknown cipher suite accepted")
	}
}

func TestAEADTamperAndMisuse(t *testing.T) {
	for _, suite := range []constants.CipherSuite{constants.CipherSuiteAES256GCM, constants.CipherSuiteChaCha20Poly1305} {
		if FIPSMode() && !suite.IsFIPSApproved() {
			continue // refused in FIPS mode by design
		}
		a, err := NewAEAD(suite, testKey(7))
		if err != nil {
			t.Fatalf("suite %v: %v", suite, err)
		}
		aad := []byte("header")
		ct, err := a.Seal([]byte("payload"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := a.Open(ct, aad); err != nil || string(pt) != "payload" {
			t.Fatalf("suite %v round trip: %q %v", suite, pt, err)
		}
		// Flip every byte in turn: nonce, body and tag must all be authenticated.
		for i := range ct {
			bad := append([]byte(nil), ct...)
			bad[i] ^= 0x01
			if _, err := a.Open(bad, aad); err == nil {
				t.Fatalf("suite %v: flip at byte %d accepted", suite, i)
			}
		}
		if _, err := a.Open(ct, []byte("other")); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
			t.Errorf("wrong AAD: got %v", err)
		}
		other, _ := NewAEAD(suite, testKey(8))
		if _, err := other.Open(ct, aad); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
			t.Errorf("wrong key: got %v", err)
		}
		if _, err := a.Open(ct[:constants.MinPacketSize-1], aad); !errors.Is(err, qerrors.ErrCiphertextTooShort) {
			t.Errorf("short ciphertext: got %v", err)
		}
		if _, err := a.SealWithNonce(make([]byte, 11), nil, nil); !errors.Is(err, qerrors.ErrInvalidNonce) {
			t.Errorf("short nonce seal: got %v", err)
		}
		if _, err := a.OpenWithNonce(make([]byte, 13), ct, nil); !errors.Is(err, qerrors.ErrInvalidNonce) {
			t.Errorf("long nonce open: got %v", err)
		}
		if _, err := a.OpenWithNonce(make([]byte, constants.AESNonceSize), make([]byte, constants.AESTagSize-1), nil); !errors.Is(err, qerrors.ErrCiphertextTooShort) {
			t.Errorf("short body: got %v", err)
		}
	}
}

func TestSafeUint32(t *testing.T) {
	if v, ok := safeUint32(0); !ok || v != 0 {
		t.Error("0 rejected")
	}
	if _, ok := safeUint32(-1); ok {
		t.Error("negative accepted")
	}
	if v, ok := safeUint32(math.MaxUint32); !ok || v != math.MaxUint32 {
		t.Error("MaxUint32 rejected")
	}
	if math.MaxInt > math.MaxUint32 { // 64-bit platforms
		if _, ok := safeUint32(int(int64(math.MaxUint32) + 1)); ok {
			t.Error("value above MaxUint32 accepted")
		}
	}
}

func TestKDFInputValidationAndSeparation(t *testing.T) {
	x := bytes.Repeat([]byte{1}, constants.X25519SharedSecretSize)
	m := bytes.Repeat([]byte{2}, constants.MLKEMSharedSecretSize)
	h := bytes.Repeat([]byte{3}, constants.TranscriptHashSize)

	bad := [][3][]byte{{x[:31], m, h}, {x, m[:31], h}, {x, m, h[:31]}, {nil, m, h}, {x, nil, h}, {x, m, nil}}
	for i, b := range bad {
		if _, err := DeriveCHKEMSecret(b[0], b[1], b[2]); err == nil {
			t.Errorf("case %d: bad sizes accepted", i)
		}
	}

	ref, err := DeriveCHKEMSecret(x, m, h)
	if err != nil || len(ref) != constants.CHKEMSharedSecretSize {
		t.Fatalf("derive: %v len=%d", err, len(ref))
	}
	again, _ := DeriveCHKEMSecret(x, m, h)
	if !bytes.Equal(ref, again) {
		t.Error("derivation is not deterministic")
	}
	// Every input must matter, and inputs of equal length must not be interchangeable.
	for name, out := range map[string][2][]byte{
		"x changed":    {mustDerive(t, bytes.Repeat([]byte{9}, 32), m, h), ref},
		"m changed":    {mustDerive(t, x, bytes.Repeat([]byte{9}, 32), h), ref},
		"h changed":    {mustDerive(t, x, m, bytes.Repeat([]byte{9}, 32)), ref},
		"x and m swap": {mustDerive(t, m, x, h), ref},
	} {
		if bytes.Equal(out[0], out[1]) {
			t.Errorf("%s: output unchanged", name)
		}
	}

	for _, n := range []int{0, -1, 1<<20 + 1} {
		if _, err := DeriveKeyMultiple("d", [][]byte{x}, n); err == nil {
			t.Errorf("output length %d accepted", n)
		}
	}
	a, _ := DeriveKeyMultiple("domain-a", [][]byte{x}, 32)
	b, _ := DeriveKeyMultiple("domain-b", [][]byte{x}, 32)
	if bytes.Equal(a, b) {
		t.Error("domain separation failed")
	}
	// Length-prefixing: splitting the same bytes differently must change the output.
	c, _ := DeriveKeyMultiple("d", [][]byte{[]byte("ab"), []byte("c")}, 32)
	d, _ := DeriveKeyMultiple("d", [][]byte{[]byte("a"), []byte("bc")}, 32)
	if bytes.Equal(c, d) {
		t.Error("input boundaries are ambiguous")
	}
}

func mustDerive(t *testing.T, x, m, h []byte) []byte {
	t.Helper()
	out, err := DeriveCHKEMSecret(x, m, h)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRekeyAndNoncePrefixDerivation(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, constants.CHKEMSharedSecretSize)
	if _, err := DeriveRekeySecret(secret[:31], nil); err == nil {
		t.Error("short secret accepted by DeriveRekeySecret")
	}
	a, err := DeriveRekeySecret(secret, []byte("ctx-1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveRekeySecret(secret, []byte("ctx-2"))
	if bytes.Equal(a, b) || bytes.Equal(a, secret) {
		t.Error("rekey secret ignores context or returns its input")
	}

	if _, _, err := DeriveDatagramNoncePrefixes(secret[:31]); err == nil {
		t.Error("short secret accepted by DeriveDatagramNoncePrefixes")
	}
	i1, r1, err := DeriveDatagramNoncePrefixes(secret)
	if err != nil {
		t.Fatal(err)
	}
	i2, r2, _ := DeriveDatagramNoncePrefixes(secret)
	if !bytes.Equal(i1, i2) || !bytes.Equal(r1, r2) {
		t.Error("nonce prefixes are not deterministic")
	}
	if bytes.Equal(i1, r1) {
		t.Error("initiator and responder nonce prefixes are equal")
	}
}

func TestKeyParsersRejectBadLengths(t *testing.T) {
	if _, err := ParseX25519PublicKey(make([]byte, constants.X25519PublicKeySize-1)); !errors.Is(err, qerrors.ErrInvalidPublicKey) {
		t.Errorf("x25519 short: %v", err)
	}
	if _, err := ParseMLKEMPublicKey(make([]byte, constants.MLKEMPublicKeySize+1)); !errors.Is(err, qerrors.ErrInvalidPublicKey) {
		t.Errorf("mlkem long: %v", err)
	}
	if _, err := ParseXWingPublicKey(make([]byte, constants.XWingPublicKeySize-1)); !errors.Is(err, qerrors.ErrInvalidPublicKey) {
		t.Errorf("xwing short: %v", err)
	}
	pub := make([]byte, constants.XWingPublicKeySize)
	pub[0] = 7
	got, err := ParseXWingPublicKey(pub)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("xwing parse: %v", err)
	}
	got[0] = 9
	if pub[0] != 7 {
		t.Error("ParseXWingPublicKey aliases its input")
	}
}

func TestMLKEMMisuseAndImplicitRejection(t *testing.T) {
	if _, _, err := MLKEMEncapsulateWithSeed(nil, make([]byte, 32)); !errors.Is(err, qerrors.ErrInvalidPublicKey) {
		t.Errorf("nil key: %v", err)
	}
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := MLKEMEncapsulateWithSeed(kp.EncapsulationKey, make([]byte, 31)); !errors.Is(err, qerrors.ErrInvalidKeySize) {
		t.Errorf("short seed: %v", err)
	}
	ct, ss, err := MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		t.Fatal(err)
	}
	// FIPS 203 implicit rejection: a tampered ciphertext decapsulates to an
	// unrelated secret rather than an error that could act as an oracle.
	ct[len(ct)/2] ^= 0x01
	if got, err := MLKEMDecapsulate(kp.DecapsulationKey, ct); err == nil && bytes.Equal(got, ss) {
		t.Error("tampered ML-KEM ciphertext produced the original secret")
	}
}

func TestXWingMisuseAndTamper(t *testing.T) {
	if _, err := NewXWingKeyPairFromSeed(make([]byte, 31)); !errors.Is(err, qerrors.ErrInvalidKeySize) {
		t.Errorf("short seed: %v", err)
	}
	kp, err := GenerateXWingKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := XWingEncapsulate(kp.PublicKeyBytes()[:10]); !errors.Is(err, qerrors.ErrInvalidPublicKey) {
		t.Errorf("short public key: %v", err)
	}
	if _, _, err := XWingEncapsulateWithSeed(kp.PublicKeyBytes(), make([]byte, 5)); !errors.Is(err, qerrors.ErrInvalidKeySize) {
		t.Errorf("short seed: %v", err)
	}
	ct, ss, err := XWingEncapsulate(kp.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := XWingDecapsulate(kp.SeedBytes()[:5], ct); !errors.Is(err, qerrors.ErrInvalidPrivateKey) {
		t.Errorf("short private key: %v", err)
	}
	if _, err := XWingDecapsulate(kp.SeedBytes(), ct[:5]); !errors.Is(err, qerrors.ErrInvalidCiphertext) {
		t.Errorf("short ciphertext: %v", err)
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)/2] ^= 0x01
	if got, err := XWingDecapsulate(kp.SeedBytes(), bad); err == nil && bytes.Equal(got, ss) {
		t.Error("tampered X-Wing ciphertext produced the original secret")
	}
	kp.Zeroize()
	if kp.SeedBytes() != nil && len(kp.SeedBytes()) != 0 {
		t.Error("Zeroize left seed bytes")
	}
}
