package crypto

import (
	"bytes"
	"crypto/sha3"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
)

// writeHexX mirrors circl's xwing test-vector formatter byte-for-byte so the digest
// below matches the published X-Wing spec vectors.
func writeHexX(w io.Writer, prefix string, val []byte) {
	indent := "  "
	width := 74
	hex := fmt.Sprintf("%x", val)
	if len(prefix)+len(hex)+5 < width {
		_, _ = fmt.Fprintf(w, "%s     %s\n", prefix, hex)
		return
	}
	_, _ = fmt.Fprintf(w, "%s\n", prefix)
	for len(hex) != 0 {
		var toPrint string
		if len(hex) < width-len(indent) {
			toPrint = hex
			hex = ""
		} else {
			toPrint = hex[:width-len(indent)]
			hex = hex[width-len(indent):]
		}
		_, _ = fmt.Fprintf(w, "%s%s\n", indent, toPrint)
	}
}

// TestXWingConformanceVectors drives the published X-Wing test vectors through this
// wrapper and checks the SHAKE-128 digest of the formatted output against the value
// from the X-Wing spec (draft-connolly-cfrg-xwing-kem). It also cross-checks each
// derived key against circl directly, so the wrapper is a faithful passthrough.
func TestXWingConformanceVectors(t *testing.T) {
	h := sha3.NewSHAKE128()
	w := new(bytes.Buffer)

	for range 3 {
		var seed [xwing.SeedSize]byte
		_, _ = h.Read(seed[:])
		writeHexX(w, "seed", seed[:])

		kp, err := NewXWingKeyPairFromSeed(seed[:])
		if err != nil {
			t.Fatalf("NewXWingKeyPairFromSeed: %v", err)
		}
		sk := kp.SeedBytes()
		pk := kp.PublicKeyBytes()

		// The wrapper must derive byte-identically to circl.
		csk, cpk := xwing.DeriveKeyPairPacked(seed[:])
		if !bytes.Equal(sk, csk) || !bytes.Equal(pk, cpk) {
			t.Fatal("wrapper key derivation diverges from circl")
		}
		writeHexX(w, "sk", sk)
		writeHexX(w, "pk", pk)

		var eseed [xwing.EncapsulationSeedSize]byte
		_, _ = h.Read(eseed[:])
		writeHexX(w, "eseed", eseed[:])

		ct, ss, err := XWingEncapsulateWithSeed(pk, eseed[:])
		if err != nil {
			t.Fatalf("encapsulate: %v", err)
		}
		writeHexX(w, "ct", ct)
		writeHexX(w, "ss", ss)

		ss2, err := XWingDecapsulate(sk, ct)
		if err != nil {
			t.Fatalf("decapsulate: %v", err)
		}
		if !bytes.Equal(ss, ss2) {
			t.Fatal("decapsulated secret does not match encapsulated secret")
		}
		_, _ = fmt.Fprintf(w, "\n")
	}

	h2 := sha3.NewSHAKE128()
	_, _ = h2.Write(w.Bytes())
	var cs [32]byte
	_, _ = h2.Read(cs[:])
	got := fmt.Sprintf("%x", cs)
	const want = "1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe"
	if got != want {
		t.Fatalf("X-Wing conformance digest mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestXWingRoundTrip checks a generated key pair encapsulates and decapsulates to a
// matching 32-byte secret, and that wrong sizes are rejected.
func TestXWingRoundTrip(t *testing.T) {
	kp, err := GenerateXWingKeyPair()
	if err != nil {
		t.Fatalf("GenerateXWingKeyPair: %v", err)
	}
	ct, ss, err := XWingEncapsulate(kp.PublicKeyBytes())
	if err != nil {
		t.Fatalf("XWingEncapsulate: %v", err)
	}
	if len(ss) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(ss))
	}
	ss2, err := XWingDecapsulate(kp.SeedBytes(), ct)
	if err != nil {
		t.Fatalf("XWingDecapsulate: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Error("round-trip shared secret mismatch")
	}

	if _, _, err := XWingEncapsulate(make([]byte, 10)); err == nil {
		t.Error("expected error for a wrong-size public key")
	}
	if _, err := XWingDecapsulate(kp.SeedBytes(), make([]byte, 10)); err == nil {
		t.Error("expected error for a wrong-size ciphertext")
	}
}
