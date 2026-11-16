package crypto

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
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

// TestXWingDraftVectors drives the three test vectors printed in Appendix C of
// draft-connolly-cfrg-xwing-kem-11 (September 2026) through the wrapper. A shared secret
// depends on the whole public key and ciphertext, so seed, encapsulation seed and shared secret
// pin all of them. The digest test above covers the older vector stream; this one is anchored to
// the text of the current draft, so a change in either the draft or the library shows here.
func TestXWingDraftVectors(t *testing.T) {
	vectors := []struct{ seed, eseed, ss string }{
		{
			"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
			"3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
			"d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
		},
		{
			"badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
			"17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
			"f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
		},
		{
			"ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
			"22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
			"953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
		},
	}
	for i, v := range vectors {
		seed, _ := hex.DecodeString(v.seed)
		eseed, _ := hex.DecodeString(v.eseed)
		kp, err := NewXWingKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("vector %d: %v", i+1, err)
		}
		ct, ss, err := XWingEncapsulateWithSeed(kp.PublicKeyBytes(), eseed)
		if err != nil {
			t.Fatalf("vector %d: encapsulate: %v", i+1, err)
		}
		if got := hex.EncodeToString(ss); got != v.ss {
			t.Fatalf("vector %d: shared secret %s, draft says %s", i+1, got, v.ss)
		}
		back, err := XWingDecapsulate(kp.SeedBytes(), ct)
		if err != nil || hex.EncodeToString(back) != v.ss {
			t.Fatalf("vector %d: decapsulation does not recover the draft's shared secret (%v)", i+1, err)
		}
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
