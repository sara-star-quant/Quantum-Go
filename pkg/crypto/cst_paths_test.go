package crypto

import (
	"bytes"
	"testing"
)

// SecureRandomWithCST is the entropy entry point the FIPS build uses. It must fill the buffer
// when the source is healthy and return the source's own error, never zeros, when it is not.
func TestSecureRandomWithCST(t *testing.T) {
	t.Run("fills the buffer", func(t *testing.T) {
		b := make([]byte, 32)
		if err := SecureRandomWithCST(b); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, make([]byte, 32)) {
			t.Fatal("the buffer is still all zero")
		}
	})
	t.Run("returns the entropy source's failure", func(t *testing.T) {
		withEntropy(t, failingReader{})
		if err := SecureRandomWithCST(make([]byte, 32)); err == nil {
			t.Fatal("a dead entropy source reported success")
		}
	})
}

// Key generation with the pairwise consistency test must return keys that work, and must fail,
// returning no key, when the entropy source fails.
func TestKeyGenerationWithCST(t *testing.T) {
	t.Run("X25519 keys agree", func(t *testing.T) {
		a, err := GenerateX25519KeyPairWithCST()
		if err != nil {
			t.Fatal(err)
		}
		b, err := GenerateX25519KeyPairWithCST()
		if err != nil {
			t.Fatal(err)
		}
		ab, err1 := X25519(a.PrivateKey, b.PublicKey)
		ba, err2 := X25519(b.PrivateKey, a.PublicKey)
		if err1 != nil || err2 != nil || !bytes.Equal(ab, ba) {
			t.Fatalf("the two sides disagree: %v %v", err1, err2)
		}
	})
	t.Run("ML-KEM keys round-trip", func(t *testing.T) {
		kp, err := GenerateMLKEMKeyPairWithCST()
		if err != nil {
			t.Fatal(err)
		}
		ct, ss, err := MLKEMEncapsulate(kp.EncapsulationKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MLKEMDecapsulate(kp.DecapsulationKey, ct)
		if err != nil || !bytes.Equal(got, ss) {
			t.Fatalf("decapsulation differs: %v", err)
		}
	})
	// ML-KEM draws its seed through the injectable entropy source. X25519 key generation reads
	// crypto/rand directly (see Reader), so this seam cannot make it fail and there is nothing to
	// assert for it here.
	t.Run("entropy failure returns no ML-KEM key", func(t *testing.T) {
		withEntropy(t, failingReader{})
		if kp, err := GenerateMLKEMKeyPairWithCST(); err == nil || kp != nil {
			t.Errorf("kp=%v err=%v, want a failure and no key", kp, err)
		}
	})
}

// A failed power-on self-test is fatal in FIPS mode and only reported otherwise; a passing one
// never stops the process.
func TestEnforcePOSTIsFatalOnlyInFIPSMode(t *testing.T) {
	panics := func(r *POSTResult) (panicked bool) {
		defer func() { panicked = recover() != nil }()
		enforcePOST(r)
		return false
	}
	if panics(&POSTResult{Passed: true}) {
		t.Error("a passing self-test panicked")
	}
	if got := panics(&POSTResult{Passed: false, Errors: []string{"KDF KAT mismatch"}}); got != FIPSMode() {
		t.Errorf("a failed self-test panicked=%v, want %v (FIPS mode)", got, FIPSMode())
	}
}

// An empty or nil ML-KEM public key must report no bytes instead of dereferencing nothing.
func TestMLKEMPublicKeyBytesOfAnEmptyKey(t *testing.T) {
	var nilKey *MLKEMPublicKey
	if nilKey.Bytes() != nil || (&MLKEMPublicKey{}).Bytes() != nil {
		t.Fatal("an empty public key returned bytes")
	}
}
