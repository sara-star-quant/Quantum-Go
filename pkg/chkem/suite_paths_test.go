package chkem

import (
	"bytes"
	"errors"
	"testing"
)

// The X-Wing static key pair comes with the seed that rebuilds it: parsing the seed must give the
// same public key, or a saved identity would not match the key the server advertises.
func TestXWingStaticKeyPairSeedRebuildsTheSameKey(t *testing.T) {
	s := xwingSuite{}
	kp, seed, err := s.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.ParseKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.PublicKey().Bytes(), again.PublicKey().Bytes()) {
		t.Fatal("the seed rebuilt a different public key")
	}
}

// Wrapping an external suite's bytes needs a nonzero id, copies its input, and Clone must give
// an independent copy: mutating the original afterwards must not change the clone.
func TestExternalSuiteKeyAndCiphertextWrapping(t *testing.T) {
	if _, err := NewSuitePublicKey(0, []byte{1}); !errors.Is(err, ErrInvalidSuite) {
		t.Errorf("public key with id 0: err = %v, want ErrInvalidSuite", err)
	}
	if _, err := NewSuiteCiphertext(0, []byte{1}); !errors.Is(err, ErrInvalidSuite) {
		t.Errorf("ciphertext with id 0: err = %v, want ErrInvalidSuite", err)
	}

	raw := []byte{1, 2, 3, 4}
	pk, err := NewSuitePublicKey(0x1234, raw)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := NewSuiteCiphertext(0x1234, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 99 // the wrappers must have copied
	if pk.Bytes()[0] != 1 || ct.Bytes()[0] != 1 {
		t.Fatal("the wrapper kept a reference to the caller's slice")
	}

	clone := pk.Clone()
	pk.raw[1] = 77 // the original's own storage, not the copy Bytes returns
	if !bytes.Equal(clone.raw, []byte{1, 2, 3, 4}) || clone.Suite() != 0x1234 {
		t.Fatalf("the clone changed with the original: %v suite=%v", clone.raw, clone.Suite())
	}
}
