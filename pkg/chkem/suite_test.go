package chkem

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// TestDefaultSuiteIsCHKEMv1 checks the registry wiring.
func TestDefaultSuiteIsCHKEMv1(t *testing.T) {
	if DefaultSuite().ID() != SuiteCHKEMv1 {
		t.Fatalf("default suite id = %#x, want SuiteCHKEMv1", DefaultSuite().ID())
	}
	if _, ok := GetSuite(SuiteCHKEMv1); !ok {
		t.Fatal("SuiteCHKEMv1 not registered")
	}
	if _, ok := GetSuite(0xFFFF); ok {
		t.Fatal("unknown suite id resolved")
	}
}

// TestSuiteSizesMatchConstants checks the v1 suite reports the existing fixed sizes.
func TestSuiteSizesMatchConstants(t *testing.T) {
	s := DefaultSuite()
	if s.PublicKeySize() != constants.CHKEMPublicKeySize {
		t.Errorf("PublicKeySize = %d, want %d", s.PublicKeySize(), constants.CHKEMPublicKeySize)
	}
	if s.CiphertextSize() != constants.CHKEMCiphertextSize {
		t.Errorf("CiphertextSize = %d, want %d", s.CiphertextSize(), constants.CHKEMCiphertextSize)
	}
	if s.SeedSize() != StaticKeySeedSize {
		t.Errorf("SeedSize = %d, want %d", s.SeedSize(), StaticKeySeedSize)
	}
}

// TestV1SuiteEquivalentToPackageFuncs proves the v1 suite is the *same construction*
// as the package-level CH-KEM: a ciphertext sealed through the suite decapsulates
// with the package Decapsulate (and vice versa) to the same secret, and a seed
// reconstructs the identical public key both ways. This is the byte-identical
// guarantee for Phase 1 - the abstraction adds no behavior.
func TestV1SuiteEquivalentToPackageFuncs(t *testing.T) {
	s := DefaultSuite()

	// Deterministic identity: same seed -> same public key bytes via suite or func.
	_, seed, err := s.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	kpSuite, err := s.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("suite ParseKeyPair: %v", err)
	}
	kpFunc, err := ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	if !bytes.Equal(kpSuite.PublicKey().Bytes(), kpFunc.PublicKey().Bytes()) {
		t.Fatal("suite and package ParseKeyPair produced different public keys")
	}

	// Suite seals -> package opens, same secret.
	ct, ssSeal, err := s.Encapsulate(kpFunc.PublicKey(), RoleResponder)
	if err != nil {
		t.Fatalf("suite Encapsulate: %v", err)
	}
	if len(ssSeal) != constants.CHKEMSharedSecretSize {
		t.Fatalf("shared secret size = %d, want %d", len(ssSeal), constants.CHKEMSharedSecretSize)
	}
	ssOpen, err := Decapsulate(ct, kpFunc, RoleInitiator)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssSeal, ssOpen) {
		t.Fatal("suite-sealed ciphertext did not open to the same secret via the package func")
	}

	// Package seals -> suite opens, same secret. Confirms a wire ciphertext parsed
	// through the suite is interoperable with the fixed construction.
	ct2, ssSeal2, err := Encapsulate(kpFunc.PublicKey(), RoleResponder)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	parsed, err := s.ParseCiphertext(ct2.Bytes())
	if err != nil {
		t.Fatalf("suite ParseCiphertext: %v", err)
	}
	ssOpen2, err := s.Decapsulate(parsed, kpSuite, RoleInitiator)
	if err != nil {
		t.Fatalf("suite Decapsulate: %v", err)
	}
	if !bytes.Equal(ssSeal2, ssOpen2) {
		t.Fatal("package-sealed ciphertext did not open to the same secret via the suite")
	}
}
