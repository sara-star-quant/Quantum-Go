package chkem_test

import (
	"bytes"
	"testing"

	"github.com/quantum-go/quantum-go/internal/constants"
	"github.com/quantum-go/quantum-go/pkg/chkem"
)

func TestKeyPairGeneration(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp == nil {
		t.Fatal("GenerateKeyPair returned nil")
	}

	pk := kp.PublicKey()
	if pk == nil {
		t.Fatal("PublicKey returned nil")
	}

	pkBytes := pk.Bytes()
	if len(pkBytes) != constants.CHKEMPublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(pkBytes), constants.CHKEMPublicKeySize)
	}
}

func TestEncapsulationDecapsulation(t *testing.T) {
	// Generate recipient key pair
	recipientKP, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Encapsulate
	ct, sharedSecretEnc, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	if ct == nil {
		t.Fatal("Encapsulate returned nil ciphertext")
	}

	if len(sharedSecretEnc) != constants.CHKEMSharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(sharedSecretEnc), constants.CHKEMSharedSecretSize)
	}

	// Verify ciphertext size
	ctBytes := ct.Bytes()
	if len(ctBytes) != constants.CHKEMCiphertextSize {
		t.Errorf("Ciphertext size: got %d, want %d", len(ctBytes), constants.CHKEMCiphertextSize)
	}

	// Decapsulate
	sharedSecretDec, err := chkem.Decapsulate(ct, recipientKP)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(sharedSecretEnc, sharedSecretDec) {
		t.Error("CH-KEM shared secrets do not match")
	}
}

func TestMultipleEncapsulations(t *testing.T) {
	// Generate recipient key pair
	recipientKP, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Multiple encapsulations should produce different ciphertexts and secrets
	// (due to ephemeral key generation)
	ct1, ss1, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("First Encapsulate failed: %v", err)
	}

	ct2, ss2, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("Second Encapsulate failed: %v", err)
	}

	// Ciphertexts should be different (ephemeral keys are random)
	if bytes.Equal(ct1.Bytes(), ct2.Bytes()) {
		t.Error("Multiple encapsulations should produce different ciphertexts")
	}

	// Shared secrets should be different
	if bytes.Equal(ss1, ss2) {
		t.Error("Multiple encapsulations should produce different shared secrets")
	}

	// But both should decapsulate correctly
	ss1Dec, err := chkem.Decapsulate(ct1, recipientKP)
	if err != nil {
		t.Fatalf("First Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ss1, ss1Dec) {
		t.Error("First shared secret mismatch")
	}

	ss2Dec, err := chkem.Decapsulate(ct2, recipientKP)
	if err != nil {
		t.Fatalf("Second Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ss2, ss2Dec) {
		t.Error("Second shared secret mismatch")
	}
}

func TestPublicKeySerialization(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Serialize
	pkBytes := kp.PublicKey().Bytes()

	// Parse
	pk, err := chkem.ParsePublicKey(pkBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	// Re-serialize and compare
	pkBytes2 := pk.Bytes()
	if !bytes.Equal(pkBytes, pkBytes2) {
		t.Error("Public key serialization roundtrip failed")
	}
}

func TestCiphertextSerialization(t *testing.T) {
	recipientKP, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, _, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Serialize
	ctBytes := ct.Bytes()

	// Parse
	ct2, err := chkem.ParseCiphertext(ctBytes)
	if err != nil {
		t.Fatalf("ParseCiphertext failed: %v", err)
	}

	// Re-serialize and compare
	ctBytes2 := ct2.Bytes()
	if !bytes.Equal(ctBytes, ctBytes2) {
		t.Error("Ciphertext serialization roundtrip failed")
	}
}

func TestInvalidPublicKey(t *testing.T) {
	// Try to parse invalid public key
	_, err := chkem.ParsePublicKey([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}

func TestInvalidCiphertext(t *testing.T) {
	// Try to parse invalid ciphertext
	_, err := chkem.ParseCiphertext([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid ciphertext")
	}
}

func TestEncapsulateNilPublicKey(t *testing.T) {
	_, _, err := chkem.Encapsulate(nil)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

func TestDecapsulateNilCiphertext(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	_, err = chkem.Decapsulate(nil, kp)
	if err == nil {
		t.Error("Expected error for nil ciphertext")
	}
}

func TestDecapsulateNilKeyPair(t *testing.T) {
	recipientKP, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, _, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	_, err = chkem.Decapsulate(ct, nil)
	if err == nil {
		t.Error("Expected error for nil key pair")
	}
}

func TestZeroize(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Zeroize should not panic
	kp.Zeroize()
}

func TestPublicKeyComponents(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pk := kp.PublicKey()

	// Check X25519 component
	x25519Pk := pk.X25519PublicKey()
	if x25519Pk == nil {
		t.Error("X25519PublicKey returned nil")
	}

	// Check ML-KEM component
	mlkemPk := pk.MLKEMPublicKey()
	if mlkemPk == nil {
		t.Error("MLKEMPublicKey returned nil")
	}
}

func TestClone(t *testing.T) {
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pk := kp.PublicKey()
	clone := pk.Clone()

	if !bytes.Equal(pk.Bytes(), clone.Bytes()) {
		t.Error("Cloned public key does not match original")
	}
}

// TestCHKEMDeterministicSharedSecret verifies that encapsulation and
// decapsulation produce the same shared secret for the same ciphertext.
func TestCHKEMDeterministicSharedSecret(t *testing.T) {
	recipientKP, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, ssEnc, err := chkem.Encapsulate(recipientKP.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Decapsulate the same ciphertext multiple times
	for i := 0; i < 5; i++ {
		ssDec, err := chkem.Decapsulate(ct, recipientKP)
		if err != nil {
			t.Fatalf("Decapsulate %d failed: %v", i, err)
		}

		if !bytes.Equal(ssEnc, ssDec) {
			t.Errorf("Decapsulation %d produced different shared secret", i)
		}
	}
}

// TestDifferentKeyPairsDifferentSecrets verifies that different key pairs
// produce different shared secrets even for the same sender.
func TestDifferentKeyPairsDifferentSecrets(t *testing.T) {
	kp1, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	_, ss1, err := chkem.Encapsulate(kp1.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	_, ss2, err := chkem.Encapsulate(kp2.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	if bytes.Equal(ss1, ss2) {
		t.Error("Different recipients should produce different shared secrets")
	}
}
