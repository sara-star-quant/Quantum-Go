package chkem

import (
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
)

func TestEncapsulateInvalidKey(t *testing.T) {
	// Encapsulate with nil key
	_, _, err := Encapsulate(nil)
	if err == nil {
		t.Error("expected error for nil public key in Encapsulate")
	}
}

func TestParsePublicKeyInvalidSize(t *testing.T) {
	_, err := ParsePublicKey(make([]byte, 10))
	if err == nil {
		t.Error("expected error for invalid public key size")
	}
}

func TestParseCiphertextInvalidSize(t *testing.T) {
	_, err := ParseCiphertext(make([]byte, 10))
	if err == nil {
		t.Error("expected error for invalid ciphertext size")
	}
}

func TestDecapsulateError(t *testing.T) {
	kp, _ := GenerateKeyPair()
	ct := &Ciphertext{
		x25519Ephemeral: make([]byte, constants.X25519PublicKeySize),
		mlkemCiphertext: make([]byte, constants.CHKEMCiphertextSize),
	}

	// Should fail with garbage ciphertext
	_, err := Decapsulate(ct, kp)
	if err == nil {
		t.Error("expected error for invalid ciphertext in Decapsulate")
	}
}
