package crypto

import (
	"errors"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

func TestNewAEADInvalidSuite(t *testing.T) {
	key := make([]byte, 32)
	_, err := NewAEAD(constants.CipherSuite(0xFF), key)
	if !errors.Is(err, qerrors.ErrUnsupportedCipherSuite) {
		t.Errorf("expected ErrUnsupportedCipherSuite, got %v", err)
	}
}

func TestAEADSealOpenErrors(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)

	// Short ciphertext for Open
	_, err := aead.Open(make([]byte, 5), nil)
	if err == nil {
		t.Error("expected error for short ciphertext in Open")
	}

	// Invalid nonce size for SealWithNonce
	_, err = aead.SealWithNonce(make([]byte, 5), nil, nil)
	if err == nil {
		t.Error("expected error for invalid nonce size in SealWithNonce")
	}
}

func TestDeriveTrafficKeysErrors(t *testing.T) {
	// Traffic keys derivation with invalid secret size
	_, _, err := DeriveTrafficKeys(make([]byte, 10))
	if err == nil {
		t.Error("expected error for invalid secret size in DeriveTrafficKeys")
	}
}
