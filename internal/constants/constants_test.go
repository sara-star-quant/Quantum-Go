package constants

import "testing"

// TestCipherSuiteString tests String method for CipherSuite.
func TestCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  string
	}{
		{CipherSuiteAES256GCM, "AES-256-GCM"},
		{CipherSuiteChaCha20Poly1305, "ChaCha20-Poly1305"},
		{CipherSuite(0x9999), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.suite.String()
		if got != tt.want {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", tt.suite, got, tt.want)
		}
	}
}

// TestCipherSuiteIsSupported tests IsSupported method for CipherSuite.
func TestCipherSuiteIsSupported(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  bool
	}{
		{CipherSuiteAES256GCM, true},
		{CipherSuiteChaCha20Poly1305, true},
		{CipherSuite(0x0000), false},
		{CipherSuite(0xFFFF), false},
		{CipherSuite(0x0003), false},
	}

	for _, tt := range tests {
		got := tt.suite.IsSupported()
		if got != tt.want {
			t.Errorf("CipherSuite(%d).IsSupported() = %v, want %v", tt.suite, got, tt.want)
		}
	}
}

// TestConstants verifies constant values.
func TestConstants(t *testing.T) {
	t.Run("KeySizes", func(t *testing.T) {
		if X25519PublicKeySize != 32 {
			t.Errorf("X25519PublicKeySize = %d, want 32", X25519PublicKeySize)
		}
		if MLKEMPublicKeySize != 1568 {
			t.Errorf("MLKEMPublicKeySize = %d, want 1568", MLKEMPublicKeySize)
		}
		if MLKEMCiphertextSize != 1568 {
			t.Errorf("MLKEMCiphertextSize = %d, want 1568", MLKEMCiphertextSize)
		}
		if MLKEMSharedSecretSize != 32 {
			t.Errorf("MLKEMSharedSecretSize = %d, want 32", MLKEMSharedSecretSize)
		}
	})

	t.Run("CHKEMSizes", func(t *testing.T) {
		expectedPublicKeySize := X25519PublicKeySize + MLKEMPublicKeySize
		if CHKEMPublicKeySize != expectedPublicKeySize {
			t.Errorf("CHKEMPublicKeySize = %d, want %d", CHKEMPublicKeySize, expectedPublicKeySize)
		}

		expectedCiphertextSize := X25519PublicKeySize + MLKEMCiphertextSize
		if CHKEMCiphertextSize != expectedCiphertextSize {
			t.Errorf("CHKEMCiphertextSize = %d, want %d", CHKEMCiphertextSize, expectedCiphertextSize)
		}

		if CHKEMSharedSecretSize != 32 {
			t.Errorf("CHKEMSharedSecretSize = %d, want 32", CHKEMSharedSecretSize)
		}
	})

	t.Run("AEADParameters", func(t *testing.T) {
		if AESNonceSize != 12 {
			t.Errorf("AESNonceSize = %d, want 12", AESNonceSize)
		}
		if AESTagSize != 16 {
			t.Errorf("AESTagSize = %d, want 16", AESTagSize)
		}
		if ChaCha20NonceSize != 12 {
			t.Errorf("ChaCha20NonceSize = %d, want 12", ChaCha20NonceSize)
		}
	})

	t.Run("SessionParameters", func(t *testing.T) {
		if SessionIDSize != 16 {
			t.Errorf("SessionIDSize = %d, want 16", SessionIDSize)
		}
	})

	t.Run("RekeyThresholds", func(t *testing.T) {
		if MaxBytesBeforeRekey == 0 {
			t.Error("MaxBytesBeforeRekey should be non-zero")
		}
		if MaxSessionDurationSeconds == 0 {
			t.Error("MaxSessionDurationSeconds should be non-zero")
		}
		if MaxPacketsBeforeRekey == 0 {
			t.Error("MaxPacketsBeforeRekey should be non-zero")
		}
	})

	t.Run("MessageLimits", func(t *testing.T) {
		if MaxMessageSize == 0 {
			t.Error("MaxMessageSize should be non-zero")
		}
		if MaxPayloadSize == 0 {
			t.Error("MaxPayloadSize should be non-zero")
		}
	})

	t.Run("DomainSeparators", func(t *testing.T) {
		if len(DomainSeparatorCHKEM) == 0 {
			t.Error("DomainSeparatorCHKEM is empty")
		}
		if len(DomainSeparatorHandshake) == 0 {
			t.Error("DomainSeparatorHandshake is empty")
		}
		if len(DomainSeparatorTraffic) == 0 {
			t.Error("DomainSeparatorTraffic is empty")
		}
		if len(DomainSeparatorRekey) == 0 {
			t.Error("DomainSeparatorRekey is empty")
		}
	})
}

// TestCipherSuiteUniqueness ensures cipher suite IDs are unique.
func TestCipherSuiteUniqueness(t *testing.T) {
	if CipherSuiteAES256GCM == CipherSuiteChaCha20Poly1305 {
		t.Error("Cipher suite IDs must be unique")
	}
}
