package errors

import (
	"errors"
	"strings"
	"testing"
)

// TestCryptoError tests CryptoError type.
func TestCryptoError(t *testing.T) {
	baseErr := errors.New("base error")
	cerr := NewCryptoError("ml-kem-encapsulate", baseErr)

	// Test Error() method
	errStr := cerr.Error()
	if !strings.Contains(errStr, "ml-kem-encapsulate") {
		t.Errorf("Error string should contain operation: %q", errStr)
	}
	if !strings.Contains(errStr, "base error") {
		t.Errorf("Error string should contain base error: %q", errStr)
	}

	// Test Unwrap() method
	unwrapped := cerr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, baseErr)
	}

	// Test fields
	if cerr.Op != "ml-kem-encapsulate" {
		t.Errorf("Op = %q, want %q", cerr.Op, "ml-kem-encapsulate")
	}
	if cerr.Err != baseErr {
		t.Errorf("Err = %v, want %v", cerr.Err, baseErr)
	}
}

// TestProtocolError tests ProtocolError type.
func TestProtocolError(t *testing.T) {
	baseErr := errors.New("invalid message")
	perr := NewProtocolError("handshake", baseErr)

	// Test Error() method
	errStr := perr.Error()
	if !strings.Contains(errStr, "handshake") {
		t.Errorf("Error string should contain phase: %q", errStr)
	}
	if !strings.Contains(errStr, "invalid message") {
		t.Errorf("Error string should contain base error: %q", errStr)
	}

	// Test Unwrap() method
	unwrapped := perr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, baseErr)
	}

	// Test fields
	if perr.Phase != "handshake" {
		t.Errorf("Phase = %q, want %q", perr.Phase, "handshake")
	}
	if perr.Err != baseErr {
		t.Errorf("Err = %v, want %v", perr.Err, baseErr)
	}
}

// TestIsFunction tests the Is helper function.
func TestIsFunction(t *testing.T) {
	// Test with sentinel error
	err := ErrInvalidKeySize
	if !Is(err, ErrInvalidKeySize) {
		t.Error("Is() should return true for matching sentinel error")
	}

	// Test with wrapped error
	wrappedErr := NewCryptoError("operation", ErrDecapsulationFailed)
	if !Is(wrappedErr, ErrDecapsulationFailed) {
		t.Error("Is() should return true for wrapped sentinel error")
	}

	// Test with non-matching error
	if Is(err, ErrInvalidCiphertext) {
		t.Error("Is() should return false for non-matching error")
	}
}

// TestAsFunction tests the As helper function.
func TestAsFunction(t *testing.T) {
	// Create a CryptoError
	cerr := NewCryptoError("test-op", ErrKeyGenerationFailed)

	// Test with matching type
	var target *CryptoError
	if !As(cerr, &target) {
		t.Error("As() should return true for matching type")
	}
	if target.Op != "test-op" {
		t.Errorf("As() extracted Op = %q, want %q", target.Op, "test-op")
	}

	// Test with non-matching type
	var protocolErr *ProtocolError
	if As(cerr, &protocolErr) {
		t.Error("As() should return false for non-matching type")
	}
}

// TestSentinelErrors tests all sentinel error definitions.
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		// Crypto errors
		{"ErrInvalidKeySize", ErrInvalidKeySize},
		{"ErrInvalidCiphertext", ErrInvalidCiphertext},
		{"ErrDecapsulationFailed", ErrDecapsulationFailed},
		{"ErrKeyGenerationFailed", ErrKeyGenerationFailed},
		{"ErrEncapsulationFailed", ErrEncapsulationFailed},
		{"ErrInvalidPublicKey", ErrInvalidPublicKey},
		{"ErrInvalidPrivateKey", ErrInvalidPrivateKey},
		// AEAD errors
		{"ErrAuthenticationFailed", ErrAuthenticationFailed},
		{"ErrInvalidNonce", ErrInvalidNonce},
		{"ErrCiphertextTooShort", ErrCiphertextTooShort},
		{"ErrNonceExhausted", ErrNonceExhausted},
		// Protocol errors
		{"ErrInvalidMessage", ErrInvalidMessage},
		{"ErrUnsupportedVersion", ErrUnsupportedVersion},
		{"ErrUnsupportedCipherSuite", ErrUnsupportedCipherSuite},
		{"ErrHandshakeFailed", ErrHandshakeFailed},
		{"ErrSessionExpired", ErrSessionExpired},
		{"ErrInvalidState", ErrInvalidState},
		{"ErrMessageTooLarge", ErrMessageTooLarge},
		{"ErrReplayDetected", ErrReplayDetected},
		// Tunnel errors
		{"ErrTunnelClosed", ErrTunnelClosed},
		{"ErrRekeyRequired", ErrRekeyRequired},
		{"ErrTimeout", ErrTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			errStr := tt.err.Error()
			if errStr == "" {
				t.Errorf("%s.Error() returned empty string", tt.name)
			}
		})
	}
}

// TestErrorWrapping tests error wrapping with CryptoError.
func TestErrorWrapping(t *testing.T) {
	baseErr := ErrInvalidKeySize
	wrapped := NewCryptoError("x25519-keygen", baseErr)

	// Test that wrapped error contains base error
	if !errors.Is(wrapped, baseErr) {
		t.Error("Wrapped error should match base error with errors.Is")
	}

	// Test double wrapping
	doubleWrapped := NewCryptoError("outer-op", wrapped)
	if !errors.Is(doubleWrapped, baseErr) {
		t.Error("Double-wrapped error should still match base error")
	}

	// Extract CryptoError
	var cryptoErr *CryptoError
	if !errors.As(doubleWrapped, &cryptoErr) {
		t.Error("Should be able to extract CryptoError from double-wrapped")
	}
	if cryptoErr.Op != "outer-op" {
		t.Errorf("Extracted Op = %q, want %q", cryptoErr.Op, "outer-op")
	}
}

// TestProtocolErrorWrapping tests error wrapping with ProtocolError.
func TestProtocolErrorWrapping(t *testing.T) {
	baseErr := ErrHandshakeFailed
	wrapped := NewProtocolError("client-hello", baseErr)

	// Test that wrapped error contains base error
	if !errors.Is(wrapped, baseErr) {
		t.Error("Wrapped error should match base error with errors.Is")
	}

	// Extract ProtocolError
	var protocolErr *ProtocolError
	if !errors.As(wrapped, &protocolErr) {
		t.Error("Should be able to extract ProtocolError")
	}
	if protocolErr.Phase != "client-hello" {
		t.Errorf("Extracted Phase = %q, want %q", protocolErr.Phase, "client-hello")
	}
}

// TestMixedErrorTypes tests mixing CryptoError and ProtocolError.
func TestMixedErrorTypes(t *testing.T) {
	cryptoErr := NewCryptoError("ml-kem", ErrDecapsulationFailed)
	protocolErr := NewProtocolError("handshake", cryptoErr)

	// Should be able to unwrap to both types
	var ce *CryptoError
	if !errors.As(protocolErr, &ce) {
		t.Error("Should be able to extract CryptoError from ProtocolError wrapper")
	}

	var pe *ProtocolError
	if !errors.As(protocolErr, &pe) {
		t.Error("Should be able to extract ProtocolError")
	}

	// Should match base sentinel error
	if !errors.Is(protocolErr, ErrDecapsulationFailed) {
		t.Error("Should match base sentinel error through multiple wrappers")
	}
}

// TestErrorContextPreservation tests that error context is preserved.
func TestErrorContextPreservation(t *testing.T) {
	err := NewCryptoError("operation-1", ErrKeyGenerationFailed)
	wrapped := NewProtocolError("phase-1", err)

	// Both contexts should be in error string
	errStr := wrapped.Error()
	if !strings.Contains(errStr, "phase-1") {
		t.Errorf("Error string missing protocol phase: %q", errStr)
	}
	if !strings.Contains(errStr, "operation-1") {
		t.Errorf("Error string missing crypto operation: %q", errStr)
	}
	if !strings.Contains(errStr, "key generation failed") {
		t.Errorf("Error string missing base error: %q", errStr)
	}
}

// TestNilErrorHandling tests handling of nil errors.
func TestNilErrorHandling(t *testing.T) {
	// Is with nil error
	if Is(nil, ErrInvalidKeySize) {
		t.Error("Is(nil, target) should return false")
	}

	// As with nil error
	var target *CryptoError
	if As(nil, &target) {
		t.Error("As(nil, target) should return false")
	}
}
