// Package errors defines custom error types for the Quantum-Go VPN encryption system.
// These errors provide detailed information for debugging while maintaining
// security by not leaking sensitive information in error messages.
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for cryptographic operations
var (
	// ErrInvalidKeySize indicates that a key has an incorrect size
	ErrInvalidKeySize = errors.New("chkem: invalid key size")

	// ErrInvalidCiphertext indicates that ciphertext is malformed or invalid
	ErrInvalidCiphertext = errors.New("chkem: invalid ciphertext")

	// ErrDecapsulationFailed indicates that KEM decapsulation failed
	ErrDecapsulationFailed = errors.New("chkem: decapsulation failed")

	// ErrKeyGenerationFailed indicates that key generation failed
	ErrKeyGenerationFailed = errors.New("chkem: key generation failed")

	// ErrEncapsulationFailed indicates that KEM encapsulation failed
	ErrEncapsulationFailed = errors.New("chkem: encapsulation failed")

	// ErrInvalidPublicKey indicates that a public key is invalid
	ErrInvalidPublicKey = errors.New("chkem: invalid public key")

	// ErrInvalidPrivateKey indicates that a private key is invalid
	ErrInvalidPrivateKey = errors.New("chkem: invalid private key")
)

// Sentinel errors for AEAD operations
var (
	// ErrAuthenticationFailed indicates AEAD authentication/decryption failed
	ErrAuthenticationFailed = errors.New("aead: authentication failed")

	// ErrInvalidNonce indicates the nonce size is incorrect
	ErrInvalidNonce = errors.New("aead: invalid nonce size")

	// ErrCiphertextTooShort indicates ciphertext is too short to be valid
	ErrCiphertextTooShort = errors.New("aead: ciphertext too short")

	// ErrNonceExhausted indicates nonce space is exhausted for the current key
	ErrNonceExhausted = errors.New("aead: nonce space exhausted, rekey required")
)

// Sentinel errors for protocol operations
var (
	// ErrInvalidMessage indicates a protocol message is malformed
	ErrInvalidMessage = errors.New("protocol: invalid message")

	// ErrUnsupportedVersion indicates an unsupported protocol version
	ErrUnsupportedVersion = errors.New("protocol: unsupported version")

	// ErrUnsupportedCipherSuite indicates an unsupported cipher suite
	ErrUnsupportedCipherSuite = errors.New("protocol: unsupported cipher suite")

	// ErrHandshakeFailed indicates the handshake failed
	ErrHandshakeFailed = errors.New("protocol: handshake failed")

	// ErrSessionExpired indicates the session has expired
	ErrSessionExpired = errors.New("protocol: session expired")

	// ErrInvalidState indicates an invalid protocol state
	ErrInvalidState = errors.New("protocol: invalid state")

	// ErrMessageTooLarge indicates message exceeds maximum size
	ErrMessageTooLarge = errors.New("protocol: message too large")

	// ErrReplayDetected indicates a potential replay attack
	ErrReplayDetected = errors.New("protocol: replay detected")

	// ErrInvalidTicket indicates a session ticket is invalid or malformed
	ErrInvalidTicket = errors.New("protocol: invalid ticket")

	// ErrExpiredTicket indicates a session ticket has expired
	ErrExpiredTicket = errors.New("protocol: expired ticket")
)

// Sentinel errors for tunnel operations
var (
	// ErrTunnelClosed indicates the tunnel has been closed
	ErrTunnelClosed = errors.New("tunnel: connection closed")

	// ErrRekeyRequired indicates a rekey operation is required
	ErrRekeyRequired = errors.New("tunnel: rekey required")

	// ErrRekeyInProgress indicates a rekey operation is already in progress
	ErrRekeyInProgress = errors.New("tunnel: rekey already in progress")

	// ErrTimeout indicates an operation timed out
	ErrTimeout = errors.New("tunnel: operation timed out")
)

// Sentinel errors for connection pool operations
var (
	// ErrPoolClosed indicates the pool has been closed
	ErrPoolClosed = errors.New("pool: pool is closed")

	// ErrPoolTimeout indicates a pool acquire operation timed out
	ErrPoolTimeout = errors.New("pool: acquire timed out")

	// ErrPoolExhausted indicates the pool has no available connections
	ErrPoolExhausted = errors.New("pool: no connections available")
)

// CryptoError wraps a cryptographic error with additional context
type CryptoError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

// NewCryptoError creates a new CryptoError
func NewCryptoError(op string, err error) *CryptoError {
	return &CryptoError{Op: op, Err: err}
}

// ProtocolError wraps a protocol error with additional context
type ProtocolError struct {
	Phase string // Protocol phase (e.g., "handshake", "transport")
	Err   error  // Underlying error
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("protocol %s: %v", e.Phase, e.Err)
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

// NewProtocolError creates a new ProtocolError
func NewProtocolError(phase string, err error) *ProtocolError {
	return &ProtocolError{Phase: phase, Err: err}
}

// Is reports whether any error in err's chain matches target.
// This is a convenience wrapper around errors.Is.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target.
// This is a convenience wrapper around errors.As.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}
