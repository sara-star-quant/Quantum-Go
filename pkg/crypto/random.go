// Package crypto provides cryptographic primitives for the Quantum-Go VPN system.
// This package wraps Go's standard library cryptographic functions with additional
// safety checks and consistent error handling.
//
// Security Note: All random number generation uses crypto/rand which provides
// cryptographically secure random bytes from the operating system's CSPRNG.
package crypto

import (
	"crypto/rand"
	"io"

	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// SecureRandom reads cryptographically secure random bytes into the provided slice.
// It uses crypto/rand.Read which sources entropy from the OS CSPRNG.
//
// This function will only return an error if the system's random number generator
// fails, which should be treated as a critical system failure.
func SecureRandom(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return qerrors.NewCryptoError("SecureRandom", err)
	}
	return nil
}

// SecureRandomBytes returns n cryptographically secure random bytes.
// Returns an error if the system's CSPRNG fails.
func SecureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := SecureRandom(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MustSecureRandom reads cryptographically secure random bytes into the provided slice.
// It panics if the system's CSPRNG fails, as this indicates a critical system failure.
//
// Use this function only in contexts where CSPRNG failure should be unrecoverable.
func MustSecureRandom(b []byte) {
	if err := SecureRandom(b); err != nil {
		panic("crypto: failed to read from CSPRNG: " + err.Error())
	}
}

// MustSecureRandomBytes returns n cryptographically secure random bytes.
// It panics if the system's CSPRNG fails.
func MustSecureRandomBytes(n int) []byte {
	b := make([]byte, n)
	MustSecureRandom(b)
	return b
}

// Reader is an io.Reader that returns cryptographically secure random bytes.
// It wraps crypto/rand.Reader for consistent error handling.
var Reader = rand.Reader

// ConstantTimeCompare compares two byte slices in constant time.
// Returns true if the slices are equal, false otherwise.
// This prevents timing attacks when comparing secrets.
func ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Zeroize securely erases sensitive data from memory by overwriting with zeros.
// This should be called on sensitive keys and secrets when they are no longer needed.
//
// Note: The Go runtime may have already copied the data, and the compiler may
// optimize away the zeroing. For maximum security, consider using memory
// protections at the OS level in production deployments.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroizeMultiple securely erases multiple byte slices.
func ZeroizeMultiple(slices ...[]byte) {
	for _, s := range slices {
		Zeroize(s)
	}
}
