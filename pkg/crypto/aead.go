// aead.go implements Authenticated Encryption with Associated Data (AEAD).
//
// This package supports two AEAD algorithms:
//   - AES-256-GCM: FIPS-approved, hardware-accelerated on modern CPUs
//   - ChaCha20-Poly1305: High performance without hardware support
//
// Mathematical Foundation:
//
// AES-256-GCM:
//   - AES: Block cipher with 256-bit key, 128-bit blocks
//   - GCM: Galois/Counter Mode for authenticated encryption
//   - Security: IND-CCA2 secure, 128-bit authentication tag
//   - Nonce: 96-bit, MUST be unique per (key, plaintext) pair
//
// ChaCha20-Poly1305:
//   - ChaCha20: Stream cipher with 256-bit key, 96-bit nonce
//   - Poly1305: One-time authenticator for MAC
//   - Security: IND-CCA2 secure, 128-bit authentication tag
//   - Nonce: 96-bit, MUST be unique per (key, plaintext) pair
//
// CRITICAL: Nonce reuse completely breaks security. Each (key, nonce) pair
// MUST be used at most once. This implementation uses counters for nonce
// generation and tracks usage to prevent reuse.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/quantum-go/quantum-go/internal/constants"
	qerrors "github.com/quantum-go/quantum-go/internal/errors"
)

// AEAD represents an authenticated encryption cipher.
type AEAD struct {
	cipher cipher.AEAD
	suite  constants.CipherSuite

	// Nonce state management
	mu      sync.Mutex
	counter uint64
	maxSeq  uint64
}

// NewAEAD creates a new AEAD cipher with the specified suite and key.
//
// Parameters:
//   - suite: CipherSuiteAES256GCM or CipherSuiteChaCha20Poly1305
//   - key: 32-byte encryption key
//
// Returns:
//   - AEAD: The initialized cipher
//   - error: Non-nil if the key size is wrong or suite unsupported
func NewAEAD(suite constants.CipherSuite, key []byte) (*AEAD, error) {
	if len(key) != constants.AESKeySize {
		return nil, qerrors.ErrInvalidKeySize
	}

	var aeadCipher cipher.AEAD
	var err error

	switch suite {
	case constants.CipherSuiteAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, qerrors.NewCryptoError("NewAEAD", err)
		}
		aeadCipher, err = cipher.NewGCM(block)
		if err != nil {
			return nil, qerrors.NewCryptoError("NewAEAD", err)
		}

	case constants.CipherSuiteChaCha20Poly1305:
		aeadCipher, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, qerrors.NewCryptoError("NewAEAD", err)
		}

	default:
		return nil, qerrors.ErrUnsupportedCipherSuite
	}

	return &AEAD{
		cipher:  aeadCipher,
		suite:   suite,
		counter: 0,
		// For a 96-bit nonce with 64-bit counter, we have 2^64 - 1 nonces available.
		// In practice, we limit to 2^28 to trigger rekey well before exhaustion.
		maxSeq: uint64(constants.MaxPacketsBeforeRekey),
	}, nil
}

// Seal encrypts and authenticates plaintext, returning ciphertext.
//
// The operation:
// 1. Generate nonce from counter (auto-incrementing)
// 2. Encrypt: ciphertext = AEAD.Seal(nonce, plaintext, additionalData)
// 3. Return: nonce || ciphertext (includes auth tag)
//
// Parameters:
//   - plaintext: Data to encrypt
//   - additionalData: Additional data to authenticate (not encrypted)
//
// Returns:
//   - ciphertext: nonce || encrypted_data || auth_tag
//   - error: Non-nil if nonce space exhausted
func (a *AEAD) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce, err := a.nextNonce()
	if err != nil {
		return nil, err
	}

	// Allocate space for nonce + ciphertext + tag
	ciphertext := make([]byte, constants.AESNonceSize+len(plaintext)+constants.AESTagSize)

	// Copy nonce to beginning
	copy(ciphertext[:constants.AESNonceSize], nonce)

	// Encrypt in place after nonce
	a.cipher.Seal(ciphertext[constants.AESNonceSize:constants.AESNonceSize], nonce, plaintext, additionalData)

	return ciphertext, nil
}

// SealWithNonce encrypts using an explicit nonce (for specific protocol needs).
//
// WARNING: The caller is responsible for ensuring nonce uniqueness.
// Prefer Seal() with automatic nonce generation when possible.
//
// Parameters:
//   - nonce: 12-byte unique nonce
//   - plaintext: Data to encrypt
//   - additionalData: Additional data to authenticate
//
// Returns:
//   - ciphertext: encrypted_data || auth_tag (nonce not included)
//   - error: Non-nil if nonce size is wrong
func (a *AEAD) SealWithNonce(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != constants.AESNonceSize {
		return nil, qerrors.ErrInvalidNonce
	}

	ciphertext := a.cipher.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Open decrypts and verifies ciphertext.
//
// The operation:
// 1. Extract nonce from ciphertext prefix
// 2. Verify authentication tag
// 3. Decrypt: plaintext = AEAD.Open(nonce, ciphertext, additionalData)
//
// Parameters:
//   - ciphertext: nonce || encrypted_data || auth_tag
//   - additionalData: Must match the additionalData used during Seal
//
// Returns:
//   - plaintext: Decrypted data
//   - error: Non-nil if authentication fails or ciphertext malformed
func (a *AEAD) Open(ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < constants.MinPacketSize {
		return nil, qerrors.ErrCiphertextTooShort
	}

	nonce := ciphertext[:constants.AESNonceSize]
	encrypted := ciphertext[constants.AESNonceSize:]

	plaintext, err := a.cipher.Open(nil, nonce, encrypted, additionalData)
	if err != nil {
		return nil, qerrors.ErrAuthenticationFailed
	}

	return plaintext, nil
}

// OpenWithNonce decrypts using an explicit nonce.
//
// Parameters:
//   - nonce: 12-byte nonce used during encryption
//   - ciphertext: encrypted_data || auth_tag (nonce not included)
//   - additionalData: Must match the additionalData used during Seal
//
// Returns:
//   - plaintext: Decrypted data
//   - error: Non-nil if authentication fails
func (a *AEAD) OpenWithNonce(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != constants.AESNonceSize {
		return nil, qerrors.ErrInvalidNonce
	}

	if len(ciphertext) < constants.AESTagSize {
		return nil, qerrors.ErrCiphertextTooShort
	}

	plaintext, err := a.cipher.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, qerrors.ErrAuthenticationFailed
	}

	return plaintext, nil
}

// nextNonce generates the next nonce and increments the counter.
// Returns error if nonce space is exhausted.
func (a *AEAD) nextNonce() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.counter >= a.maxSeq {
		return nil, qerrors.ErrNonceExhausted
	}

	nonce := make([]byte, constants.AESNonceSize)
	// Use big-endian counter in the last 8 bytes, first 4 bytes are zero
	binary.BigEndian.PutUint64(nonce[4:], a.counter)
	a.counter++

	return nonce, nil
}

// Counter returns the current nonce counter value.
// This can be used to check how many messages have been sent.
func (a *AEAD) Counter() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counter
}

// SetCounter sets the nonce counter value.
// Use with caution - only for resuming sessions with known state.
func (a *AEAD) SetCounter(counter uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if counter >= a.maxSeq {
		return qerrors.ErrNonceExhausted
	}
	a.counter = counter
	return nil
}

// NeedsRekey returns true if the cipher is approaching nonce exhaustion.
// Callers should initiate rekey when this returns true.
func (a *AEAD) NeedsRekey() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Trigger rekey at 90% of capacity to allow graceful transition
	return a.counter >= (a.maxSeq * 9 / 10)
}

// Suite returns the cipher suite identifier.
func (a *AEAD) Suite() constants.CipherSuite {
	return a.suite
}

// Overhead returns the number of bytes of overhead added by encryption.
// This is nonce size + authentication tag size.
func (a *AEAD) Overhead() int {
	return constants.AESNonceSize + a.cipher.Overhead()
}

// NonceSize returns the required nonce size in bytes.
func (a *AEAD) NonceSize() int {
	return a.cipher.NonceSize()
}
