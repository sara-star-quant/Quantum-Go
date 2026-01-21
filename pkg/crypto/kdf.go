// Package crypto implements key derivation functions using SHAKE-256 (SHA-3 XOF).
//
// This file (kdf.go) uses SHAKE-256 (FIPS 202), an extendable-output function (XOF) based on the
// Keccak sponge construction. It provides 256-bit security against collision
// and preimage attacks, and 128-bit security against length-extension attacks.
//
// Mathematical Foundation:
//
// SHAKE-256 uses the Keccak-f[1600] permutation with rate r = 1088 and
// capacity c = 512. The sponge construction:
//
// 1. Absorb: Process message blocks through the permutation
// 2. Squeeze: Extract arbitrary-length output
//
// Security Properties:
//   - 256-bit preimage and collision resistance
//   - Extendable output: can generate arbitrary length keys
//   - No length-extension attacks (unlike SHA-2)
//   - Domain separation prevents key/message confusion
//
// Usage in CH-KEM:
// The KDF combines multiple secret values with domain separation to derive
// the final shared secret:
//
//	K = SHAKE-256(K_x25519 || K_mlkem || transcript_hash || context_info, 256)
package crypto

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// DeriveKey derives a key using SHAKE-256 with domain separation.
//
// The derivation follows the construction:
//
//	output = SHAKE-256(
//	    domain_separator_length || domain_separator ||
//	    input_length || input,
//	    output_length
//	)
//
// Length prefixes are 4-byte big-endian integers to ensure unambiguous parsing.
//
// Parameters:
//   - domain: Domain separation string (prevents cross-protocol attacks)
//   - input: Secret input material to derive from
//   - outputLen: Desired output length in bytes
//
// Returns:
//   - derived: The derived key material
//   - error: Non-nil if parameters are invalid
func DeriveKey(domain string, input []byte, outputLen int) ([]byte, error) {
	if outputLen <= 0 || outputLen > 1<<20 { // Max 1MB
		return nil, qerrors.NewCryptoError("DeriveKey", qerrors.ErrInvalidKeySize)
	}

	h := sha3.NewShake256()

	// Write domain separator with length prefix
	domainBytes := []byte(domain)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(domainBytes)))
	h.Write(lenBuf)
	h.Write(domainBytes)

	// Write input with length prefix
	binary.BigEndian.PutUint32(lenBuf, uint32(len(input)))
	h.Write(lenBuf)
	h.Write(input)

	// Extract output
	output := make([]byte, outputLen)
	_, _ = h.Read(output) // SHAKE256.Read never fails

	return output, nil
}

// DeriveKeyMultiple derives a key from multiple inputs with domain separation.
//
// This is used for CH-KEM key derivation where we combine:
//   - X25519 shared secret
//   - ML-KEM shared secret
//   - Transcript hash
//   - Context info
//
// Parameters:
//   - domain: Domain separation string
//   - inputs: Multiple input values to combine
//   - outputLen: Desired output length in bytes
//
// Returns:
//   - derived: The derived key material
//   - error: Non-nil if parameters are invalid
func DeriveKeyMultiple(domain string, inputs [][]byte, outputLen int) ([]byte, error) {
	if outputLen <= 0 || outputLen > 1<<20 {
		return nil, qerrors.NewCryptoError("DeriveKeyMultiple", qerrors.ErrInvalidKeySize)
	}

	h := sha3.NewShake256()
	lenBuf := make([]byte, 4)

	// Write domain separator with length prefix
	domainBytes := []byte(domain)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(domainBytes)))
	h.Write(lenBuf)
	h.Write(domainBytes)

	// Write number of inputs
	binary.BigEndian.PutUint32(lenBuf, uint32(len(inputs)))
	h.Write(lenBuf)

	// Write each input with length prefix
	for _, input := range inputs {
		binary.BigEndian.PutUint32(lenBuf, uint32(len(input)))
		h.Write(lenBuf)
		h.Write(input)
	}

	// Extract output
	output := make([]byte, outputLen)
	_, _ = h.Read(output) // SHAKE256.Read never fails

	return output, nil
}

// TranscriptHash computes a hash of the handshake transcript.
//
// The transcript includes all public values exchanged during the handshake:
//   - Initiator's public keys (X25519 + ML-KEM)
//   - Responder's public keys (X25519 + ML-KEM ciphertext)
//   - Protocol version and cipher suite
//
// Using SHA3-256 for the transcript hash provides:
//   - 128-bit collision resistance
//   - Binding: changes to any transcript component change the hash
//   - Non-malleability: prevents transcript manipulation attacks
//
// Parameters:
//   - components: Ordered list of transcript components
//
// Returns:
//   - hash: 32-byte transcript hash
func TranscriptHash(components ...[]byte) []byte {
	h := sha3.New256()
	lenBuf := make([]byte, 4)

	// Write number of components
	binary.BigEndian.PutUint32(lenBuf, uint32(len(components)))
	h.Write(lenBuf)

	// Write each component with length prefix
	for _, component := range components {
		binary.BigEndian.PutUint32(lenBuf, uint32(len(component)))
		h.Write(lenBuf)
		h.Write(component)
	}

	return h.Sum(nil)
}

// DeriveCHKEMSecret derives the final shared secret for CH-KEM.
//
// This is the core key derivation for the Cascaded Hybrid KEM:
//
//	K_final = SHAKE-256(
//	    K_classical || K_pq || transcript_hash || context_info,
//	    output_length = 256 bits
//	)
//
// Security Properties:
//   - If EITHER X25519 OR ML-KEM is secure, the output is indistinguishable from random
//   - Transcript binding prevents man-in-the-middle attacks
//   - Domain separation prevents cross-protocol attacks
//
// Parameters:
//   - x25519Secret: 32-byte X25519 shared secret
//   - mlkemSecret: 32-byte ML-KEM shared secret
//   - transcriptHash: 32-byte hash of the handshake transcript
//
// Returns:
//   - sharedSecret: 32-byte final shared secret
//   - error: Non-nil if inputs are invalid
func DeriveCHKEMSecret(x25519Secret, mlkemSecret, transcriptHash []byte) ([]byte, error) {
	if len(x25519Secret) != constants.X25519SharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveCHKEMSecret", qerrors.ErrInvalidKeySize)
	}
	if len(mlkemSecret) != constants.MLKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveCHKEMSecret", qerrors.ErrInvalidKeySize)
	}
	if len(transcriptHash) != constants.TranscriptHashSize {
		return nil, qerrors.NewCryptoError("DeriveCHKEMSecret", qerrors.ErrInvalidKeySize)
	}

	return DeriveKeyMultiple(
		constants.DomainSeparatorCHKEM,
		[][]byte{x25519Secret, mlkemSecret, transcriptHash},
		constants.CHKEMSharedSecretSize,
	)
}

// DeriveHandshakeKeys derives keys for handshake message encryption.
//
// From the master secret, derives:
//   - Initiator write key (32 bytes)
//   - Responder write key (32 bytes)
//   - Initiator write IV (12 bytes)
//   - Responder write IV (12 bytes)
//
// Parameters:
//   - masterSecret: The CH-KEM shared secret
//
// Returns:
//   - initiatorKey, responderKey: 32-byte encryption keys
//   - initiatorIV, responderIV: 12-byte IVs for AEAD
//   - error: Non-nil if derivation fails
func DeriveHandshakeKeys(masterSecret []byte) (initiatorKey, responderKey, initiatorIV, responderIV []byte, err error) {
	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return nil, nil, nil, nil, qerrors.NewCryptoError("DeriveHandshakeKeys", qerrors.ErrInvalidKeySize)
	}

	// Derive all keys in one pass for efficiency
	keyMaterial, err := DeriveKey(
		constants.DomainSeparatorHandshake,
		masterSecret,
		2*constants.AESKeySize+2*constants.AESNonceSize,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	offset := 0
	initiatorKey = keyMaterial[offset : offset+constants.AESKeySize]
	offset += constants.AESKeySize
	responderKey = keyMaterial[offset : offset+constants.AESKeySize]
	offset += constants.AESKeySize
	initiatorIV = keyMaterial[offset : offset+constants.AESNonceSize]
	offset += constants.AESNonceSize
	responderIV = keyMaterial[offset : offset+constants.AESNonceSize]

	return initiatorKey, responderKey, initiatorIV, responderIV, nil
}

// DeriveTrafficKeys derives keys for tunnel traffic encryption.
//
// Similar to handshake keys but uses a different domain separator
// to ensure traffic keys are independent from handshake keys.
//
// Parameters:
//   - masterSecret: The CH-KEM shared secret
//
// Returns:
//   - initiatorKey, responderKey: 32-byte encryption keys
//   - error: Non-nil if derivation fails
func DeriveTrafficKeys(masterSecret []byte) (initiatorKey, responderKey []byte, err error) {
	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return nil, nil, qerrors.NewCryptoError("DeriveTrafficKeys", qerrors.ErrInvalidKeySize)
	}

	keyMaterial, err := DeriveKey(
		constants.DomainSeparatorTraffic,
		masterSecret,
		2*constants.AESKeySize,
	)
	if err != nil {
		return nil, nil, err
	}

	initiatorKey = keyMaterial[:constants.AESKeySize]
	responderKey = keyMaterial[constants.AESKeySize:]

	return initiatorKey, responderKey, nil
}

// DeriveRekeySecret derives a new master secret for session rekeying.
//
// The rekey process:
// 1. Derive new secret from current master secret + additional entropy
// 2. Use new secret to derive fresh traffic keys
// 3. Zeroize old keys
//
// Parameters:
//   - currentSecret: The current master secret
//   - additionalData: Additional entropy (e.g., timestamp, counter)
//
// Returns:
//   - newSecret: New 32-byte master secret
//   - error: Non-nil if derivation fails
func DeriveRekeySecret(currentSecret, additionalData []byte) ([]byte, error) {
	if len(currentSecret) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveRekeySecret", qerrors.ErrInvalidKeySize)
	}

	return DeriveKeyMultiple(
		constants.DomainSeparatorRekey,
		[][]byte{currentSecret, additionalData},
		constants.CHKEMSharedSecretSize,
	)
}
