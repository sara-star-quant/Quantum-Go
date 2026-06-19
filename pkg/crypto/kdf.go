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
	"crypto/sha3"
	"encoding/binary"
	"math"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// safeUint32 safely converts an int to uint32, returning false if overflow would occur.
func safeUint32(n int) (uint32, bool) {
	if n < 0 || n > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

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

	// Validate input sizes to prevent uint32 overflow
	domainBytes := []byte(domain)
	domainLen, ok := safeUint32(len(domainBytes))
	if !ok {
		return nil, qerrors.NewCryptoError("DeriveKey", qerrors.ErrInvalidKeySize)
	}
	inputLen, ok := safeUint32(len(input))
	if !ok {
		return nil, qerrors.NewCryptoError("DeriveKey", qerrors.ErrInvalidKeySize)
	}

	h := sha3.NewSHAKE256()
	lenBuf := make([]byte, 4)

	// Write domain separator with length prefix
	// Note: sha3.ShakeHash.Write never returns an error (in-memory operation)
	binary.BigEndian.PutUint32(lenBuf, domainLen)
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(domainBytes)

	// Write input with length prefix
	binary.BigEndian.PutUint32(lenBuf, inputLen)
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(input)

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

	// Validate input sizes to prevent uint32 overflow
	domainBytes := []byte(domain)
	domainLen, ok := safeUint32(len(domainBytes))
	if !ok {
		return nil, qerrors.NewCryptoError("DeriveKeyMultiple", qerrors.ErrInvalidKeySize)
	}
	inputsCount, ok := safeUint32(len(inputs))
	if !ok {
		return nil, qerrors.NewCryptoError("DeriveKeyMultiple", qerrors.ErrInvalidKeySize)
	}

	h := sha3.NewSHAKE256()
	lenBuf := make([]byte, 4)

	// Write domain separator with length prefix
	// Note: sha3.ShakeHash.Write never returns an error (in-memory operation)
	binary.BigEndian.PutUint32(lenBuf, domainLen)
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(domainBytes)

	// Write number of inputs
	binary.BigEndian.PutUint32(lenBuf, inputsCount)
	_, _ = h.Write(lenBuf)

	// Write each input with length prefix
	for _, input := range inputs {
		inputLen, ok := safeUint32(len(input))
		if !ok {
			return nil, qerrors.NewCryptoError("DeriveKeyMultiple", qerrors.ErrInvalidKeySize)
		}
		binary.BigEndian.PutUint32(lenBuf, inputLen)
		_, _ = h.Write(lenBuf)
		_, _ = h.Write(input)
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
func TranscriptHash(components ...[]byte) ([]byte, error) {
	h := sha3.New256()
	lenBuf := make([]byte, 4)

	// Write number of components
	// Note: sha3.Hash.Write never returns an error (in-memory operation)
	// Components count is bounded by protocol (typically 3-5 items)
	componentsCount, ok := safeUint32(len(components))
	if !ok {
		return nil, qerrors.NewCryptoError("TranscriptHash", qerrors.ErrInvalidKeySize)
	}
	binary.BigEndian.PutUint32(lenBuf, componentsCount)
	_, _ = h.Write(lenBuf)

	// Write each component with length prefix
	// Component sizes are bounded by protocol message limits
	for _, component := range components {
		componentLen, ok := safeUint32(len(component))
		if !ok {
			return nil, qerrors.NewCryptoError("TranscriptHash", qerrors.ErrInvalidKeySize)
		}
		binary.BigEndian.PutUint32(lenBuf, componentLen)
		_, _ = h.Write(lenBuf)
		_, _ = h.Write(component)
	}

	return h.Sum(nil), nil
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

// DeriveDatagramNoncePrefixes derives the two per-direction nonce prefixes for
// the datagram transport. The datagram path never transmits the AEAD nonce; it
// builds nonce = prefix || seq(8B), so both peers must agree on the prefix. They
// are derived from the master secret under a distinct domain separator, split by
// role exactly like DeriveTrafficKeys: the initiator seals with initiatorPrefix
// and opens with responderPrefix, and vice versa.
//
// Parameters:
//   - masterSecret: The CH-KEM shared secret
//
// Returns:
//   - initiatorPrefix, responderPrefix: DatagramNoncePrefixSize-byte prefixes
//   - error: Non-nil if derivation fails
func DeriveDatagramNoncePrefixes(masterSecret []byte) (initiatorPrefix, responderPrefix []byte, err error) {
	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return nil, nil, qerrors.NewCryptoError("DeriveDatagramNoncePrefixes", qerrors.ErrInvalidKeySize)
	}

	material, err := DeriveKey(
		constants.DomainSeparatorDatagramNonce,
		masterSecret,
		2*constants.DatagramNoncePrefixSize,
	)
	if err != nil {
		return nil, nil, err
	}

	initiatorPrefix = material[:constants.DatagramNoncePrefixSize]
	responderPrefix = material[constants.DatagramNoncePrefixSize:]

	return initiatorPrefix, responderPrefix, nil
}

// DeriveResumptionSecret derives a new master secret for resumed sessions.
//
// This combines the PSK (ticket secret) with a fresh KEM shared secret,
// providing forward secrecy even when the ticket is compromised.
// Similar to TLS 1.3's PSK+ECDHE mode.
//
// Parameters:
//   - psk: Pre-shared key from the session ticket
//   - freshSecret: Fresh shared secret from new CH-KEM exchange
//
// Returns:
//   - newSecret: New 32-byte master secret
//   - error: Non-nil if inputs are invalid
func DeriveResumptionSecret(psk, freshSecret []byte) ([]byte, error) {
	if len(psk) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveResumptionSecret", qerrors.ErrInvalidKeySize)
	}
	if len(freshSecret) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveResumptionSecret", qerrors.ErrInvalidKeySize)
	}

	return DeriveKeyMultiple(
		constants.DomainSeparatorResumption,
		[][]byte{psk, freshSecret},
		constants.CHKEMSharedSecretSize,
	)
}

// DeriveRekeySecret derives a new master secret for session rekeying.
//
// The ratcheting pattern mixes the current master secret with fresh KEM output,
// ensuring forward secrecy: compromise of a single rekey does not expose prior
// or subsequent traffic. Inspired by Rosenpass's frequent key refresh cadence
// and standard KDF composition (NIST SP 800-56C).
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

// DeriveAuthenticatedSecret folds a static-key authentication secret into the
// ephemeral master secret for endpoint authentication.
//
// The client encapsulates to the server's pinned static public key and both
// sides mix the resulting secret into the master secret. Only the holder of the
// static private key can derive the same secret, so a wrong or absent key yields
// a different master secret and the Finished MAC fails closed. The ephemeral
// secret remains a mandatory input, so forward secrecy is preserved: a later
// static-key compromise does not expose past sessions.
//
// Parameters:
//   - ephemeralSecret: The ephemeral CH-KEM master secret (32 bytes)
//   - staticSecret: The static-key authentication secret (32 bytes)
//
// Returns:
//   - newSecret: New 32-byte master secret
//   - error: Non-nil if either input is the wrong size
func DeriveAuthenticatedSecret(ephemeralSecret, staticSecret []byte) ([]byte, error) {
	if len(ephemeralSecret) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveAuthenticatedSecret", qerrors.ErrInvalidKeySize)
	}
	if len(staticSecret) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DeriveAuthenticatedSecret", qerrors.ErrInvalidKeySize)
	}

	return DeriveKeyMultiple(
		constants.DomainSeparatorAuthentication,
		[][]byte{ephemeralSecret, staticSecret},
		constants.CHKEMSharedSecretSize,
	)
}

// DerivePSKSecret folds a pre-shared key into the master secret for mutual
// authentication. Only peers that hold the same PSK derive a matching secret, so
// a wrong or absent PSK surfaces as a Finished MAC failure. The ephemeral secret
// stays a mandatory input, so forward secrecy holds even if the PSK later leaks.
//
// Parameters:
//   - masterSecret: The current master secret (32 bytes)
//   - psk: The pre-shared key (PSKSize bytes)
//
// Returns:
//   - newSecret: New 32-byte master secret
//   - error: Non-nil if either input is the wrong size
func DerivePSKSecret(masterSecret, psk []byte) ([]byte, error) {
	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return nil, qerrors.NewCryptoError("DerivePSKSecret", qerrors.ErrInvalidKeySize)
	}
	if len(psk) != constants.PSKSize {
		return nil, qerrors.NewCryptoError("DerivePSKSecret", qerrors.ErrInvalidKeySize)
	}

	return DeriveKeyMultiple(
		constants.DomainSeparatorPSK,
		[][]byte{masterSecret, psk},
		constants.CHKEMSharedSecretSize,
	)
}
