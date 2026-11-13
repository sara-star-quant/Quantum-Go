// Package crypto implements ML-KEM-1024 key encapsulation mechanism wrapper.
//
// This file (mlkem.go) wraps ML-KEM, which is standardized in
// NIST FIPS 203. The security of ML-KEM is based on the computational difficulty
// of the Module Learning With Errors (MLWE) problem.
//
// Mathematical Foundation:
//
// The MLWE problem is defined over the polynomial ring R_q = Z_q[X]/(X^n + 1)
// where n = 256 and q = 3329 for ML-KEM-1024.
//
// Given (A, b = As + e) where:
//   - A ∈ R_q^{k×k} is a uniformly random matrix (k=4 for ML-KEM-1024)
//   - s ∈ R_q^k is the secret vector
//   - e is an error vector sampled from a centered binomial distribution
//
// It is computationally infeasible to distinguish (A, As + e) from uniform random.
//
// Security Level: NIST Category 5 (equivalent to AES-256 against quantum adversaries)

package crypto

import (
	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// MLKEMPublicKey wraps an ML-KEM-1024 public key
type MLKEMPublicKey struct {
	key *mlkemEK
}

// MLKEMPrivateKey wraps an ML-KEM-1024 private key
type MLKEMPrivateKey struct {
	key *mlkemDK
}

// MLKEMKeyPair represents an ML-KEM-1024 key pair for post-quantum key encapsulation.
type MLKEMKeyPair struct {
	// EncapsulationKey is the public key used by others to encapsulate secrets
	EncapsulationKey *MLKEMPublicKey

	// DecapsulationKey is the private key used to decapsulate secrets
	DecapsulationKey *MLKEMPrivateKey
}

// GenerateMLKEMKeyPair generates a new ML-KEM-1024 key pair.
//
// The key generation process (the 64-byte seed d || z comes from SecureRandom and is
// wiped after the key is derived):
// 1. Sample random seed d ← {0,1}^256
// 2. Sample random seed z ← {0,1}^256
// 3. Expand matrix A from seed using SHAKE-128
// 4. Sample secret vector s and error vector e from CBD(η₁)
// 5. Compute public key pk = (A, As + e)
// 6. Compute private key sk = (s, pk, H(pk), z)
//
// Returns error if the system's CSPRNG fails.
func GenerateMLKEMKeyPair() (*MLKEMKeyPair, error) {
	// Draw the 64-byte seed (d || z) from our entropy source, then derive the key: the same
	// FIPS 203 KeyGen as GenerateKey1024, with the entropy source injectable and testable.
	seed := make([]byte, mlkemSeedSize)
	defer Zeroize(seed) // wipes this buffer; the key object keeps its own copy until it is collected
	if err := SecureRandom(seed); err != nil {
		return nil, err
	}
	return NewMLKEMKeyPairFromSeed(seed)
}

// mlkemSeedSize is the FIPS 203 key-generation seed, d || z.
const mlkemSeedSize = 64

// NewMLKEMKeyPairFromSeed generates an ML-KEM-1024 key pair from a 64-byte seed.
// This is deterministic: the same seed will always produce the same key pair.
//
// The seed should be generated from a cryptographically secure source.
// This function is useful for key derivation from a master secret.
func NewMLKEMKeyPairFromSeed(seed []byte) (*MLKEMKeyPair, error) {
	if len(seed) != mlkemSeedSize {
		return nil, qerrors.ErrInvalidKeySize
	}
	ek, dk, err := mlkemKeyFromSeed(seed)
	if err != nil {
		return nil, qerrors.NewCryptoError("MLKEMKeyPair.FromSeed", err)
	}
	return &MLKEMKeyPair{
		EncapsulationKey: &MLKEMPublicKey{key: ek},
		DecapsulationKey: &MLKEMPrivateKey{key: dk},
	}, nil
}

// MLKEMEncapsulate performs key encapsulation using ML-KEM-1024.
//
// Encapsulation process:
// 1. Sample random coins m ← {0,1}^256
// 2. Compute (K̄, r) = G(m || H(pk)) where G is SHA3-512
// 3. Compute ciphertext c using r as randomness
// 4. Compute K = KDF(K̄ || H(c)) as the final shared secret
//
// Parameters:
//   - ek: The recipient's encapsulation key (public key)
//
// Returns:
//   - ciphertext: The encapsulated ciphertext (1568 bytes for ML-KEM-1024)
//   - sharedSecret: The shared secret (32 bytes)
//   - error: Non-nil if encapsulation fails
func MLKEMEncapsulate(ek *MLKEMPublicKey) (ciphertext, sharedSecret []byte, err error) {
	if ek == nil || ek.key == nil {
		return nil, nil, qerrors.ErrInvalidPublicKey
	}
	ciphertext, sharedSecret, err = mlkemEncapsulate(ek.key)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("MLKEMEncapsulate", err)
	}
	return ciphertext, sharedSecret, nil
}

// MLKEMDecapsulate performs key decapsulation using ML-KEM-1024.
//
// Decapsulation process (IND-CCA2 secure via Fujisaki-Okamoto transform):
// 1. Decrypt ciphertext c to obtain m'
// 2. Recompute (K̄', r') = G(m' || H(pk))
// 3. Re-encrypt m' with r' to get c'
// 4. If c == c': return K = KDF(K̄' || H(c))
// 5. If c != c': return K = KDF(z || H(c)) (implicit rejection)
//
// The implicit rejection (step 5) ensures that decapsulation always returns
// a value that looks random, preventing distinguishing attacks.
//
// Parameters:
//   - dk: The decapsulation key (private key)
//   - ciphertext: The ciphertext to decapsulate
//
// Returns:
//   - sharedSecret: The shared secret (32 bytes)
//   - error: Non-nil if ciphertext is malformed
func MLKEMDecapsulate(dk *MLKEMPrivateKey, ciphertext []byte) ([]byte, error) {
	if dk == nil || dk.key == nil {
		return nil, qerrors.ErrInvalidPrivateKey
	}

	if len(ciphertext) != constants.MLKEMCiphertextSize {
		return nil, qerrors.ErrInvalidCiphertext
	}

	ss, err := mlkemDecapsulate(dk.key, ciphertext)
	if err != nil {
		return nil, qerrors.ErrInvalidCiphertext
	}
	return ss, nil
}

// Bytes returns the encoded bytes of the public key.
func (pk *MLKEMPublicKey) Bytes() []byte {
	if pk == nil || pk.key == nil {
		return nil
	}
	return mlkemPublicKeyBytes(pk.key)
}

// PublicKeyBytes returns the encoded bytes of the encapsulation key.
func (kp *MLKEMKeyPair) PublicKeyBytes() []byte {
	return kp.EncapsulationKey.Bytes()
}

// ParseMLKEMPublicKey parses an ML-KEM-1024 public key from its encoded form.
func ParseMLKEMPublicKey(data []byte) (*MLKEMPublicKey, error) {
	if len(data) != constants.MLKEMPublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}

	pk, err := mlkemParsePublicKey(data)
	if err != nil {
		return nil, qerrors.NewCryptoError("ParseMLKEMPublicKey", err)
	}

	return &MLKEMPublicKey{key: pk}, nil
}

// Zeroize securely erases the private key material.
// This should be called when the key pair is no longer needed.
func (kp *MLKEMKeyPair) Zeroize() {
	if kp.DecapsulationKey != nil {
		// Note: neither backend exposes direct zeroization of its key, so we only clear
		// our reference. GenerateMLKEMKeyPair wipes its own seed buffer, but the key object
		// keeps a copy until it is collected. In production, consider OS-level memory
		// protection.
		kp.DecapsulationKey = nil
	}
	kp.EncapsulationKey = nil
}
