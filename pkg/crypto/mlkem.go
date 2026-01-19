// mlkem.go implements ML-KEM-1024 key encapsulation mechanism wrapper.
//
// ML-KEM (Module-Lattice-based Key-Encapsulation Mechanism) is standardized in
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
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// MLKEMPublicKey wraps an ML-KEM-1024 public key
type MLKEMPublicKey struct {
	key *mlkem1024.PublicKey
}

// MLKEMPrivateKey wraps an ML-KEM-1024 private key
type MLKEMPrivateKey struct {
	key *mlkem1024.PrivateKey
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
// The key generation process:
// 1. Sample random seed d ← {0,1}^256
// 2. Sample random seed z ← {0,1}^256
// 3. Expand matrix A from seed using SHAKE-128
// 4. Sample secret vector s and error vector e from CBD(η₁)
// 5. Compute public key pk = (A, As + e)
// 6. Compute private key sk = (s, pk, H(pk), z)
//
// Returns error if the system's CSPRNG fails.
func GenerateMLKEMKeyPair() (*MLKEMKeyPair, error) {
	pk, sk, err := mlkem1024.GenerateKeyPair(Reader)
	if err != nil {
		return nil, qerrors.NewCryptoError("MLKEMKeyPair.Generate", err)
	}

	return &MLKEMKeyPair{
		EncapsulationKey: &MLKEMPublicKey{key: pk},
		DecapsulationKey: &MLKEMPrivateKey{key: sk},
	}, nil
}

// NewMLKEMKeyPairFromSeed generates an ML-KEM-1024 key pair from a 64-byte seed.
// This is deterministic: the same seed will always produce the same key pair.
//
// The seed should be generated from a cryptographically secure source.
// This function is useful for key derivation from a master secret.
func NewMLKEMKeyPairFromSeed(seed []byte) (*MLKEMKeyPair, error) {
	if len(seed) != 64 {
		return nil, qerrors.ErrInvalidKeySize
	}

	// Use the seed as deterministic randomness source
	pk, sk, err := mlkem1024.GenerateKeyPair(&deterministicReader{data: seed})
	if err != nil {
		return nil, qerrors.NewCryptoError("MLKEMKeyPair.FromSeed", err)
	}

	return &MLKEMKeyPair{
		EncapsulationKey: &MLKEMPublicKey{key: pk},
		DecapsulationKey: &MLKEMPrivateKey{key: sk},
	}, nil
}

// deterministicReader provides deterministic "randomness" from a seed
type deterministicReader struct {
	data   []byte
	offset int
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
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

	ct := make([]byte, mlkem1024.CiphertextSize)
	ss := make([]byte, mlkem1024.SharedKeySize)

	// Generate random seed for encapsulation
	seed := make([]byte, mlkem1024.EncapsulationSeedSize)
	if err := SecureRandom(seed); err != nil {
		return nil, nil, qerrors.NewCryptoError("MLKEMEncapsulate", err)
	}

	ek.key.EncapsulateTo(ct, ss, seed)

	return ct, ss, nil
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

	ss := make([]byte, mlkem1024.SharedKeySize)
	dk.key.DecapsulateTo(ss, ciphertext)

	return ss, nil
}

// Bytes returns the encoded bytes of the public key.
func (pk *MLKEMPublicKey) Bytes() []byte {
	if pk == nil || pk.key == nil {
		return nil
	}
	buf := make([]byte, mlkem1024.PublicKeySize)
	pk.key.Pack(buf)
	return buf
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

	pk := new(mlkem1024.PublicKey)
	if err := pk.Unpack(data); err != nil {
		return nil, qerrors.NewCryptoError("ParseMLKEMPublicKey", err)
	}

	return &MLKEMPublicKey{key: pk}, nil
}

// Zeroize securely erases the private key material.
// This should be called when the key pair is no longer needed.
func (kp *MLKEMKeyPair) Zeroize() {
	if kp.DecapsulationKey != nil {
		// Note: CIRCL doesn't expose direct zeroization,
		// so we clear our reference. In production, consider OS-level
		// memory protection.
		kp.DecapsulationKey = nil
	}
	kp.EncapsulationKey = nil
}
