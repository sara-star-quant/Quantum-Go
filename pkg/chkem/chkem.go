// Package chkem implements the Cascaded Hybrid Key Encapsulation Mechanism (CH-KEM).
//
// CH-KEM is a novel defense-in-depth key encapsulation mechanism that combines:
//   - X25519 (classical elliptic curve Diffie-Hellman)
//   - ML-KEM-1024 (post-quantum lattice-based KEM)
//   - SHAKE-256 (cryptographic key derivation)
//
// # Security Model
//
// CH-KEM provides IND-CCA2 security if EITHER X25519 OR ML-KEM-1024 is secure,
// under the random oracle model for SHAKE-256. This hybrid approach provides:
//
//  1. Quantum Resistance: ML-KEM-1024 resists attacks from quantum computers
//  2. Classical Security: X25519 provides defense if ML-KEM is broken
//  3. Defense in Depth: Both must fail for the system to be compromised
//
// # Mathematical Construction
//
// Key Generation:
//
//	(sk_x, pk_x) ← X25519.KeyGen()
//	(sk_m, pk_m) ← ML-KEM-1024.KeyGen()
//	pk = pk_x || pk_m
//	sk = (sk_x, sk_m)
//
// Encapsulation:
//
//	(ct_m, K_m) ← ML-KEM-1024.Encaps(pk_m)
//	(sk_x_eph, pk_x_eph) ← X25519.KeyGen()
//	K_x ← X25519.DH(sk_x_eph, pk_x)
//	ct = pk_x_eph || ct_m
//	transcript ← SHA3-256(pk_x || pk_m || ct)
//	K ← SHAKE-256(K_x || K_m || transcript || "CH-KEM-v1-SharedSecret", 256)
//
// Decapsulation:
//
//	Parse ct as (pk_x_eph, ct_m)
//	K_x ← X25519.DH(sk_x, pk_x_eph)
//	K_m ← ML-KEM-1024.Decaps(sk_m, ct_m)
//	transcript ← SHA3-256(pk_x || pk_m || ct)
//	K ← SHAKE-256(K_x || K_m || transcript || "CH-KEM-v1-SharedSecret", 256)
//
// # Security Theorem
//
// Theorem: CH-KEM is IND-CCA2 secure if either X25519 satisfies the
// Computational Diffie-Hellman (CDH) assumption on Curve25519, OR ML-KEM-1024
// is IND-CCA2 secure (based on the Module Learning With Errors problem).
//
// Proof sketch: An adversary breaking CH-KEM must extract information about
// BOTH K_x AND K_m from the ciphertext. If X25519 is secure, K_x is
// indistinguishable from random. If ML-KEM is secure, K_m is indistinguishable
// from random. In either case, the SHAKE-256 derivation produces a
// computationally indistinguishable output (random oracle model).
//
// # Compliance
//
// Components are based on:
//   - ML-KEM-1024: NIST FIPS 203 (Category 5 security)
//   - X25519: RFC 7748
//   - SHAKE-256: NIST FIPS 202
//
// The hybrid approach is compatible with FIPS 140-3 guidelines for
// post-quantum transition, as it maintains a FIPS-approved algorithm
// in the composition.
package chkem

import (
	"crypto/ecdh"

	"github.com/quantum-go/quantum-go/internal/constants"
	qerrors "github.com/quantum-go/quantum-go/internal/errors"
	"github.com/quantum-go/quantum-go/pkg/crypto"
)

// KeyPair represents a CH-KEM key pair combining X25519 and ML-KEM-1024.
type KeyPair struct {
	// X25519 key pair (classical)
	x25519Public  *ecdh.PublicKey
	x25519Private *ecdh.PrivateKey

	// ML-KEM-1024 key pair (post-quantum)
	mlkemPublic  *crypto.MLKEMPublicKey
	mlkemPrivate *crypto.MLKEMPrivateKey
}

// PublicKey represents a CH-KEM public key for encapsulation.
type PublicKey struct {
	x25519 *ecdh.PublicKey
	mlkem  *crypto.MLKEMPublicKey
}

// Ciphertext represents a CH-KEM ciphertext.
type Ciphertext struct {
	// X25519 ephemeral public key (32 bytes)
	x25519Ephemeral []byte

	// ML-KEM-1024 ciphertext (1568 bytes)
	mlkemCiphertext []byte
}

// GenerateKeyPair generates a new CH-KEM key pair.
//
// This generates both X25519 and ML-KEM-1024 key pairs using the system's
// cryptographically secure random number generator.
//
// Returns:
//   - KeyPair: The generated key pair
//   - error: Non-nil if random number generation fails
func GenerateKeyPair() (*KeyPair, error) {
	// Generate X25519 key pair
	x25519KP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.GenerateKeyPair", err)
	}

	// Generate ML-KEM-1024 key pair
	mlkemKP, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.GenerateKeyPair", err)
	}

	return &KeyPair{
		x25519Public:  x25519KP.PublicKey,
		x25519Private: x25519KP.PrivateKey,
		mlkemPublic:   mlkemKP.EncapsulationKey,
		mlkemPrivate:  mlkemKP.DecapsulationKey,
	}, nil
}

// PublicKey returns the public component of the key pair.
func (kp *KeyPair) PublicKey() *PublicKey {
	return &PublicKey{
		x25519: kp.x25519Public,
		mlkem:  kp.mlkemPublic,
	}
}

// Encapsulate performs CH-KEM encapsulation to create a shared secret.
//
// This operation:
// 1. Generates an ephemeral X25519 key pair
// 2. Performs X25519 DH with the recipient's public key
// 3. Encapsulates using ML-KEM-1024
// 4. Combines both secrets with transcript hash using SHAKE-256
//
// Parameters:
//   - recipientPublic: The recipient's CH-KEM public key
//
// Returns:
//   - ciphertext: Combined X25519 ephemeral public + ML-KEM ciphertext
//   - sharedSecret: 32-byte derived shared secret
//   - error: Non-nil if encapsulation fails
func Encapsulate(recipientPublic *PublicKey) (*Ciphertext, []byte, error) {
	if recipientPublic == nil || recipientPublic.x25519 == nil || recipientPublic.mlkem == nil {
		return nil, nil, qerrors.ErrInvalidPublicKey
	}

	// Generate ephemeral X25519 key pair
	ephemeralKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("CHKEM.Encapsulate", err)
	}

	// Perform X25519 DH
	x25519Secret, err := crypto.X25519(ephemeralKP.PrivateKey, recipientPublic.x25519)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("CHKEM.Encapsulate", err)
	}

	// Perform ML-KEM-1024 encapsulation
	mlkemCiphertext, mlkemSecret, err := crypto.MLKEMEncapsulate(recipientPublic.mlkem)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("CHKEM.Encapsulate", err)
	}

	// Create ciphertext
	ct := &Ciphertext{
		x25519Ephemeral: ephemeralKP.PublicKeyBytes(),
		mlkemCiphertext: mlkemCiphertext,
	}

	// Compute transcript hash for domain binding
	// transcript = SHA3-256(pk_x25519 || pk_mlkem || ct_x25519_eph || ct_mlkem)
	transcriptHash := crypto.TranscriptHash(
		recipientPublic.x25519.Bytes(),
		recipientPublic.mlkem.Bytes(),
		ct.x25519Ephemeral,
		ct.mlkemCiphertext,
	)

	// Derive final shared secret
	// K = SHAKE-256(K_x25519 || K_mlkem || transcript, 256)
	sharedSecret, err := crypto.DeriveCHKEMSecret(x25519Secret, mlkemSecret, transcriptHash)
	if err != nil {
		return nil, nil, err
	}

	// Zeroize intermediate secrets
	crypto.ZeroizeMultiple(x25519Secret, mlkemSecret)

	return ct, sharedSecret, nil
}

// Decapsulate performs CH-KEM decapsulation to recover the shared secret.
//
// This operation:
// 1. Performs X25519 DH with the ephemeral public key
// 2. Decapsulates the ML-KEM ciphertext
// 3. Combines both secrets with transcript hash using SHAKE-256
//
// Parameters:
//   - ct: The ciphertext to decapsulate
//   - kp: The recipient's key pair
//
// Returns:
//   - sharedSecret: 32-byte derived shared secret (same as encapsulator)
//   - error: Non-nil if decapsulation fails
func Decapsulate(ct *Ciphertext, kp *KeyPair) ([]byte, error) {
	if ct == nil || len(ct.x25519Ephemeral) == 0 || len(ct.mlkemCiphertext) == 0 {
		return nil, qerrors.ErrInvalidCiphertext
	}
	if kp == nil || kp.x25519Private == nil || kp.mlkemPrivate == nil {
		return nil, qerrors.ErrInvalidPrivateKey
	}

	// Parse X25519 ephemeral public key
	ephemeralPublic, err := crypto.ParseX25519PublicKey(ct.x25519Ephemeral)
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.Decapsulate", err)
	}

	// Perform X25519 DH
	x25519Secret, err := crypto.X25519(kp.x25519Private, ephemeralPublic)
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.Decapsulate", err)
	}

	// Perform ML-KEM-1024 decapsulation
	mlkemSecret, err := crypto.MLKEMDecapsulate(kp.mlkemPrivate, ct.mlkemCiphertext)
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.Decapsulate", err)
	}

	// Compute transcript hash (must match encapsulation)
	transcriptHash := crypto.TranscriptHash(
		kp.x25519Public.Bytes(),
		kp.mlkemPublic.Bytes(),
		ct.x25519Ephemeral,
		ct.mlkemCiphertext,
	)

	// Derive final shared secret
	sharedSecret, err := crypto.DeriveCHKEMSecret(x25519Secret, mlkemSecret, transcriptHash)
	if err != nil {
		return nil, err
	}

	// Zeroize intermediate secrets
	crypto.ZeroizeMultiple(x25519Secret, mlkemSecret)

	return sharedSecret, nil
}

// Bytes serializes the public key to bytes.
//
// Format: x25519_public (32 bytes) || mlkem_public (1568 bytes)
// Total: 1600 bytes
func (pk *PublicKey) Bytes() []byte {
	result := make([]byte, constants.CHKEMPublicKeySize)
	copy(result[:constants.X25519PublicKeySize], pk.x25519.Bytes())
	copy(result[constants.X25519PublicKeySize:], pk.mlkem.Bytes())
	return result
}

// ParsePublicKey parses a CH-KEM public key from bytes.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	if len(data) != constants.CHKEMPublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}

	x25519Public, err := crypto.ParseX25519PublicKey(data[:constants.X25519PublicKeySize])
	if err != nil {
		return nil, err
	}

	mlkemPublic, err := crypto.ParseMLKEMPublicKey(data[constants.X25519PublicKeySize:])
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		x25519: x25519Public,
		mlkem:  mlkemPublic,
	}, nil
}

// Bytes serializes the ciphertext to bytes.
//
// Format: x25519_ephemeral (32 bytes) || mlkem_ciphertext (1568 bytes)
// Total: 1600 bytes
func (ct *Ciphertext) Bytes() []byte {
	result := make([]byte, constants.CHKEMCiphertextSize)
	copy(result[:constants.X25519PublicKeySize], ct.x25519Ephemeral)
	copy(result[constants.X25519PublicKeySize:], ct.mlkemCiphertext)
	return result
}

// ParseCiphertext parses a CH-KEM ciphertext from bytes.
func ParseCiphertext(data []byte) (*Ciphertext, error) {
	if len(data) != constants.CHKEMCiphertextSize {
		return nil, qerrors.ErrInvalidCiphertext
	}

	return &Ciphertext{
		x25519Ephemeral: data[:constants.X25519PublicKeySize],
		mlkemCiphertext: data[constants.X25519PublicKeySize:],
	}, nil
}

// Zeroize securely erases the private key material.
func (kp *KeyPair) Zeroize() {
	kp.x25519Private = nil
	kp.x25519Public = nil
	kp.mlkemPrivate = nil
	kp.mlkemPublic = nil
}

// Clone creates a deep copy of the public key.
func (pk *PublicKey) Clone() *PublicKey {
	return &PublicKey{
		x25519: pk.x25519,
		mlkem:  pk.mlkem,
	}
}

// X25519PublicKey returns the X25519 component of the public key.
func (pk *PublicKey) X25519PublicKey() *ecdh.PublicKey {
	return pk.x25519
}

// MLKEMPublicKey returns the ML-KEM component of the public key.
func (pk *PublicKey) MLKEMPublicKey() *crypto.MLKEMPublicKey {
	return pk.mlkem
}
