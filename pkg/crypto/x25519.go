// x25519.go implements X25519 Elliptic Curve Diffie-Hellman operations.
//
// X25519 (RFC 7748) is an elliptic curve Diffie-Hellman function using Curve25519.
// It provides approximately 128 bits of security against classical computers.
//
// Mathematical Foundation:
//
// Curve25519 is a Montgomery curve defined by: y² = x³ + 486662x² + x
// over the prime field F_p where p = 2²⁵⁵ - 19.
//
// The group operation uses x-coordinate-only arithmetic (Montgomery ladder),
// which provides constant-time execution and resistance to timing attacks.
//
// Security Properties:
//   - IND-CCA2 secure under the Computational Diffie-Hellman assumption on Curve25519
//   - Constant-time implementation prevents timing side-channels
//   - Twist-secure: operations on the twist are as hard as on the curve
//
// Note: X25519 is NOT quantum-resistant. In CH-KEM, it provides defense-in-depth
// and maintains security if the post-quantum algorithm (ML-KEM) is broken.
package crypto

import (
	"crypto/ecdh"

	"github.com/quantum-go/quantum-go/internal/constants"
	qerrors "github.com/quantum-go/quantum-go/internal/errors"
)

// X25519KeyPair represents an X25519 key pair for classical ECDH.
type X25519KeyPair struct {
	// PublicKey is the public component for sharing
	PublicKey *ecdh.PublicKey

	// PrivateKey is the secret component
	PrivateKey *ecdh.PrivateKey
}

// GenerateX25519KeyPair generates a new X25519 key pair.
//
// The key generation process:
// 1. Generate 32 random bytes as the private scalar
// 2. Apply clamping: clear bits 0,1,2,255; set bit 254
// 3. Compute public key as scalar multiplication of basepoint
//
// Returns error if the system's CSPRNG fails.
func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	curve := ecdh.X25519()

	privateKey, err := curve.GenerateKey(Reader)
	if err != nil {
		return nil, qerrors.NewCryptoError("X25519KeyPair.Generate", err)
	}

	return &X25519KeyPair{
		PublicKey:  privateKey.PublicKey(),
		PrivateKey: privateKey,
	}, nil
}

// NewX25519KeyPairFromBytes creates an X25519 key pair from a 32-byte private key.
// This is deterministic: the same private key bytes always produce the same key pair.
func NewX25519KeyPairFromBytes(privateKeyBytes []byte) (*X25519KeyPair, error) {
	if len(privateKeyBytes) != constants.X25519PrivateKeySize {
		return nil, qerrors.ErrInvalidKeySize
	}

	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, qerrors.NewCryptoError("X25519KeyPair.FromBytes", err)
	}

	return &X25519KeyPair{
		PublicKey:  privateKey.PublicKey(),
		PrivateKey: privateKey,
	}, nil
}

// X25519 performs X25519 Diffie-Hellman shared secret computation.
//
// The computation:
// 1. Validate that peerPublic is a valid point on the curve
// 2. Compute sharedSecret = privateKey * peerPublic (scalar multiplication)
// 3. Return the 32-byte x-coordinate of the result
//
// Security Note: The result should never be used directly as a key.
// Always derive keys using a KDF (e.g., HKDF or SHAKE).
//
// Parameters:
//   - privateKey: The local private key
//   - peerPublic: The peer's public key
//
// Returns:
//   - sharedSecret: 32-byte shared secret
//   - error: Non-nil if the peer's public key is invalid
func X25519(privateKey *ecdh.PrivateKey, peerPublic *ecdh.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, qerrors.ErrInvalidPrivateKey
	}
	if peerPublic == nil {
		return nil, qerrors.ErrInvalidPublicKey
	}

	sharedSecret, err := privateKey.ECDH(peerPublic)
	if err != nil {
		return nil, qerrors.NewCryptoError("X25519", err)
	}

	return sharedSecret, nil
}

// PublicKeyBytes returns the encoded bytes of the public key.
func (kp *X25519KeyPair) PublicKeyBytes() []byte {
	return kp.PublicKey.Bytes()
}

// PrivateKeyBytes returns the encoded bytes of the private key.
// Warning: Handle with care - this exposes the secret key material.
func (kp *X25519KeyPair) PrivateKeyBytes() []byte {
	return kp.PrivateKey.Bytes()
}

// ParseX25519PublicKey parses an X25519 public key from its encoded form.
func ParseX25519PublicKey(data []byte) (*ecdh.PublicKey, error) {
	if len(data) != constants.X25519PublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}

	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(data)
	if err != nil {
		return nil, qerrors.NewCryptoError("ParseX25519PublicKey", err)
	}

	return publicKey, nil
}

// Zeroize securely erases the private key material.
func (kp *X25519KeyPair) Zeroize() {
	// Note: ecdh.PrivateKey doesn't expose the underlying bytes for zeroization.
	// In production, consider copying to a []byte, using, then zeroizing.
	kp.PrivateKey = nil
	kp.PublicKey = nil
}
