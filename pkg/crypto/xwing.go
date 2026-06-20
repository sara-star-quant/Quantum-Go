// Package crypto - xwing.go wraps the standardized X-Wing KEM (ML-KEM-768 + X25519
// with a fixed SHA3-256 combiner) from draft-connolly-cfrg-xwing-kem. It delegates
// to cloudflare/circl's certified implementation, so the wire output is byte-exact
// with any other X-Wing implementation; this package never re-implements the
// combiner. The private key is the 32-byte derivation seed (circl PrivateKeySize).
package crypto

import (
	"github.com/cloudflare/circl/kem/xwing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// XWingKeyPair is an X-Wing key pair: the 32-byte private seed and the 1216-byte
// packed public key.
type XWingKeyPair struct {
	privateSeed []byte
	publicKey   []byte
}

// GenerateXWingKeyPair generates a fresh X-Wing key pair from system randomness.
func GenerateXWingKeyPair() (*XWingKeyPair, error) {
	seed := make([]byte, xwing.SeedSize)
	if err := SecureRandom(seed); err != nil {
		return nil, qerrors.NewCryptoError("XWing.Generate", err)
	}
	return NewXWingKeyPairFromSeed(seed)
}

// NewXWingKeyPairFromSeed deterministically derives an X-Wing key pair from a
// 32-byte seed. The same seed always yields the same key pair and public pin.
func NewXWingKeyPairFromSeed(seed []byte) (*XWingKeyPair, error) {
	if len(seed) != xwing.SeedSize {
		return nil, qerrors.ErrInvalidKeySize
	}
	sk, pk := xwing.DeriveKeyPairPacked(seed)
	return &XWingKeyPair{privateSeed: sk, publicKey: pk}, nil
}

// PublicKeyBytes returns the packed public key.
func (kp *XWingKeyPair) PublicKeyBytes() []byte {
	out := make([]byte, len(kp.publicKey))
	copy(out, kp.publicKey)
	return out
}

// SeedBytes returns the 32-byte private seed (the X-Wing private key).
func (kp *XWingKeyPair) SeedBytes() []byte {
	out := make([]byte, len(kp.privateSeed))
	copy(out, kp.privateSeed)
	return out
}

// Zeroize erases the private seed.
func (kp *XWingKeyPair) Zeroize() {
	Zeroize(kp.privateSeed)
	kp.privateSeed = nil
	kp.publicKey = nil
}

// XWingEncapsulate encapsulates to a packed X-Wing public key, returning the
// ciphertext and the 32-byte shared secret. It samples its own encapsulation
// randomness.
func XWingEncapsulate(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != constants.XWingPublicKeySize {
		return nil, nil, qerrors.ErrInvalidPublicKey
	}
	seed := make([]byte, xwing.EncapsulationSeedSize)
	if err := SecureRandom(seed); err != nil {
		return nil, nil, qerrors.NewCryptoError("XWing.Encapsulate", err)
	}
	return XWingEncapsulateWithSeed(publicKey, seed)
}

// XWingEncapsulateWithSeed is the seed-injected core of XWingEncapsulate: it takes
// caller-supplied encapsulation randomness (EncapsulationSeedSize bytes) and is
// deterministic in (publicKey, seed), which conformance known-answer vectors rely on.
// Production code calls XWingEncapsulate, which samples the seed from the CSPRNG.
func XWingEncapsulateWithSeed(publicKey, seed []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(seed) != xwing.EncapsulationSeedSize {
		return nil, nil, qerrors.ErrInvalidKeySize
	}
	ss, ct, err := xwing.Encapsulate(publicKey, seed)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("XWing.Encapsulate", err)
	}
	return ct, ss, nil
}

// XWingDecapsulate recovers the 32-byte shared secret from a ciphertext using the
// 32-byte private seed.
func XWingDecapsulate(privateSeed, ciphertext []byte) ([]byte, error) {
	if len(privateSeed) != constants.XWingSeedSize {
		return nil, qerrors.ErrInvalidPrivateKey
	}
	if len(ciphertext) != constants.XWingCiphertextSize {
		return nil, qerrors.ErrInvalidCiphertext
	}
	return xwing.Decapsulate(ciphertext, privateSeed), nil
}

// ParseXWingPublicKey validates and copies a packed X-Wing public key.
func ParseXWingPublicKey(data []byte) ([]byte, error) {
	if len(data) != constants.XWingPublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}
