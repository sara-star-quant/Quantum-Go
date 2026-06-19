package chkem

import (
	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// SuiteXWing is the standardized X-Wing KEM (ML-KEM-768 + X25519 with a fixed
// SHA3-256 combiner, draft-connolly-cfrg-xwing-kem). It is the interop-friendly
// alternative to CH-KEM-v1: smaller key share, byte-exact with any X-Wing peer.
const SuiteXWing SuiteID = 0x0002

// xwingSuite adapts the X-Wing crypto wrapper to the Suite interface. It stores the
// live key handle in KeyPair.impl and the serialized public key/ciphertext in the
// raw field of PublicKey/Ciphertext.
type xwingSuite struct{}

func (xwingSuite) ID() SuiteID { return SuiteXWing }

func (xwingSuite) GenerateKeyPair() (*KeyPair, error) {
	kp, err := crypto.GenerateXWingKeyPair()
	if err != nil {
		return nil, err
	}
	return &KeyPair{suite: SuiteXWing, impl: kp}, nil
}

func (xwingSuite) GenerateStaticKeyPair() (*KeyPair, []byte, error) {
	seed, err := crypto.SecureRandomBytes(constants.XWingSeedSize)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("XWing.GenerateStaticKeyPair", err)
	}
	kp, err := crypto.NewXWingKeyPairFromSeed(seed)
	if err != nil {
		crypto.Zeroize(seed)
		return nil, nil, err
	}
	return &KeyPair{suite: SuiteXWing, impl: kp}, seed, nil
}

func (xwingSuite) ParseKeyPair(seed []byte) (*KeyPair, error) {
	kp, err := crypto.NewXWingKeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return &KeyPair{suite: SuiteXWing, impl: kp}, nil
}

// Encapsulate ignores role: X-Wing's combiner is spec-fixed, so it cannot bind the
// role the way CH-KEM-v1 does. Role, version, and suite downgrade protection come
// from the handshake transcript / Finished MAC instead.
func (xwingSuite) Encapsulate(recipient *PublicKey, _ Role) (*Ciphertext, []byte, error) {
	if recipient == nil || recipient.suite != SuiteXWing {
		return nil, nil, qerrors.ErrInvalidPublicKey
	}
	ct, ss, err := crypto.XWingEncapsulate(recipient.raw)
	if err != nil {
		return nil, nil, err
	}
	return &Ciphertext{suite: SuiteXWing, raw: ct}, ss, nil
}

func (xwingSuite) Decapsulate(ct *Ciphertext, kp *KeyPair, _ Role) ([]byte, error) {
	if ct == nil || ct.suite != SuiteXWing {
		return nil, qerrors.ErrInvalidCiphertext
	}
	if kp == nil {
		return nil, qerrors.ErrInvalidPrivateKey
	}
	xkp, ok := kp.impl.(*crypto.XWingKeyPair)
	if !ok {
		return nil, qerrors.ErrInvalidPrivateKey
	}
	seed := xkp.SeedBytes()
	defer crypto.Zeroize(seed)
	return crypto.XWingDecapsulate(seed, ct.raw)
}

func (xwingSuite) ParsePublicKey(data []byte) (*PublicKey, error) {
	raw, err := crypto.ParseXWingPublicKey(data)
	if err != nil {
		return nil, err
	}
	return &PublicKey{suite: SuiteXWing, raw: raw}, nil
}

func (xwingSuite) ParseCiphertext(data []byte) (*Ciphertext, error) {
	if len(data) != constants.XWingCiphertextSize {
		return nil, qerrors.ErrInvalidCiphertext
	}
	return &Ciphertext{suite: SuiteXWing, raw: cloneBytes(data)}, nil
}

func (xwingSuite) PublicKeySize() int { return constants.XWingPublicKeySize }

func (xwingSuite) CiphertextSize() int { return constants.XWingCiphertextSize }

func (xwingSuite) SeedSize() int { return constants.XWingSeedSize }

// IsFIPSApproved follows v1's operational posture: the hybrid uses X25519, so this
// is not a strict FIPS 140-3 algorithm claim. X-Wing is NIST Category 3 (ML-KEM-768)
// versus v1's Category 5 (ML-KEM-1024); both stay allowed in the FIPS build.
func (xwingSuite) IsFIPSApproved() bool { return true }
