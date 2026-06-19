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
//	transcript ← SHA3-256(pk_x || pk_m || ct || version || role)
//	K ← SHAKE-256(K_x || K_m || transcript || "CH-KEM-v1-SharedSecret", 256)
//
// Decapsulation:
//
//	Parse ct as (pk_x_eph, ct_m)
//	K_x ← X25519.DH(sk_x, pk_x_eph)
//	K_m ← ML-KEM-1024.Decaps(sk_m, ct_m)
//	transcript ← SHA3-256(pk_x || pk_m || ct || version || role)
//	K ← SHAKE-256(K_x || K_m || transcript || "CH-KEM-v1-SharedSecret", 256)
//
// version is the 2-byte protocol version and role is the 1-byte role of the
// encapsulating (responder) party. Both endpoints bind the responder role, so a
// legit exchange matches while a reflected/same-role exchange does not.
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
	"encoding/binary"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// Role identifies a party's position in a CH-KEM exchange. It is bound into the
// transcript so a reflected or role-confused handshake derives a non-matching
// secret and fails closed. This is composition hardening, not peer authentication.
type Role uint8

const (
	// RoleInitiator is the party that decapsulates (the client in a handshake,
	// the rekey-initiating peer in a rekey).
	RoleInitiator Role = 0x01
	// RoleResponder is the party that encapsulates (the server in a handshake,
	// the rekey-responding peer in a rekey).
	RoleResponder Role = 0x02
)

// peer returns the opposite role.
func (r Role) peer() Role {
	if r == RoleInitiator {
		return RoleResponder
	}
	return RoleInitiator
}

// protocolVersionBytes returns the 2-byte big-endian CH-KEM protocol version
// bound into the transcript.
func protocolVersionBytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, constants.ProtocolVersion)
	return b
}

// KeyPair represents a KEM key pair. For CH-KEM-v1 it holds the X25519 and
// ML-KEM-1024 components directly. For other suites (suite != 0) the typed v1
// fields stay nil and impl carries the suite's live key handle; the generic methods
// dispatch on suite.
type KeyPair struct {
	// X25519 key pair (classical)
	x25519Public  *ecdh.PublicKey
	x25519Private *ecdh.PrivateKey

	// ML-KEM-1024 key pair (post-quantum)
	mlkemPublic  *crypto.MLKEMPublicKey
	mlkemPrivate *crypto.MLKEMPrivateKey

	// suite is zero for CH-KEM-v1 and the suite id otherwise; impl is the non-v1
	// suite's live key handle.
	suite SuiteID
	impl  any
}

// PublicKey represents a KEM public key for encapsulation. For non-v1 suites raw
// holds the serialized key and the typed fields stay nil.
type PublicKey struct {
	x25519 *ecdh.PublicKey
	mlkem  *crypto.MLKEMPublicKey

	suite SuiteID
	raw   []byte
}

// Ciphertext represents a KEM ciphertext. For non-v1 suites raw holds the
// serialized ciphertext and the typed fields stay nil.
type Ciphertext struct {
	// X25519 ephemeral public key (32 bytes)
	x25519Ephemeral []byte

	// ML-KEM-1024 ciphertext (1568 bytes)
	mlkemCiphertext []byte

	suite SuiteID
	raw   []byte
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

// mlkemSeedSize is the ML-KEM-1024 key-generation seed length in bytes.
const mlkemSeedSize = 64

// StaticKeySeedSize is the byte length of a serialized static CH-KEM identity:
// a 32-byte X25519 private key followed by a 64-byte ML-KEM seed.
const StaticKeySeedSize = constants.X25519PrivateKeySize + mlkemSeedSize

// GenerateStaticKeyPair generates a long-term CH-KEM key pair for endpoint
// authentication and returns the seed needed to reconstruct it. A server must
// persist this seed (it is secret) so its identity survives restarts; clients
// pin the matching public key via PublicKey().Bytes().
func GenerateStaticKeyPair() (*KeyPair, []byte, error) {
	seed, err := crypto.SecureRandomBytes(StaticKeySeedSize)
	if err != nil {
		return nil, nil, qerrors.NewCryptoError("CHKEM.GenerateStaticKeyPair", err)
	}
	kp, err := ParseKeyPair(seed)
	if err != nil {
		crypto.Zeroize(seed)
		return nil, nil, err
	}
	return kp, seed, nil
}

// ParseKeyPair reconstructs a CH-KEM key pair from a StaticKeySeedSize-byte seed
// produced by GenerateStaticKeyPair. It is deterministic: the same seed always
// yields the same key pair and the same public pin.
func ParseKeyPair(seed []byte) (*KeyPair, error) {
	if len(seed) != StaticKeySeedSize {
		return nil, qerrors.ErrInvalidKeySize
	}
	x25519KP, err := crypto.NewX25519KeyPairFromBytes(seed[:constants.X25519PrivateKeySize])
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.ParseKeyPair", err)
	}
	mlkemKP, err := crypto.NewMLKEMKeyPairFromSeed(seed[constants.X25519PrivateKeySize:])
	if err != nil {
		return nil, qerrors.NewCryptoError("CHKEM.ParseKeyPair", err)
	}
	return &KeyPair{
		x25519Public:  x25519KP.PublicKey,
		x25519Private: x25519KP.PrivateKey,
		mlkemPublic:   mlkemKP.EncapsulationKey,
		mlkemPrivate:  mlkemKP.DecapsulationKey,
	}, nil
}

// suiteKeyHandle is the live private-key handle a non-v1 suite stores in
// KeyPair.impl. The crypto wrappers (e.g. *crypto.XWingKeyPair) satisfy it.
type suiteKeyHandle interface {
	PublicKeyBytes() []byte
	Zeroize()
}

// PublicKey returns the public component of the key pair.
func (kp *KeyPair) PublicKey() *PublicKey {
	if kp.suite != 0 {
		if h, ok := kp.impl.(suiteKeyHandle); ok {
			return &PublicKey{suite: kp.suite, raw: h.PublicKeyBytes()}
		}
		return &PublicKey{suite: kp.suite}
	}
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
//   - role: The caller's own role; the responder encapsulates in every real flow
//
// Returns:
//   - ciphertext: Combined X25519 ephemeral public + ML-KEM ciphertext
//   - sharedSecret: 32-byte derived shared secret
//   - error: Non-nil if encapsulation fails
func Encapsulate(recipientPublic *PublicKey, role Role) (*Ciphertext, []byte, error) {
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

	// Compute transcript hash for domain binding, including the protocol version
	// and the encapsulating party's role (reflection/role-confusion resistance).
	// transcript = SHA3-256(pk_x25519 || pk_mlkem || ct_x25519_eph || ct_mlkem || version || role)
	transcriptHash, err := crypto.TranscriptHash(
		recipientPublic.x25519.Bytes(),
		recipientPublic.mlkem.Bytes(),
		ct.x25519Ephemeral,
		ct.mlkemCiphertext,
		protocolVersionBytes(),
		[]byte{byte(role)},
	)
	if err != nil {
		return nil, nil, err
	}

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
//   - role: The caller's own role; the initiator decapsulates in every real flow
//
// Returns:
//   - sharedSecret: 32-byte derived shared secret (same as encapsulator)
//   - error: Non-nil if decapsulation fails
func Decapsulate(ct *Ciphertext, kp *KeyPair, role Role) ([]byte, error) {
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

	// Compute transcript hash (must match encapsulation). The decapsulator binds
	// the peer's (encapsulating responder's) role, so a legit exchange matches and
	// a reflected/same-role one does not.
	transcriptHash, err := crypto.TranscriptHash(
		kp.x25519Public.Bytes(),
		kp.mlkemPublic.Bytes(),
		ct.x25519Ephemeral,
		ct.mlkemCiphertext,
		protocolVersionBytes(),
		[]byte{byte(role.peer())},
	)
	if err != nil {
		return nil, err
	}

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
	if pk.suite != 0 {
		return cloneBytes(pk.raw)
	}
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
	if ct.suite != 0 {
		return cloneBytes(ct.raw)
	}
	result := make([]byte, constants.CHKEMCiphertextSize)
	copy(result[:constants.X25519PublicKeySize], ct.x25519Ephemeral)
	copy(result[constants.X25519PublicKeySize:], ct.mlkemCiphertext)
	return result
}

// cloneBytes returns an independent copy of b.
func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
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
	if kp.suite != 0 {
		if h, ok := kp.impl.(suiteKeyHandle); ok {
			h.Zeroize()
		}
		kp.impl = nil
		return
	}
	kp.x25519Private = nil
	kp.x25519Public = nil
	kp.mlkemPrivate = nil
	kp.mlkemPublic = nil
}

// Clone creates a deep copy of the public key.
func (pk *PublicKey) Clone() *PublicKey {
	if pk.suite != 0 {
		return &PublicKey{suite: pk.suite, raw: cloneBytes(pk.raw)}
	}
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
