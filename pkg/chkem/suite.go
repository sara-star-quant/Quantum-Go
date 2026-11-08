package chkem

import (
	"sync"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// SuiteID is the 2-byte wire identifier of a KEM suite. It is negotiated in the
// handshake so peers can agree on the KEM construction (the cascade, the combiner)
// the way they already agree on an AEAD cipher suite.
type SuiteID uint16

const (
	// SuiteCHKEMv1 is the original Cascaded Hybrid KEM: ML-KEM-1024 + X25519 with a
	// SHAKE-256 combiner. It is the default and mandatory-to-implement suite.
	SuiteCHKEMv1 SuiteID = 0x0001
)

// Suite is a pluggable KEM construction. Every suite derives a 32-byte shared
// secret (constants.CHKEMSharedSecretSize), so all downstream KDF and handshake
// code is suite-independent; only the public-key/ciphertext sizes and the internal
// construction differ. The methods mirror the package-level CH-KEM functions so a
// caller can hold a Suite instead of calling the fixed construction directly.
type Suite interface {
	// ID returns the suite's wire identifier.
	ID() SuiteID
	// GenerateKeyPair generates a fresh ephemeral key pair.
	GenerateKeyPair() (*KeyPair, error)
	// GenerateStaticKeyPair generates a long-term identity key pair and its seed.
	GenerateStaticKeyPair() (*KeyPair, []byte, error)
	// ParseKeyPair reconstructs a key pair from a SeedSize-byte seed.
	ParseKeyPair(seed []byte) (*KeyPair, error)
	// Encapsulate produces a ciphertext and a 32-byte shared secret for the recipient.
	Encapsulate(recipient *PublicKey, role Role) (*Ciphertext, []byte, error)
	// Decapsulate recovers the 32-byte shared secret from a ciphertext.
	Decapsulate(ct *Ciphertext, kp *KeyPair, role Role) ([]byte, error)
	// ParsePublicKey parses a PublicKeySize-byte public key.
	ParsePublicKey(data []byte) (*PublicKey, error)
	// ParseCiphertext parses a CiphertextSize-byte ciphertext.
	ParseCiphertext(data []byte) (*Ciphertext, error)
	// PublicKeySize is the serialized public-key length in bytes.
	PublicKeySize() int
	// CiphertextSize is the serialized ciphertext length in bytes.
	CiphertextSize() int
	// SeedSize is the static-identity seed length in bytes.
	SeedSize() int
	// IsFIPSApproved reports whether the suite is allowed in FIPS mode.
	IsFIPSApproved() bool
}

// chkemV1 adapts the original CH-KEM construction (the package-level functions) to
// the Suite interface. It delegates verbatim, so its output is byte-for-byte the
// pre-suite CH-KEM.
type chkemV1 struct{}

func (chkemV1) ID() SuiteID { return SuiteCHKEMv1 }

func (chkemV1) GenerateKeyPair() (*KeyPair, error) { return GenerateKeyPair() }

func (chkemV1) GenerateStaticKeyPair() (*KeyPair, []byte, error) { return GenerateStaticKeyPair() }

func (chkemV1) ParseKeyPair(seed []byte) (*KeyPair, error) { return ParseKeyPair(seed) }

func (chkemV1) Encapsulate(recipient *PublicKey, role Role) (*Ciphertext, []byte, error) {
	return Encapsulate(recipient, role)
}

func (chkemV1) Decapsulate(ct *Ciphertext, kp *KeyPair, role Role) ([]byte, error) {
	return Decapsulate(ct, kp, role)
}

func (chkemV1) ParsePublicKey(data []byte) (*PublicKey, error) { return ParsePublicKey(data) }

func (chkemV1) ParseCiphertext(data []byte) (*Ciphertext, error) { return ParseCiphertext(data) }

func (chkemV1) PublicKeySize() int { return constants.CHKEMPublicKeySize }

func (chkemV1) CiphertextSize() int { return constants.CHKEMCiphertextSize }

func (chkemV1) SeedSize() int { return StaticKeySeedSize }

// IsFIPSApproved preserves the pre-suite FIPS behavior: the FIPS build handshakes
// with CH-KEM-v1 today (it has no KEM-level FIPS gate), so v1 stays allowed. The
// hybrid uses X25519, so this is the project's operational posture, not a strict
// FIPS 140-3 algorithm claim.
func (chkemV1) IsFIPSApproved() bool { return true }

// registry maps a SuiteID to its implementation. Built-ins are fixed; RegisterSuite
// adds external suites under registryMu.
var (
	registryMu sync.RWMutex
	registry   = map[SuiteID]Suite{
		SuiteCHKEMv1: chkemV1{},
		SuiteXWing:   xwingSuite{},
	}
	// order lists suite ids in preference order: built-ins first, then registered.
	order = []SuiteID{SuiteCHKEMv1, SuiteXWing}
)

// builtinSuites is how many leading entries of order are built in.
const builtinSuites = 2

// DefaultSuite returns the default KEM suite (CH-KEM-v1). It is the suite used when
// no negotiation has selected another.
func DefaultSuite() Suite { return chkemV1{} }

// GetSuite returns the registered suite for id, or false if unknown.
func GetSuite(id SuiteID) (Suite, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[id]
	return s, ok
}

// SupportedSuites returns the offerable suite ids in preference order (most
// preferred first): built-ins, then registered suites in registration order. In FIPS
// mode, suites that are not FIPS approved are dropped. CH-KEM-v1 is always present
// and first, so any two peers share it. The returned slice is a copy.
func SupportedSuites() []SuiteID {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]SuiteID, 0, len(order))
	for _, id := range order {
		if crypto.FIPSMode() && !registry[id].IsFIPSApproved() {
			continue
		}
		out = append(out, id)
	}
	return out
}

// BindsRole reports that CH-KEM-v1 binds the caller role into the secret, so the
// conformance battery checks reflection resistance for it.
func (chkemV1) BindsRole() bool { return true }
