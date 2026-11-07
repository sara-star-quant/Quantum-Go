package chkem

import (
	"errors"
	"fmt"
)

// CustomSuiteMin is the lowest id RegisterSuite accepts. Ids below it are reserved
// for built-in suites so an external id can never collide with a future built-in.
const CustomSuiteMin SuiteID = 0x8000

// MaxCustomSuites bounds how many external suites can be registered. Every offered
// suite adds 2 bytes to each ClientHello, and the hello encodes the count in one byte.
const MaxCustomSuites = 16

// ErrInvalidSuite is returned when a suite or suite-typed value is malformed.
var ErrInvalidSuite = errors.New("chkem: invalid suite")

// RegisterSuite adds an external KEM suite so it is offered in handshakes after the
// built-ins. The id must be >= CustomSuiteMin and unused, and the suite must report
// positive key, ciphertext and seed sizes. Registration is permanent and safe for
// concurrent use. Run suitetest.Run against the suite before registering it.
func RegisterSuite(s Suite) error {
	if s == nil {
		return fmt.Errorf("%w: nil suite", ErrInvalidSuite)
	}
	id := s.ID()
	if id < CustomSuiteMin {
		return fmt.Errorf("%w: id %#x is below %#x", ErrInvalidSuite, uint16(id), uint16(CustomSuiteMin))
	}
	if s.PublicKeySize() <= 0 || s.CiphertextSize() <= 0 || s.SeedSize() <= 0 {
		return fmt.Errorf("%w: sizes must be positive", ErrInvalidSuite)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[id]; dup {
		return fmt.Errorf("%w: id %#x already registered", ErrInvalidSuite, uint16(id))
	}
	if len(order)-builtinSuites >= MaxCustomSuites {
		return fmt.Errorf("%w: at most %d external suites", ErrInvalidSuite, MaxCustomSuites)
	}
	registry[id] = s
	order = append(order, id)
	return nil
}

// NewSuiteKeyPair wraps an external suite's live key handle as a KeyPair.
func NewSuiteKeyPair(id SuiteID, h SuiteKeyHandle) (*KeyPair, error) {
	if id == 0 || h == nil {
		return nil, fmt.Errorf("%w: key pair needs a nonzero id and a handle", ErrInvalidSuite)
	}
	return &KeyPair{suite: id, impl: h}, nil
}

// NewSuitePublicKey wraps an external suite's serialized public key.
func NewSuitePublicKey(id SuiteID, raw []byte) (*PublicKey, error) {
	if id == 0 {
		return nil, fmt.Errorf("%w: public key needs a nonzero id", ErrInvalidSuite)
	}
	return &PublicKey{suite: id, raw: cloneBytes(raw)}, nil
}

// NewSuiteCiphertext wraps an external suite's serialized ciphertext.
func NewSuiteCiphertext(id SuiteID, raw []byte) (*Ciphertext, error) {
	if id == 0 {
		return nil, fmt.Errorf("%w: ciphertext needs a nonzero id", ErrInvalidSuite)
	}
	return &Ciphertext{suite: id, raw: cloneBytes(raw)}, nil
}

// Handle returns the suite's live key handle (nil for CH-KEM-v1 key pairs).
func (kp *KeyPair) Handle() any { return kp.impl }
