package chkem

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

var nextID atomic.Uint32

// isolateRegistry restores the global registry when the test ends, so registrations
// never accumulate across tests or -count runs.
func isolateRegistry(t *testing.T) {
	t.Helper()
	registryMu.Lock()
	saved := make(map[SuiteID]Suite, len(registry))
	for k, v := range registry {
		saved[k] = v
	}
	savedOrder := append([]SuiteID(nil), order...)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry, order = saved, savedOrder
		registryMu.Unlock()
	})
}

// freshID returns an unused custom id, so tests survive -count=N on the global registry.
func freshID() SuiteID { return CustomSuiteMin + SuiteID(nextID.Add(1)) }

// stubSuite is a minimal external-style suite: it only uses exported chkem API.
type stubSuite struct {
	id           SuiteID
	pk, ct, seed int
	fipsOK       bool
}

func (s stubSuite) ID() SuiteID { return s.id }
func (s stubSuite) GenerateKeyPair() (*KeyPair, error) {
	return NewSuiteKeyPair(s.id, stubHandle{})
}
func (s stubSuite) GenerateStaticKeyPair() (*KeyPair, []byte, error) {
	kp, err := s.GenerateKeyPair()
	return kp, make([]byte, s.seed), err
}
func (s stubSuite) ParseKeyPair([]byte) (*KeyPair, error) { return s.GenerateKeyPair() }
func (s stubSuite) Encapsulate(*PublicKey, Role) (*Ciphertext, []byte, error) {
	ct, err := NewSuiteCiphertext(s.id, make([]byte, s.ct))
	return ct, make([]byte, 32), err
}
func (s stubSuite) Decapsulate(*Ciphertext, *KeyPair, Role) ([]byte, error) {
	return make([]byte, 32), nil
}
func (s stubSuite) ParsePublicKey(d []byte) (*PublicKey, error)   { return NewSuitePublicKey(s.id, d) }
func (s stubSuite) ParseCiphertext(d []byte) (*Ciphertext, error) { return NewSuiteCiphertext(s.id, d) }
func (s stubSuite) PublicKeySize() int                            { return s.pk }
func (s stubSuite) CiphertextSize() int                           { return s.ct }
func (s stubSuite) SeedSize() int                                 { return s.seed }
func (s stubSuite) IsFIPSApproved() bool                          { return s.fipsOK }

type stubHandle struct{}

func (stubHandle) PublicKeyBytes() []byte { return []byte{1, 2, 3} }
func (stubHandle) Zeroize()               {}

func TestRegisterSuiteRejects(t *testing.T) {
	isolateRegistry(t)
	good := stubSuite{id: freshID(), pk: 8, ct: 8, seed: 8, fipsOK: true}
	cases := map[string]Suite{
		"nil":          nil,
		"zero id":      stubSuite{id: 0, pk: 8, ct: 8, seed: 8},
		"builtin id":   stubSuite{id: SuiteXWing, pk: 8, ct: 8, seed: 8},
		"below custom": stubSuite{id: CustomSuiteMin - 1, pk: 8, ct: 8, seed: 8},
		"zero pk":      stubSuite{id: freshID(), pk: 0, ct: 8, seed: 8},
		"zero ct":      stubSuite{id: freshID(), pk: 8, ct: 0, seed: 8},
		"zero seed":    stubSuite{id: freshID(), pk: 8, ct: 8, seed: 0},
	}
	for name, s := range cases {
		if err := RegisterSuite(s); !errors.Is(err, ErrInvalidSuite) {
			t.Errorf("%s: err = %v, want ErrInvalidSuite", name, err)
		}
	}
	if err := RegisterSuite(good); err != nil {
		t.Fatalf("register good: %v", err)
	}
	if err := RegisterSuite(good); !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("duplicate: err = %v, want ErrInvalidSuite", err)
	}
	if _, ok := GetSuite(good.id); !ok {
		t.Fatal("registered suite not found")
	}
}

func TestSupportedSuitesOrderAndFIPSFilter(t *testing.T) {
	isolateRegistry(t)
	s := stubSuite{id: freshID(), pk: 8, ct: 8, seed: 8, fipsOK: true}
	if err := RegisterSuite(s); err != nil {
		t.Fatal(err)
	}
	ids := SupportedSuites()
	if ids[0] != SuiteCHKEMv1 || ids[1] != SuiteXWing {
		t.Fatalf("built-ins must lead in order, got %v", ids)
	}
	if !contains(ids, s.id) {
		t.Fatalf("registered suite missing from %v", ids)
	}
	bad := stubSuite{id: freshID(), pk: 8, ct: 8, seed: 8, fipsOK: false}
	if err := RegisterSuite(bad); err != nil {
		t.Fatal(err)
	}
	if got := contains(SupportedSuites(), bad.id); got == crypto.FIPSMode() {
		t.Fatalf("non-FIPS suite offered=%v with FIPSMode=%v", got, crypto.FIPSMode())
	}
	ids[0] = 0xDEAD // returned slice is a copy
	if SupportedSuites()[0] != SuiteCHKEMv1 {
		t.Fatal("SupportedSuites leaked internal slice")
	}
}

func TestExternalConstructorsRejectReservedID(t *testing.T) {
	if _, err := NewSuitePublicKey(0, []byte{1}); !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("public key id 0: %v", err)
	}
	if _, err := NewSuiteCiphertext(0, []byte{1}); !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("ciphertext id 0: %v", err)
	}
	if _, err := NewSuiteKeyPair(0, stubHandle{}); !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("key pair id 0: %v", err)
	}
	kp, err := NewSuiteKeyPair(CustomSuiteMin, stubHandle{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kp.Handle().(stubHandle); !ok {
		t.Fatal("Handle did not return the stored handle")
	}
	if got := kp.PublicKey().Bytes(); len(got) != 3 {
		t.Fatalf("public key bytes = %v", got)
	}
}

func TestRegistryConcurrent(t *testing.T) {
	isolateRegistry(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = RegisterSuite(stubSuite{id: freshID(), pk: 8, ct: 8, seed: 8, fipsOK: true})
			_ = SupportedSuites()
			_, _ = GetSuite(SuiteXWing)
		}(i)
	}
	wg.Wait()
}

func contains(ids []SuiteID, id SuiteID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestRegisterSuiteCap(t *testing.T) {
	isolateRegistry(t)
	var err error
	for i := 0; i < MaxCustomSuites+1 && err == nil; i++ {
		err = RegisterSuite(stubSuite{id: freshID(), pk: 8, ct: 8, seed: 8, fipsOK: true})
	}
	if !errors.Is(err, ErrInvalidSuite) {
		t.Fatalf("registering past MaxCustomSuites: err = %v, want ErrInvalidSuite", err)
	}
	if n := len(SupportedSuites()); n > 2+MaxCustomSuites || n > 255 {
		t.Fatalf("offer list has %d suites", n)
	}
}
