package tunnel

import (
	"net"
	"sync"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

func TestResolveKEMSuite(t *testing.T) {
	s, err := resolveKEMSuite(uint16(chkem.SuiteCHKEMv1))
	if err != nil {
		t.Fatalf("resolveKEMSuite(v1): %v", err)
	}
	if s.ID() != chkem.SuiteCHKEMv1 {
		t.Errorf("resolved suite id = %#x, want CH-KEM-v1", s.ID())
	}

	if _, err := resolveKEMSuite(0xFFFF); !qerrors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("unknown suite: got %v, want ErrUnsupportedKEMSuite", err)
	}
}

func TestSupportedKEMSuiteIDsIncludesV1(t *testing.T) {
	ids := supportedKEMSuiteIDs()
	if len(ids) == 0 || ids[0] != uint16(chkem.SuiteCHKEMv1) {
		t.Fatalf("supported KEM suites = %v, want CH-KEM-v1 first", ids)
	}
}

// TestHandshakeNegotiatesV1 confirms a full stream handshake leaves both sessions
// on CH-KEM-v1 (the only registered suite).
func TestHandshakeNegotiatesV1(t *testing.T) {
	initiator, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	responder, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	errCh := make(chan error, 2)
	go func() { errCh <- InitiatorHandshake(initiator, clientConn) }()
	go func() { errCh <- ResponderHandshake(responder, serverConn) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	if initiator.kemSuite.ID() != chkem.SuiteCHKEMv1 || responder.kemSuite.ID() != chkem.SuiteCHKEMv1 {
		t.Errorf("negotiated suites: initiator=%#x responder=%#x, want CH-KEM-v1",
			initiator.kemSuite.ID(), responder.kemSuite.ID())
	}
}

// TestResolveKEMSuiteHonorsFIPSOffer: a registered suite that is not FIPS approved
// must not resolve in FIPS mode (the server resolves the client's first-flight
// suite), and must resolve otherwise.
func TestResolveKEMSuiteHonorsFIPSOffer(t *testing.T) {
	const id = chkem.CustomSuiteMin + 0x0F00
	nonFIPSOnce.Do(func() {
		if err := chkem.RegisterSuite(nonFIPSSuite{DefaultSuiteBase: chkem.DefaultSuite(), id: id}); err != nil {
			t.Fatal(err)
		}
	})
	_, err := resolveKEMSuite(uint16(id))
	if crypto.FIPSMode() == (err == nil) {
		t.Fatalf("FIPSMode=%v but resolve err=%v", crypto.FIPSMode(), err)
	}
}

var nonFIPSOnce sync.Once

// nonFIPSSuite reuses CH-KEM-v1's behavior under a custom id and reports it as not
// FIPS approved.
type nonFIPSSuite struct {
	DefaultSuiteBase chkem.Suite
	id               chkem.SuiteID
}

func (s nonFIPSSuite) ID() chkem.SuiteID { return s.id }
func (s nonFIPSSuite) GenerateKeyPair() (*chkem.KeyPair, error) {
	return s.DefaultSuiteBase.GenerateKeyPair()
}
func (s nonFIPSSuite) GenerateStaticKeyPair() (*chkem.KeyPair, []byte, error) {
	return s.DefaultSuiteBase.GenerateStaticKeyPair()
}
func (s nonFIPSSuite) ParseKeyPair(b []byte) (*chkem.KeyPair, error) {
	return s.DefaultSuiteBase.ParseKeyPair(b)
}
func (s nonFIPSSuite) Encapsulate(p *chkem.PublicKey, r chkem.Role) (*chkem.Ciphertext, []byte, error) {
	return s.DefaultSuiteBase.Encapsulate(p, r)
}
func (s nonFIPSSuite) Decapsulate(c *chkem.Ciphertext, k *chkem.KeyPair, r chkem.Role) ([]byte, error) {
	return s.DefaultSuiteBase.Decapsulate(c, k, r)
}
func (s nonFIPSSuite) ParsePublicKey(b []byte) (*chkem.PublicKey, error) {
	return s.DefaultSuiteBase.ParsePublicKey(b)
}
func (s nonFIPSSuite) ParseCiphertext(b []byte) (*chkem.Ciphertext, error) {
	return s.DefaultSuiteBase.ParseCiphertext(b)
}
func (s nonFIPSSuite) PublicKeySize() int   { return s.DefaultSuiteBase.PublicKeySize() }
func (s nonFIPSSuite) CiphertextSize() int  { return s.DefaultSuiteBase.CiphertextSize() }
func (s nonFIPSSuite) SeedSize() int        { return s.DefaultSuiteBase.SeedSize() }
func (s nonFIPSSuite) IsFIPSApproved() bool { return false }
