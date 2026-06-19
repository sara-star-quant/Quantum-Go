package tunnel

import (
	"net"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
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
