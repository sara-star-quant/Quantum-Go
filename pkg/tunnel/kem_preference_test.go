package tunnel

import (
	"net"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// TestInitiatorSuitePreference starts the initiator on X-Wing; the default responder
// accepts it on the first flight, so both sessions end on X-Wing with no retry.
func TestInitiatorSuitePreference(t *testing.T) {
	suite, err := kemPolicy(nil).initiator(chkem.SuiteXWing)
	if err != nil {
		t.Fatalf("initiatorSuite: %v", err)
	}
	initiator, err := NewSessionWithSuite(RoleInitiator, suite)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()
	errCh := make(chan error, 2)
	go func() { errCh <- InitiatorHandshake(initiator, c) }()
	go func() { errCh <- ResponderHandshake(responder, s) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	if initiator.kemSuite.ID() != chkem.SuiteXWing || responder.kemSuite.ID() != chkem.SuiteXWing {
		t.Fatalf("suites: initiator=%#x responder=%#x, want X-Wing", initiator.kemSuite.ID(), responder.kemSuite.ID())
	}
}

func TestInitiatorSuiteZeroIsDefault(t *testing.T) {
	s, err := kemPolicy(nil).initiator(0)
	if err != nil || s.ID() != chkem.SuiteCHKEMv1 {
		t.Fatalf("zero id: suite=%v err=%v, want CH-KEM-v1", s, err)
	}
}

func TestInitiatorSuiteRejectsUnoffered(t *testing.T) {
	if _, err := kemPolicy(nil).initiator(0x7FFF); !qerrors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("unknown id: %v, want ErrUnsupportedKEMSuite", err)
	}
	_, err := DialWithConfig("tcp", "127.0.0.1:1", TransportConfig{KEMSuite: 0x7FFF, AllowUnauthenticated: true})
	if !qerrors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("DialWithConfig: %v, want ErrUnsupportedKEMSuite before dialing", err)
	}
	if _, err := NewDatagramEndpoint(nil, WithAllowUnauthenticated(), WithKEMSuite(0x7FFF)); !qerrors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("NewDatagramEndpoint: %v, want ErrUnsupportedKEMSuite", err)
	}
}

// TestDatagramInitiatorSuitePreference dials with X-Wing over a lossy channel; both
// sessions must land on X-Wing.
func TestDatagramInitiatorSuitePreference(t *testing.T) {
	connA, connB := memPipe(7, 0.1, 0.05, 0.05)
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	WithKEMSuite(chkem.SuiteXWing)(epA)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 50 * time.Millisecond
		ep.maxRetries = 40
	}
	go epA.Serve()
	go epB.Serve()
	t.Cleanup(func() { _ = epA.Close(); _ = epB.Close() })

	c, err := DialDatagram(epA, connB.addr)
	if err != nil {
		t.Fatalf("DialDatagram: %v", err)
	}
	if got := c.Session().kemSuite.ID(); got != chkem.SuiteXWing {
		t.Fatalf("client suite = %#x, want X-Wing", got)
	}
	select {
	case ds := <-epB.acceptCh:
		if got := ds.getSession().kemSuite.ID(); got != chkem.SuiteXWing {
			t.Fatalf("server suite = %#x, want X-Wing", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never accepted")
	}
}
