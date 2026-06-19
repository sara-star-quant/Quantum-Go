package tunnel

import (
	"net"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// newXWingInitiator returns an initiator session whose key share uses the X-Wing
// suite, so a handshake against a default responder negotiates X-Wing end to end.
func newXWingInitiator(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	suite, ok := chkem.GetSuite(chkem.SuiteXWing)
	if !ok {
		t.Fatal("X-Wing suite is not registered")
	}
	kp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("X-Wing GenerateKeyPair: %v", err)
	}
	s.LocalKeyPair.Zeroize()
	s.kemSuite = suite
	s.LocalKeyPair = kp
	return s
}

// TestXWingHandshakeStream runs a full stream handshake where the client leads with
// X-Wing; the responder adopts it (both peers support it) and the handshake
// completes on X-Wing with no HelloRetryRequest.
func TestXWingHandshakeStream(t *testing.T) {
	initiator := newXWingInitiator(t)
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
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	if initiator.kemSuite.ID() != chkem.SuiteXWing || responder.kemSuite.ID() != chkem.SuiteXWing {
		t.Errorf("negotiated suites: initiator=%#x responder=%#x, want X-Wing",
			initiator.kemSuite.ID(), responder.kemSuite.ID())
	}
	if initiator.State() != SessionStateEstablished || responder.State() != SessionStateEstablished {
		t.Errorf("not established: initiator=%v responder=%v", initiator.State(), responder.State())
	}
}

// TestXWingHandshakeDatagram drives the datagram FSM through an X-Wing handshake.
func TestXWingHandshakeDatagram(t *testing.T) {
	client := newDgramHandshake(newXWingInitiator(t))
	server := newDgramHandshake(mustResponder(t))

	ch, err := client.start()
	if err != nil {
		t.Fatalf("client start: %v", err)
	}
	sh, _ := fsmStep(t, server, ch)
	if sh == nil || sh.typ != protocol.MessageTypeServerHello {
		t.Fatalf("responder did not emit ServerHello, got %+v", sh)
	}
	cf, _ := fsmStep(t, client, sh)
	if cf == nil || cf.typ != protocol.MessageTypeClientFinished {
		t.Fatalf("initiator did not emit ClientFinished, got %+v", cf)
	}
	sf, serverDone := fsmStep(t, server, cf)
	if sf == nil || sf.typ != protocol.MessageTypeServerFinished || !serverDone {
		t.Fatalf("responder did not complete, got %+v done=%v", sf, serverDone)
	}
	if _, clientDone := fsmStep(t, client, sf); !clientDone {
		t.Fatal("initiator did not complete")
	}
	if client.hs.session.kemSuite.ID() != chkem.SuiteXWing || server.hs.session.kemSuite.ID() != chkem.SuiteXWing {
		t.Error("datagram handshake did not negotiate X-Wing")
	}
}
