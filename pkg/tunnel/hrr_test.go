package tunnel

import (
	"net"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// stubSuite wraps CH-KEM-v1 but reports an unregistered suite id, so a server
// (which only has v1 in its registry) cannot resolve it and must HelloRetryRequest
// the client down to v1. All crypto delegates to v1.
type stubSuite struct {
	chkem.Suite
}

const stubSuiteID chkem.SuiteID = 0x9999

func (stubSuite) ID() chkem.SuiteID { return stubSuiteID }

func newStubLedInitiator(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stub := stubSuite{Suite: chkem.DefaultSuite()}
	kp, err := stub.GenerateKeyPair()
	if err != nil {
		t.Fatalf("stub GenerateKeyPair: %v", err)
	}
	s.LocalKeyPair.Zeroize()
	s.kemSuite = stub
	s.LocalKeyPair = kp
	return s
}

// TestHelloRetryRequestStream drives a stream handshake where the client leads with
// a suite the server does not support; the server HelloRetryRequests down to v1 and
// the handshake completes on v1.
func TestHelloRetryRequestStream(t *testing.T) {
	initiator := newStubLedInitiator(t)
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
		t.Errorf("after HRR: initiator=%#x responder=%#x, want CH-KEM-v1",
			initiator.kemSuite.ID(), responder.kemSuite.ID())
	}
	if initiator.State() != SessionStateEstablished || responder.State() != SessionStateEstablished {
		t.Errorf("not established: initiator=%v responder=%v", initiator.State(), responder.State())
	}
}

// driveHRR runs the HRR exchange through the handshake methods directly (no network),
// optionally mutating the first ClientHello bytes the server sees. It returns the
// error from ProcessClientFinished, which fails if the two transcripts diverge.
func driveHRR(t *testing.T, mutateCH1 func([]byte)) error {
	t.Helper()
	client := NewHandshake(newStubLedInitiator(t))
	server := NewHandshake(mustResponder(t))

	ch1, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}
	seen := append([]byte(nil), ch1...)
	if mutateCH1 != nil {
		mutateCH1(seen)
	}
	if err := server.ProcessClientHello(seen); err != nil {
		t.Fatalf("server ProcessClientHello(ch1): %v", err)
	}
	if !server.sendHRR {
		t.Fatal("server did not signal HelloRetryRequest for the unsupported suite")
	}
	hrr, err := server.CreateHelloRetryRequest()
	if err != nil {
		t.Fatalf("CreateHelloRetryRequest: %v", err)
	}
	if err := client.ProcessHelloRetryRequest(hrr); err != nil {
		t.Fatalf("client ProcessHelloRetryRequest: %v", err)
	}
	ch2, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("CreateClientHello(retry): %v", err)
	}
	if err := server.ProcessClientHello(ch2); err != nil {
		t.Fatalf("server ProcessClientHello(ch2): %v", err)
	}
	sh, err := server.CreateServerHello()
	if err != nil {
		t.Fatalf("CreateServerHello: %v", err)
	}
	if err := client.ProcessServerHello(sh); err != nil {
		t.Fatalf("client ProcessServerHello: %v", err)
	}
	cf, err := client.CreateClientFinished()
	if err != nil {
		t.Fatalf("CreateClientFinished: %v", err)
	}
	return server.ProcessClientFinished(cf)
}

func mustResponder(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// TestHRRUntamperedCompletes is the control: an unmodified HRR exchange verifies.
func TestHRRUntamperedCompletes(t *testing.T) {
	if err := driveHRR(t, nil); err != nil {
		t.Fatalf("untampered HRR ClientFinished failed: %v", err)
	}
}

// TestHRRClientHello1TamperBreaksFinished proves the synthetic message hash binds
// ClientHello1: changing any byte of the first hello the server sees diverges the
// transcripts so the ClientFinished MAC fails (a downgrade attempt is detected).
func TestHRRClientHello1TamperBreaksFinished(t *testing.T) {
	// Flip a byte inside ClientHello1's random (offset 7: header(5)+version(2)).
	err := driveHRR(t, func(ch1 []byte) { ch1[10] ^= 0xFF })
	if err == nil {
		t.Fatal("tampered ClientHello1 still produced a valid ClientFinished (synthetic hash not binding)")
	}
}

// TestHRRSecondUnsupportedHelloRejected bounds the retry: after one HelloRetryRequest
// the server rejects a second unsupported ClientHello rather than looping.
func TestHRRSecondUnsupportedHelloRejected(t *testing.T) {
	client := NewHandshake(newStubLedInitiator(t))
	server := NewHandshake(mustResponder(t))

	ch1, _ := client.CreateClientHello()
	if err := server.ProcessClientHello(ch1); err != nil {
		t.Fatalf("ProcessClientHello(ch1): %v", err)
	}
	if _, err := server.CreateHelloRetryRequest(); err != nil {
		t.Fatalf("CreateHelloRetryRequest: %v", err)
	}
	// A misbehaving client re-sends the same unsupported suite; the server must fail.
	if err := server.ProcessClientHello(ch1); err == nil {
		t.Fatal("server accepted a second unsupported ClientHello after a HelloRetryRequest")
	}
}
