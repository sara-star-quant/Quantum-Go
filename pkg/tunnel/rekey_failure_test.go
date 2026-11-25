package tunnel

import (
	"errors"
	"net"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// rekeyPair completes a real handshake over TCP and returns both transports and sessions.
// Each side wraps its conn in a faultConn so a test can fail one side's writes.
func rekeyPair(t *testing.T) (ct, rt *Transport, cfc, rfc *faultConn, ci, ri *Session) {
	t.Helper()
	ca, cb := tcpPair(t)
	cfc = &faultConn{Conn: ca, done: make(chan struct{})}
	rfc = &faultConn{Conn: cb, done: make(chan struct{})}
	ci, _ = NewSession(RoleInitiator)
	ri, _ = NewSession(RoleResponder)
	errs := make(chan error, 2)
	go func() { errs <- InitiatorHandshake(ci, net.Conn(cfc)) }()
	go func() { errs <- ResponderHandshake(ri, net.Conn(rfc)) }()
	for range 2 {
		if err := within(t, "handshake", func() error { return <-errs }); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	var err error
	if ct, err = NewTransport(ci, cfc, DefaultTransportConfig()); err != nil {
		t.Fatal(err)
	}
	if rt, err = NewTransport(ri, rfc, DefaultTransportConfig()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ct.Close(); _ = rt.Close() })
	return
}

// A rekey that fails after it began cannot be resumed: the request or the response may already
// be on the wire, so the peer may switch keys while this side does not. Leaving the session
// marked as rekeying forever (every later SendRekey returns ErrRekeyInProgress, the responder
// ignores later requests) is the worst of both. The session closes instead, and says so.

func TestFailedRekeyRequestWriteClosesTheSession(t *testing.T) {
	ct, _, cfc, _, ci, _ := rekeyPair(t)
	cfc.set(func(c *faultConn) { c.writeErr = errors.New("write failed") })

	if err := ct.SendRekey(); err == nil {
		t.Fatal("SendRekey must report the failed write")
	}
	if ci.State() != SessionStateClosed {
		t.Fatalf("session state after a failed rekey request = %v, want Closed", ci.State())
	}
	if err := ct.SendRekey(); !errors.Is(err, qerrors.ErrTunnelClosed) {
		t.Fatalf("a later SendRekey must fail as closed, got %v", err)
	}
}

func TestFailedRekeyResponseWriteClosesTheResponder(t *testing.T) {
	ct, rt, _, rfc, _, ri := rekeyPair(t)
	if err := ct.SendRekey(); err != nil {
		t.Fatal(err)
	}
	rfc.set(func(c *faultConn) { c.writeErr = errors.New("write failed") })

	if _, err := receiveResult(t, rt); err == nil {
		t.Fatal("the responder must report the failed response write")
	}
	if ri.State() != SessionStateClosed {
		t.Fatalf("responder state after a failed rekey response = %v, want Closed", ri.State())
	}
}

func TestUndecapsulatableRekeyResponseClosesTheInitiator(t *testing.T) {
	ct, rt, _, _, ci, _ := rekeyPair(t)
	if err := ct.SendRekey(); err != nil {
		t.Fatal(err)
	}
	// The responder answers with a response that is the wrong size for a ciphertext.
	if err := rt.sendRekeyResponse([]byte("not a ciphertext"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveResult(t, ct); err == nil {
		t.Fatal("the initiator must reject a response that is not a ciphertext")
	}
	if ci.State() != SessionStateClosed {
		t.Fatalf("initiator state after a bad rekey response = %v, want Closed", ci.State())
	}
}
