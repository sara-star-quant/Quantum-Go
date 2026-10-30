package tunnel

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// newFSMPair builds an initiator/responder FSM pair over fresh sessions.
func newFSMPair(t *testing.T) (initiator, responder *dgramHandshake) {
	t.Helper()
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	ri, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}
	return newDgramHandshake(ci), newDgramHandshake(ri)
}

// serverFlight returns the responder's ServerHello and ServerFinished from its flight.
func serverFlight(t *testing.T, flight []hsMessage) (sh, sf hsMessage) {
	t.Helper()
	if len(flight) != 2 || flight[0].typ != protocol.MessageTypeServerHello ||
		flight[1].typ != protocol.MessageTypeServerFinished {
		t.Fatalf("responder flight = %v; want ServerHello, ServerFinished", flight)
	}
	return flight[0], flight[1]
}

// TestDgramHandshakeFSMRoundTrip drives a full handshake by passing each FSM's
// output straight into the peer, no transport. The initiator completes on
// ServerFinished (one round trip) and the responder on ClientFinished. Reaching
// Complete on both cryptographically proves key agreement: each Finished MAC covers
// the shared secret and the transcript.
func TestDgramHandshakeFSMRoundTrip(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(chs) != 1 || chs[0].typ != protocol.MessageTypeClientHello {
		t.Fatalf("start produced %v, want ClientHello", chs)
	}
	ch := chs[0]

	flight, done := responder.onMessage(ch.typ, ch.body)
	if done {
		t.Fatal("responder complete after ClientHello")
	}
	sh, sf := serverFlight(t, flight)
	if responder.isComplete() {
		t.Fatal("responder complete before ClientFinished")
	}

	out, done := initiator.onMessage(sh.typ, sh.body)
	if out != nil || done {
		t.Fatalf("initiator(ServerHello) = %v, done=%v; want nothing, false", out, done)
	}

	cf, done := initiator.onMessage(sf.typ, sf.body)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished || !done {
		t.Fatalf("initiator(ServerFinished) = %v, done=%v; want ClientFinished, true", cf, done)
	}
	if !initiator.isComplete() {
		t.Fatal("initiator not complete after sending ClientFinished")
	}

	out, done = responder.onMessage(cf[0].typ, cf[0].body)
	if out != nil || !done {
		t.Fatalf("responder(ClientFinished) = %v, done=%v; want nothing, true", out, done)
	}
	if !responder.isComplete() {
		t.Fatal("responder not complete after ClientFinished")
	}

	if got := initiator.hs.session.State(); got != SessionStateEstablished {
		t.Fatalf("initiator session state = %v, want Established", got)
	}
	if got := responder.hs.session.State(); got != SessionStateEstablished {
		t.Fatalf("responder session state = %v, want Established", got)
	}
}

// TestDgramHandshakeFSMDuplicateReplay verifies a retransmitted ClientHello, after
// the responder already answered, replays the byte-identical server flight without
// re-running the KEM (re-encapsulation would derive a different secret).
func TestDgramHandshakeFSMDuplicateReplay(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, _ := initiator.start()
	ch := chs[0]
	f1, _ := responder.onMessage(ch.typ, ch.body)
	sh1, sf1 := serverFlight(t, f1)
	stateAfter := responder.state()

	f2, done := responder.onMessage(ch.typ, ch.body) // duplicate ClientHello
	if done {
		t.Fatal("duplicate ClientHello reported complete")
	}
	sh2, sf2 := serverFlight(t, f2)
	if !bytes.Equal(sh1.body, sh2.body) || !bytes.Equal(sf1.body, sf2.body) {
		t.Fatal("duplicate ClientHello did not replay the identical server flight")
	}
	if responder.state() != stateAfter {
		t.Fatal("duplicate ClientHello advanced responder state")
	}
}

// TestDgramHandshakeFSMBadMessageDropped verifies a tampered ServerFinished is
// dropped, not fatal: the initiator stays put and a genuine retransmit still
// completes the handshake.
func TestDgramHandshakeFSMBadMessageDropped(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, _ := initiator.start()
	flight, _ := responder.onMessage(chs[0].typ, chs[0].body)
	sh, sf := serverFlight(t, flight)
	initiator.onMessage(sh.typ, sh.body)

	tampered := append([]byte(nil), sf.body...)
	tampered[len(tampered)-1] ^= 0xFF
	out, done := initiator.onMessage(sf.typ, tampered)
	if out != nil || done {
		t.Fatalf("tampered ServerFinished = %v, done=%v; want nil, false (dropped)", out, done)
	}
	if initiator.isComplete() {
		t.Fatal("tampered ServerFinished wrongly completed the handshake")
	}

	cf, done := initiator.onMessage(sf.typ, sf.body)
	if len(cf) != 1 || !done {
		t.Fatalf("genuine ServerFinished after tamper = %v, done=%v; want ClientFinished, true", cf, done)
	}
	if !initiator.isComplete() {
		t.Fatal("genuine ServerFinished did not complete the handshake")
	}
}

// TestDgramHandshakeFSMReplayAfterComplete verifies the initiator, after
// completing, still replays its cached ClientFinished for a retransmitted
// ServerFinished (recovers a lost final message) and stays complete.
func TestDgramHandshakeFSMReplayAfterComplete(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, _ := initiator.start()
	flight, _ := responder.onMessage(chs[0].typ, chs[0].body)
	sh, sf := serverFlight(t, flight)
	initiator.onMessage(sh.typ, sh.body)
	cf1, done := initiator.onMessage(sf.typ, sf.body)
	if !done || len(cf1) != 1 {
		t.Fatal("initiator did not complete with a ClientFinished")
	}

	cf2, done := initiator.onMessage(sf.typ, sf.body) // duplicate ServerFinished
	if done {
		t.Fatal("duplicate ServerFinished re-reported completion transition")
	}
	if len(cf2) != 1 || !bytes.Equal(cf1[0].body, cf2[0].body) {
		t.Fatal("duplicate ServerFinished did not replay the identical ClientFinished")
	}
	if !initiator.isComplete() {
		t.Fatal("initiator lost completion after replay")
	}
}

// TestDgramHandshakeFSMRepeatedServerHelloDropped verifies a repeated ServerHello
// while the initiator awaits ServerFinished is dropped rather than answered with a
// ClientHello replay, so a replayed server flight does not trigger a resend storm.
func TestDgramHandshakeFSMRepeatedServerHelloDropped(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, _ := initiator.start()
	flight, _ := responder.onMessage(chs[0].typ, chs[0].body)
	sh, _ := serverFlight(t, flight)
	initiator.onMessage(sh.typ, sh.body)

	if out, done := initiator.onMessage(sh.typ, sh.body); out != nil || done {
		t.Fatalf("repeated ServerHello = %v, done=%v; want nil, false", out, done)
	}
}

// TestDgramHandshakeFSMUnexpectedDropped verifies an out-of-order message (a
// ServerHello arriving at a fresh responder) is dropped with no state change.
func TestDgramHandshakeFSMUnexpectedDropped(t *testing.T) {
	_, responder := newFSMPair(t)
	before := responder.state()

	out, done := responder.onMessage(protocol.MessageTypeServerHello, []byte("garbage"))
	if out != nil || done {
		t.Fatalf("unexpected ServerHello = %v, done=%v; want nil, false", out, done)
	}
	if responder.state() != before {
		t.Fatal("unexpected message changed responder state")
	}
}

// TestDgramHandshakeFSMReorderedFlight verifies a ServerFinished that arrives before
// the ServerHello completes the handshake once the ServerHello lands, with no
// retransmit.
func TestDgramHandshakeFSMReorderedFlight(t *testing.T) {
	initiator, responder := newFSMPair(t)

	chs, _ := initiator.start()
	flight, _ := responder.onMessage(chs[0].typ, chs[0].body)
	sh, sf := serverFlight(t, flight)

	if out, done := initiator.onMessage(sf.typ, sf.body); out != nil || done {
		t.Fatalf("early ServerFinished = %v, done=%v; want nil, false", out, done)
	}
	cf, done := initiator.onMessage(sh.typ, sh.body)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished || !done {
		t.Fatalf("ServerHello after early ServerFinished = %v, done=%v; want ClientFinished, true", cf, done)
	}
	if _, done := responder.onMessage(cf[0].typ, cf[0].body); !done {
		t.Fatal("responder did not complete")
	}
}
