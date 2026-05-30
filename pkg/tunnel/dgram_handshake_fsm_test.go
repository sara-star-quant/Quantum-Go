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

// TestDgramHandshakeFSMRoundTrip drives a full handshake by passing each FSM's
// output straight into the peer, no transport. Reaching Complete on the initiator
// cryptographically proves key agreement: ProcessServerFinished verifies a MAC
// computed over the shared secret and transcript.
func TestDgramHandshakeFSMRoundTrip(t *testing.T) {
	initiator, responder := newFSMPair(t)

	ch, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if ch.typ != protocol.MessageTypeClientHello {
		t.Fatalf("start produced %v, want ClientHello", ch.typ)
	}

	sh, done := responder.onMessage(ch.typ, ch.body)
	if sh == nil || sh.typ != protocol.MessageTypeServerHello || done {
		t.Fatalf("responder(ClientHello) = %v, done=%v; want ServerHello, false", sh, done)
	}

	cf, done := initiator.onMessage(sh.typ, sh.body)
	if cf == nil || cf.typ != protocol.MessageTypeClientFinished || done {
		t.Fatalf("initiator(ServerHello) = %v, done=%v; want ClientFinished, false", cf, done)
	}

	sf, done := responder.onMessage(cf.typ, cf.body)
	if sf == nil || sf.typ != protocol.MessageTypeServerFinished || !done {
		t.Fatalf("responder(ClientFinished) = %v, done=%v; want ServerFinished, true", sf, done)
	}
	if !responder.isComplete() {
		t.Fatal("responder not complete after sending ServerFinished")
	}

	out, done := initiator.onMessage(sf.typ, sf.body)
	if out != nil || !done {
		t.Fatalf("initiator(ServerFinished) = %v, done=%v; want nil, true", out, done)
	}
	if !initiator.isComplete() {
		t.Fatal("initiator not complete after receiving ServerFinished")
	}

	if got := initiator.hs.session.State(); got != SessionStateEstablished {
		t.Fatalf("initiator session state = %v, want Established", got)
	}
	if got := responder.hs.session.State(); got != SessionStateEstablished {
		t.Fatalf("responder session state = %v, want Established", got)
	}
}

// TestDgramHandshakeFSMDuplicateReplay verifies a retransmitted ClientHello, after
// the responder already answered, replays the byte-identical cached ServerHello
// without re-running the KEM (re-encapsulation would derive a different secret).
func TestDgramHandshakeFSMDuplicateReplay(t *testing.T) {
	initiator, responder := newFSMPair(t)

	ch, _ := initiator.start()
	sh1, _ := responder.onMessage(ch.typ, ch.body)
	if sh1 == nil {
		t.Fatal("no ServerHello on first ClientHello")
	}
	stateAfter := responder.state()

	sh2, done := responder.onMessage(ch.typ, ch.body) // duplicate ClientHello
	if done {
		t.Fatal("duplicate ClientHello reported complete")
	}
	if sh2 == nil || !bytes.Equal(sh1.body, sh2.body) {
		t.Fatal("duplicate ClientHello did not replay the identical ServerHello")
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

	ch, _ := initiator.start()
	sh, _ := responder.onMessage(ch.typ, ch.body)
	cf, _ := initiator.onMessage(sh.typ, sh.body)
	sf, done := responder.onMessage(cf.typ, cf.body)
	if !done {
		t.Fatal("responder not complete")
	}

	tampered := append([]byte(nil), sf.body...)
	tampered[len(tampered)-1] ^= 0xFF
	out, done := initiator.onMessage(sf.typ, tampered)
	if out != nil || done {
		t.Fatalf("tampered ServerFinished = %v, done=%v; want nil, false (dropped)", out, done)
	}
	if initiator.isComplete() {
		t.Fatal("tampered ServerFinished wrongly completed the handshake")
	}

	if out, done := initiator.onMessage(sf.typ, sf.body); out != nil || !done {
		t.Fatalf("genuine ServerFinished after tamper = %v, done=%v; want nil, true", out, done)
	}
	if !initiator.isComplete() {
		t.Fatal("genuine ServerFinished did not complete the handshake")
	}
}

// TestDgramHandshakeFSMReplayAfterComplete verifies the responder, after
// completing, still replays its cached ServerFinished for a retransmitted
// ClientFinished (recovers a lost final flight) and stays complete.
func TestDgramHandshakeFSMReplayAfterComplete(t *testing.T) {
	initiator, responder := newFSMPair(t)

	ch, _ := initiator.start()
	sh, _ := responder.onMessage(ch.typ, ch.body)
	cf, _ := initiator.onMessage(sh.typ, sh.body)
	sf1, done := responder.onMessage(cf.typ, cf.body)
	if !done || sf1 == nil {
		t.Fatal("responder did not complete with a ServerFinished")
	}

	sf2, done := responder.onMessage(cf.typ, cf.body) // duplicate ClientFinished
	if done {
		t.Fatal("duplicate ClientFinished re-reported completion transition")
	}
	if sf2 == nil || !bytes.Equal(sf1.body, sf2.body) {
		t.Fatal("duplicate ClientFinished did not replay the identical ServerFinished")
	}
	if !responder.isComplete() {
		t.Fatal("responder lost completion after replay")
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
