package tunnel

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// fsmStep passes a flight into an FSM, one message at a time, and returns the last
// non-empty reply and whether the handshake completed.
func fsmStep(t *testing.T, d *dgramHandshake, flight []hsMessage) (reply []hsMessage, complete bool) {
	t.Helper()
	if len(flight) == 0 {
		t.Fatal("empty flight fed to FSM")
	}
	for _, m := range flight {
		out, done := d.onMessage(m.typ, m.body)
		if out != nil {
			reply = out
		}
		complete = complete || done
	}
	return reply, complete
}

// onlyMsg returns the single message of a one-message flight, or nil.
func onlyMsg(flight []hsMessage) *hsMessage {
	if len(flight) != 1 {
		return nil
	}
	return &flight[0]
}

// TestDatagramHRR drives the datagram handshake FSM through a HelloRetryRequest:
// the initiator leads with an unsupported (stub) suite, the responder steers it to
// CH-KEM-v1, and the handshake completes on v1.
func TestDatagramHRR(t *testing.T) {
	clientSess := newStubLedInitiator(t)
	serverSess := mustResponder(t)
	client := newDgramHandshake(clientSess)
	server := newDgramHandshake(serverSess)

	ch1, err := client.start()
	if err != nil {
		t.Fatalf("client start: %v", err)
	}

	hrr, _ := fsmStep(t, server, ch1)
	if m := onlyMsg(hrr); m == nil || m.typ != protocol.MessageTypeHelloRetryRequest {
		t.Fatalf("responder did not emit HelloRetryRequest, got %+v", hrr)
	}

	// A lost HRR: the initiator retransmits ClientHello1; the responder must replay
	// the cached HRR (not reprocess), recovering from the loss.
	replay, _ := fsmStep(t, server, ch1)
	if m := onlyMsg(replay); m == nil || m.typ != protocol.MessageTypeHelloRetryRequest {
		t.Fatalf("responder did not replay HRR on a retransmitted ClientHello1, got %+v", replay)
	}

	ch2, _ := fsmStep(t, client, hrr)
	if m := onlyMsg(ch2); m == nil || m.typ != protocol.MessageTypeClientHello {
		t.Fatalf("initiator did not emit a retried ClientHello, got %+v", ch2)
	}

	flight, _ := fsmStep(t, server, ch2)
	if len(flight) != 2 || flight[0].typ != protocol.MessageTypeServerHello ||
		flight[1].typ != protocol.MessageTypeServerFinished {
		t.Fatalf("responder did not emit ServerHello+ServerFinished after the retry, got %+v", flight)
	}

	cf, clientDone := fsmStep(t, client, flight)
	if m := onlyMsg(cf); m == nil || m.typ != protocol.MessageTypeClientFinished || !clientDone {
		t.Fatalf("initiator did not complete with ClientFinished, got %+v done=%v", cf, clientDone)
	}

	if _, serverDone := fsmStep(t, server, cf); !serverDone {
		t.Fatal("responder did not complete on ClientFinished")
	}

	if clientSess.kemSuite.ID() != chkem.SuiteCHKEMv1 || serverSess.kemSuite.ID() != chkem.SuiteCHKEMv1 {
		t.Errorf("after datagram HRR: client=%#x server=%#x, want CH-KEM-v1",
			clientSess.kemSuite.ID(), serverSess.kemSuite.ID())
	}
	if !client.isComplete() || !server.isComplete() {
		t.Error("FSMs did not both report complete")
	}
}
