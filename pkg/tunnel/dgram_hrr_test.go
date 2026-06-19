package tunnel

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// fsmStep passes one message into an FSM and returns its reply.
func fsmStep(t *testing.T, d *dgramHandshake, m *hsMessage) (*hsMessage, bool) {
	t.Helper()
	if m == nil {
		t.Fatal("nil message fed to FSM")
	}
	return d.onMessage(m.typ, m.body)
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
	if hrr == nil || hrr.typ != protocol.MessageTypeHelloRetryRequest {
		t.Fatalf("responder did not emit HelloRetryRequest, got %+v", hrr)
	}

	// A lost HRR: the initiator retransmits ClientHello1; the responder must replay
	// the cached HRR (not reprocess), recovering from the loss.
	replay, _ := fsmStep(t, server, ch1)
	if replay == nil || replay.typ != protocol.MessageTypeHelloRetryRequest {
		t.Fatalf("responder did not replay HRR on a retransmitted ClientHello1, got %+v", replay)
	}

	ch2, _ := fsmStep(t, client, hrr)
	if ch2 == nil || ch2.typ != protocol.MessageTypeClientHello {
		t.Fatalf("initiator did not emit a retried ClientHello, got %+v", ch2)
	}

	sh, _ := fsmStep(t, server, ch2)
	if sh == nil || sh.typ != protocol.MessageTypeServerHello {
		t.Fatalf("responder did not emit ServerHello after the retry, got %+v", sh)
	}

	cf, _ := fsmStep(t, client, sh)
	if cf == nil || cf.typ != protocol.MessageTypeClientFinished {
		t.Fatalf("initiator did not emit ClientFinished, got %+v", cf)
	}

	sf, serverDone := fsmStep(t, server, cf)
	if sf == nil || sf.typ != protocol.MessageTypeServerFinished || !serverDone {
		t.Fatalf("responder did not complete with ServerFinished, got %+v done=%v", sf, serverDone)
	}

	if _, clientDone := fsmStep(t, client, sf); !clientDone {
		t.Fatal("initiator did not complete on ServerFinished")
	}

	if clientSess.kemSuite.ID() != chkem.SuiteCHKEMv1 || serverSess.kemSuite.ID() != chkem.SuiteCHKEMv1 {
		t.Errorf("after datagram HRR: client=%#x server=%#x, want CH-KEM-v1",
			clientSess.kemSuite.ID(), serverSess.kemSuite.ID())
	}
	if !client.isComplete() || !server.isComplete() {
		t.Error("FSMs did not both report complete")
	}
}
