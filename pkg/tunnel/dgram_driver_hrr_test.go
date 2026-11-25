package tunnel

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// A HelloRetryRequest proves the peer is alive and answering, so the retried ClientHello starts a
// fresh retransmit schedule. The driver used to see no change of handshake state across a
// HelloRetryRequest (the state goes back to its initial value and forward again inside one call),
// so it treated the message as a replay: the backoff and retry count carried over, and a retry that
// came after a lossy start failed sooner than the schedule promises.
func TestHelloRetryRequestResetsTheInitiatorBackoff(t *testing.T) {
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	ri, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	ri.AllowedKEMSuites = []chkem.SuiteID{chkem.SuiteXWing} // the initiator leads with CH-KEM-v1
	clk := &fakeClock{t: epoch}
	initiator := newDgramDriver(ci, clk.now)
	responder := newDgramDriver(ri, (&fakeClock{t: epoch}).now)

	ch, err := initiator.start()
	if err != nil {
		t.Fatal(err)
	}

	// A lossy start: the first flight is retransmitted three times before any answer arrives.
	for range 3 {
		clk.set(initiator.nextWake())
		initiator.onTimeout()
	}
	if initiator.retries != 3 {
		t.Fatalf("test assumption: %d retries before the answer, want 3", initiator.retries)
	}

	hrr := feed(responder, ch)
	if len(hrr) != 1 || hrr[0].typ != protocol.MessageTypeHelloRetryRequest {
		t.Fatalf("responder answered with %v, want one HelloRetryRequest", hrr)
	}
	retried := feed(initiator, hrr)
	if len(retried) != 1 || retried[0].typ != protocol.MessageTypeClientHello {
		t.Fatalf("initiator answered the HelloRetryRequest with %v, want one ClientHello", retried)
	}

	if initiator.retries != 0 || initiator.rto != initiator.rtoInitial {
		t.Fatalf("after the HelloRetryRequest retries = %d and rto = %v, want 0 and %v", initiator.retries, initiator.rto, initiator.rtoInitial)
	}
	if want := clk.now().Add(initiator.rtoInitial); !initiator.nextWake().Equal(want) {
		t.Fatalf("next wake = %v, want %v (one initial timeout after the retry)", initiator.nextWake().Sub(clk.now()), initiator.rtoInitial)
	}
}
