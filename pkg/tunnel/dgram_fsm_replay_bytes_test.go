package tunnel

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// The FSM replays its cached flight when the peer repeats the last message it processed, because
// the first flight may have been lost. The replay must answer only a byte-identical repeat. A
// message of the same type with other bytes is unauthenticated input, and answering it would send
// the full flight (about 3 KB for the responder) to whoever sent it.
func TestResponderReplaysOnlyForAByteIdenticalClientHello(t *testing.T) {
	initiator, responder := newDriverPair(t)
	ch, err := initiator.start()
	if err != nil {
		t.Fatal(err)
	}
	flight := feed(responder, ch)
	if len(flight) != 2 {
		t.Fatalf("responder flight = %d messages, want 2", len(flight))
	}

	same := responder.onInbound(protocol.MessageTypeClientHello, ch[0].body)
	if len(same) != 2 {
		t.Fatalf("a byte-identical ClientHello must replay the flight, got %d messages", len(same))
	}

	other := bytes.Clone(ch[0].body)
	other[len(other)-1] ^= 0x01
	if out := responder.onInbound(protocol.MessageTypeClientHello, other); len(out) != 0 {
		t.Fatalf("a different ClientHello drew %d messages from the responder", len(out))
	}
	if out := responder.onInbound(protocol.MessageTypeClientHello, []byte("junk")); len(out) != 0 {
		t.Fatalf("junk of the ClientHello type drew %d messages from the responder", len(out))
	}
}

func TestInitiatorReplaysOnlyForAByteIdenticalServerFlight(t *testing.T) {
	initiator, responder := newDriverPair(t)
	ch, err := initiator.start()
	if err != nil {
		t.Fatal(err)
	}
	flight := feed(responder, ch)
	cf := feed(initiator, flight)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("initiator answered the flight with %v, want one ClientFinished", cf)
	}

	// The initiator lingers to answer a retransmitted server flight with its cached ClientFinished.
	sf := flight[1]
	if out := initiator.onInbound(sf.typ, sf.body); len(out) != 1 {
		t.Fatalf("a byte-identical ServerFinished must replay ClientFinished, got %d messages", len(out))
	}
	other := bytes.Clone(sf.body)
	other[len(other)-1] ^= 0x01
	if out := initiator.onInbound(sf.typ, other); len(out) != 0 {
		t.Fatalf("a different ServerFinished drew %d messages from the initiator", len(out))
	}
}
