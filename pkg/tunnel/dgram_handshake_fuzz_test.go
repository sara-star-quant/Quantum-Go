package tunnel

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

var fuzzTypes = []protocol.MessageType{
	protocol.MessageTypeClientHello, protocol.MessageTypeServerHello,
	protocol.MessageTypeServerFinished, protocol.MessageTypeClientFinished,
	protocol.MessageTypeHelloRetryRequest,
}

// FuzzDgramHandshakeFSM feeds both state machines arbitrary message sequences before
// any authentication. They must never panic, and forged input must never complete
// a handshake: the responder only completes on a ClientFinished that verifies
// against its own transcript, and the initiator on a verifying ServerFinished.
func FuzzDgramHandshakeFSM(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 0xff, 0xff, 0xff, 2, 0, 3, 4, 1})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		initiator, responder := newFSMPair(t)
		if _, err := initiator.start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		// Each step: one byte picks the message type, the next picks a body length.
		for len(data) >= 2 {
			typ := fuzzTypes[int(data[0])%len(fuzzTypes)]
			n := int(data[1])
			data = data[2:]
			if n > len(data) {
				n = len(data)
			}
			body := data[:n]
			data = data[n:]
			for _, fsm := range []*dgramHandshake{initiator, responder} {
				if _, done := fsm.onMessage(typ, body); done {
					t.Fatalf("forged %v completed a handshake (role %v)", typ, fsm.role)
				}
			}
		}
	})
}
