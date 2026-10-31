package tunnel

import (
	"encoding/binary"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// FuzzReassembler feeds the pre-authentication fragment reassembler arbitrary
// fragment headers and bodies from a few sources. It must never panic, must keep its
// state within the configured bounds, and a message it completes must have exactly
// the declared length.
func FuzzReassembler(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 10, 0, 10, 'a', 'b'})
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReassembler(0, 0, 0)
		for len(data) >= 9 {
			src := string(rune('a' + data[0]%4))
			h := protocol.DatagramHandshakeHeader{
				SenderIndex: uint32(data[1]),
				MsgType:     protocol.MessageTypeClientHello,
				FragOffset:  binary.BigEndian.Uint16(data[2:]),
				FragLength:  uint16(data[4]),
				TotalLength: binary.BigEndian.Uint16(data[5:]),
			}
			n := int(data[7])
			data = data[8:]
			if n > len(data) {
				n = len(data)
			}
			msg, done, err := r.Add(src, h, data[:n])
			data = data[n:]
			if err == nil && done && len(msg) != int(h.TotalLength) {
				t.Fatalf("completed message is %d bytes, declared %d", len(msg), h.TotalLength)
			}
			if r.sourceCount() > r.maxSources {
				t.Fatalf("reassembler holds %d sources, limit %d", r.sourceCount(), r.maxSources)
			}
		}
	})
}

// FuzzRouteDatagram feeds an endpoint arbitrary datagrams from a few spoofed
// sources, as an attacker on the network could. It must never panic and must not
// accumulate unbounded per-source state.
func FuzzRouteDatagram(f *testing.F) {
	f.Add([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(protocol.AppendDatagramDataHeader(nil, protocol.DatagramHeader{Epoch: 0, RecvIndex: 5, Seq: 1}))
	f.Add(protocol.EncodeDatagramRetry(1, []byte("cookie")))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		connA, _ := memPipe(1, 0, 0, 0)
		ep, err := NewDatagramEndpoint(connA)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ep.Close() }()
		for i := 0; i < 4; i++ {
			_ = ep.routeDatagram(memAddr{name: string(rune('a' + i))}, data)
		}
		ep.registry.mu.Lock()
		half, srcs := ep.registry.halfOpenTotal, len(ep.registry.bySource)
		ep.registry.mu.Unlock()
		if half > ep.registry.maxHalfOpen || srcs > ep.registry.maxHalfOpen {
			t.Fatalf("per-source state exceeded the half-open bound: halfOpen=%d bySource=%d", half, srcs)
		}
	})
}
