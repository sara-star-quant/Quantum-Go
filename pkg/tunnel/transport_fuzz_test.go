package tunnel

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// FuzzTransportReceive drives the stream receive loop with arbitrary bytes after a real
// handshake, as a peer that holds no valid key could. Every message type reaches its
// handler (data, ping, pong, close, rekey, alert, unknown). Receive must return an error
// or data, never panic and never hang.
func FuzzTransportReceive(f *testing.F) {
	for _, typ := range []protocol.MessageType{
		protocol.MessageTypeData, protocol.MessageTypePing, protocol.MessageTypePong,
		protocol.MessageTypeClose, protocol.MessageTypeRekey, protocol.MessageTypeAlert,
		protocol.MessageType(0xEE),
	} {
		f.Add(frame(typ, nil))
		f.Add(frame(typ, make([]byte, 48)))
	}
	f.Add([]byte(nil))
	f.Add([]byte{byte(protocol.MessageTypeData), 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		ca, cb := net.Pipe()
		defer func() { _ = ca.Close(); _ = cb.Close() }()
		_ = ca.SetDeadline(time.Now().Add(5 * time.Second))
		_ = cb.SetDeadline(time.Now().Add(5 * time.Second))

		ci, _ := NewSession(RoleInitiator)
		ri, _ := NewSession(RoleResponder)
		errs := make(chan error, 2)
		go func() { errs <- InitiatorHandshake(ci, ca) }()
		go func() { errs <- ResponderHandshake(ri, cb) }()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatalf("handshake: %v", err)
			}
		}
		tr, err := NewTransport(ri, cb, DefaultTransportConfig())
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			_, _ = ca.Write(data)
			_ = ca.Close()
		}()
		go func() { _, _ = io.Copy(io.Discard, ca) }()

		for range 64 {
			if _, err := tr.Receive(); err != nil {
				break
			}
		}
	})
}
