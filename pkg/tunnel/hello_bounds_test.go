package tunnel_test

import (
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// One short ClientHello whose session-ID length runs past the message used to panic the server's
// handshake goroutine and end the process. The listener must refuse it and keep serving.
func TestListenerSurvivesAHelloWithAnOversizedSessionID(t *testing.T) {
	ln, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *tunnel.Tunnel, 1)
	go func() {
		for {
			tn, err := ln.Accept()
			if err != nil {
				continue // a refused handshake: keep listening
			}
			accepted <- tn
			return
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	const payloadLen = 60
	msg := make([]byte, protocol.HeaderSize+payloadLen)
	msg[0] = byte(protocol.MessageTypeClientHello)
	msg[4] = payloadLen
	msg[protocol.HeaderSize] = protocol.Current.Major
	msg[protocol.HeaderSize+1] = protocol.Current.Minor
	msg[protocol.HeaderSize+2+32] = 255 // session ID length
	if _, err := raw.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = raw.Read(make([]byte, 64)) // the refusal alert, or the close
	_ = raw.Close()

	client, err := tunnel.DialInsecure("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the listener stopped serving after the malformed hello: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case srv := <-accepted:
		_ = srv.Close()
	case <-time.After(15 * time.Second):
		t.Fatal("the listener did not accept the honest client")
	}
}
