package tunnel

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// TestFragmentHandshake_PaddingUniformSize asserts that with padding on every
// frame is exactly DatagramMTU, with padding off no frame is padded, and that a
// padded flight still reassembles to the identical original message (the padding
// is sliced off by the parser before reassembly).
func TestFragmentHandshake_PaddingUniformSize(t *testing.T) {
	msg := make([]byte, 1644) // spans two datagrams
	for i := range msg {
		msg[i] = byte(i)
	}
	base := protocol.DatagramHandshakeHeader{
		DatagramHeader: protocol.DatagramHeader{RecvIndex: 7, Seq: 100},
		SenderIndex:    42,
		MsgType:        protocol.MessageTypeClientHello,
	}

	padded, err := fragmentHandshake(base, msg, true)
	if err != nil {
		t.Fatalf("padded fragment: %v", err)
	}
	if len(padded) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(padded))
	}
	for i, f := range padded {
		if len(f) != constants.DatagramMTU {
			t.Fatalf("padded frame %d is %d bytes, want exactly MTU %d", i, len(f), constants.DatagramMTU)
		}
	}

	plain, err := fragmentHandshake(base, msg, false)
	if err != nil {
		t.Fatalf("unpadded fragment: %v", err)
	}
	// At least one frame (the last, short one) must be below MTU when not padded.
	allMTU := true
	for _, f := range plain {
		if len(f) != constants.DatagramMTU {
			allMTU = false
		}
	}
	if allMTU {
		t.Fatal("unpadded frames should not all be MTU-sized")
	}

	// A padded flight reassembles to the identical original.
	r := NewReassembler(4, 8192, time.Second)
	var out []byte
	var done bool
	for i, f := range padded {
		h, frag, perr := protocol.ParseDatagramHandshake(f)
		if perr != nil {
			t.Fatalf("frame %d parse: %v", i, perr)
		}
		out, done, err = r.Add("peer", h, frag)
		if err != nil {
			t.Fatalf("frame %d reassemble: %v", i, err)
		}
	}
	if !done || !bytes.Equal(out, msg) {
		t.Fatal("padded flight did not reassemble to the original message")
	}
}

// recordingConn wraps a net.PacketConn and records the size and frame type of
// every datagram written, so a test can assert handshake datagrams are padded to
// the MTU while data datagrams are not.
type recordingConn struct {
	net.PacketConn
	mu          sync.Mutex
	handshakeSz []int
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if typ, err := protocol.PeekDatagramType(p); err == nil && typ == protocol.DatagramFrameHandshake {
		c.mu.Lock()
		c.handshakeSz = append(c.handshakeSz, len(p))
		c.mu.Unlock()
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *recordingConn) sizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.handshakeSz...)
}

// TestDgramHandshakePaddingE2E runs a full handshake with both ends padding, over
// a lossless in-memory pipe, and asserts the handshake completes, data flows both
// ways, and every handshake datagram either side emitted was exactly DatagramMTU.
func TestDgramHandshakePaddingE2E(t *testing.T) {
	connA, connB := memPipe(1, 0, 0, 0) // lossless: deterministic size assertions
	recA := &recordingConn{PacketConn: connA}
	recB := &recordingConn{PacketConn: connB}

	epA, err := NewDatagramEndpoint(recA, WithHandshakePadding())
	if err != nil {
		t.Fatalf("endpoint A: %v", err)
	}
	epB, err := NewDatagramEndpoint(recB, WithHandshakePadding())
	if err != nil {
		t.Fatalf("endpoint B: %v", err)
	}
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 2 * time.Millisecond
		ep.rtoMax = 20 * time.Millisecond
	}
	go epA.Serve()
	go epB.Serve()
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	type dialResult struct {
		conn *DatagramConn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, err := DialDatagram(epA, connB.addr)
		dialCh <- dialResult{c, err}
	}()

	var server *Session
	select {
	case ds := <-epB.acceptCh:
		server = ds.session
	case <-time.After(5 * time.Second):
		t.Fatal("responder did not surface a session")
	}

	var client *Session
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("dial: %v", r.err)
		}
		client = r.conn.Session()
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not complete")
	}

	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
	assertDataRoundTrip(t, client, server)
	assertDataRoundTrip(t, server, client)

	// Every handshake datagram both ends sent must be padded to the MTU.
	for _, rec := range []*recordingConn{recA, recB} {
		sizes := rec.sizes()
		if len(sizes) == 0 {
			t.Fatal("no handshake datagrams recorded")
		}
		for i, sz := range sizes {
			if sz != constants.DatagramMTU {
				t.Fatalf("handshake datagram %d is %d bytes, want padded MTU %d", i, sz, constants.DatagramMTU)
			}
		}
	}
}
