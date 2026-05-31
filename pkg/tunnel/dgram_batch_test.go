package tunnel

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// scriptedConn is a net.PacketConn for exercising the portable fallbackIO path.
// ReadFrom returns each queued datagram once, then net.ErrClosed (so a recv loop
// terminates); WriteTo records every write. Because it is not a *net.UDPConn,
// newBatchIO returns the fallback on every platform, so this covers the fallback
// uniformly in CI.
type scriptedConn struct {
	mu      sync.Mutex
	reads   []scriptedPkt
	readIdx int
	writes  []scriptedPkt
}

type scriptedPkt struct {
	data []byte
	addr net.Addr
}

func (c *scriptedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readIdx >= len(c.reads) {
		return 0, nil, net.ErrClosed
	}
	pkt := c.reads[c.readIdx]
	c.readIdx++
	n := copy(p, pkt.data)
	return n, pkt.addr, nil
}

func (c *scriptedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, scriptedPkt{data: append([]byte(nil), p...), addr: addr})
	return len(p), nil
}

func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func TestFallbackIORecvDispatchesEachDatagram(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	want := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	conn := &scriptedConn{}
	for _, d := range want {
		conn.reads = append(conn.reads, scriptedPkt{data: d, addr: addr})
	}

	bio := newBatchIO(conn)
	var got [][]byte
	for {
		err := bio.recv(func(src net.Addr, payload []byte) {
			if src != addr {
				t.Errorf("src = %v, want %v", src, addr)
			}
			got = append(got, payload)
		})
		if err != nil {
			break
		}
	}

	if len(got) != len(want) {
		t.Fatalf("dispatched %d datagrams, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("datagram %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFallbackIORecvCopiesPayload(t *testing.T) {
	// recv must hand the callee a copy that survives the reuse of the read buffer
	// on the following recv.
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	conn := &scriptedConn{reads: []scriptedPkt{
		{data: []byte("first"), addr: addr},
		{data: []byte("SECOND-and-longer"), addr: addr},
	}}

	bio := newBatchIO(conn)
	var retained []byte
	_ = bio.recv(func(_ net.Addr, payload []byte) { retained = payload })
	_ = bio.recv(func(_ net.Addr, _ []byte) {})

	if !bytes.Equal(retained, []byte("first")) {
		t.Fatalf("retained payload corrupted by a later recv: %q", retained)
	}
}

func TestWriteAllEmitsEachFrameToDst(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	frames := [][]byte{[]byte("f0"), []byte("f1"), []byte("f2")}
	conn := &scriptedConn{}

	bio := newBatchIO(conn)
	bio.writeAll(frames, dst)

	if len(conn.writes) != len(frames) {
		t.Fatalf("wrote %d datagrams, want %d", len(conn.writes), len(frames))
	}
	for i, w := range conn.writes {
		if !bytes.Equal(w.data, frames[i]) {
			t.Errorf("frame %d = %q, want %q", i, w.data, frames[i])
		}
		if w.addr != dst {
			t.Errorf("frame %d addr = %v, want %v", i, w.addr, dst)
		}
	}
}

func TestWriteAllEmptyEmitsNothing(t *testing.T) {
	conn := &scriptedConn{}
	bio := newBatchIO(conn)
	bio.writeAll(nil, &net.UDPAddr{})
	if len(conn.writes) != 0 {
		t.Fatalf("empty writeAll emitted %d datagrams", len(conn.writes))
	}
}
