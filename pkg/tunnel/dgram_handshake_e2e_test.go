package tunnel

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// memAddr is a stable in-memory packet address.
type memAddr struct{ name string }

func (a memAddr) Network() string { return "mempipe" }
func (a memAddr) String() string  { return a.name }

// memPacket is one datagram in flight.
type memPacket struct {
	data []byte
	src  net.Addr
}

// faultModel deterministically drops, duplicates, and reorders datagrams on the
// send path using a seeded PRNG, so a given seed reproduces a run exactly.
type faultModel struct {
	mu                    sync.Mutex
	rng                   *rand.Rand
	dropP, dupP, reorderP float64
	held                  []byte // a single packet held back to reorder with the next
}

func newFaultModel(seed uint64, drop, dup, reorder float64) *faultModel {
	return &faultModel{
		rng:      rand.New(rand.NewPCG(seed, seed+0x9e3779b9)),
		dropP:    drop,
		dupP:     dup,
		reorderP: reorder,
	}
}

func (f *faultModel) emit(peer *memPacketConn, data []byte, src net.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.rng.Float64() < f.dropP {
		return // lost
	}
	if f.held == nil && f.rng.Float64() < f.reorderP {
		f.held = data // hold it back; the next packet overtakes it
		return
	}
	if f.held != nil {
		held := f.held
		f.held = nil
		f.deliver(peer, data, src) // newer packet first
		f.deliver(peer, held, src) // then the held (reordered) one
		return
	}
	f.deliver(peer, data, src)
}

func (f *faultModel) deliver(peer *memPacketConn, data []byte, src net.Addr) {
	n := 1
	if f.rng.Float64() < f.dupP {
		n = 2
	}
	for range n {
		peer.enqueue(memPacket{data: data, src: src})
	}
}

// memPacketConn is one end of an in-memory net.PacketConn pair.
type memPacketConn struct {
	addr      memAddr
	peer      *memPacketConn
	fault     *faultModel
	in        chan memPacket
	closed    chan struct{}
	closeOnce sync.Once
}

func newMemPacketConn(name string, fault *faultModel) *memPacketConn {
	return &memPacketConn{
		addr:   memAddr{name: name},
		fault:  fault,
		in:     make(chan memPacket, 256),
		closed: make(chan struct{}),
	}
}

func (c *memPacketConn) enqueue(p memPacket) {
	select {
	case c.in <- p:
	case <-c.closed:
	default: // full: drop (an additional, rare loss)
	}
}

func (c *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.in:
		return copy(p, pkt.data), pkt.src, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.fault.emit(c.peer, append([]byte(nil), p...), c.addr)
	return len(p), nil
}

func (c *memPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *memPacketConn) LocalAddr() net.Addr              { return c.addr }
func (c *memPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *memPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memPacketConn) SetWriteDeadline(time.Time) error { return nil }

// memPipe wires two endpoints together with independent per-direction faults.
func memPipe(seed uint64, drop, dup, reorder float64) (a, b *memPacketConn) {
	a = newMemPacketConn("A", newFaultModel(seed, drop, dup, reorder))
	b = newMemPacketConn("B", newFaultModel(seed+1, drop, dup, reorder))
	a.peer, b.peer = b, a
	return a, b
}

// TestDgramHandshakeE2E runs the full datagram handshake over an in-memory
// transport that drops, duplicates, and reorders datagrams, across many seeds. It
// asserts the handshake completes, the responder surfaces the session on its
// accept channel, and the two sides derive matching directional keys (proven by a
// bidirectional encrypt/decrypt round-trip).
func TestDgramHandshakeE2E(t *testing.T) {
	const (
		drop    = 0.2
		dup     = 0.1
		reorder = 0.15
	)
	for seed := uint64(1); seed <= 24; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			runE2E(t, seed, drop, dup, reorder)
		})
	}
}

func runE2E(t *testing.T, seed uint64, drop, dup, reorder float64) {
	t.Helper()
	connA, connB := memPipe(seed, drop, dup, reorder)
	epA := NewDatagramEndpoint(connA)
	epB := NewDatagramEndpoint(connB)
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

	if client == nil || server == nil {
		t.Fatal("nil session(s) after handshake")
	}
	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
	assertDataRoundTrip(t, client, server)
	assertDataRoundTrip(t, server, client)
}

// assertDataRoundTrip encrypts on from and decrypts on to, proving their
// directional keys agree.
func assertDataRoundTrip(t *testing.T, from, to *Session) {
	t.Helper()
	plaintext := []byte("quantum-go datagram payload")
	ct, seq, err := from.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := to.Decrypt(ct, seq)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}
