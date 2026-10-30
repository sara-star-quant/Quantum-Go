package tunnel

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
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

	// dropFirst, if non-zero, drops exactly the first handshake datagram of this
	// message type (a targeted loss for recovery tests).
	dropFirst   protocol.MessageType
	dropFirstOK bool
}

// isFirstOfDropType reports whether data is the first datagram of the targeted
// handshake message type, and marks the target consumed.
func (f *faultModel) isFirstOfDropType(data []byte) bool {
	if f.dropFirst == 0 || f.dropFirstOK {
		return false
	}
	if ft, err := protocol.PeekDatagramType(data); err != nil || ft != protocol.DatagramFrameHandshake {
		return false
	}
	h, _, err := protocol.ParseDatagramHandshake(data)
	if err != nil || h.MsgType != f.dropFirst {
		return false
	}
	f.dropFirstOK = true
	return true
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

	if f.isFirstOfDropType(data) || f.rng.Float64() < f.dropP {
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
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 250 * time.Millisecond
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

// TestDgramHandshakeCookieRoundTrip drives a full handshake with the responder
// forced permanently under cookie pressure, so the initiator's first ClientHello
// is answered with a RETRY. It asserts the initiator adopts the cookie, re-sends,
// and the handshake then completes with working bidirectional data keys.
func TestDgramHandshakeCookieRoundTrip(t *testing.T) {
	connA, connB := memPipe(1, 0, 0, 0) // lossless: isolate the cookie round trip
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	epB.cookiePressureHighWater = 0 // responder always demands a cookie
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 250 * time.Millisecond
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
		t.Fatal("responder did not surface a session through the cookie gate")
	}

	var client *Session
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("dial: %v", r.err)
		}
		client = r.conn.Session()
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not complete through the cookie gate")
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

// runTargetedLoss runs one handshake where the dialer's or responder's send path
// drops exactly the first datagram of msg, then checks both sides still establish
// and exchange data. fromDialer selects which side's sends are cut.
func runTargetedLoss(t *testing.T, msg protocol.MessageType, fromDialer bool) {
	t.Helper()
	connA, connB := memPipe(1, 0, 0, 0)
	if fromDialer {
		connA.fault.dropFirst = msg
	} else {
		connB.fault.dropFirst = msg
	}
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 250 * time.Millisecond
	}
	go epA.Serve()
	go epB.Serve()
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	dialCh := make(chan *DatagramConn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := DialDatagram(epA, connB.addr)
		if err != nil {
			errCh <- err
			return
		}
		dialCh <- c
	}()

	var server *Session
	select {
	case ds := <-epB.acceptCh:
		server = ds.session
	case <-time.After(5 * time.Second):
		t.Fatalf("responder did not surface a session after losing %v", msg)
	}
	var client *Session
	select {
	case c := <-dialCh:
		client = c.Session()
	case err := <-errCh:
		t.Fatalf("dial after losing %v: %v", msg, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("dial did not complete after losing %v", msg)
	}
	if connA.fault.dropFirst != 0 && !connA.fault.dropFirstOK || connB.fault.dropFirst != 0 && !connB.fault.dropFirstOK {
		t.Fatalf("the targeted %v datagram was never sent, so nothing was lost", msg)
	}
	assertDataRoundTrip(t, client, server)
	assertDataRoundTrip(t, server, client)
}

// TestDgramHandshakeLostClientFinished drops the dialer's first ClientFinished. The
// responder never completes until its retransmitted server flight makes the lingering
// initiator replay the cached ClientFinished.
func TestDgramHandshakeLostClientFinished(t *testing.T) {
	runTargetedLoss(t, protocol.MessageTypeClientFinished, true)
}

// TestDgramHandshakeLostServerFinished drops the responder's first ServerFinished. The
// initiator stays unkeyed, retransmits its ClientHello, and the responder replays the
// cached flight.
func TestDgramHandshakeLostServerFinished(t *testing.T) {
	runTargetedLoss(t, protocol.MessageTypeServerFinished, false)
}

// TestDgramHandshakeLostServerHello drops the responder's first ServerHello; the rest
// of the flight (ServerFinished) arrives first and is dropped as out of order until
// the replayed flight delivers both in order.
func TestDgramHandshakeLostServerHello(t *testing.T) {
	runTargetedLoss(t, protocol.MessageTypeServerHello, false)
}

// TestDgramEarlyDataSurvivesLostClientFinished loses the dialer's first ClientFinished
// and has the dialer send application data the moment its dial returns, so the data
// reaches the responder before the responder is keyed. The responder must hold those
// datagrams and deliver them, in order, once the replayed ClientFinished keys it.
func TestDgramEarlyDataSurvivesLostClientFinished(t *testing.T) {
	connA, connB := memPipe(1, 0, 0, 0)
	connA.fault.dropFirst = protocol.MessageTypeClientFinished
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 50 * time.Millisecond // slow replay so the data races ahead of it
		ep.rtoMax = 200 * time.Millisecond
	}
	go epA.Serve()
	go epB.Serve()
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	client, err := DialDatagram(epA, connB.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	want := [][]byte{[]byte("early-0"), []byte("early-1"), []byte("early-2")}
	for _, m := range want {
		if err := client.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	type accepted struct {
		conn *DatagramConn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := epB.Accept()
		accCh <- accepted{c, err}
	}()
	var server *DatagramConn
	select {
	case a := <-accCh:
		if a.err != nil {
			t.Fatalf("accept: %v", a.err)
		}
		server = a.conn
	case <-time.After(5 * time.Second):
		t.Fatal("responder did not surface a session")
	}

	for i, m := range want {
		got := make(chan []byte, 1)
		go func() { b, _ := server.Recv(); got <- b }()
		select {
		case b := <-got:
			if !bytes.Equal(b, m) {
				t.Fatalf("datagram %d = %q, want %q", i, b, m)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("early datagram %d (%q) was lost", i, m)
		}
	}
}

// TestDgramRedialSameSourceNoStall dials repeatedly from one source address and
// asserts no handshake waits out a retransmit timeout. A ClientHello that races the
// previous responder's cleanup must be re-dispatched, not dropped.
func TestDgramRedialSameSourceNoStall(t *testing.T) {
	connA, connB := memPipe(1, 0, 0, 0)
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 300 * time.Millisecond
		ep.rtoMax = time.Second
	}
	go epA.Serve()
	go epB.Serve()
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	dials := 300
	if v, err := strconv.Atoi(os.Getenv("QGO_SOAK_DIALS")); err == nil && v > 0 {
		dials = v // longer soak run, set by the bench workflow
	}
	for i := 0; i < dials; i++ {
		start := time.Now()
		if _, err := DialDatagram(epA, connB.addr); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("dial %d took %v: stalled on a retransmit timeout", i, d)
		}
	}

	// Every handshake finished, so the responder must hold no half-open slot and no
	// in-progress source entry.
	deadline := time.Now().Add(5 * time.Second)
	for {
		epB.registry.mu.Lock()
		half, srcs := epB.registry.halfOpenTotal, len(epB.registry.bySource)
		epB.registry.mu.Unlock()
		if half == 0 && srcs == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaked responder state after redials: halfOpen=%d bySource=%d", half, srcs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
