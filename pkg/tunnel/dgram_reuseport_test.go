package tunnel

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// TestReserveSourceBootstrapRace drives two concurrent bootstrap ClientHellos for
// the SAME source through routeDatagram from two goroutines (what the SO_REUSEPORT
// parallel-receive path does when the kernel hashes a ClientHello and its retransmit
// to different sockets). Exactly one responder session must be created and exactly
// one half-open slot claimed - the regression test for the reserveSource fix. On the
// old separate-lock deliverHandshake this fails (two sessions, leaked slot) under
// -race / repetition.
func TestReserveSourceBootstrapRace(t *testing.T) {
	for attempt := 0; attempt < 50; attempt++ {
		ep := mustEndpoint(t, newBlackholeConn())
		src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
		frame := clientHelloFrame(t, 0x1234, 0, 64, 64, nil)

		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = ep.routeDatagram(src, append([]byte(nil), frame...))
			}()
		}
		wg.Wait()

		// Exactly one responder session and one half-open slot for the source.
		if got := ep.registry.count(); got != 1 {
			t.Fatalf("attempt %d: created %d responder sessions for one source, want 1", attempt, got)
		}
		if got := ep.registry.halfOpenLoad(); got != 1 {
			t.Fatalf("attempt %d: half-open count = %d, want 1 (a leaked or double slot)", attempt, got)
		}
		_ = ep.Close()
	}
}

// blackholeConn is a net.PacketConn whose ReadFrom blocks until close and whose
// WriteTo discards. The bootstrap-race test drives routeDatagram directly and never
// runs Serve, but startResponder's handshake goroutine may try to send a
// ServerHello; this swallows it without a real socket.
type blackholeConn struct{ closed chan struct{} }

func newBlackholeConn() *blackholeConn { return &blackholeConn{closed: make(chan struct{})} }

func (c *blackholeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *blackholeConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *blackholeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *blackholeConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blackholeConn) SetDeadline(time.Time) error      { return nil }
func (c *blackholeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blackholeConn) SetWriteDeadline(time.Time) error { return nil }

// TestReserveSourceOutcomes exercises reserveSource's three outcomes directly: admit
// a new source, route a second ClientHello for an in-progress source to the existing
// responder, and drop once the per-source half-open cap is reached. It also asserts
// the build closure runs ONLY on the admit path, so a lost retransmit or a capped
// ClientHello allocates no session. This is the production bootstrap admission path
// the SO_REUSEPORT fan-out relies on; the tryAddHalfOpen-based tests no longer cover
// it since reserveSource owns the decision.
//
// The cap branch is defensive: in production reserveSource is the only half-open
// incrementer and it dedups per source (the existing-responder check fires first), so
// one source tops out at a single in-progress responder and never reaches the cap on
// its own. The test fills the slots directly via tryAddHalfOpen to reach that branch.
func TestReserveSourceOutcomes(t *testing.T) {
	r := newConnRegistry()
	builds := 0
	build := func() *datagramSession { builds++; return &datagramSession{} }

	// New source: admitted, build runs once, one slot claimed.
	const src = "203.0.113.7:51820"
	first, won := r.reserveSource(src, build)
	if !won || first == nil {
		t.Fatalf("new source: got (%v, %v), want admitted", first, won)
	}
	if builds != 1 || r.halfOpenLoad() != 1 {
		t.Fatalf("after admit: builds=%d halfOpen=%d, want 1 and 1", builds, r.halfOpenLoad())
	}

	// Same in-progress source: routes to the existing responder, no build, no extra slot.
	again, won := r.reserveSource(src, build)
	if won || again != first {
		t.Fatalf("retransmit: got (%v, %v), want the existing session and won=false", again, won)
	}
	if builds != 1 || r.halfOpenLoad() != 1 {
		t.Fatalf("after retransmit: builds=%d halfOpen=%d, want unchanged 1 and 1", builds, r.halfOpenLoad())
	}

	// Capped source: fill its half-open slots, then reserveSource must drop without building.
	const capped = "198.51.100.4:51820"
	for i := 0; i < constants.DatagramMaxHalfOpenPerSource; i++ {
		if !r.tryAddHalfOpen(capped) {
			t.Fatalf("slot %d for capped source should be admitted (cap %d)", i, constants.DatagramMaxHalfOpenPerSource)
		}
	}
	buildsBefore := builds
	ds, won := r.reserveSource(capped, build)
	if won || ds != nil {
		t.Fatalf("capped source: got (%v, %v), want (nil, false)", ds, won)
	}
	if builds != buildsBefore {
		t.Fatalf("build ran on the capped path (%d -> %d), want no allocation", buildsBefore, builds)
	}
}

// TestListenDatagram checks the constructor works on every platform: it returns a
// usable endpoint bound to a concrete port, honoring WithReceiveSockets. On Linux it
// opens multiple SO_REUSEPORT sockets sharing the port; elsewhere it degrades to one
// (still usable). It does not assert the socket count (that is platform-specific and
// covered by the Linux e2e test); it asserts construction + a real bound address.
func TestListenDatagram(t *testing.T) {
	ep, err := ListenDatagram("udp", "127.0.0.1:0", WithReceiveSockets(4))
	if err != nil {
		t.Fatalf("ListenDatagram: %v", err)
	}
	defer func() { _ = ep.Close() }()

	addr := ep.conn.LocalAddr().(*net.UDPAddr)
	if addr.Port == 0 {
		t.Fatal("ListenDatagram did not resolve an ephemeral port")
	}
	// Every receive socket (primary + extras) must share that resolved port.
	for i, c := range ep.extraConns {
		if got := c.LocalAddr().(*net.UDPAddr).Port; got != addr.Port {
			t.Fatalf("extra socket %d on port %d, want shared %d", i, got, addr.Port)
		}
	}
}

// TestListenDatagramEndToEnd dials several concurrent flows into a ListenDatagram
// responder (parallel receive across sockets where available) and asserts every
// handshake completes and data round-trips both ways - proving concurrent
// routeDatagram over the fan-out receive path is correct.
func TestListenDatagramEndToEnd(t *testing.T) {
	server, err := ListenDatagram("udp", "127.0.0.1:0", WithReceiveSockets(4))
	if err != nil {
		t.Fatalf("ListenDatagram: %v", err)
	}
	defer func() { _ = server.Close() }()
	go server.Serve()
	dst := server.conn.LocalAddr()

	const flows = 6
	type result struct {
		conn *DatagramConn
		err  error
	}
	dialCh := make(chan result, flows)
	initiators := make([]*DatagramEndpoint, 0, flows)
	for range flows {
		rx, lerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if lerr != nil {
			t.Fatalf("listen initiator: %v", lerr)
		}
		ep, eerr := NewDatagramEndpoint(rx)
		if eerr != nil {
			t.Fatalf("initiator endpoint: %v", eerr)
		}
		go ep.Serve()
		initiators = append(initiators, ep)
		go func() {
			c, derr := DialDatagram(ep, dst)
			dialCh <- result{c, derr}
		}()
	}
	defer func() {
		for _, ep := range initiators {
			_ = ep.Close()
		}
	}()

	clients := make([]*DatagramConn, 0, flows)
	servers := make([]*datagramSession, 0, flows)
	for range flows {
		select {
		case ds := <-server.acceptCh:
			servers = append(servers, ds)
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d responder sessions surfaced", len(servers), flows)
		}
		select {
		case r := <-dialCh:
			if r.err != nil {
				t.Fatalf("dial: %v", r.err)
			}
			clients = append(clients, r.conn)
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d dials completed", len(clients), flows)
		}
	}

	// Pair each client with ITS server session: concurrent dials complete and
	// surface in arbitrary order, so the i-th client is not the i-th accepted
	// session. A client's peerIndex is the responder session's local index (echoed
	// back during the handshake), so match on that.
	byIndex := make(map[uint32]*datagramSession, len(servers))
	for _, srv := range servers {
		byIndex[srv.index] = srv
	}
	for _, c := range clients {
		srv := byIndex[c.ds.peerIndex]
		if srv == nil {
			t.Fatalf("no responder session for client peerIndex %d", c.ds.peerIndex)
		}
		assertDataRoundTrip(t, c.Session(), srv.session)
		assertDataRoundTrip(t, srv.session, c.Session())
	}
}

// BenchmarkDatagramListenScale measures aggregate delivered goodput into a
// ListenDatagram responder as the receive-socket count varies. On Linux the kernel
// load-balances across the sockets, so this shows the parallel-receive scaling curve
// against the Phase-2 single-goroutine plateau; elsewhere it degrades to one socket.
// Run on Linux with -benchmem (and a hard -timeout). It reuses the flow harness from
// dgram_perf_test.go.
func BenchmarkDatagramListenScale(b *testing.B) {
	for _, sockets := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("sockets=%d", sockets), func(b *testing.B) {
			benchListenFlows(b, sockets, 8)
		})
	}
}
