package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// dialEstablished stands up two endpoints over a real loopback UDP socket pair,
// runs their Serve loops, completes a handshake, and returns the initiator's
// established DatagramConn plus the responder session. Used by the end-to-end
// throughput benchmark so the measurement includes the full receive loop (batched
// recvmmsg where available), demux, AEAD open, and channel hand-off, not just the
// isolated send path.
func dialEstablished(tb testing.TB, opts ...DatagramEndpointOption) (client *DatagramConn, server *datagramSession, stop func()) {
	tb.Helper()
	rxA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatalf("listen A: %v", err)
	}
	rxB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatalf("listen B: %v", err)
	}

	epA, err := NewDatagramEndpoint(rxA, opts...)
	if err != nil {
		tb.Fatalf("endpoint A: %v", err)
	}
	epB, err := NewDatagramEndpoint(rxB, opts...)
	if err != nil {
		tb.Fatalf("endpoint B: %v", err)
	}
	go epA.Serve()
	go epB.Serve()

	dialCh := make(chan *DatagramConn, 1)
	go func() {
		c, derr := DialDatagram(epA, rxB.LocalAddr())
		if derr != nil {
			tb.Errorf("dial: %v", derr)
			dialCh <- nil
			return
		}
		dialCh <- c
	}()

	select {
	case server = <-epB.acceptCh:
	case <-time.After(5 * time.Second):
		tb.Fatal("responder did not surface a session")
	}
	select {
	case client = <-dialCh:
		if client == nil {
			tb.Fatal("dial failed")
		}
	case <-time.After(5 * time.Second):
		tb.Fatal("dial did not complete")
	}

	stop = func() {
		_ = epA.Close()
		_ = epB.Close()
	}
	return client, server, stop
}

// BenchmarkDatagramEndToEnd measures one-way application goodput over a real
// loopback UDP socket pair through the full data path: zero-alloc seal and send on
// the initiator, then the responder's receive loop (batched recvmmsg on Linux),
// demux, AEAD open, and delivery to recvCh.
//
// It reports DELIVERED goodput, not send rate. The receive path drops on a full
// recvCh (UDP semantics), so a sender that outruns the receiver would have its
// drops silently counted as throughput. A credit window bounds in-flight datagrams
// below the recvCh buffer: the sender needs a credit per Send and the drainer
// issues one credit per datagram pulled off recvCh, so the sender can never overrun
// the receiver and every counted datagram is actually delivered. If the kernel ever
// dropped one, the missing credit would stall the sender (a visible hang) rather
// than inflate the number. The post-loop check asserts delivery covered all but the
// in-flight window.
func BenchmarkDatagramEndToEnd(b *testing.B) {
	client, server, stop := dialEstablished(b)
	defer stop()

	payload := make([]byte, constants.DatagramMaxDataPayload)

	// window must stay below the recvCh buffer (dataInboxCap) so recvCh never
	// overflows; that is what makes every sent datagram a delivered one.
	const window = 32
	credits := make(chan struct{}, window)
	for range window {
		credits <- struct{}{}
	}
	var received int64
	stopDrain := make(chan struct{})
	go func() {
		for {
			select {
			case <-server.recvCh:
				atomic.AddInt64(&received, 1)
				select {
				case credits <- struct{}{}:
				case <-stopDrain:
					return
				}
			case <-server.closed:
				return
			case <-stopDrain:
				return
			}
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		<-credits
		if err := client.Send(payload); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
	b.StopTimer()
	close(stopDrain)

	// Every datagram except the at-most-window still in flight must have been
	// delivered; a larger shortfall means silent drops were inflating the rate.
	if got := atomic.LoadInt64(&received); got < int64(b.N)-window {
		b.Fatalf("delivered %d of %d datagrams: drops are inflating the throughput number", got, b.N)
	}
}

// dialFlows establishes n concurrent sessions into one shared single-socket
// responder endpoint. See dialFlowsInto for the mechanics and why one initiator per
// flow is used.
func dialFlows(tb testing.TB, n int) (clients []*DatagramConn, servers []*datagramSession, stop func()) {
	tb.Helper()
	rxB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatalf("listen responder: %v", err)
	}
	// A real server sets a large receive buffer; without it the default socket
	// buffer drops heavily under many concurrent flows (worse on macOS loopback),
	// which would make the aggregate number reflect the test harness, not the
	// transport. Best-effort: the OS may clamp it.
	_ = rxB.SetReadBuffer(8 << 20)
	epB, err := NewDatagramEndpoint(rxB)
	if err != nil {
		tb.Fatalf("responder endpoint: %v", err)
	}
	go epB.Serve()
	return dialFlowsInto(tb, epB, rxB.LocalAddr(), n)
}

// dialFlowsInto dials n concurrent sessions into the already-serving responder
// endpoint at dst, each from its own initiator endpoint (socket). One initiator per
// flow is both realistic (n clients = n sockets) and necessary: the responder
// bootstraps a new handshake keyed by source address for the RecvIndex-0
// ClientHello, so several simultaneous handshakes from one source would collide at
// bootstrap (they are only index-demuxed after establishment). The responder is the
// system under test - its receive goroutine(s) demux and drain all n flows. Returns
// the n initiator conns paired with their responder sessions and a stop func that
// closes both the responder and the initiators.
func dialFlowsInto(tb testing.TB, responder *DatagramEndpoint, dst net.Addr, n int) (clients []*DatagramConn, servers []*datagramSession, stop func()) {
	tb.Helper()
	initiators := make([]*DatagramEndpoint, 0, n)
	type dialResult struct {
		conn *DatagramConn
		err  error
	}
	dialCh := make(chan dialResult, n)
	for range n {
		rxA, lerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if lerr != nil {
			tb.Fatalf("listen initiator: %v", lerr)
		}
		epA, eerr := NewDatagramEndpoint(rxA)
		if eerr != nil {
			tb.Fatalf("initiator endpoint: %v", eerr)
		}
		go epA.Serve()
		initiators = append(initiators, epA)
		go func() {
			c, derr := DialDatagram(epA, dst)
			dialCh <- dialResult{c, derr}
		}()
	}
	for range n {
		select {
		case ds := <-responder.acceptCh:
			servers = append(servers, ds)
		case <-time.After(10 * time.Second):
			tb.Fatalf("only %d of %d responder sessions surfaced", len(servers), n)
		}
		select {
		case r := <-dialCh:
			if r.err != nil {
				tb.Fatalf("dial: %v", r.err)
			}
			clients = append(clients, r.conn)
		case <-time.After(10 * time.Second):
			tb.Fatalf("only %d of %d dials completed", len(clients), n)
		}
	}

	stop = func() {
		_ = responder.Close()
		for _, ep := range initiators {
			_ = ep.Close()
		}
	}
	return clients, servers, stop
}

// BenchmarkDatagramEndToEndFlows measures AGGREGATE delivered goodput across N
// concurrent flows into one shared responder endpoint - the server-relevant number,
// where one Serve goroutine demuxes and drains all flows. Run with -benchmem and
// e.g. -cpu=1,4,8 to see how aggregate throughput scales with cores.
//
// Each flow is closed-loop rate-matched: a per-flow credit window bounds in-flight
// datagrams, and the drainer returns a credit on each delivery, so the sender
// naturally paces to the rate the receiver can sustain (no blasting, so almost
// nothing is dropped and the number is honest goodput). Two safety mechanisms keep
// it from the failure modes earlier versions hit: a large responder receive buffer
// (set in dialFlows) makes kernel drops rare, and a watchdog tops up each flow's
// credits every 100ms so a datagram the kernel does drop cannot permanently remove
// a credit and wedge the sender (the deadlock a strict credit window hit). The
// watchdog's top-up rate is negligible against the real delivery rate, so it does
// not distort the measurement the way a per-send timeout did. SetBytes reports the
// send rate; recv-MB/s reports delivered goodput over the same wall-clock - the two
// track closely while the responder keeps up and diverge once it saturates.
func BenchmarkDatagramEndToEndFlows(b *testing.B) {
	// 1..8 flows shows the scaling curve; the single responder Serve goroutine
	// saturates within this range, so higher counts add only contention (and, in a
	// resource-constrained CI container, socket/goroutine pressure across the shared
	// benchmark process) without new signal.
	for _, flows := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("flows=%d", flows), func(b *testing.B) {
			clients, servers, stop := dialFlows(b, flows)
			defer stop()
			runFlowGoodput(b, clients, servers)
		})
	}
}

// runFlowGoodput drives the closed-loop aggregate-goodput measurement over the
// established clients/servers: each flow sends b.N/flows datagrams paced by a
// per-flow credit window the drainer refills on delivery, with a watchdog top-up so
// a kernel drop cannot wedge a sender. SetBytes reports the send rate; recv-MB/s
// reports delivered goodput over the same wall-clock. Shared by the single-socket
// (BenchmarkDatagramEndToEndFlows) and SO_REUSEPORT (BenchmarkDatagramListenScale)
// benchmarks so they measure identically.
func runFlowGoodput(b *testing.B, clients []*DatagramConn, servers []*datagramSession) {
	b.Helper()
	flows := len(clients)
	payload := make([]byte, constants.DatagramMaxDataPayload)
	const window = 16 // per-flow in-flight bound; well below dataInboxCap (64)
	var received int64
	stopDrain := make(chan struct{})
	var drainWG sync.WaitGroup

	// Per-flow credit semaphores (buffered channels), pre-filled to the window.
	credits := make([]chan struct{}, flows)
	for i := range credits {
		credits[i] = make(chan struct{}, window)
		for range window {
			credits[i] <- struct{}{}
		}
	}

	// One drainer per responder session: count the delivery and return a credit to
	// its flow (non-blocking - the window cap means the channel can be full).
	for i := range servers {
		srv, cr := servers[i], credits[i]
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			for {
				select {
				case <-srv.recvCh:
					atomic.AddInt64(&received, 1)
					select {
					case cr <- struct{}{}:
					default:
					}
				case <-srv.closed:
					return
				case <-stopDrain:
					return
				}
			}
		}()
	}

	// Watchdog: restore a credit per flow every 100ms so a kernel-dropped datagram
	// (whose credit the drainer never returns) cannot permanently wedge a sender. Far
	// below the real delivery rate, so it does not pace the bench.
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, cr := range credits {
					select {
					case cr <- struct{}{}:
					default:
					}
				}
			case <-stopDrain:
				return
			}
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	// Spread b.N sends across the flows concurrently so all cores stay busy. Capture
	// the first send error atomically rather than calling b.Errorf from these
	// goroutines: testing.B is not safe for concurrent Errorf, and CI runs under
	// -race. Report it on the main goroutine after the senders join.
	var wg sync.WaitGroup
	var sendErr atomic.Value
	per := b.N / flows
	for i := range clients {
		count := per
		if i == len(clients)-1 {
			count = b.N - per*(flows-1) // remainder on the last flow
		}
		c, cr := clients[i], credits[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range count {
				<-cr
				if err := c.Send(payload); err != nil {
					sendErr.CompareAndSwap(nil, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := b.Elapsed()
	b.StopTimer()
	close(stopDrain)
	drainWG.Wait() // do not leak drainers past this measurement

	if err, _ := sendErr.Load().(error); err != nil {
		b.Fatalf("send: %v", err)
	}
	if secs := elapsed.Seconds(); secs > 0 {
		got := atomic.LoadInt64(&received)
		b.ReportMetric(float64(got*int64(len(payload)))/secs/1e6, "recv-MB/s")
	}
}

// benchListenFlows runs the aggregate-goodput measurement against a ListenDatagram
// responder configured with the given SO_REUSEPORT socket count, so the benchmark
// shows how aggregate throughput scales with receive sockets.
func benchListenFlows(b *testing.B, sockets, flows int) {
	b.Helper()
	responder, err := ListenDatagram("udp", "127.0.0.1:0", WithReceiveSockets(sockets))
	if err != nil {
		b.Fatalf("ListenDatagram: %v", err)
	}
	for _, c := range append([]net.PacketConn{responder.conn}, responder.extraConns...) {
		if uc, ok := c.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(8 << 20)
		}
	}
	go responder.Serve()
	clients, servers, stop := dialFlowsInto(b, responder, responder.conn.LocalAddr(), flows)
	defer stop()
	runFlowGoodput(b, clients, servers)
}

// BenchmarkDatagramRecvBacklog measures the receive path under a real backlog: a
// background flood keeps the socket buffer full so each recvmmsg ReadBatch returns
// a full batch, which is the condition recvmmsg amortization is for (the matched-
// rate BenchmarkDatagramRecv* return only 1-2 datagrams per call and hide it). It
// drives the batchIO recv directly (raw datagrams, no session), so it isolates the
// syscall-batching effect from the crypto path. Compare batch vs single here for the
// honest recvmmsg win.
func BenchmarkDatagramRecvBacklog(b *testing.B) {
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer func() { _ = rx.Close() }()
	// A large socket receive buffer lets the flood build a real backlog.
	_ = rx.SetReadBuffer(4 << 20)
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer func() { _ = tx.Close() }()

	payload := make([]byte, constants.DatagramMaxDataPayload)
	stop := make(chan struct{})
	// Several flooders to keep the buffer full even as the receiver drains fast.
	for range 3 {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = tx.Write(payload)
				}
			}
		}()
	}

	bio := newBatchIO(rx)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	received := 0
	for received < b.N {
		if err := bio.recv(func(_ net.Addr, _ []byte) { received++ }); err != nil {
			b.Fatalf("recv: %v", err)
		}
	}
	b.StopTimer()
	close(stop)
}

// handshakeWireBytes sums the on-wire bytes of one handshake flight (here a
// ClientHello-sized message) fragmented with and without padding, so a test can
// report the padding bandwidth overhead in concrete terms.
func handshakeWireBytes(pad bool) int {
	msg := make([]byte, 1644) // ~ ClientHello size
	base := protocol.DatagramHandshakeHeader{
		SenderIndex: 1,
		MsgType:     protocol.MessageTypeClientHello,
	}
	frames, err := fragmentHandshake(base, msg, pad)
	if err != nil {
		return -1
	}
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	return total
}

// TestHandshakePaddingOverhead records the concrete bandwidth cost of handshake
// padding: it is a measurement, not a pass/fail invariant beyond "padding is
// larger and rounds each datagram to the MTU". The numbers feed the docs.
func TestHandshakePaddingOverhead(t *testing.T) {
	unpadded := handshakeWireBytes(false)
	padded := handshakeWireBytes(true)
	if unpadded <= 0 || padded <= 0 {
		t.Fatalf("fragmentation failed: unpadded=%d padded=%d", unpadded, padded)
	}
	if padded <= unpadded {
		t.Fatalf("padded flight (%d B) should exceed unpadded (%d B)", padded, unpadded)
	}
	t.Logf("ClientHello flight on the wire: unpadded=%d B, padded=%d B (+%d B, %.1f%%)",
		unpadded, padded, padded-unpadded, 100*float64(padded-unpadded)/float64(unpadded))
}
