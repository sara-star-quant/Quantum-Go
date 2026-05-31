package tunnel

import (
	"net"
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
