package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// captureConn is a net.PacketConn that records every WriteTo and never delivers a
// read. Tests drive routeDatagram directly (no Serve loop), so ReadFrom is unused.
type captureConn struct {
	mu      sync.Mutex
	written [][]byte
}

func (c *captureConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *captureConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.written = append(c.written, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return memAddr{name: "cap"} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func (c *captureConn) writes() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.written))
	copy(out, c.written)
	return out
}

// clientHelloFrame builds a single bootstrap ClientHello handshake frame with a
// fragment of fragLen bytes and the given declared total length and cookie.
func clientHelloFrame(t *testing.T, senderIndex uint32, recvIndex uint32, fragLen, total int, cookie []byte) []byte {
	t.Helper()
	frame, err := protocol.EncodeDatagramHandshake(protocol.DatagramHandshakeHeader{
		DatagramHeader: protocol.DatagramHeader{RecvIndex: recvIndex},
		SenderIndex:    senderIndex,
		MsgType:        protocol.MessageTypeClientHello,
		FragOffset:     0,
		FragLength:     uint16(fragLen),
		TotalLength:    uint16(total),
		Cookie:         cookie,
	}, make([]byte, fragLen))
	if err != nil {
		t.Fatalf("EncodeDatagramHandshake: %v", err)
	}
	return frame
}

func TestKnownSource(t *testing.T) {
	r := newConnRegistry()
	const src = "203.0.113.7:5000"

	if r.knownSource(0, src) {
		t.Fatal("empty registry must not report any source as known")
	}

	// An established session is known by its index regardless of source.
	ds := &datagramSession{}
	idx, err := r.add(ds)
	if err != nil {
		t.Fatal(err)
	}
	if !r.knownSource(idx, "anything:1") {
		t.Fatal("established index must be known")
	}
	if r.knownSource(idx^0xffffffff, src) {
		t.Fatal("a different index with an unknown source must not be known")
	}

	// An in-progress responder is known by its source even with RecvIndex 0.
	r.addSource(src, &datagramSession{})
	if !r.knownSource(0, src) {
		t.Fatal("in-progress source must be known")
	}
}

func TestHalfOpenGlobalAccounting(t *testing.T) {
	r := newConnRegistry()
	if r.halfOpenLoad() != 0 {
		t.Fatalf("initial load = %d, want 0", r.halfOpenLoad())
	}
	r.tryAddHalfOpen("a:1")
	r.tryAddHalfOpen("a:1")
	r.tryAddHalfOpen("b:1")
	if got := r.halfOpenLoad(); got != 3 {
		t.Fatalf("load = %d, want 3", got)
	}
	r.releaseHalfOpen("a:1")
	if got := r.halfOpenLoad(); got != 2 {
		t.Fatalf("load after release = %d, want 2", got)
	}
	// A spurious release must not drive the global counter negative.
	r.releaseHalfOpen("never-added:1")
	if got := r.halfOpenLoad(); got != 2 {
		t.Fatalf("load after spurious release = %d, want 2", got)
	}
}

func TestUnderCookiePressure(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	e.cookiePressureHighWater = 2

	if e.underCookiePressure() {
		t.Fatal("idle endpoint must not be under pressure")
	}
	e.registry.tryAddHalfOpen("a:1")
	e.registry.tryAddHalfOpen("b:1")
	if !e.underCookiePressure() {
		t.Fatal("half-open count at the high-water must trip pressure")
	}
}

func TestCookieGateDropsSpoofedFlood(t *testing.T) {
	cc := &captureConn{}
	e := mustEndpoint(t, cc)
	e.cookiePressureHighWater = 0 // always under pressure

	// Many distinct spoofed sources, each a full first-fragment ClientHello with a
	// forged nonzero RecvIndex (the bypass attempt) and no cookie.
	for i := 0; i < 50; i++ {
		src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(i)), Port: 1234}
		frame := clientHelloFrame(t, uint32(i+1), uint32(0xdead0000+i), 1000, 1600, nil)
		if err := e.routeDatagram(src, frame); err != nil {
			t.Fatalf("routeDatagram: %v", err)
		}
	}

	if got := e.registry.count(); got != 0 {
		t.Fatalf("spoofed flood created %d sessions, want 0", got)
	}
	if got := e.reasm.sourceCount(); got != 0 {
		t.Fatalf("spoofed flood allocated %d reassembly sources, want 0", got)
	}
	// Every emitted frame must be a (de-amplifying) RETRY, never a ServerHello.
	writes := cc.writes()
	if len(writes) == 0 {
		t.Fatal("expected RETRY responses to the flood")
	}
	for _, w := range writes {
		ft, err := protocol.PeekDatagramType(w)
		if err != nil || ft != protocol.DatagramFrameRetry {
			t.Fatalf("emitted non-RETRY frame type %v (err %v)", ft, err)
		}
		// The first ClientHello fragment was ~1026 B; the RETRY must be smaller.
		if len(w) >= 1000 {
			t.Fatalf("RETRY of %d bytes is not de-amplifying", len(w))
		}
	}
}

func TestCookieGateNoRetryOnRunt(t *testing.T) {
	cc := &captureConn{}
	e := mustEndpoint(t, cc)
	e.cookiePressureHighWater = 0

	// A runt first fragment smaller than a RETRY: dropped, but no RETRY (so it can
	// never be used as an amplifier).
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1234}
	runt := clientHelloFrame(t, 1, 0, 1, 1600, nil)
	if len(runt) >= protocol.DatagramHeaderSize+cookieSize {
		t.Fatalf("runt frame %d bytes is not actually a runt", len(runt))
	}
	if err := e.routeDatagram(src, runt); err != nil {
		t.Fatalf("routeDatagram: %v", err)
	}
	if got := len(cc.writes()); got != 0 {
		t.Fatalf("runt fragment elicited %d responses, want 0", got)
	}
	if e.reasm.sourceCount() != 0 {
		t.Fatal("runt fragment allocated reassembly state")
	}
}

func TestCookieGateAdmitsValidCookie(t *testing.T) {
	cc := &captureConn{}
	e := mustEndpoint(t, cc)
	e.cookiePressureHighWater = 0

	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1234}
	cookie := e.cookie.issue(src)
	frame := clientHelloFrame(t, 1, 0, 1000, 1600, cookie)
	if err := e.routeDatagram(src, frame); err != nil {
		t.Fatalf("routeDatagram: %v", err)
	}
	// A valid cookie lets the fragment through to reassembly (a partial message, so
	// one reassembly source is now tracked) and emits no RETRY.
	if got := e.reasm.sourceCount(); got != 1 {
		t.Fatalf("valid-cookie fragment reassembly sources = %d, want 1", got)
	}
	for _, w := range cc.writes() {
		if ft, _ := protocol.PeekDatagramType(w); ft == protocol.DatagramFrameRetry {
			t.Fatal("a valid cookie must not elicit a RETRY")
		}
	}
}

func TestRouteRetryDeliversCookie(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	ds := &datagramSession{retryCh: make(chan []byte, 1)}
	idx, err := e.registry.add(ds)
	if err != nil {
		t.Fatal(err)
	}
	cookie := []byte("a-server-cookie")
	frame := protocol.EncodeDatagramRetry(idx, cookie)
	if err := e.routeDatagram(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, frame); err != nil {
		t.Fatalf("routeDatagram: %v", err)
	}
	select {
	case got := <-ds.retryCh:
		if string(got) != string(cookie) {
			t.Fatalf("delivered cookie = %q, want %q", got, cookie)
		}
	default:
		t.Fatal("RETRY did not deliver a cookie to the initiator")
	}

	// A RETRY for an unknown index is dropped cleanly.
	if err := e.routeDatagram(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		protocol.EncodeDatagramRetry(idx^0xffffffff, cookie)); err != nil {
		t.Fatalf("RETRY for unknown index should drop, got %v", err)
	}
}

// Guard: the pressure default is the configured constant.
func TestCookiePressureDefault(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	if e.cookiePressureHighWater != constants.DatagramCookiePressureHighWater {
		t.Fatalf("default high-water = %d, want %d",
			e.cookiePressureHighWater, constants.DatagramCookiePressureHighWater)
	}
}
