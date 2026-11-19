package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// A ServerFinished that arrives before the ServerHello cannot be checked yet, because the keys
// do not exist, so the initiator keeps one and tests it when the ServerHello lands. Whichever copy it
// keeps, a forged early copy must cost only a retransmit: it never completes the handshake, and the
// genuine ServerFinished that follows still does.
func TestForgedEarlyServerFinishedCostsOnlyARetransmit(t *testing.T) {
	setup := func(t *testing.T) (initiator *dgramHandshake, sh, sf hsMessage) {
		t.Helper()
		initiator, responder := newFSMPair(t)
		chs, err := initiator.start()
		if err != nil {
			t.Fatal(err)
		}
		flight, _ := responder.onMessage(protocol.MessageTypeClientHello, chs[0].body)
		sh, sf = serverFlight(t, flight)
		return initiator, sh, sf
	}

	t.Run("only a forged copy arrives early", func(t *testing.T) {
		initiator, sh, sf := setup(t)
		forged := bytes.Repeat([]byte{0xEE}, len(sf.body))
		if out, done := initiator.onMessage(protocol.MessageTypeServerFinished, forged); out != nil || done {
			t.Fatalf("forged early ServerFinished produced output=%v done=%v", out, done)
		}
		if _, done := initiator.onMessage(protocol.MessageTypeServerHello, sh.body); done {
			t.Fatal("the initiator completed on a forged ServerFinished")
		}
		if _, done := initiator.onMessage(protocol.MessageTypeServerFinished, sf.body); !done {
			t.Fatal("the genuine retransmit did not complete the handshake after a forged early copy")
		}
	})

	t.Run("a forged copy follows the genuine one", func(t *testing.T) {
		initiator, sh, sf := setup(t)
		forged := bytes.Repeat([]byte{0xEE}, len(sf.body))
		initiator.onMessage(protocol.MessageTypeServerFinished, sf.body)
		initiator.onMessage(protocol.MessageTypeServerFinished, forged)
		_, done := initiator.onMessage(protocol.MessageTypeServerHello, sh.body)
		if !done {
			// The initiator kept the forged copy: the retransmit must still finish the handshake.
			if _, done = initiator.onMessage(protocol.MessageTypeServerFinished, sf.body); !done {
				t.Fatal("neither the kept copy nor the genuine retransmit completed the handshake")
			}
		}
	})
}

// Reassembly state belongs to a source. One source that floods past its own cap must lose only
// its own oldest buffers, never another source's message that is half way through.
func TestReassemblerFloodFromOneSourceLeavesAnotherSourcesMessageAlone(t *testing.T) {
	r := NewReassembler(4, 4096, 10*time.Second)
	full := []byte("a message that source B is still receiving")
	a, b := full[:20], full[20:]
	if _, done, err := r.Add("203.0.113.2:1", frag(7, 0, len(full), a), a); done || err != nil {
		t.Fatalf("B first half: done=%v err=%v", done, err)
	}

	one := []byte{1}
	for i := range 200 { // far past the per-source cap, every key different
		if _, _, err := r.Add("198.51.100.9:1", frag(uint32(1000+i), 0, 4096, one), one); err != nil {
			t.Fatalf("flood fragment %d: %v", i, err)
		}
	}

	msg, done, err := r.Add("203.0.113.2:1", frag(7, 20, len(full), b), b)
	if err != nil || !done || !bytes.Equal(msg, full) {
		t.Fatalf("B second half after the flood: done=%v err=%v msg=%q", done, err, msg)
	}
}

// The reassembler allocates the size a sender declares, not the size it has sent, so its worst case
// is fixed by the caps: sources x per-source buffers x (message + coverage bits). The test pins that
// bound for a small ceiling and logs the amplification, so a change to the caps or the allocation
// shows up as a failing number.
func TestReassemblerHeldBytesStayWithinTheCapsAndAmplificationIsRecorded(t *testing.T) {
	const sources, perSource = 64, 4
	r := NewReassembler(perSource, constants.DatagramMaxHandshakeMessageSize, 10*time.Second)
	r.maxSources = sources

	one := []byte{1}
	received := 0
	for s := range sources * 3 { // three times as many senders as the ceiling admits
		for k := range perSource * 2 { // twice the per-source cap
			addr := fmt.Sprintf("10.0.%d.%d:1", s/250, s%250)
			if _, _, err := r.Add(addr, frag(uint32(k), 0, constants.DatagramMaxHandshakeMessageSize, one), one); err == nil {
				received++
			}
		}
	}

	held := 0
	r.mu.Lock()
	if len(r.bySource) > sources {
		t.Errorf("%d sources held, ceiling is %d", len(r.bySource), sources)
	}
	for _, bufs := range r.bySource {
		if len(bufs) > perSource {
			t.Errorf("a source holds %d buffers, cap is %d", len(bufs), perSource)
		}
		for _, fb := range bufs {
			held += len(fb.buf) + 8*len(fb.covered)
		}
	}
	r.mu.Unlock()

	perBuffer := constants.DatagramMaxHandshakeMessageSize + 8*((constants.DatagramMaxHandshakeMessageSize+63)/64)
	if limit := sources * perSource * perBuffer; held > limit {
		t.Fatalf("held %d bytes, the caps allow at most %d", held, limit)
	}
	t.Logf("held %d bytes from %d accepted one-byte fragments: %dx amplification at this ceiling", held, received, held/max(received, 1))
}

// Once the endpoint holds as many reassembling sources as its high-water mark, a new source with no
// valid cookie must get a retry and no reassembly state. Below the mark the gate stays open. The
// fragments are 200 bytes because the gate answers only a packet at least as large as its reply, so
// a spoofed source cannot use it to amplify.
func TestCookieGateStopsNewReassemblyStateAtTheHighWaterMark(t *testing.T) {
	conn := &captureConn{}
	ep, err := NewDatagramEndpoint(conn, WithAllowUnauthenticated(), WithMaxHalfOpen(64))
	if err != nil {
		t.Fatal(err)
	}
	highWater := ep.cookiePressureHighWater
	src := func(i int) net.Addr { return &net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(i)), Port: 4000 + i} }

	for i := range highWater {
		if err := ep.routeDatagram(src(i), clientHelloFrame(t, uint32(i+1), 0, 200, 2048, nil)); err != nil {
			t.Fatalf("source %d below the mark: %v", i, err)
		}
	}
	if got := ep.reasm.sourceCount(); got != highWater {
		t.Fatalf("%d sources held below the mark, want %d", got, highWater)
	}
	before := len(conn.writes())

	for i := highWater; i < highWater+40; i++ {
		_ = ep.routeDatagram(src(i), clientHelloFrame(t, uint32(i+1), 0, 200, 2048, nil))
	}
	if got := ep.reasm.sourceCount(); got != highWater {
		t.Fatalf("%d sources held after 40 more cookieless sources, want the mark %d: the gate let state through", got, highWater)
	}
	if retries := len(conn.writes()) - before; retries != 40 {
		t.Fatalf("%d retries for 40 refused sources, want one each", retries)
	}
}
