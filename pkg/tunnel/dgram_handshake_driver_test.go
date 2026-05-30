package tunnel

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// fakeClock is a manually advanced clock for deterministic timer tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time  { return c.t }
func (c *fakeClock) set(t time.Time) { c.t = t }

// epoch is a fixed base time so tests never read the wall clock.
var epoch = time.Unix(1_700_000_000, 0)

func feed(d *dgramDriver, msgs []hsMessage) []hsMessage {
	var out []hsMessage
	for _, m := range msgs {
		out = append(out, d.onInbound(m.typ, m.body)...)
	}
	return out
}

func newDriverPair(t *testing.T) (initiator, responder *dgramDriver) {
	t.Helper()
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	ri, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}
	ic := &fakeClock{t: epoch}
	rc := &fakeClock{t: epoch}
	return newDgramDriver(ci, ic.now), newDgramDriver(ri, rc.now)
}

// TestDgramHandshakeDriverRoundTrip runs a clean handshake through both drivers
// and checks both reach an established session.
func TestDgramHandshakeDriverRoundTrip(t *testing.T) {
	initiator, responder := newDriverPair(t)

	ch, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sh := feed(responder, ch)
	cf := feed(initiator, sh)
	sf := feed(responder, cf)
	if out := feed(initiator, sf); len(out) != 0 {
		t.Fatalf("initiator emitted %d messages on completion, want 0", len(out))
	}

	if !initiator.established() || !responder.established() {
		t.Fatalf("not both established: initiator=%v responder=%v",
			initiator.established(), responder.established())
	}
	if initiator.session().State() != SessionStateEstablished ||
		responder.session().State() != SessionStateEstablished {
		t.Fatal("sessions not established")
	}
	if !initiator.done() {
		t.Fatal("initiator should be done immediately after establishment")
	}
}

// TestDgramHandshakeDriverBackoff verifies the retransmit schedule
// (500/1000/2000/4000/8000 capped) and that the handshake fails once the retry
// ceiling is exceeded.
func TestDgramHandshakeDriverBackoff(t *testing.T) {
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	clk := &fakeClock{t: epoch}
	d := newDgramDriver(ci, clk.now)

	if _, err := d.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// First arm is at +500ms (the initial RTO).
	if want := epoch.Add(500 * time.Millisecond); !d.nextWake().Equal(want) {
		t.Fatalf("first wake = %v, want %v", d.nextWake(), want)
	}

	wantRTOs := []time.Duration{1000, 2000, 4000, 8000, 8000, 8000, 8000, 8000}
	var resends int
	for i := range constants.DatagramHandshakeMaxRetries {
		clk.set(d.nextWake())
		out := d.onTimeout()
		if len(out) != 1 || out[0].typ != protocol.MessageTypeClientHello {
			t.Fatalf("retransmit %d emitted %v, want one ClientHello", i, out)
		}
		resends++
		gotRTO := d.nextWake().Sub(clk.now())
		if gotRTO != wantRTOs[i]*time.Millisecond {
			t.Fatalf("after retransmit %d, RTO = %v, want %v", i, gotRTO, wantRTOs[i]*time.Millisecond)
		}
	}
	if resends != constants.DatagramHandshakeMaxRetries {
		t.Fatalf("resends = %d, want %d", resends, constants.DatagramHandshakeMaxRetries)
	}

	// One more timeout exceeds the ceiling and fails the handshake.
	clk.set(d.nextWake())
	if out := d.onTimeout(); out != nil {
		t.Fatalf("post-ceiling timeout emitted %v, want nil", out)
	}
	if !d.failed() {
		t.Fatal("driver should be failed after exceeding the retry ceiling")
	}
	if !d.nextWake().IsZero() {
		t.Fatal("failed driver should have no armed timer")
	}
}

// TestDgramHandshakeDriverResponderLinger verifies a completed responder replays
// its cached ServerFinished for a retransmitted ClientFinished, bounded by the
// replay cap, and stops once the linger window expires.
func TestDgramHandshakeDriverResponderLinger(t *testing.T) {
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	ic := &fakeClock{t: epoch}
	rc := &fakeClock{t: epoch}
	initiator := newDgramDriver(ci, ic.now)
	responder := newDgramDriver(ri, rc.now)

	ch, _ := initiator.start()
	sh := feed(responder, ch)
	cf := feed(initiator, sh)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("expected one ClientFinished, got %v", cf)
	}
	sf := feed(responder, cf)
	if len(sf) != 1 || sf[0].typ != protocol.MessageTypeServerFinished {
		t.Fatalf("expected one ServerFinished, got %v", sf)
	}
	if !responder.established() || responder.done() {
		t.Fatal("responder should be established and lingering")
	}

	// Retransmitted ClientFinished replays ServerFinished, up to the cap.
	for i := range constants.DatagramHandshakeLingerReplays {
		out := responder.onInbound(cf[0].typ, cf[0].body)
		if len(out) != 1 || out[0].typ != protocol.MessageTypeServerFinished {
			t.Fatalf("linger replay %d = %v, want one ServerFinished", i, out)
		}
	}
	// Cap exhausted: no more replays.
	if out := responder.onInbound(cf[0].typ, cf[0].body); out != nil {
		t.Fatalf("replay past cap = %v, want nil", out)
	}

	// Linger expiry ends the driver.
	rc.set(responder.nextWake())
	if out := responder.onTimeout(); out != nil {
		t.Fatalf("linger-expiry timeout = %v, want nil", out)
	}
	if !responder.done() {
		t.Fatal("responder should be done after linger expiry")
	}
	if out := responder.onInbound(cf[0].typ, cf[0].body); out != nil {
		t.Fatalf("post-linger replay = %v, want nil", out)
	}
}

// TestDgramHandshakeDriverDuplicateNoBackoffReset verifies a duplicate ClientHello
// replays the cached ServerHello without disturbing the responder's own
// retransmit schedule.
func TestDgramHandshakeDriverDuplicateNoBackoffReset(t *testing.T) {
	initiator, responder := newDriverPair(t)

	ch, _ := initiator.start()
	if out := feed(responder, ch); len(out) != 1 || out[0].typ != protocol.MessageTypeServerHello {
		t.Fatalf("first ClientHello -> %v, want ServerHello", out)
	}
	wakeBefore := responder.nextWake()

	dup := responder.onInbound(ch[0].typ, ch[0].body)
	if len(dup) != 1 || dup[0].typ != protocol.MessageTypeServerHello {
		t.Fatalf("duplicate ClientHello -> %v, want replayed ServerHello", dup)
	}
	if !responder.nextWake().Equal(wakeBefore) {
		t.Fatal("duplicate ClientHello reset the responder retransmit timer")
	}
}
