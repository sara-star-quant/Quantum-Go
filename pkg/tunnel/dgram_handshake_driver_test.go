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
// and checks both reach an established session: the initiator after verifying the
// server flight (it sends ClientFinished and lingers), the responder on receiving
// ClientFinished (nothing left to send, so it is done at once).
func TestDgramHandshakeDriverRoundTrip(t *testing.T) {
	initiator, responder := newDriverPair(t)

	ch, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	flight := feed(responder, ch)
	if len(flight) != 2 || flight[0].typ != protocol.MessageTypeServerHello ||
		flight[1].typ != protocol.MessageTypeServerFinished {
		t.Fatalf("responder flight = %v, want ServerHello, ServerFinished", flight)
	}
	cf := feed(initiator, flight)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("initiator emitted %v, want one ClientFinished", cf)
	}
	if out := feed(responder, cf); len(out) != 0 {
		t.Fatalf("responder emitted %d messages on completion, want 0", len(out))
	}

	if !initiator.established() || !responder.established() {
		t.Fatalf("not both established: initiator=%v responder=%v",
			initiator.established(), responder.established())
	}
	if initiator.session().State() != SessionStateEstablished ||
		responder.session().State() != SessionStateEstablished {
		t.Fatal("sessions not established")
	}
	if !responder.done() {
		t.Fatal("responder should be done immediately after establishment")
	}
	if initiator.done() {
		t.Fatal("initiator should linger to replay a lost ClientFinished")
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

// TestDgramHandshakeDriverInitiatorLinger verifies a completed initiator replays its
// cached ClientFinished for a retransmitted ServerFinished, bounded by the replay
// cap, and stops once the linger window expires.
func TestDgramHandshakeDriverInitiatorLinger(t *testing.T) {
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	ic := &fakeClock{t: epoch}
	rc := &fakeClock{t: epoch}
	initiator := newDgramDriver(ci, ic.now)
	responder := newDgramDriver(ri, rc.now)

	ch, _ := initiator.start()
	flight := feed(responder, ch)
	cf := feed(initiator, flight)
	if len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("expected one ClientFinished, got %v", cf)
	}
	if !initiator.established() || initiator.done() {
		t.Fatal("initiator should be established and lingering")
	}
	sf := flight[1]

	// Retransmitted ServerFinished replays ClientFinished, up to the cap.
	for i := range constants.DatagramHandshakeLingerReplays {
		out := initiator.onInbound(sf.typ, sf.body)
		if len(out) != 1 || out[0].typ != protocol.MessageTypeClientFinished {
			t.Fatalf("linger replay %d = %v, want one ClientFinished", i, out)
		}
	}
	// Cap exhausted: no more replays.
	if out := initiator.onInbound(sf.typ, sf.body); out != nil {
		t.Fatalf("replay past cap = %v, want nil", out)
	}

	// Linger expiry ends the driver.
	ic.set(initiator.nextWake())
	if out := initiator.onTimeout(); out != nil {
		t.Fatalf("linger-expiry timeout = %v, want nil", out)
	}
	if !initiator.done() {
		t.Fatal("initiator should be done after linger expiry")
	}
	if out := initiator.onInbound(sf.typ, sf.body); out != nil {
		t.Fatalf("post-linger replay = %v, want nil", out)
	}
}

// TestDgramHandshakeDriverDuplicateNoBackoffReset verifies a duplicate ClientHello
// replays the cached server flight without disturbing the responder's own
// retransmit schedule.
func TestDgramHandshakeDriverDuplicateNoBackoffReset(t *testing.T) {
	initiator, responder := newDriverPair(t)

	ch, _ := initiator.start()
	if out := feed(responder, ch); len(out) != 2 || out[0].typ != protocol.MessageTypeServerHello {
		t.Fatalf("first ClientHello -> %v, want ServerHello+ServerFinished", out)
	}
	wakeBefore := responder.nextWake()

	dup := responder.onInbound(ch[0].typ, ch[0].body)
	if len(dup) != 2 || dup[0].typ != protocol.MessageTypeServerHello {
		t.Fatalf("duplicate ClientHello -> %v, want replayed ServerHello+ServerFinished", dup)
	}
	if !responder.nextWake().Equal(wakeBefore) {
		t.Fatal("duplicate ClientHello reset the responder retransmit timer")
	}
}

// newDriverPairRTO pairs an initiator and responder driver with non-default
// backoff. The non-default values are the point: they differ from the package
// constants, so a path that reads a constant where the configured value belongs
// shows up. Both clocks start at epoch and are advanced explicitly.
func newDriverPairRTO(t *testing.T, rtoInitial, rtoMax time.Duration) (ini, res *dgramDriver, iclk, rclk *fakeClock) {
	t.Helper()
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	ri, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}
	iclk = &fakeClock{t: epoch}
	rclk = &fakeClock{t: epoch}
	return newDgramDriverWithRTO(ci, iclk.now, rtoInitial, rtoMax),
		newDgramDriverWithRTO(ri, rclk.now, rtoInitial, rtoMax), iclk, rclk
}

// TestDgramHandshakeDriverAdvanceKeepsConfiguredRTO is a regression test for the
// RTO reset bug: advancing to the next flight must re-arm the retransmit timer at
// the configured rtoInitial, not the default package constant. The existing
// backoff test missed this because it uses the default driver, where the two are
// equal.
func TestDgramHandshakeDriverAdvanceKeepsConfiguredRTO(t *testing.T) {
	const rtoInitial = 5 * time.Millisecond
	const rtoMax = 50 * time.Millisecond
	ini, res, iclk, _ := newDriverPairRTO(t, rtoInitial, rtoMax)

	ch, err := ini.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	flight := feed(res, ch)

	// Advance the clock so the re-armed timer differs from the one start() set.
	iclk.set(epoch.Add(2 * time.Millisecond))
	if out := ini.onInbound(flight[0].typ, flight[0].body); out != nil {
		t.Fatalf("ServerHello alone produced %v, want nothing", out)
	}

	got := ini.nextWake().Sub(iclk.now())
	dflt := time.Duration(constants.DatagramHandshakeInitialTimeoutMillis) * time.Millisecond
	if got != rtoInitial {
		t.Fatalf("post-advance RTO = %v, want configured %v (a value of %v means it reverted to the default constant)",
			got, rtoInitial, dflt)
	}
}

// TestDgramHandshakeDriverLingerCoversRetransmitWindow is a regression test for
// the short-linger bug: a completed initiator must keep answering server-flight
// retransmits for the responder's whole retransmit window, not one RTO, so a lost
// ClientFinished is recovered by replay.
func TestDgramHandshakeDriverLingerCoversRetransmitWindow(t *testing.T) {
	const rtoInitial = 5 * time.Millisecond
	const rtoMax = 50 * time.Millisecond
	ini, res, iclk, _ := newDriverPairRTO(t, rtoInitial, rtoMax)

	ch, _ := ini.start()
	flight := feed(res, ch)
	if cf := feed(ini, flight); len(cf) != 1 || cf[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("initiator did not complete: %v", cf)
	}
	if !ini.established() {
		t.Fatal("initiator not established")
	}

	// Linger must span the responder's full flight retransmit window (MaxRetries
	// backoffs capped at rtoMax), well beyond the one-RTO old value.
	got := ini.nextWake().Sub(iclk.now())
	want := constants.DatagramHandshakeMaxRetries * rtoMax
	if got != want {
		t.Fatalf("linger window = %v, want MaxRetries*rtoMax = %v (one rtoMax %v was the buggy value)", got, want, rtoMax)
	}

	// A ServerFinished arriving late but within the window still replays CF.
	sf := flight[1]
	iclk.set(ini.nextWake().Add(-time.Millisecond))
	if out := ini.onInbound(sf.typ, sf.body); len(out) != 1 || out[0].typ != protocol.MessageTypeClientFinished {
		t.Fatalf("late-but-in-window ServerFinished did not replay ClientFinished: %v", out)
	}

	// At the window edge the linger ends.
	iclk.set(ini.nextWake())
	_ = ini.onTimeout()
	if !ini.done() {
		t.Fatal("initiator still lingering after the window expired")
	}
}

// TestDatagramEndpointPropagatesRTO guards the wiring class of the RTO bug: the
// endpoint must build drivers carrying its configured backoff. Without this, a
// change that built drivers with the defaults would silently run at 500ms RTOs,
// and neither the driver tests nor the e2e (which would just pass, slowly) would
// catch it.
func TestDatagramEndpointPropagatesRTO(t *testing.T) {
	ep := mustEndpoint(t, nil)
	ep.rtoInitial = 7 * time.Millisecond
	ep.rtoMax = 70 * time.Millisecond

	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	d := ep.newDriver(s)
	if d.rtoInitial != ep.rtoInitial || d.rtoMax != ep.rtoMax {
		t.Fatalf("driver RTO = (%v, %v), want endpoint config (%v, %v)",
			d.rtoInitial, d.rtoMax, ep.rtoInitial, ep.rtoMax)
	}
}
