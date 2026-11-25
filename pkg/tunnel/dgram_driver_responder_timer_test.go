package tunnel

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// A responder admitted for a ClientHello that never advances its state (a body that does not
// parse, or a hello that only draws a HelloRetryRequest) must still run out of retries and fail,
// or its half-open slot is never freed. Before the fix the retransmit timer was armed only when
// the state moved, so such a driver reported no wake-up time at all; the run loop then fired its
// timer immediately and again, in a busy loop, and the slot stayed taken for good.
func TestResponderThatNeverAdvancesStillFails(t *testing.T) {
	rs, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: epoch}
	d := newDgramDriver(rs, clk.now)

	if out := d.onInbound(protocol.MessageTypeClientHello, []byte("not a client hello")); len(out) != 0 {
		t.Fatalf("a garbage ClientHello produced %d messages", len(out))
	}
	if d.nextWake().IsZero() {
		t.Fatal("the responder has no wake-up time, so nothing will ever fail it")
	}

	// Drive the timer the way the run loop does until the driver gives up. A bound of twice the
	// whole retry schedule is generous; reaching it means the driver never fails.
	limit := 2 * time.Duration(constants.DatagramHandshakeMaxRetries+1) * maxRTO()
	deadline := epoch.Add(limit)
	for steps := 0; !d.failed(); steps++ {
		wake := d.nextWake()
		if wake.IsZero() || wake.After(deadline) || steps > 1000 {
			t.Fatalf("driver did not fail after %d steps (next wake %v, deadline %v)", steps, wake, deadline)
		}
		clk.set(wake)
		d.onTimeout()
	}
}

// The same property end to end: one ClientHello whose body does not parse, from a source that
// passed the cookie gate, takes a half-open slot and must give it back once the retry schedule
// runs out. Before the fix the slot stayed taken and the handshake goroutine spun.
func TestUnparseableClientHelloFreesItsHalfOpenSlot(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	e.rtoInitial = 2 * time.Millisecond
	e.rtoMax = 5 * time.Millisecond

	src := udp("198.51.100.77", 4000)
	if err := e.routeDatagram(src, clientHelloFrame(t, 1, 0, 200, 200, nil)); err != nil {
		t.Fatalf("route: %v", err)
	}
	if e.registry.halfOpenLoad() != 1 {
		t.Fatalf("the hello was not admitted: half-open load %d", e.registry.halfOpenLoad())
	}
	deadline := time.Now().Add(10 * time.Second)
	for e.registry.halfOpenLoad() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the half-open slot was never freed (load %d)", e.registry.halfOpenLoad())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
