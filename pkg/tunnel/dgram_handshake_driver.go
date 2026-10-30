// Package tunnel - dgram_handshake_driver.go adds reliability around the
// transport-agnostic FSM (dgram_handshake_fsm.go): retransmission with
// exponential backoff, a retry ceiling that bounds an un-established handshake's
// lifetime, and role-specific completion (the initiator lingers briefly to answer
// a retransmitted ServerHello + ServerFinished flight with its cached
// ClientFinished, recovering a lost final message).
//
// The driver is event-driven and clock-injected so it is testable without sockets
// or real timers: feed it inbound messages and timer ticks, and it returns the
// messages to send. The endpoint wiring (datagram.go) owns the goroutine, the
// real clock, fragmentation, and the socket.
package tunnel

import (
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

type driverStatus int

const (
	driverRunning driverStatus = iota
	driverEstablished
	driverFailed
)

// dgramDriver wraps a dgramHandshake with time. All methods are called by the one
// goroutine that owns this handshake, so the driver needs no locking.
type dgramDriver struct {
	fsm *dgramHandshake
	now func() time.Time

	rtoInitial time.Duration // first retransmit timeout
	rtoMax     time.Duration // backoff cap
	rto        time.Duration // current retransmit timeout
	retries    int

	// retransmitAt is when to resend the cached flight (zero = disarmed).
	retransmitAt time.Time
	// lingerAt is when a completed initiator stops answering retransmits
	// (zero = not lingering).
	lingerAt    time.Time
	replaysLeft int

	status driverStatus
}

func initialRTO() time.Duration {
	return time.Duration(constants.DatagramHandshakeInitialTimeoutMillis) * time.Millisecond
}

func maxRTO() time.Duration {
	return time.Duration(constants.DatagramHandshakeMaxTimeoutMillis) * time.Millisecond
}

// newDgramDriver builds a driver for session with the default backoff. now may be
// nil for the real clock.
func newDgramDriver(session *Session, now func() time.Time) *dgramDriver {
	return newDgramDriverWithRTO(session, now, initialRTO(), maxRTO())
}

// newDgramDriverWithRTO builds a driver with explicit backoff bounds (tests pass
// short values for fast, deterministic runs; production uses the defaults).
func newDgramDriverWithRTO(session *Session, now func() time.Time, rtoInitial, rtoMax time.Duration) *dgramDriver {
	if now == nil {
		now = time.Now
	}
	return &dgramDriver{
		fsm:        newDgramHandshake(session),
		now:        now,
		rtoInitial: rtoInitial,
		rtoMax:     rtoMax,
		rto:        rtoInitial,
		status:     driverRunning,
	}
}

// start emits the initiator's ClientHello and arms its retransmit timer.
func (d *dgramDriver) start() ([]hsMessage, error) {
	msg, err := d.fsm.start()
	if err != nil {
		return nil, err
	}
	d.armRetransmit()
	return msg, nil
}

// onInbound feeds one reassembled handshake message and returns the messages to
// send in response (a freshly advanced flight, or a replayed cached flight). It
// distinguishes advance from replay by whether the FSM state moved, so it knows
// when to reset the backoff and when to charge the linger replay cap.
func (d *dgramDriver) onInbound(typ protocol.MessageType, body []byte) []hsMessage {
	if d.status == driverFailed {
		return nil
	}
	if d.status == driverEstablished && !d.lingering() {
		return nil // initiator (or expired responder) is done; ignore further input
	}

	before := d.fsm.state()
	out, complete := d.fsm.onMessage(typ, body)
	advanced := d.fsm.state() != before
	if out == nil && !complete && !advanced {
		return nil // dropped
	}

	if complete {
		return d.onComplete(out)
	}
	if advanced {
		d.rto = d.rtoInitial
		d.retries = 0
		d.armRetransmit()
		return out // nil when the step produced no message (initiator awaiting ServerFinished)
	}
	// Replay: peer retransmitted; resend cached without touching our backoff or
	// ceiling. During linger this is the recovery path, bounded by the cap.
	if d.lingering() {
		if d.replaysLeft <= 0 {
			return nil
		}
		d.replaysLeft--
	}
	return out
}

// onComplete records establishment and, for the initiator, opens the bounded
// linger window during which a retransmitted server flight is answered with the
// cached ClientFinished. final is the initiator's ClientFinished (nil for the
// responder, which sends nothing on completion).
func (d *dgramDriver) onComplete(final []hsMessage) []hsMessage {
	d.status = driverEstablished
	d.retransmitAt = time.Time{}
	if d.fsm.role == RoleInitiator {
		// Linger long enough to cover the responder's whole flight retransmit window
		// (it backs off up to rtoMax for MaxRetries tries), so a lost ClientFinished
		// is recovered by replay rather than timing out.
		d.lingerAt = d.now().Add(constants.DatagramHandshakeMaxRetries * d.rtoMax)
		d.replaysLeft = constants.DatagramHandshakeLingerReplays
	}
	return final
}

// onTimeout handles an elapsed timer: it ends an expired linger, or retransmits
// the cached flight (growing the backoff) until the retry ceiling, past which the
// handshake fails. It returns the messages to resend, if any.
func (d *dgramDriver) onTimeout() []hsMessage {
	now := d.now()

	if d.lingering() && !now.Before(d.lingerAt) {
		d.lingerAt = time.Time{} // linger over; driver is now fully done
		return nil
	}

	if d.status == driverRunning && !d.retransmitAt.IsZero() && !now.Before(d.retransmitAt) {
		d.retries++
		if d.retries > constants.DatagramHandshakeMaxRetries {
			d.status = driverFailed
			d.retransmitAt = time.Time{}
			return nil
		}
		d.rto = min(d.rto*2, d.rtoMax)
		d.armRetransmit()
		return d.fsm.cached
	}
	return nil
}

// nextWake reports the earliest time onTimeout must be called, or the zero time if
// no timer is armed (the driver is terminal).
func (d *dgramDriver) nextWake() time.Time {
	switch {
	case d.status == driverRunning:
		return d.retransmitAt
	case d.lingering():
		return d.lingerAt
	default:
		return time.Time{}
	}
}

func (d *dgramDriver) armRetransmit() { d.retransmitAt = d.now().Add(d.rto) }

func (d *dgramDriver) lingering() bool {
	return d.status == driverEstablished && d.fsm.role == RoleInitiator && !d.lingerAt.IsZero()
}

// established reports a successful handshake (the session is keyed).
func (d *dgramDriver) established() bool { return d.status == driverEstablished }

// failed reports the handshake aborted (retry ceiling exceeded).
func (d *dgramDriver) failed() bool { return d.status == driverFailed }

// done reports the owner can stop driving: failed, or established with no linger
// left to serve.
func (d *dgramDriver) done() bool {
	return d.status == driverFailed || (d.status == driverEstablished && !d.lingering())
}

// session returns the underlying session (established once established() is true).
func (d *dgramDriver) session() *Session { return d.fsm.hs.session }

// cachedFlight returns the FSM's last outbound message for an on-demand resend
// (the initiator replaying its ClientHello after a RETRY), or nil if the driver
// is terminal or has nothing cached. It does not touch the retransmit backoff or
// ceiling, so a resend on a RETRY is independent of the loss-timer budget.
func (d *dgramDriver) cachedFlight() []hsMessage {
	if d.status != driverRunning {
		return nil
	}
	return d.fsm.cached
}
