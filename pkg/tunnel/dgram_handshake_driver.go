// Package tunnel - dgram_handshake_driver.go adds reliability around the
// transport-agnostic FSM (dgram_handshake_fsm.go): retransmission with
// exponential backoff, a retry ceiling that bounds an un-established handshake's
// lifetime, and role-specific completion (the responder lingers briefly to answer
// a retransmitted ClientFinished with its cached ServerFinished, recovering a lost
// final flight).
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

	rto     time.Duration // current retransmit timeout
	retries int

	// retransmitAt is when to resend the cached flight (zero = disarmed).
	retransmitAt time.Time
	// lingerAt is when a completed responder stops answering retransmits
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

// newDgramDriver builds a driver for session. now may be nil for the real clock.
func newDgramDriver(session *Session, now func() time.Time) *dgramDriver {
	if now == nil {
		now = time.Now
	}
	return &dgramDriver{
		fsm:    newDgramHandshake(session),
		now:    now,
		rto:    initialRTO(),
		status: driverRunning,
	}
}

// start emits the initiator's ClientHello and arms its retransmit timer.
func (d *dgramDriver) start() ([]hsMessage, error) {
	msg, err := d.fsm.start()
	if err != nil {
		return nil, err
	}
	d.armRetransmit()
	return []hsMessage{*msg}, nil
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
	if out == nil && !complete {
		return nil // dropped
	}
	advanced := d.fsm.state() != before

	if complete {
		return d.onComplete(out)
	}
	if advanced {
		d.rto = initialRTO()
		d.retries = 0
		d.armRetransmit()
		return []hsMessage{*out}
	}
	// Replay: peer retransmitted; resend cached without touching our backoff or
	// ceiling. During linger this is the recovery path, bounded by the cap.
	if d.lingering() {
		if d.replaysLeft <= 0 {
			return nil
		}
		d.replaysLeft--
	}
	return []hsMessage{*out}
}

// onComplete records establishment and, for the responder, opens the bounded
// linger window during which a retransmitted ClientFinished is answered with the
// cached ServerFinished. final is the responder's ServerFinished (nil for the
// initiator, which sends nothing on completion).
func (d *dgramDriver) onComplete(final *hsMessage) []hsMessage {
	d.status = driverEstablished
	d.retransmitAt = time.Time{}
	if d.fsm.role == RoleResponder {
		d.lingerAt = d.now().Add(maxRTO())
		d.replaysLeft = constants.DatagramHandshakeLingerReplays
	}
	if final != nil {
		return []hsMessage{*final}
	}
	return nil
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
		d.rto = min(d.rto*2, maxRTO())
		d.armRetransmit()
		if d.fsm.cached != nil {
			return []hsMessage{*d.fsm.cached}
		}
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
	return d.status == driverEstablished && d.fsm.role == RoleResponder && !d.lingerAt.IsZero()
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
