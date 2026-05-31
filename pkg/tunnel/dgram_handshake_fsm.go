// Package tunnel - dgram_handshake_fsm.go is the transport-agnostic handshake
// state machine for the datagram path. It drives the existing CH-KEM flight
// builders (handshake.go) over an unreliable transport: it classifies each
// inbound handshake message as advance / replay / drop and caches its last
// outbound message so a peer retransmit is answered from bytes, never by
// re-invoking a builder (the builders zeroize their secrets via cleanup() on
// completion, so re-invocation is neither correct nor possible).
//
// This file holds no sockets, timers, fragmentation, or sequence numbers; those
// belong to the driver (dgram_handshake_driver.go) and the endpoint wiring
// (datagram.go). Each transition produces exactly one handshake message.
package tunnel

import "github.com/sara-star-quant/quantum-go/pkg/protocol"

// hsMessage is one serialized handshake message plus its type. The bytes are the
// verbatim output of a flight builder (a plaintext codec frame for the Hellos, or
// self-contained ciphertext for the Finished messages).
type hsMessage struct {
	typ  protocol.MessageType
	body []byte
}

// dgramHandshake is the per-handshake state machine. It wraps a *Handshake (the
// crypto building blocks) and tracks, for the datagram transport, which inbound
// message advances the handshake, which one is a retransmit to replay, and the
// last outbound message to replay.
type dgramHandshake struct {
	hs   *Handshake
	role Role

	// expecting is the inbound message type that advances the handshake from the
	// current state. It is zero (not a valid MessageType) once complete.
	expecting protocol.MessageType
	// prev is the most recently processed inbound type; a repeat of it is a
	// retransmit and replays cached.
	prev protocol.MessageType
	// cached is the last outbound message produced, replayed on a retransmit.
	cached *hsMessage
}

// newDgramHandshake builds an FSM for session. The initiator must call start() to
// emit the ClientHello; the responder waits for one.
func newDgramHandshake(session *Session) *dgramHandshake {
	hs := NewHandshake(session)
	hs.datagram = true // complete via InitializeDatagramKeys (epoch-keyed, derived nonces)
	d := &dgramHandshake{
		hs:   hs,
		role: session.Role,
	}
	if d.role == RoleResponder {
		d.expecting = protocol.MessageTypeClientHello
	}
	return d
}

// start emits the initiator's ClientHello and arms the FSM to expect a
// ServerHello. It is a no-op error for the responder.
func (d *dgramHandshake) start() (*hsMessage, error) {
	body, err := d.hs.CreateClientHello()
	if err != nil {
		return nil, err
	}
	d.cached = &hsMessage{typ: protocol.MessageTypeClientHello, body: body}
	d.expecting = protocol.MessageTypeServerHello
	return d.cached, nil
}

// onMessage feeds one reassembled inbound handshake message to the FSM. It returns
// the outbound message to send (nil if none) and whether the handshake is now
// complete. A single inbound never fails the handshake: an unexpected type, or a
// builder error on the expected type (malformed/forged/decap failure), is dropped
// (nil, false) so the genuine retransmit can still complete it. A repeat of the
// last processed message replays the cached outbound.
func (d *dgramHandshake) onMessage(typ protocol.MessageType, body []byte) (out *hsMessage, complete bool) {
	switch {
	case typ != 0 && typ == d.expecting:
		return d.advance(typ, body)
	case typ != 0 && typ == d.prev && d.cached != nil:
		return d.cached, false // retransmit: replay last flight, no re-invocation
	default:
		return nil, false // stray / out-of-order / post-complete: drop
	}
}

// advance runs the builder pair for the expected inbound type. It commits the new
// outbound, prev, and expecting only when every builder call succeeds; on any
// builder error it leaves all FSM state untouched and drops, so a later genuine
// retransmit retries the same transition.
func (d *dgramHandshake) advance(typ protocol.MessageType, body []byte) (out *hsMessage, complete bool) {
	switch {
	case d.role == RoleInitiator && typ == protocol.MessageTypeServerHello:
		if err := d.hs.ProcessServerHello(body); err != nil {
			return nil, false
		}
		reply, err := d.hs.CreateClientFinished()
		if err != nil {
			return nil, false
		}
		d.commit(typ, &hsMessage{typ: protocol.MessageTypeClientFinished, body: reply}, protocol.MessageTypeServerFinished)
		return d.cached, false

	case d.role == RoleInitiator && typ == protocol.MessageTypeServerFinished:
		if err := d.hs.ProcessServerFinished(body); err != nil {
			return nil, false
		}
		d.prev = typ
		d.expecting = 0 // no further inbound
		return nil, true

	case d.role == RoleResponder && typ == protocol.MessageTypeClientHello:
		if err := d.hs.ProcessClientHello(body); err != nil {
			return nil, false
		}
		reply, err := d.hs.CreateServerHello()
		if err != nil {
			return nil, false
		}
		d.commit(typ, &hsMessage{typ: protocol.MessageTypeServerHello, body: reply}, protocol.MessageTypeClientFinished)
		return d.cached, false

	case d.role == RoleResponder && typ == protocol.MessageTypeClientFinished:
		if err := d.hs.ProcessClientFinished(body); err != nil {
			return nil, false
		}
		reply, err := d.hs.CreateServerFinished()
		if err != nil {
			return nil, false
		}
		d.commit(typ, &hsMessage{typ: protocol.MessageTypeServerFinished, body: reply}, 0)
		return d.cached, true

	default:
		return nil, false
	}
}

// commit records a successful transition: the inbound just processed (prev), the
// new outbound to cache and replay, and the next inbound to expect.
func (d *dgramHandshake) commit(processed protocol.MessageType, out *hsMessage, next protocol.MessageType) {
	d.prev = processed
	d.cached = out
	d.expecting = next
}

// state reports the wrapped handshake's state.
func (d *dgramHandshake) state() HandshakeState { return d.hs.State() }

// isComplete reports whether the handshake completed successfully.
func (d *dgramHandshake) isComplete() bool { return d.hs.IsComplete() }
