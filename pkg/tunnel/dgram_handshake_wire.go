// Package tunnel - dgram_handshake_wire.go connects the reliability driver
// (dgram_handshake_driver.go) to a real DatagramEndpoint: it owns one goroutine
// per in-progress handshake, fragments outbound flights onto the PacketConn, and
// demultiplexes reassembled inbound messages from the receive loop to the right
// handshake by connection index (with a source-keyed bootstrap for the first
// ClientHello, which still carries RecvIndex 0).
package tunnel

import (
	"errors"
	"net"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// inboxCap buffers a handful of reassembled messages per handshake; the receive
// loop forwards non-blocking, so overflow just drops and the peer retransmits.
const inboxCap = 8

var (
	errHandshakeFailed = errors.New("tunnel: datagram handshake failed")
	errEndpointClosed  = errors.New("tunnel: datagram endpoint closed")
)

// inboundMsg is one reassembled handshake message handed from the receive loop to
// a handshake goroutine. sender is the peer's SenderIndex, which the initiator
// uses to learn the responder's connection index.
type inboundMsg struct {
	typ    protocol.MessageType
	body   []byte
	sender uint32
}

// trySend forwards without blocking; a full inbox drops (the sender retransmits).
func trySend(ch chan inboundMsg, m inboundMsg) {
	select {
	case ch <- m:
	default:
	}
}

// deliverHandshake routes one fully reassembled handshake message. A frame that
// names our connection index goes to that handshake's inbox; a ClientHello with
// RecvIndex 0 goes to the in-progress responder for its source, or starts one
// (gated by the half-open cap) - the gate precedes any decapsulation, so we never
// do CH-KEM work or emit a ServerHello for an unvalidated source until its full
// ClientHello has arrived.
func (e *DatagramEndpoint) deliverHandshake(src net.Addr, h protocol.DatagramHandshakeHeader, msg []byte) {
	in := inboundMsg{typ: h.MsgType, body: msg, sender: h.SenderIndex}

	if h.RecvIndex != 0 {
		if ds := e.registry.lookup(h.RecvIndex); ds != nil && ds.inbox != nil {
			trySend(ds.inbox, in)
		}
		return
	}

	// RecvIndex 0: only a ClientHello bootstraps a responder.
	if h.MsgType != protocol.MessageTypeClientHello {
		return
	}
	// Atomically resolve the bootstrap under one registry lock: route to an existing
	// in-progress responder, or install this fresh session and start one, or drop at
	// the cap. reserveSource registers the session in bySource as it claims the
	// half-open slot - BEFORE the slow CH-KEM work in startResponder - so concurrent
	// receive goroutines (the SO_REUSEPORT path) cannot both start a responder for the
	// same new source: the loser sees the winner's session and routes to it.
	ds := &datagramSession{
		inbox:  make(chan inboundMsg, inboxCap),
		recvCh: make(chan []byte, dataInboxCap),
		closed: make(chan struct{}),
	}
	ds.setPeerAddr(src)
	reserved, won := e.registry.reserveSource(src.String(), ds)
	if !won {
		if reserved != nil { // an existing responder owns this source: route the retransmit
			trySend(reserved.inbox, in)
		}
		return // reserved == nil means the per-source cap is reached: drop
	}
	e.startResponder(src, ds, in)
}

// startResponder finishes bootstrapping the responder session ds (already registered
// in bySource and holding a half-open slot, via reserveSource): it keys a session,
// allocates the connection index, and runs the handshake in its own goroutine. On a
// setup error it unwinds the source reservation and the half-open slot.
func (e *DatagramEndpoint) startResponder(src net.Addr, ds *datagramSession, first inboundMsg) {
	session, err := NewSession(RoleResponder)
	if err != nil {
		e.registry.removeSource(src.String())
		e.registry.releaseHalfOpen(src.String())
		return
	}
	idx, err := e.registry.add(ds)
	if err != nil {
		e.registry.removeSource(src.String())
		e.registry.releaseHalfOpen(src.String())
		return
	}

	l := &handshakeLoop{
		ep:          e,
		ds:          ds,
		src:         src,
		driver:      e.newDriver(session),
		localIndex:  idx,
		peerIndex:   first.sender, // the initiator's index, echoed as RecvIndex in our replies
		established: func() { e.surface(ds) },
	}
	trySend(ds.inbox, first)
	go func() { _, _ = l.run() }()
}

// DialDatagram performs the initiator handshake to dst over ep (whose Serve loop
// must be running) and returns the established session as a DatagramConn.
func DialDatagram(ep *DatagramEndpoint, dst net.Addr) (*DatagramConn, error) {
	session, err := NewSession(RoleInitiator)
	if err != nil {
		return nil, err
	}
	ds := &datagramSession{
		inbox:      make(chan inboundMsg, inboxCap),
		recvCh:     make(chan []byte, dataInboxCap),
		closed:     make(chan struct{}),
		rekeyInbox: make(chan []byte, 4),
		retryCh:    make(chan []byte, 1),
	}
	ds.setPeerAddr(dst)
	idx, err := ep.registry.add(ds)
	if err != nil {
		return nil, err
	}
	l := &handshakeLoop{
		ep:         ep,
		ds:         ds,
		src:        dst,
		driver:     ep.newDriver(session),
		localIndex: idx,
	}
	if _, err := l.run(); err != nil {
		ep.registry.remove(idx)
		return nil, err
	}
	return newDatagramConn(ep, ds), nil
}

// newDriver builds a handshake driver carrying this endpoint's configured
// retransmission backoff. Both the dial and responder paths go through here so the
// configured RTO cannot be dropped on the way to the driver.
func (e *DatagramEndpoint) newDriver(session *Session) *dgramDriver {
	return newDgramDriverWithRTO(session, nil, e.rtoInitial, e.rtoMax)
}

// surface offers an established inbound session on the accept channel without
// blocking the handshake goroutine.
func (e *DatagramEndpoint) surface(ds *datagramSession) {
	select {
	case e.acceptCh <- ds:
	default:
	}
}

// handshakeLoop owns one in-progress handshake: its driver, connection indices,
// the outbound sequence counter, and the socket sends. Exactly one goroutine runs
// it, so its fields need no locking.
type handshakeLoop struct {
	ep         *DatagramEndpoint
	ds         *datagramSession
	src        net.Addr
	driver     *dgramDriver
	localIndex uint32
	peerIndex  uint32
	seq        uint64

	// cookie is the server's anti-DoS cookie echoed on ClientHello resends, set
	// from a RETRY. retriesHonored bounds how many RETRYs we act on, so a forged
	// RETRY stream (the index is guessable) cannot drive unbounded resends.
	cookie         []byte
	retriesHonored int

	// established, if set, is called once when the session is keyed (responders
	// surface it on acceptCh). Initiators leave it nil and take the session from
	// run's return value.
	established func()
	surfaced    bool
}

// maxHonoredRetries bounds RETRY-driven ClientHello resends per handshake.
const maxHonoredRetries = 3

// run drives the handshake to completion or failure. The initiator sends the
// first ClientHello; both roles then loop on {inbound, retransmit timer, close},
// retransmitting on silence and (responder) lingering after completion to answer a
// retransmitted ClientFinished.
func (l *handshakeLoop) run() (*Session, error) {
	if l.driver.fsm.role == RoleInitiator {
		msgs, err := l.driver.start()
		if err != nil {
			return nil, err
		}
		l.send(msgs)
	}

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for !l.driver.done() {
		armTimer(timer, l.driver.nextWake().Sub(l.driver.now()))
		select {
		case m := <-l.ds.inbox:
			if m.sender != 0 {
				l.peerIndex = m.sender
			}
			l.send(l.driver.onInbound(m.typ, m.body))
		case cookie := <-l.retryCh():
			l.onRetry(cookie)
		case <-timer.C:
			l.send(l.driver.onTimeout())
		case <-l.ep.done:
			return nil, errEndpointClosed
		}
		l.maybeSurface()
	}

	if l.driver.failed() {
		l.ep.registry.removeSource(l.src.String())
		l.ep.registry.releaseHalfOpen(l.src.String())
		l.ep.registry.remove(l.localIndex)
		return nil, errHandshakeFailed
	}
	return l.ds.session, nil
}

// retryCh returns the session's RETRY-cookie channel, or nil for a responder
// (which has none). A nil channel makes the run-loop's RETRY select case block
// forever, so only initiators ever react to a RETRY.
func (l *handshakeLoop) retryCh() chan []byte {
	if l.ds == nil {
		return nil
	}
	return l.ds.retryCh
}

// onRetry reacts to a server anti-DoS RETRY: adopt the cookie and re-send the
// cached ClientHello carrying it. It acts only while the cached flight is still
// the ClientHello (a RETRY is meaningless once the handshake has advanced) and is
// bounded by maxHonoredRetries, so a forged RETRY stream (the index is guessable)
// cannot drive unbounded resends.
func (l *handshakeLoop) onRetry(cookie []byte) {
	if l.retriesHonored >= maxHonoredRetries {
		return
	}
	flight := l.driver.cachedFlight()
	if len(flight) == 0 || flight[0].typ != protocol.MessageTypeClientHello {
		return
	}
	l.retriesHonored++
	l.cookie = cookie
	l.send(flight)
}

// maybeSurface publishes the session the instant it is established (so a responder
// surfaces it on acceptCh without waiting out its linger window) and frees the
// half-open slot exactly once.
func (l *handshakeLoop) maybeSurface() {
	if l.surfaced || !l.driver.established() {
		return
	}
	l.surfaced = true
	l.ds.session = l.driver.session()
	l.ds.peerIndex = l.peerIndex
	l.ep.registry.removeSource(l.src.String())
	l.ep.registry.releaseHalfOpen(l.src.String())
	if l.established != nil {
		l.established()
	}
}

// send fragments each outbound message onto the PacketConn, advancing the global
// sequence counter across all frames.
func (l *handshakeLoop) send(msgs []hsMessage) {
	for _, m := range msgs {
		base := protocol.DatagramHandshakeHeader{
			DatagramHeader: protocol.DatagramHeader{
				Type:      protocol.DatagramFrameHandshake,
				RecvIndex: l.peerIndex,
				Seq:       l.seq,
			},
			SenderIndex: l.localIndex,
			MsgType:     m.typ,
		}
		// Echo the server's anti-DoS cookie only on the ClientHello; the server
		// only ever demands it on the bootstrap flight, and later flights are
		// already gated through by then (knownSource is true).
		if m.typ == protocol.MessageTypeClientHello {
			base.Cookie = l.cookie
		}
		frames, err := fragmentHandshake(base, m.body, l.ep.padHandshake)
		if err != nil {
			return
		}
		l.ep.batch.writeAll(frames, l.src)
		l.seq += uint64(len(frames))
	}
}

// armTimer resets t to fire after d (clamped to >= 0), draining any stale tick.
func armTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	if d < 0 {
		d = 0
	}
	t.Reset(d)
}
