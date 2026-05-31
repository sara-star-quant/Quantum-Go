// Package tunnel — datagram.go is the connectionless UDP/datagram transport
// endpoint. It is a separate transport from the TCP/stream `Transport`: there is
// no per-peer `net.Conn` and no `Accept` in the stream sense. A single
// `net.PacketConn` carries many sessions, which are demultiplexed by a random
// per-session connection index (carried in every frame), not by source address.
//
// Demuxing by index rather than address means a session survives NAT rebind and
// roaming, one address can host many sessions, and the index space resists
// off-path guessing because indices are drawn from the CSPRNG.
//
// This file provides the endpoint shell and the connection-index registry. The
// reliable handshake state machine (dgram_handshake.go) and the epoch-keyed data
// path (Session datagram methods) plug into the routing seams marked below.
package tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// errConnIndexExhausted is returned if a free random connection index cannot be
// found after a bounded number of attempts (practically impossible until the
// active-session table is enormous).
var errConnIndexExhausted = errors.New("tunnel: could not allocate a free connection index")

// maxIndexAllocAttempts bounds the retry loop when drawing a random index.
const maxIndexAllocAttempts = 100

// datagramSession is the per-session routing state held by a DatagramEndpoint,
// keyed in the registry by the connection index. index and inbox are immutable
// after creation (the receive loop reads only those), so the owning handshake
// goroutine and the receive loop need no shared lock; session is written once by
// the handshake goroutine and published via acceptCh / the dial return.
type datagramSession struct {
	index   uint32          // the local connection index we assigned (peer echoes it)
	inbox   chan inboundMsg // reassembled handshake messages for this session's goroutine
	session *Session        // set once the handshake establishes

	// Set once at establishment, then read-only. peerIndex is the index the peer
	// assigned to us (we echo it as RecvIndex when sending so the peer demuxes by
	// it); peerAddr is the peer's current address (the data-path send target, and
	// the rebinding anchor for roaming); recvCh delivers decrypted application
	// payloads to the DatagramConn.
	peerIndex uint32
	peerAddr  net.Addr
	recvCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	// Rekey transport state. The initiator (handshake RoleInitiator) drives rekey
	// from a goroutine and reads RekeyResponse bodies off rekeyInbox; the responder
	// answers reactively on the receive loop and caches its sealed response frames
	// (keyed by the epoch the rekey transitions from) to replay verbatim on a
	// retransmitted RekeyInit, never re-encapsulating. rekeyActive guards a single
	// in-flight initiator rekey.
	rekeyInbox      chan []byte
	rekeyActive     atomic.Bool
	rekeyRespMu     sync.Mutex
	rekeyRespFrom   uint8
	rekeyRespValid  bool
	rekeyRespFrames [][]byte

	// retryCh delivers a server anti-DoS cookie (from a RETRY frame) to an
	// initiator handshake goroutine so it can re-send its ClientHello carrying the
	// cookie. Only the initiator (DialDatagram) creates it.
	retryCh chan []byte
}

// beginRekey claims the single initiator rekey slot, returning false if one is
// already in flight.
func (ds *datagramSession) beginRekey() bool { return ds.rekeyActive.CompareAndSwap(false, true) }

// endRekey releases the initiator rekey slot.
func (ds *datagramSession) endRekey() { ds.rekeyActive.Store(false) }

// dataInboxCap buffers decrypted application datagrams between the receive loop
// and the DatagramConn reader. The receive loop delivers non-blocking, so a slow
// reader drops datagrams (UDP semantics) rather than stalling the whole endpoint.
const dataInboxCap = 64

// teardown removes the session from the registry and signals its conn closed. It
// is idempotent and must be called WITHOUT holding the registry lock.
func (ds *datagramSession) teardown(r *connRegistry) {
	r.remove(ds.index)
	ds.closeOnce.Do(func() {
		if ds.closed != nil {
			close(ds.closed)
		}
	})
}

// connRegistry maps the random connection indices we assign to their sessions
// and provides per-source half-open (un-established) accounting. The handshake
// FSM gates new half-open sessions through tryAddHalfOpen (releasing on
// establishment or teardown); until that is wired, the reassembler's global and
// per-source caps are the active pre-auth memory bounds. A future stateless
// cookie/retry exchange removes the spoofed-source vector entirely.
type connRegistry struct {
	mu            sync.Mutex
	byIndex       map[uint32]*datagramSession
	bySource      map[string]*datagramSession // in-progress responder handshakes, keyed by source
	halfOpen      map[string]int              // source identity -> count of un-established sessions
	halfOpenTotal int                         // sum of halfOpen across all sources (cookie-pressure signal)
}

func newConnRegistry() *connRegistry {
	return &connRegistry{
		byIndex:  make(map[uint32]*datagramSession),
		bySource: make(map[string]*datagramSession),
		halfOpen: make(map[string]int),
	}
}

// randIndex draws a non-zero random 32-bit connection index. Index 0 is reserved
// to mean "unknown" (a peer's first frame before it has learned our index).
func randIndex() (uint32, error) {
	var b [4]byte
	if err := crypto.SecureRandom(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// add assigns a free random index to s, records it, and returns the index. It
// regenerates on the (rare) collision. The whole allocation happens under the
// lock so two goroutines cannot pick the same index.
func (r *connRegistry) add(s *datagramSession) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < maxIndexAllocAttempts; i++ {
		idx, err := randIndex()
		if err != nil {
			return 0, err
		}
		if idx == 0 {
			continue
		}
		if _, exists := r.byIndex[idx]; exists {
			continue
		}
		s.index = idx
		r.byIndex[idx] = s
		return idx, nil
	}
	return 0, errConnIndexExhausted
}

// lookup returns the session for a connection index, or nil if none.
func (r *connRegistry) lookup(index uint32) *datagramSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byIndex[index]
}

// remove deletes a session by index. It is idempotent.
func (r *connRegistry) remove(index uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byIndex, index)
}

// count returns the number of registered sessions (test/metrics helper).
func (r *connRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byIndex)
}

// idleSince returns established sessions whose last datagram activity predates
// cutoffNanos. It only snapshots under the lock; the caller tears the victims down
// afterwards (teardown re-acquires the lock, so holding it here would deadlock).
func (r *connRegistry) idleSince(cutoffNanos int64) []*datagramSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	var idle []*datagramSession
	for _, ds := range r.byIndex {
		if ds.session != nil && ds.session.lastActivityNanos.Load() < cutoffNanos {
			idle = append(idle, ds)
		}
	}
	return idle
}

// tryAddHalfOpen increments the half-open count for source and returns false if
// the per-source cap is already reached (the caller must then drop the new
// handshake attempt). Pair every successful call with releaseHalfOpen.
func (r *connRegistry) tryAddHalfOpen(source string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.halfOpen[source] >= constants.DatagramMaxHalfOpenPerSource {
		return false
	}
	r.halfOpen[source]++
	r.halfOpenTotal++
	return true
}

// releaseHalfOpen decrements the half-open count for source (on establishment or
// teardown of a half-open session). It never goes negative.
func (r *connRegistry) releaseHalfOpen(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.halfOpen[source]
	if n == 0 {
		return
	}
	if n > 1 {
		r.halfOpen[source] = n - 1
	} else {
		delete(r.halfOpen, source)
	}
	r.halfOpenTotal--
}

// halfOpenLoad returns the global half-open count, one of the endpoint's
// cookie-pressure signals.
func (r *connRegistry) halfOpenLoad() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.halfOpenTotal
}

// knownSource reports whether an incoming handshake frame belongs to a source we
// already track: an established session under index, or an in-progress responder
// for src. The cookie gate lets known sources through unchallenged; gating on
// "known" (not on RecvIndex == 0) is what stops an attacker from dodging the gate
// by stamping a random nonzero RecvIndex on a spoofed bootstrap ClientHello.
func (r *connRegistry) knownSource(index uint32, src string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if index != 0 {
		if _, ok := r.byIndex[index]; ok {
			return true
		}
	}
	_, ok := r.bySource[src]
	return ok
}

// addSource registers an in-progress responder handshake under its source so a
// retransmitted ClientHello (which still carries RecvIndex 0) routes to it.
func (r *connRegistry) addSource(source string, s *datagramSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bySource[source] = s
}

// lookupSource returns the in-progress responder handshake for a source, or nil.
func (r *connRegistry) lookupSource(source string) *datagramSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bySource[source]
}

// removeSource drops the source mapping (on establishment or teardown). It is
// idempotent.
func (r *connRegistry) removeSource(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bySource, source)
}

// DatagramEndpoint is a connectionless UDP transport over a single PacketConn.
// It demultiplexes incoming datagrams to per-session state by connection index
// and surfaces newly-established inbound sessions on an accept channel.
type DatagramEndpoint struct {
	conn     net.PacketConn
	registry *connRegistry
	reasm    *Reassembler
	acceptCh chan *datagramSession

	// cookie mints and verifies stateless return-routability cookies for the
	// anti-DoS gate (see dgram_cookie.go).
	cookie *cookieSigner
	// cookiePressureHighWater is the load at which the endpoint demands a cookie
	// from new sources; defaulted from constants, lowered (in-package) for tests
	// so pressure can be forced without thousands of real sources.
	cookiePressureHighWater int

	// rtoInitial/rtoMax bound handshake retransmission backoff; defaulted from
	// constants, overridable (in-package) for fast tests.
	rtoInitial time.Duration
	rtoMax     time.Duration

	// idleTimeout is how long an established session may be idle before the reaper
	// tears it down; defaulted from constants, overridable for fast tests.
	idleTimeout time.Duration

	closeOnce sync.Once
	done      chan struct{}
}

// NewDatagramEndpoint wraps a PacketConn (a *net.UDPConn in production, or a
// fault-injecting conn in tests). It does not start the receive loop; callers
// start it explicitly so tests can drive routing deterministically. It returns an
// error only if the per-endpoint cookie secret cannot be drawn from the CSPRNG.
func NewDatagramEndpoint(conn net.PacketConn) (*DatagramEndpoint, error) {
	cookie, err := newCookieSigner(nil)
	if err != nil {
		return nil, err
	}
	return &DatagramEndpoint{
		conn:                    conn,
		registry:                newConnRegistry(),
		reasm:                   NewReassembler(0, 0, 0),
		acceptCh:                make(chan *datagramSession, 16),
		cookie:                  cookie,
		cookiePressureHighWater: constants.DatagramCookiePressureHighWater,
		rtoInitial:              time.Duration(constants.DatagramHandshakeInitialTimeoutMillis) * time.Millisecond,
		rtoMax:                  time.Duration(constants.DatagramHandshakeMaxTimeoutMillis) * time.Millisecond,
		idleTimeout:             time.Duration(constants.DatagramIdleTimeoutSeconds) * time.Second,
		done:                    make(chan struct{}),
	}, nil
}

// underCookiePressure reports whether the endpoint should demand a
// return-routability cookie from new sources. Either the in-progress reassembly
// source count or the global half-open count crossing the high-water mark trips
// it: reassembler occupancy catches a partial-fragment flood (nothing completes,
// so the half-open count stays at zero), while the half-open count catches a
// completed-ClientHello / CH-KEM flood.
func (e *DatagramEndpoint) underCookiePressure() bool {
	return e.reasm.sourceCount() >= e.cookiePressureHighWater ||
		e.registry.halfOpenLoad() >= e.cookiePressureHighWater
}

// Close shuts the endpoint down and closes the underlying PacketConn. It is
// idempotent and safe for concurrent use.
func (e *DatagramEndpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.done)
		err = e.conn.Close()
	})
	return err
}

// Serve runs the receive loop: it reads datagrams and dispatches each through
// routeDatagram until the endpoint is closed. Callers run it in their own
// goroutine (go ep.Serve()). It returns when the underlying conn is closed.
func (e *DatagramEndpoint) Serve() {
	go e.reapIdle()
	buf := make([]byte, constants.DatagramMTU+512)
	for {
		n, src, err := e.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		_ = e.routeDatagram(src, data)
	}
}

// reapIdle tears down sessions with no datagram activity within idleTimeout. It
// snapshots victims under the registry lock, then tears them down outside it.
// There is no FIN over UDP, so idle reaping is the primary teardown mechanism.
func (e *DatagramEndpoint) reapIdle() {
	interval := e.idleTimeout / 4
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-e.idleTimeout).UnixNano()
			for _, ds := range e.registry.idleSince(cutoff) {
				if ds.session != nil {
					ds.session.Close()
				}
				ds.teardown(e.registry)
			}
		}
	}
}

// routeDatagram parses one received datagram and dispatches it. It is the demux
// seam: handshake frames go to the reassembler + handshake FSM, data frames are
// looked up by connection index and handed to the session's datagram recv path,
// and close frames tear the session down.
//
// The cryptographic actions (handshake processing, AEAD open + epoch cipher
// selection) are implemented in dgram_handshake.go and the Session datagram
// methods; this routing layer only parses headers and selects the destination.
func (e *DatagramEndpoint) routeDatagram(src net.Addr, data []byte) error {
	ft, err := protocol.PeekDatagramType(data)
	if err != nil {
		return err
	}
	switch ft {
	case protocol.DatagramFrameHandshake:
		h, fragment, perr := protocol.ParseDatagramHandshake(data)
		if perr != nil {
			return perr
		}
		if e.cookieGateRejects(src, h, data) {
			return nil // dropped before any reassembly/CH-KEM state is committed
		}
		msg, complete, aerr := e.reasm.Add(src.String(), h, fragment)
		if aerr != nil {
			return aerr
		}
		if complete {
			switch h.MsgType {
			case protocol.MessageTypeDatagramRekeyInit, protocol.MessageTypeDatagramRekeyResponse:
				e.handleRekey(h, msg)
			default:
				e.deliverHandshake(src, h, msg)
			}
		}
		return nil
	case protocol.DatagramFrameData:
		hdr, body, perr := protocol.ParseDatagramHeader(data)
		if perr != nil {
			return perr
		}
		ds := e.registry.lookup(hdr.RecvIndex)
		if ds == nil || ds.session == nil {
			return nil // unknown index / not yet established: drop (no state created)
		}
		// peek -> authenticate -> commit. Admissible cheaply rejects obvious
		// replays and too-old sequences before the AEAD Open, so replayed captured
		// frames cannot force a decryption each. The window is only recorded (Check)
		// after authentication succeeds, so a spoofed sequence cannot advance it.
		if !ds.session.dgramReplay.Admissible(hdr.Seq) {
			return nil
		}
		pt, oerr := ds.session.DatagramOpen(hdr.Epoch, hdr.Seq, body, protocol.DatagramAAD(data))
		if oerr != nil {
			return nil // authentication failed: drop
		}
		if !ds.session.dgramReplay.Check(hdr.Seq) {
			return nil // duplicate that slipped past the peek: drop
		}
		ds.session.BytesReceived.Add(int64(len(pt)))
		ds.session.PacketsRecv.Add(1)
		select {
		case ds.recvCh <- pt:
		default: // slow reader: drop (UDP semantics)
		}
		return nil
	case protocol.DatagramFrameClose:
		hdr, body, perr := protocol.ParseDatagramHeader(data)
		if perr != nil {
			return perr
		}
		ds := e.registry.lookup(hdr.RecvIndex)
		if ds == nil || ds.session == nil {
			return nil
		}
		// A CLOSE is authenticated like a data frame (AEAD tag over the header):
		// teardown only on a verified, replay-fresh CLOSE, so an off-path attacker
		// who learns the index cannot kill the session.
		if !ds.session.dgramReplay.Admissible(hdr.Seq) {
			return nil
		}
		if _, oerr := ds.session.DatagramOpen(hdr.Epoch, hdr.Seq, body, protocol.DatagramAAD(data)); oerr != nil {
			return nil
		}
		if !ds.session.dgramReplay.Check(hdr.Seq) {
			return nil
		}
		ds.session.Close()
		ds.teardown(e.registry)
		return nil
	case protocol.DatagramFrameRetry:
		// A server's anti-DoS RETRY: hand the cookie to the initiator handshake
		// named by RecvIndex so it can re-send its ClientHello carrying the cookie.
		recvIndex, cookie, rerr := protocol.ParseDatagramRetry(data)
		if rerr != nil {
			return rerr
		}
		ds := e.registry.lookup(recvIndex)
		if ds == nil || ds.retryCh == nil {
			return nil // unknown index or not an initiator handshake: drop
		}
		select {
		case ds.retryCh <- append([]byte(nil), cookie...):
		default: // a RETRY is already queued: drop (the initiator only needs one)
		}
		return nil
	default:
		return nil // unknown frame type: drop
	}
}

// cookieGateRejects implements the stateless return-routability gate. Under load,
// a handshake frame from a source we do not already track must echo a valid cookie
// (return-routability proof) or it is dropped before committing any reassembly or
// CH-KEM state. It answers a plausible bootstrap ClientHello first fragment with a
// RETRY carrying a fresh cookie, but only when that RETRY is no larger than the
// triggering datagram, so RETRY can never be an amplifier. It returns true when
// the caller must drop the frame.
func (e *DatagramEndpoint) cookieGateRejects(src net.Addr, h protocol.DatagramHandshakeHeader, data []byte) bool {
	if !e.underCookiePressure() {
		return false
	}
	if e.registry.knownSource(h.RecvIndex, src.String()) {
		return false
	}
	if e.cookie.verify(src, h.Cookie) {
		return false
	}
	retry := protocol.EncodeDatagramRetry(h.SenderIndex, e.cookie.issue(src))
	if h.MsgType == protocol.MessageTypeClientHello && h.FragOffset == 0 && len(data) >= len(retry) {
		_, _ = e.conn.WriteTo(retry, src)
	}
	return true
}
