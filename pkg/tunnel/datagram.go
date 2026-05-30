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
	index   uint32             // the local connection index we assigned (peer echoes it)
	inbox   chan inboundMsg    // reassembled handshake messages for this session's goroutine
	session *Session           // set once the handshake establishes
}

// connRegistry maps the random connection indices we assign to their sessions
// and provides per-source half-open (un-established) accounting. The handshake
// FSM gates new half-open sessions through tryAddHalfOpen (releasing on
// establishment or teardown); until that is wired, the reassembler's global and
// per-source caps are the active pre-auth memory bounds. A future stateless
// cookie/retry exchange removes the spoofed-source vector entirely.
type connRegistry struct {
	mu       sync.Mutex
	byIndex  map[uint32]*datagramSession
	bySource map[string]*datagramSession // in-progress responder handshakes, keyed by source
	halfOpen map[string]int              // source identity -> count of un-established sessions
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
	return true
}

// releaseHalfOpen decrements the half-open count for source (on establishment or
// teardown of a half-open session). It never goes negative.
func (r *connRegistry) releaseHalfOpen(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.halfOpen[source]; n > 1 {
		r.halfOpen[source] = n - 1
	} else {
		delete(r.halfOpen, source)
	}
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

	// rtoInitial/rtoMax bound handshake retransmission backoff; defaulted from
	// constants, overridable (in-package) for fast tests.
	rtoInitial time.Duration
	rtoMax     time.Duration

	closeOnce sync.Once
	done      chan struct{}
}

// NewDatagramEndpoint wraps a PacketConn (a *net.UDPConn in production, or a
// fault-injecting conn in tests). It does not start the receive loop; callers
// start it explicitly so tests can drive routing deterministically.
func NewDatagramEndpoint(conn net.PacketConn) *DatagramEndpoint {
	return &DatagramEndpoint{
		conn:       conn,
		registry:   newConnRegistry(),
		reasm:      NewReassembler(0, 0, 0),
		acceptCh:   make(chan *datagramSession, 16),
		rtoInitial: time.Duration(constants.DatagramHandshakeInitialTimeoutMillis) * time.Millisecond,
		rtoMax:     time.Duration(constants.DatagramHandshakeMaxTimeoutMillis) * time.Millisecond,
		done:       make(chan struct{}),
	}
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
		msg, complete, aerr := e.reasm.Add(src.String(), h, fragment)
		if aerr != nil {
			return aerr
		}
		if complete {
			e.deliverHandshake(src, h, msg)
		}
		return nil
	case protocol.DatagramFrameData:
		hdr, body, perr := protocol.ParseDatagramHeader(data)
		if perr != nil {
			return perr
		}
		ds := e.registry.lookup(hdr.RecvIndex)
		if ds == nil {
			return nil // unknown index: drop (no error, no state created)
		}
		// TODO: hand (hdr, body) to ds.session's datagram recv path — epoch-keyed
		// cipher selection + AEAD open with the derived nonce
		// (AAD = DatagramAAD(data)) + global replay window check.
		_, _ = ds, body
		return nil
	case protocol.DatagramFrameClose:
		hdr, _, perr := protocol.ParseDatagramHeader(data)
		if perr != nil {
			return perr
		}
		if ds := e.registry.lookup(hdr.RecvIndex); ds != nil {
			// TODO: a CLOSE carries a seq + AEAD tag like a data frame and MUST be
			// authenticated (AEAD open with AAD = the header) before teardown;
			// otherwise an off-path attacker who learns the index could kill the
			// session. Do nothing here for now; teardown is driven by the idle reaper.
			_ = ds
		}
		return nil
	default:
		return nil // unknown or reserved frame type (e.g. RETRY, not yet handled): drop
	}
}
