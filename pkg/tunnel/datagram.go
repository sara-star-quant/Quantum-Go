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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
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

	// peerIndex is the index the peer assigned to us (we echo it as RecvIndex when
	// sending so the peer demuxes by it); set once at establishment, then read-only.
	// recvCh delivers decrypted application payloads to the DatagramConn.
	peerIndex uint32
	recvCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	// peerAddr is the peer's current address: the data-path send target and the
	// roaming anchor. Unlike peerIndex it is mutable - the receive loop advances it
	// when an AEAD-authenticated, replay-fresh frame arrives from a new source (see
	// routeDatagram), so a session follows a peer across NAT rebind/roaming. It is
	// atomic because the receive loop writes it while the send/rekey goroutines read
	// it. Access only via currentPeerAddr/setPeerAddr.
	peerAddr atomic.Pointer[net.Addr]

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

// currentPeerAddr returns the peer's current send address, or nil if unset.
func (ds *datagramSession) currentPeerAddr() net.Addr {
	if p := ds.peerAddr.Load(); p != nil {
		return *p
	}
	return nil
}

// setPeerAddr updates the peer's send address (roaming, or the initial set).
func (ds *datagramSession) setPeerAddr(a net.Addr) { ds.peerAddr.Store(&a) }

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
// and provides half-open (un-established) accounting. The bootstrap path admits new
// half-open responder sessions through reserveSource and releases them on
// establishment or teardown; the global half-open ceiling (maxHalfOpen) it enforces,
// the reassembler's caps, and the stateless cookie gate are the pre-auth memory
// bounds against spoofed sources.
type connRegistry struct {
	mu            sync.Mutex
	byIndex       map[uint32]*datagramSession
	bySource      map[string]*datagramSession // in-progress responder handshakes, keyed by source
	halfOpen      map[string]int              // source identity -> count of un-established sessions
	halfOpenTotal int                         // sum of halfOpen across all sources (cookie-pressure signal)
	maxHalfOpen   int                         // hard ceiling on halfOpenTotal; reserveSource drops new sources at it
}

func newConnRegistry(maxHalfOpen int) *connRegistry {
	return &connRegistry{
		byIndex:     make(map[uint32]*datagramSession),
		bySource:    make(map[string]*datagramSession),
		halfOpen:    make(map[string]int),
		maxHalfOpen: maxHalfOpen,
	}
}

// addrEqual reports whether two peer addresses are the same endpoint. It compares
// *net.UDPAddr without allocating (the data hot path runs it per received frame to
// detect roaming) and falls back to String() for other net.Addr implementations.
func addrEqual(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == b
	}
	au, aok := a.(*net.UDPAddr)
	bu, bok := b.(*net.UDPAddr)
	if aok && bok {
		return au.Port == bu.Port && au.IP.Equal(bu.IP) && au.Zone == bu.Zone
	}
	return a.String() == b.String()
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
// the global half-open ceiling is already reached (the caller must then drop the
// new handshake attempt). Pair every successful call with releaseHalfOpen.
func (r *connRegistry) tryAddHalfOpen(source string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addHalfOpenLocked(source)
}

// addHalfOpenLocked admits one half-open session, or returns false if the global
// half-open ceiling (maxHalfOpen) is already reached. The caller must hold r.mu. It
// is the single admission check shared by tryAddHalfOpen and reserveSource. The
// per-source halfOpen map is kept for release idempotency (see releaseHalfOpen), not
// for a per-source cap: reserveSource dedups per source before calling this, so a
// source holds at most one half-open slot.
func (r *connRegistry) addHalfOpenLocked(source string) bool {
	if r.halfOpenTotal >= r.maxHalfOpen {
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

// reserveSource makes the bootstrap decision for a RecvIndex-0 ClientHello from
// source atomically under one lock, so concurrent receive goroutines (the
// SO_REUSEPORT parallel-receive path) cannot both start a responder for the same new
// source. build constructs the not-yet-keyed session to install, and runs ONLY when
// source is admitted - so a retransmit that loses the race or a ClientHello past the
// cap costs no session allocation. It returns:
//   - (ds, true): source was new and admitted - the built session is now registered
//     in bySource and a half-open slot is claimed; the caller MUST run startResponder
//     with this session and release the slot on failure. Registering in bySource
//     here (not later, after the slow CH-KEM work in startResponder) is what closes
//     the window where a second goroutine could also start a responder.
//   - (existing, false): a responder for source already exists (this goroutine raced
//     a retransmit, or the kernel hashed two copies to two sockets); the caller
//     routes the ClientHello to existing. build did not run.
//   - (nil, false): the global half-open ceiling is reached; the caller drops. build
//     did not run.
func (r *connRegistry) reserveSource(source string, build func() *datagramSession) (ds *datagramSession, reserved bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.bySource[source]; existing != nil {
		return existing, false
	}
	if !r.addHalfOpenLocked(source) {
		return nil, false
	}
	fresh := build()
	r.bySource[source] = fresh
	return fresh, true
}

// addSource registers an in-progress responder handshake under its source. The
// production bootstrap path installs the session atomically via reserveSource; this
// remains as a direct primitive for tests that set up registry state.
func (r *connRegistry) addSource(source string, s *datagramSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bySource[source] = s
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
	// conn is the designated send socket and the primary receive socket; batch is
	// its batchIO. All outbound sends (data plane, cookie RETRY, handshake/rekey
	// flights) go through conn. With SO_REUSEPORT parallel receive (ListenDatagram),
	// extraBatch holds the batchIO for the additional receive sockets; Serve runs one
	// receive goroutine per socket, all dispatching into the shared, concurrency-safe
	// routeDatagram. extraConns keeps those sockets only so Close can shut them.
	conn       net.PacketConn
	batch      batchIO
	extraConns []net.PacketConn
	extraBatch []batchIO
	registry   *connRegistry
	reasm      *Reassembler
	acceptCh   chan *datagramSession

	// cookie mints and verifies stateless return-routability cookies for the
	// anti-DoS gate (see dgram_cookie.go).
	cookie *cookieSigner
	// cookiePressureHighWater is the load at which the endpoint demands a cookie
	// from new sources; derived as maxHalfOpen/2 in newEndpoint, lowered (in-package)
	// for tests so pressure can be forced without thousands of real sources.
	cookiePressureHighWater int

	// rtoInitial/rtoMax bound handshake retransmission backoff; defaulted from
	// constants, overridable (in-package) for fast tests.
	rtoInitial time.Duration
	rtoMax     time.Duration

	// idleTimeout is how long an established session may be idle before the reaper
	// tears it down; defaulted from constants, overridable for fast tests.
	idleTimeout time.Duration

	// padHandshake, when set, zero-pads every outbound handshake and rekey datagram
	// to DatagramMTU so the flight is uniform-size on the wire (anti-fingerprinting).
	// Off by default (it costs bandwidth); set via WithHandshakePadding. The receiver
	// always tolerates padding regardless of this flag, so a padding peer interops
	// with a non-padding one; full hiding needs both ends to enable it.
	padHandshake bool

	// receiveSockets is the requested SO_REUSEPORT socket count for ListenDatagram,
	// set by WithReceiveSockets; 0 means use the default. Ignored by
	// NewDatagramEndpoint.
	receiveSockets int

	// maxHalfOpen is the operator override for the half-open ceiling, set by
	// WithMaxHalfOpen; 0 means autoscale with core count. newEndpoint resolves it into
	// the registry's hard cap and the cookie-pressure water-mark.
	maxHalfOpen int

	// offload requests Linux UDP receive offload (UDP_GRO), set by WithDatagramOffload.
	// newEndpoint passes it to each receive socket's batchIO; it is a no-op off Linux,
	// on non-UDP conns, or on kernels without UDP_GRO.
	offload bool

	// staticIdentity is the responder's long-term CH-KEM identity for endpoint
	// authentication, set by WithStaticIdentity. Nil means unauthenticated.
	staticIdentity *chkem.KeyPair

	// pinnedServerKey is the server static public key the initiator requires the
	// server to prove possession of, set by WithPinnedServerKey. Nil means the
	// initiator does not authenticate the server.
	pinnedServerKey *chkem.PublicKey

	// requireStaticAuth makes the responder reject any initiator that does not
	// authenticate it via static-key pinning, set by WithRequireStaticAuth. It
	// requires staticIdentity to be set.
	requireStaticAuth bool

	closeOnce sync.Once
	done      chan struct{}
}

// DatagramEndpointOption configures a DatagramEndpoint at construction.
type DatagramEndpointOption func(*DatagramEndpoint)

// WithHandshakePadding pads every outbound handshake and rekey datagram to the
// datagram MTU, so ClientHello, ServerHello, and the rekey sub-handshake are all
// size-indistinguishable on the wire. It trades bandwidth for resistance to
// passive size-based traffic analysis; the data plane is never padded. For full
// effect both peers should enable it.
func WithHandshakePadding() DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.padHandshake = true }
}

// WithReceiveSockets sets how many SO_REUSEPORT receive sockets ListenDatagram
// opens (clamped to [1, DatagramMaxReceiveSockets]). More sockets let the kernel
// spread inbound datagrams across more cores, raising aggregate receive throughput
// for a busy multi-session server. The default is min(GOMAXPROCS,
// DatagramMaxReceiveSockets). It has no effect on NewDatagramEndpoint (single
// socket) or on platforms without SO_REUSEPORT (which degrade to one socket).
func WithReceiveSockets(n int) DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.receiveSockets = n }
}

// WithMaxHalfOpen overrides the concurrent half-open handshake ceiling (the number
// of in-progress, not-yet-established responder sessions the endpoint admits before
// dropping new sources). The default autoscales with core count
// (clamp(GOMAXPROCS*DatagramMaxHalfOpenPerCore, floor, ceiling)); set this to pin a
// fixed budget for a known deployment. Values below 1 are ignored (autoscale stays
// in effect); larger values are honored as-is. The cookie-pressure water-mark tracks
// at half the effective ceiling.
func WithMaxHalfOpen(n int) DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.maxHalfOpen = n }
}

// WithDatagramOffload enables Linux UDP receive offload (UDP_GRO): the kernel
// coalesces a burst of same-flow datagrams into one larger buffer, so one recvmmsg
// returns many datagrams' worth of bytes and the receive loop re-splits them, cutting
// receive syscalls on a busy flow. It is off by default and Linux-only; on other
// platforms, non-UDP conns, or kernels without UDP_GRO it is a no-op and the receive
// path runs unchanged. Send-side UDP_SEGMENT (GSO) is not yet wired. Enabling it grows
// the per-socket receive buffers (it must hold a coalesced burst).
func WithDatagramOffload() DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.offload = true }
}

// WithStaticIdentity sets the responder's long-term CH-KEM identity so it can
// prove possession of a pinned key during the handshake (endpoint authentication).
// Generate and persist the key pair with chkem.GenerateStaticKeyPair and distribute
// kp.PublicKey().Bytes() to clients as the pin. Unset, the endpoint is unauthenticated.
func WithStaticIdentity(kp *chkem.KeyPair) DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.staticIdentity = kp }
}

// WithRequireStaticAuth makes the responder reject any initiator that does not
// authenticate it via static-key pinning. It requires WithStaticIdentity; an
// endpoint set to require auth without an identity fails construction with
// ErrStaticAuthMisconfigured. Unset, the endpoint admits unpinned initiators
// alongside pinned ones.
func WithRequireStaticAuth() DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.requireStaticAuth = true }
}

// WithPinnedServerKey makes DialDatagram require the server to prove possession of
// the given static public key; a wrong, absent, or stripped key fails the handshake
// with ErrServerKeyMismatch. Unset, the initiator does not authenticate the server.
func WithPinnedServerKey(pub *chkem.PublicKey) DatagramEndpointOption {
	return func(e *DatagramEndpoint) { e.pinnedServerKey = pub }
}

// clampMaxHalfOpen returns the autoscaled half-open ceiling for a host with the given
// core count: cores * per-core allotment, clamped to [floor, ceiling]. Pure so the
// scaling curve is testable without touching GOMAXPROCS.
func clampMaxHalfOpen(cores int) int {
	n := cores * constants.DatagramMaxHalfOpenPerCore
	if n < constants.DatagramMaxHalfOpenFloor {
		return constants.DatagramMaxHalfOpenFloor
	}
	if n > constants.DatagramMaxHalfOpenCeiling {
		return constants.DatagramMaxHalfOpenCeiling
	}
	return n
}

// NewDatagramEndpoint wraps a PacketConn (a *net.UDPConn in production, or a
// fault-injecting conn in tests). It does not start the receive loop; callers
// start it explicitly so tests can drive routing deterministically. It returns an
// error only if the per-endpoint cookie secret cannot be drawn from the CSPRNG.
//
// It serves a single socket. For a server that wants the receive path spread across
// cores, use ListenDatagram.
func NewDatagramEndpoint(conn net.PacketConn, opts ...DatagramEndpointOption) (*DatagramEndpoint, error) {
	return newEndpoint(conn, opts)
}

// newEndpoint builds an endpoint around its primary (send + first receive) conn and
// applies opts. ListenDatagram fills extraConns/extraBatch afterward.
func newEndpoint(conn net.PacketConn, opts []DatagramEndpointOption) (*DatagramEndpoint, error) {
	cookie, err := newCookieSigner(nil)
	if err != nil {
		return nil, err
	}
	e := &DatagramEndpoint{
		conn:        conn,
		reasm:       NewReassembler(0, 0, 0),
		acceptCh:    make(chan *datagramSession, 16),
		cookie:      cookie,
		rtoInitial:  time.Duration(constants.DatagramHandshakeInitialTimeoutMillis) * time.Millisecond,
		rtoMax:      time.Duration(constants.DatagramHandshakeMaxTimeoutMillis) * time.Millisecond,
		idleTimeout: time.Duration(constants.DatagramIdleTimeoutSeconds) * time.Second,
		done:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.requireStaticAuth && e.staticIdentity == nil {
		return nil, qerrors.ErrStaticAuthMisconfigured
	}
	// Resolve the half-open ceiling after opts: autoscale with core count unless an
	// operator pinned it via WithMaxHalfOpen. The cookie-pressure water-mark and the
	// reassembler's source cap both track it so the soft (cookie) and hard (drop)
	// anti-DoS signals stay proportional across host sizes.
	if e.maxHalfOpen < 1 {
		e.maxHalfOpen = clampMaxHalfOpen(runtime.GOMAXPROCS(0))
	}
	e.cookiePressureHighWater = e.maxHalfOpen / 2
	e.registry = newConnRegistry(e.maxHalfOpen)
	e.reasm.maxSources = e.maxHalfOpen
	// Build the primary receive batchIO after opts so WithDatagramOffload is in effect.
	e.batch = newBatchIO(conn, e.offload)
	return e, nil
}

// ListenDatagram opens a datagram endpoint on (network, addr) whose receive path is
// spread across multiple SO_REUSEPORT sockets so demux and AEAD-open scale across
// cores - the way a busy multi-session tunnel server reaches aggregate throughput
// past a single core. network is "udp", "udp4", or "udp6". The socket count is
// WithReceiveSockets, defaulting to min(GOMAXPROCS, DatagramMaxReceiveSockets);
// addr may use port 0 to get an ephemeral port (resolved once and shared by all
// sockets). On platforms without SO_REUSEPORT it transparently uses one socket.
//
// Callers start the receive loop with Serve, as with NewDatagramEndpoint.
func ListenDatagram(network, addr string, opts ...DatagramEndpointOption) (*DatagramEndpoint, error) {
	probe := &DatagramEndpoint{}
	for _, opt := range opts {
		opt(probe)
	}
	n := probe.receiveSockets
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	if n > constants.DatagramMaxReceiveSockets {
		n = constants.DatagramMaxReceiveSockets
	}
	if n < 1 {
		n = 1
	}

	conns, err := listenReusePort(network, addr, n)
	if err != nil {
		return nil, err
	}
	e, err := newEndpoint(conns[0], opts)
	if err != nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, err
	}
	for _, c := range conns[1:] {
		e.extraConns = append(e.extraConns, c)
		e.extraBatch = append(e.extraBatch, newBatchIO(c, e.offload))
	}
	return e, nil
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

// Close shuts the endpoint down and closes every underlying socket (the send conn
// and any extra SO_REUSEPORT receive sockets). It is idempotent and safe for
// concurrent use. Closing the sockets unblocks all receive goroutines in Serve.
func (e *DatagramEndpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.done)
		err = e.conn.Close()
		for _, c := range e.extraConns {
			if cerr := c.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
	})
	return err
}

// Serve runs the receive loop until the endpoint is closed. It dispatches every
// datagram through routeDatagram. Callers run it in their own goroutine
// (go ep.Serve()); it returns when the sockets are closed.
//
// With SO_REUSEPORT parallel receive (ListenDatagram), it runs one receive
// goroutine per socket - the kernel load-balances inbound datagrams across the
// sockets by flow hash, so demux and AEAD-open scale across cores. routeDatagram is
// concurrency-safe (the registry, each session's replay window, and the reassembler
// are all mutex-guarded, and the RecvIndex-0 bootstrap goes through the atomic
// reserveSource), so the goroutines need no further coordination. A single-socket
// endpoint (NewDatagramEndpoint) runs exactly one receive goroutine, as before.
func (e *DatagramEndpoint) Serve() {
	go e.reapIdle()
	dispatch := func(src net.Addr, data []byte) {
		_ = e.routeDatagram(src, data)
	}
	recvLoop := func(bio batchIO) {
		for {
			if err := bio.recv(dispatch); err != nil {
				return
			}
		}
	}
	if len(e.extraBatch) == 0 {
		recvLoop(e.batch) // single-socket: stay on the caller's goroutine, as before
		return
	}
	var wg sync.WaitGroup
	for _, bio := range append([]batchIO{e.batch}, e.extraBatch...) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recvLoop(bio)
		}()
	}
	wg.Wait()
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
		// Authenticated roaming: a frame that authenticated AND was replay-fresh is
		// proof the peer holds the send key and is live at src, so follow it there if
		// it moved (NAT rebind / roaming). Gating on Check is what makes this safe -
		// a replayed captured frame fails Check above, so an off-path attacker cannot
		// steer the session to an address it controls.
		if !addrEqual(ds.currentPeerAddr(), src) {
			ds.setPeerAddr(src)
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
