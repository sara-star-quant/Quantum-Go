package tunnel

import (
	"errors"
	"sync"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// errReassemblerFull is returned when a new source cannot be admitted because the
// global reassembly source cap is reached. The caller drops the fragment.
var errReassemblerFull = errors.New("tunnel: reassembler at global source capacity")

// Reassembler reassembles fragmented HANDSHAKE messages. Only handshake
// messages are ever fragmented (the PQ Hellos exceed the datagram MTU); data
// frames are capped to a single datagram, so the reassembler is never exposed to
// data traffic — it only ever sees the bounded, few-message handshake.
//
// Because reassembly runs before the peer is authenticated, it is bounded
// against memory exhaustion in four independent ways:
//
//   - a global cap on the number of distinct sources reassembling at once (UDP
//     source addresses are spoofable, so a per-source cap alone does not bound
//     total memory),
//   - a per-source cap on the number of concurrent in-progress messages,
//   - a per-message size cap (declared TotalLength is rejected if too large),
//   - a per-message timeout after which partial state is evicted.
type Reassembler struct {
	mu       sync.Mutex
	bySource map[string]map[reasmKey]*fragmentBuffer

	maxSources             int
	maxConcurrentPerSource int
	maxMessageSize         int
	timeout                time.Duration
	now                    func() time.Time
	lastSweep              time.Time
}

// reasmKey names one message in flight. The declared total is part of the key because a
// HelloRetryRequest handshake sends two ClientHellos of different sizes under one sender and
// type, and a late fragment of the first must not poison the retried second.
type reasmKey struct {
	sender uint32
	msg    protocol.MessageType
	total  int
}

type fragmentBuffer struct {
	total     int
	buf       []byte
	covered   []uint64 // per-byte coverage bitset; tolerates overlapping retransmits
	coveredN  int
	createdAt time.Time
}

// NewReassembler creates a Reassembler with the configured bounds. Non-positive
// arguments fall back to the package defaults in internal/constants.
func NewReassembler(maxConcurrentPerSource, maxMessageSize int, timeout time.Duration) *Reassembler {
	if maxConcurrentPerSource <= 0 {
		maxConcurrentPerSource = constants.DatagramMaxConcurrentReassembly
	}
	if maxMessageSize <= 0 {
		maxMessageSize = constants.DatagramMaxHandshakeMessageSize
	}
	if timeout <= 0 {
		timeout = time.Duration(constants.DatagramReassemblyTimeoutSeconds) * time.Second
	}
	return &Reassembler{
		bySource:               make(map[string]map[reasmKey]*fragmentBuffer),
		maxSources:             constants.DatagramMaxHalfOpenFloor,
		maxConcurrentPerSource: maxConcurrentPerSource,
		maxMessageSize:         maxMessageSize,
		timeout:                timeout,
		now:                    time.Now,
	}
}

// Add ingests one handshake fragment from source (a stable string identity for
// the remote, e.g. its UDP address). It returns the fully reassembled message
// when the final missing fragment arrives (complete=true); otherwise it returns
// complete=false with no message. A returned error means the fragment was
// rejected (malformed or over a bound); the caller should drop it.
func (r *Reassembler) Add(source string, h protocol.DatagramHandshakeHeader, fragment []byte) (msg []byte, complete bool, err error) {
	total := int(h.TotalLength)
	if total <= 0 || total > r.maxMessageSize {
		return nil, false, qerrors.ErrMessageTooLarge
	}
	if int(h.FragOffset)+int(h.FragLength) > total || int(h.FragLength) != len(fragment) {
		return nil, false, qerrors.ErrInvalidMessage
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.sweepLocked(false)

	bufs := r.bySource[source]
	if bufs == nil {
		// Global ceiling across all sources. Force a sweep so stale state never
		// holds the cap; if we are still at it, drop this new source rather than grow
		// without bound (UDP sources are spoofable). Legit peers retry.
		if len(r.bySource) >= r.maxSources {
			r.sweepLocked(true)
			if len(r.bySource) >= r.maxSources {
				return nil, false, errReassemblerFull
			}
		}
		bufs = make(map[reasmKey]*fragmentBuffer)
		r.bySource[source] = bufs
	}

	key := reasmKey{sender: h.SenderIndex, msg: h.MsgType, total: total}
	fb := bufs[key]
	if fb != nil && r.now().Sub(fb.createdAt) > r.timeout {
		// The sweep is throttled, so a buffer can outlive its timeout by a little.
		delete(bufs, key)
		fb = nil
	}
	if fb == nil {
		if len(bufs) >= r.maxConcurrentPerSource {
			// Over the per-source cap: evict this source's oldest buffer to make
			// room rather than rejecting outright, so a single stalled message
			// cannot wedge a legitimate retry.
			r.evictOldestLocked(bufs)
		}
		fb = &fragmentBuffer{
			total:     total,
			buf:       make([]byte, total),
			covered:   make([]uint64, (total+63)/64),
			createdAt: r.now(),
		}
		bufs[key] = fb
	}

	off := int(h.FragOffset)
	copy(fb.buf[off:off+len(fragment)], fragment)
	for i := off; i < off+len(fragment); i++ {
		if fb.covered[i>>6]&(1<<(i&63)) == 0 {
			fb.covered[i>>6] |= 1 << (i & 63)
			fb.coveredN++
		}
	}

	if fb.coveredN < fb.total {
		return nil, false, nil
	}

	delete(bufs, key)
	if len(bufs) == 0 {
		delete(r.bySource, source)
	}
	return fb.buf, true, nil
}

// Drop discards all in-progress reassembly state for a source. The endpoint
// calls this once a session is established (or torn down) so completed
// handshakes do not retain buffers.
func (r *Reassembler) Drop(source string) {
	r.mu.Lock()
	delete(r.bySource, source)
	r.mu.Unlock()
}

// sourceCount returns the number of sources with in-progress reassembly state.
// The endpoint reads it as one of the cookie-pressure signals for every handshake
// frame, and an attacker drives that path before any authentication, so it must stay
// cheap: it uses the throttled sweep, which runs at most once per quarter of the
// timeout, and the count can include state up to that long past its expiry.
func (r *Reassembler) sourceCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(false)
	return len(r.bySource)
}

// sweepLocked evicts timed-out buffers. Unforced calls run at most once per quarter
// timeout, so a fragment flood does not rescan every source and buffer per packet.
func (r *Reassembler) sweepLocked(force bool) {
	now := r.now()
	if !force && now.Sub(r.lastSweep) < r.timeout/4 {
		return
	}
	r.lastSweep = now
	deadline := now.Add(-r.timeout)
	for src, bufs := range r.bySource {
		for k, fb := range bufs {
			if fb.createdAt.Before(deadline) {
				delete(bufs, k)
			}
		}
		if len(bufs) == 0 {
			delete(r.bySource, src)
		}
	}
}

func (r *Reassembler) evictOldestLocked(bufs map[reasmKey]*fragmentBuffer) {
	var oldestKey reasmKey
	var oldest *fragmentBuffer
	for k, fb := range bufs {
		if oldest == nil || fb.createdAt.Before(oldest.createdAt) {
			oldest, oldestKey = fb, k
		}
	}
	if oldest != nil {
		delete(bufs, oldestKey)
	}
}
