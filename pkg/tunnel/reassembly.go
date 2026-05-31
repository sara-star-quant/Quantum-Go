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
}

type reasmKey struct {
	sender uint32
	msg    protocol.MessageType
}

type fragmentBuffer struct {
	total     int
	buf       []byte
	covered   []bool // per-byte coverage; tolerates overlapping retransmits
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
		maxSources:             constants.DatagramMaxHalfOpenTotal,
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

	r.evictExpiredLocked()

	bufs := r.bySource[source]
	if bufs == nil {
		// Global ceiling across all sources. evictExpiredLocked already ran above;
		// if we are still at the cap, drop this new source rather than grow without
		// bound (UDP sources are spoofable). Legit peers retry; stale state times out.
		if len(r.bySource) >= r.maxSources {
			return nil, false, errReassemblerFull
		}
		bufs = make(map[reasmKey]*fragmentBuffer)
		r.bySource[source] = bufs
	}

	key := reasmKey{sender: h.SenderIndex, msg: h.MsgType}
	fb := bufs[key]
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
			covered:   make([]bool, total),
			createdAt: r.now(),
		}
		bufs[key] = fb
	} else if fb.total != total {
		// TotalLength must be stable across a message's fragments.
		return nil, false, qerrors.ErrInvalidMessage
	}

	off := int(h.FragOffset)
	copy(fb.buf[off:off+len(fragment)], fragment)
	for i := off; i < off+len(fragment); i++ {
		if !fb.covered[i] {
			fb.covered[i] = true
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
// The endpoint reads it as one of the cookie-pressure signals; it is only
// consulted on the handshake-frame path (never the data hot path), so the lock
// cost is irrelevant and a mirrored atomic is not worth the desync risk.
func (r *Reassembler) sourceCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bySource)
}

func (r *Reassembler) evictExpiredLocked() {
	deadline := r.now().Add(-r.timeout)
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
