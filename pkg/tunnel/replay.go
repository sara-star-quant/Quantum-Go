package tunnel

import "sync"

// DatagramReplayWindowSize is the number of sequence numbers tracked by the
// datagram replay window, in bits. It is deliberately much larger than the
// stream ReplayWindow (64) so the filter tolerates the deeper packet reordering
// that is normal on UDP/datagram paths. It must be a multiple of 64.
const DatagramReplayWindowSize = 1024

const replayWordBits = 64

// DatagramReplayWindow is a multi-word sliding-bitmap anti-replay filter over a
// 64-bit monotonic sequence space (RFC 6479 style, expressed as an explicit
// shifting bitmap for clarity).
//
// It differs from the stream ReplayWindow in two deliberate ways:
//
//   - It is wide (DatagramReplayWindowSize bits) to absorb datagram reordering.
//   - It is NEVER reset across a rekey. The datagram transport keeps the
//     sequence number globally monotonic and never resets it when keys rotate
//     (the epoch in the frame header selects the cipher; the window tracks the
//     sequence independently). Resetting the window on a key change would re-arm
//     a fresh window whose first Check accepts any sequence, re-opening a
//     one-packet replay at the rekey boundary — the same hazard the stream path
//     guards against in promotePendingRecvCipher.
//
// Bit i of the window represents sequence number (highest - i); bit 0 is the
// highest sequence accepted so far.
type DatagramReplayWindow struct {
	mu      sync.Mutex
	bitmap  []uint64
	highSeq uint64
	size    uint64 // window width in bits
	seen    bool   // whether any sequence has been accepted yet
}

// NewDatagramReplayWindow creates a replay window with the default size.
func NewDatagramReplayWindow() *DatagramReplayWindow {
	return NewDatagramReplayWindowSize(DatagramReplayWindowSize)
}

// NewDatagramReplayWindowSize creates a replay window of the given bit width.
// size is rounded up to a multiple of 64; a non-positive size uses the default.
func NewDatagramReplayWindowSize(size uint64) *DatagramReplayWindow {
	if size == 0 {
		size = DatagramReplayWindowSize
	}
	words := (size + replayWordBits - 1) / replayWordBits
	return &DatagramReplayWindow{
		bitmap: make([]uint64, words),
		size:   words * replayWordBits,
	}
}

// Check validates a sequence number against the window. It returns true if the
// sequence is fresh (not previously seen and not older than the window), and
// records it. It returns false for duplicates and for sequences that have fallen
// out of the trailing edge of the window. Check is safe for concurrent use.
func (w *DatagramReplayWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// First packet ever: accept and anchor the window on it.
	if !w.seen {
		w.seen = true
		w.highSeq = seq
		w.setBit(0)
		return true
	}

	switch {
	case seq > w.highSeq:
		// Newer than anything seen: advance the window.
		w.advance(seq - w.highSeq)
		w.highSeq = seq
		w.setBit(0)
		return true

	case seq == w.highSeq:
		// Exactly the current head — always already recorded.
		return false

	default:
		diff := w.highSeq - seq
		if diff >= w.size {
			return false // too old, outside the window
		}
		if w.testBit(diff) {
			return false // duplicate
		}
		w.setBit(diff)
		return true
	}
}

// Admissible reports whether seq would be accepted by Check without recording it.
// The datagram recv path uses it to cheaply reject obvious replays and too-old
// sequences before doing the (relatively expensive) AEAD Open, so a flood of
// replayed captured frames cannot force a decryption each. The authoritative
// record still happens in Check after authentication succeeds. Admissible is safe
// for concurrent use.
func (w *DatagramReplayWindow) Admissible(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.seen {
		return true
	}
	switch {
	case seq > w.highSeq:
		return true
	case seq == w.highSeq:
		return false
	default:
		diff := w.highSeq - seq
		if diff >= w.size {
			return false
		}
		return !w.testBit(diff)
	}
}

// advance shifts the bitmap toward higher bit positions by delta, dropping bits
// that fall off the high end of the window. Existing bit i moves to bit i+delta.
func (w *DatagramReplayWindow) advance(delta uint64) {
	if delta >= w.size {
		// The jump clears the whole window.
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}
	wordShift := delta / replayWordBits
	bitShift := delta % replayWordBits
	for i := len(w.bitmap) - 1; i >= 0; i-- {
		src := uint64(i) - wordShift
		var v uint64
		if int64(src) >= 0 {
			v = w.bitmap[src] << bitShift
			if bitShift != 0 && int64(src)-1 >= 0 {
				v |= w.bitmap[src-1] >> (replayWordBits - bitShift)
			}
		}
		w.bitmap[i] = v
	}
}

func (w *DatagramReplayWindow) setBit(pos uint64) {
	w.bitmap[pos/replayWordBits] |= 1 << (pos % replayWordBits)
}

func (w *DatagramReplayWindow) testBit(pos uint64) bool {
	return w.bitmap[pos/replayWordBits]&(1<<(pos%replayWordBits)) != 0
}
