package tunnel

import (
	"math/rand/v2"
	"testing"
)

func TestDatagramReplayWindow_InOrder(t *testing.T) {
	w := NewDatagramReplayWindow()
	for seq := uint64(0); seq < 10000; seq++ {
		if !w.Check(seq) {
			t.Fatalf("in-order seq %d rejected", seq)
		}
	}
}

func TestDatagramReplayWindow_Duplicate(t *testing.T) {
	w := NewDatagramReplayWindow()
	if !w.Check(5) {
		t.Fatal("first seq 5 rejected")
	}
	if w.Check(5) {
		t.Fatal("duplicate seq 5 accepted")
	}
	// Advance, then replay an older one already seen.
	if !w.Check(6) {
		t.Fatal("seq 6 rejected")
	}
	if w.Check(6) {
		t.Fatal("duplicate seq 6 accepted")
	}
	if w.Check(5) {
		t.Fatal("duplicate older seq 5 accepted")
	}
}

func TestDatagramReplayWindow_Reorder(t *testing.T) {
	w := NewDatagramReplayWindow()
	order := []uint64{10, 8, 9, 7, 12, 11, 6}
	for _, s := range order {
		if !w.Check(s) {
			t.Fatalf("reordered seq %d rejected on first sight", s)
		}
	}
	// All of them are now duplicates.
	for _, s := range order {
		if w.Check(s) {
			t.Fatalf("reordered seq %d accepted as duplicate", s)
		}
	}
}

func TestDatagramReplayWindow_TooOld(t *testing.T) {
	w := NewDatagramReplayWindowSize(128)
	if !w.Check(0) {
		t.Fatal("seq 0 rejected")
	}
	if !w.Check(1000) {
		t.Fatal("seq 1000 rejected")
	}
	// 1000 - 128 = 872 and below are outside the window now.
	if w.Check(800) {
		t.Fatal("stale seq 800 accepted")
	}
	// Just inside the trailing edge should still be acceptable.
	if !w.Check(1000 - 127) {
		t.Fatal("seq at trailing edge rejected")
	}
}

func TestDatagramReplayWindow_BoundaryEdge(t *testing.T) {
	const size = 64
	w := NewDatagramReplayWindowSize(size)
	if !w.Check(size) {
		t.Fatal("seq=size rejected")
	}
	// seq 0 is exactly size away from highSeq=size -> diff==size -> too old.
	if w.Check(0) {
		t.Fatal("seq exactly window-width away accepted")
	}
	// diff == size-1 is the oldest acceptable.
	if !w.Check(1) {
		t.Fatal("oldest in-window seq rejected")
	}
}

func TestDatagramReplayWindow_LargeJumpClears(t *testing.T) {
	w := NewDatagramReplayWindowSize(256)
	if !w.Check(5) {
		t.Fatal("seq 5 rejected")
	}
	// Jump far beyond the window; everything below the new edge becomes stale.
	if !w.Check(1_000_000) {
		t.Fatal("large jump seq rejected")
	}
	if w.Check(5) {
		t.Fatal("seq 5 accepted after window cleared by large jump")
	}
	if !w.Check(1_000_000 - 1) {
		t.Fatal("seq just below new head rejected")
	}
}

func TestDatagramReplayWindow_NeverResetAcrossEpochs(t *testing.T) {
	// The window is shared across epochs and never reset; a boundary sequence
	// recorded under the old epoch must not be replayable under the new one.
	w := NewDatagramReplayWindow()
	if !w.Check(100) {
		t.Fatal("boundary seq rejected")
	}
	// Simulate continued traffic after a (cipher-only) rekey: same window.
	if !w.Check(101) {
		t.Fatal("post-rekey seq rejected")
	}
	if w.Check(100) {
		t.Fatal("boundary seq replayable after rekey")
	}
}

// BenchmarkReplayWindowCheck measures the stream replay-window check at its
// widened 1024-bit width: the common in-order path advances the multi-word
// bitmap by one each call.
func BenchmarkReplayWindowCheck(b *testing.B) {
	rw := NewReplayWindow()
	for i := 0; i < b.N; i++ {
		rw.Check(uint64(i))
	}
}

// Admissible is the cheap filter in front of the AEAD open, so it must agree with Check on
// every input and must not record anything. A model with a plain set and a high mark decides
// what each call should answer, over reordering, repeats and jumps past the window.
func TestDatagramReplayWindow_AdmissibleAgreesWithCheck(t *testing.T) {
	for seed := uint64(1); seed <= 8; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed*7919))
		w := NewDatagramReplayWindow()
		const size = DatagramReplayWindowSize
		accepted := map[uint64]bool{}
		var high uint64
		anySeen := false
		base := uint64(5000)
		for step := range 4000 {
			var seq uint64
			switch rng.IntN(5) {
			case 0: // a jump forward, sometimes past the whole window
				seq = base + uint64(rng.IntN(3*size))
			case 1: // a repeat of something already accepted
				seq = base
				for k := range accepted {
					seq = k
					break
				}
			default: // near the head, in or just outside the window
				seq = base + uint64(rng.IntN(size+64)) - 32
			}
			want := !anySeen || seq > high || (high-seq < size && !accepted[seq])
			if got := w.Admissible(seq); got != want {
				t.Fatalf("seed %d step %d seq %d: Admissible = %v, want %v", seed, step, seq, got, want)
			}
			if got := w.Admissible(seq); got != want {
				t.Fatalf("seed %d step %d seq %d: a second Admissible = %v, so the first one recorded it", seed, step, seq, got)
			}
			if got := w.Check(seq); got != want {
				t.Fatalf("seed %d step %d seq %d: Check = %v, want %v", seed, step, seq, got, want)
			}
			if want {
				accepted[seq] = true
				if !anySeen || seq > high {
					high, anySeen = seq, true
				}
				base = max(base, seq)
			}
		}
	}
}
