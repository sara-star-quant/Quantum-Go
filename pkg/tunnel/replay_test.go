package tunnel

import "testing"

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
