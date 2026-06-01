package tunnel

import (
	"testing"
	"time"
)

// TestCoarseTimeNanos checks the coarse clock returns a plausible current time and
// advances over time. It does not assert exact granularity (that is an internal
// tuning detail); it only pins the two properties the idle reaper depends on: the
// value is a real Unix-nanos timestamp, and it moves forward.
func TestCoarseTimeNanos(t *testing.T) {
	got := coarseTimeNanos()
	now := time.Now().UnixNano()
	// Within a generous window of wall clock (the updater seeds from time.Now on
	// first use, then refreshes on a ticker).
	if delta := now - got; delta < -int64(time.Second) || delta > int64(2*time.Second) {
		t.Fatalf("coarseTimeNanos = %d, wall clock = %d, delta %v out of range", got, now, time.Duration(delta))
	}

	// It must advance within a few tick intervals.
	start := coarseTimeNanos()
	deadline := time.Now().Add(2 * time.Second)
	for coarseTimeNanos() == start {
		if time.Now().After(deadline) {
			t.Fatal("coarse clock did not advance within 2s")
		}
		time.Sleep(coarseTickInterval)
	}
}
