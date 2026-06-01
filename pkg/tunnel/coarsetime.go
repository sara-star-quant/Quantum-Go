package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

// Coarse monotonic-ish wall clock for the datagram hot path.
//
// The data path stamps a per-session "last activity" time on every sealed and
// opened datagram, read only by the idle reaper (a 120s window checked every
// ~30s). Calling time.Now() twice per datagram showed up as ~7% of the
// end-to-end CPU profile purely to feed that coarse-grained reaper. Instead, one
// process-lifetime goroutine refreshes a shared timestamp ~10x/sec and the hot
// path reads it with a single atomic load. 100ms granularity is irrelevant
// against a 120s idle timeout, and the value is never used for any cryptographic
// freshness decision (cookies, replay, and rekey all carry their own timing).
const coarseTickInterval = 100 * time.Millisecond

var (
	coarseNanos atomic.Int64
	coarseOnce  sync.Once
)

// coarseTimeNanos returns the current time in Unix nanoseconds at ~100ms
// resolution. The first call lazily starts a single background updater goroutine
// (so processes that never use the datagram transport pay nothing); the goroutine
// then runs for the lifetime of the process - a fixed one-goroutine cost, not a
// per-endpoint leak.
func coarseTimeNanos() int64 {
	coarseOnce.Do(startCoarseClock)
	return coarseNanos.Load()
}

func startCoarseClock() {
	coarseNanos.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(coarseTickInterval)
		defer ticker.Stop()
		for range ticker.C {
			coarseNanos.Store(time.Now().UnixNano())
		}
	}()
}
