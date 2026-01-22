package tunnel

import (
	"sync/atomic"
	"time"
)

// PoolStats collects statistics about pool usage.
// All fields use atomic operations for thread safety.
type PoolStats struct {
	// Gauges (current state)
	connectionsTotal atomic.Int64
	connectionsIdle  atomic.Int64
	connectionsInUse atomic.Int64
	waitingCount     atomic.Int64

	// Counters (cumulative since pool creation)
	acquiresTotal        atomic.Uint64
	acquireTimeoutsTotal atomic.Uint64
	connectionsCreated   atomic.Uint64
	connectionsClosed    atomic.Uint64
	healthChecksTotal    atomic.Uint64
	healthChecksFailed   atomic.Uint64

	// Timing accumulators for averages
	totalAcquireWaitNanos atomic.Int64
	totalDialNanos        atomic.Int64
	acquireCount          atomic.Uint64
	dialCount             atomic.Uint64

	// Peak tracking
	peakConnections atomic.Int64
	peakWaiting     atomic.Int64

	// Creation time
	createdAt time.Time
}

// newPoolStats creates a new PoolStats instance.
func newPoolStats() *PoolStats {
	return &PoolStats{
		createdAt: time.Now(),
	}
}

// recordAcquire records a successful acquire operation.
func (s *PoolStats) recordAcquire(waitDuration time.Duration, reused bool) {
	s.acquiresTotal.Add(1)
	s.acquireCount.Add(1)
	waitNanos := waitDuration.Nanoseconds()
	if waitNanos < 0 {
		waitNanos = 0
	}
	s.totalAcquireWaitNanos.Add(waitNanos)
	s.connectionsInUse.Add(1)
	if reused {
		s.connectionsIdle.Add(-1)
	}
}

// recordAcquireTimeout records an acquire timeout.
func (s *PoolStats) recordAcquireTimeout() {
	s.acquireTimeoutsTotal.Add(1)
}

// recordRelease records a connection release.
func (s *PoolStats) recordRelease() {
	current := s.connectionsInUse.Add(-1)
	if current < 0 {
		s.connectionsInUse.Store(0)
	}
	s.connectionsIdle.Add(1)
}

// recordConnectionCreated records a new connection being created.
func (s *PoolStats) recordConnectionCreated(dialDuration time.Duration) {
	s.connectionsCreated.Add(1)
	s.dialCount.Add(1)
	dialNanos := dialDuration.Nanoseconds()
	if dialNanos < 0 {
		dialNanos = 0
	}
	s.totalDialNanos.Add(dialNanos)
	total := s.connectionsTotal.Add(1)
	s.updatePeakConnections(total)
}

// recordConnectionClosed records a connection being closed.
func (s *PoolStats) recordConnectionClosed(wasIdle bool) {
	s.connectionsClosed.Add(1)
	s.connectionsTotal.Add(-1)
	if wasIdle {
		s.connectionsIdle.Add(-1)
	}
}

// recordHealthCheck records a health check result.
func (s *PoolStats) recordHealthCheck(healthy bool) {
	s.healthChecksTotal.Add(1)
	if !healthy {
		s.healthChecksFailed.Add(1)
	}
}

// incrementWaiting increments the waiting count.
func (s *PoolStats) incrementWaiting() {
	current := s.waitingCount.Add(1)
	s.updatePeakWaiting(current)
}

// decrementWaiting decrements the waiting count.
func (s *PoolStats) decrementWaiting() {
	s.waitingCount.Add(-1)
}

// setIdleCount sets the idle connection count.
func (s *PoolStats) setIdleCount(count int64) {
	s.connectionsIdle.Store(count)
}

// setTotalCount sets the total connection count.
func (s *PoolStats) setTotalCount(count int64) {
	s.connectionsTotal.Store(count)
	s.updatePeakConnections(count)
}

// updatePeakConnections updates peak connections if current is higher.
func (s *PoolStats) updatePeakConnections(current int64) {
	for {
		peak := s.peakConnections.Load()
		if current <= peak {
			return
		}
		if s.peakConnections.CompareAndSwap(peak, current) {
			return
		}
	}
}

// updatePeakWaiting updates peak waiting if current is higher.
func (s *PoolStats) updatePeakWaiting(current int64) {
	for {
		peak := s.peakWaiting.Load()
		if current <= peak {
			return
		}
		if s.peakWaiting.CompareAndSwap(peak, current) {
			return
		}
	}
}

// PoolStatsSnapshot is an immutable snapshot of pool statistics.
type PoolStatsSnapshot struct {
	// Timestamp of the snapshot
	Timestamp time.Time

	// Uptime since pool creation
	Uptime time.Duration

	// Current state (gauges)
	ConnectionsTotal int64
	ConnectionsIdle  int64
	ConnectionsInUse int64
	WaitingCount     int64

	// Cumulative counters
	AcquiresTotal        uint64
	AcquireTimeoutsTotal uint64
	ConnectionsCreated   uint64
	ConnectionsClosed    uint64
	HealthChecksTotal    uint64
	HealthChecksFailed   uint64

	// Averages (in milliseconds)
	AvgAcquireWaitMs float64
	AvgDialMs        float64

	// Peak values
	PeakConnections int64
	PeakWaiting     int64
}

// Snapshot returns an immutable snapshot of current statistics.
func (s *PoolStats) Snapshot() PoolStatsSnapshot {
	now := time.Now()

	// Calculate averages
	var avgAcquireWait, avgDial float64
	if acquireCount := s.acquireCount.Load(); acquireCount > 0 {
		totalWaitNanos := s.totalAcquireWaitNanos.Load()
		if totalWaitNanos < 0 {
			totalWaitNanos = 0
		}
		avgAcquireWait = float64(totalWaitNanos) / float64(acquireCount) / 1e6
	}
	if dialCount := s.dialCount.Load(); dialCount > 0 {
		totalDialNanos := s.totalDialNanos.Load()
		if totalDialNanos < 0 {
			totalDialNanos = 0
		}
		avgDial = float64(totalDialNanos) / float64(dialCount) / 1e6
	}

	return PoolStatsSnapshot{
		Timestamp:            now,
		Uptime:               now.Sub(s.createdAt),
		ConnectionsTotal:     s.connectionsTotal.Load(),
		ConnectionsIdle:      s.connectionsIdle.Load(),
		ConnectionsInUse:     s.connectionsInUse.Load(),
		WaitingCount:         s.waitingCount.Load(),
		AcquiresTotal:        s.acquiresTotal.Load(),
		AcquireTimeoutsTotal: s.acquireTimeoutsTotal.Load(),
		ConnectionsCreated:   s.connectionsCreated.Load(),
		ConnectionsClosed:    s.connectionsClosed.Load(),
		HealthChecksTotal:    s.healthChecksTotal.Load(),
		HealthChecksFailed:   s.healthChecksFailed.Load(),
		AvgAcquireWaitMs:     avgAcquireWait,
		AvgDialMs:            avgDial,
		PeakConnections:      s.peakConnections.Load(),
		PeakWaiting:          s.peakWaiting.Load(),
	}
}
