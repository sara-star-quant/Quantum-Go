package metrics

import (
	"sync/atomic"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// PoolMetricsObserver implements tunnel.PoolObserver and records metrics.
type PoolMetricsObserver struct {
	// Gauges (current state)
	connectionsTotal atomic.Int64
	connectionsIdle  atomic.Int64
	connectionsInUse atomic.Int64
	waitingCount     atomic.Int64

	// Counters (cumulative)
	acquiresTotal        atomic.Uint64
	acquireTimeoutsTotal atomic.Uint64
	connectionsCreated   atomic.Uint64
	connectionsClosed    atomic.Uint64
	healthChecksTotal    atomic.Uint64
	healthChecksFailed   atomic.Uint64

	// Histograms
	acquireLatency *Histogram
	dialLatency    *Histogram

	// Logger
	logger *Logger

	// Pool name/identifier for labeling
	poolName string
}

// Default bucket configurations for pool histograms.
var (
	// PoolAcquireLatencyBuckets for acquire duration (milliseconds).
	PoolAcquireLatencyBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000}

	// PoolDialLatencyBuckets for dial duration (milliseconds).
	PoolDialLatencyBuckets = []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
)

// PoolMetricsObserverConfig configures a pool metrics observer.
type PoolMetricsObserverConfig struct {
	Logger   *Logger
	PoolName string
}

// NewPoolMetricsObserver creates a new pool metrics observer.
func NewPoolMetricsObserver(cfg PoolMetricsObserverConfig) *PoolMetricsObserver {
	if cfg.Logger == nil {
		cfg.Logger = GetLogger()
	}
	if cfg.PoolName == "" {
		cfg.PoolName = "default"
	}

	return &PoolMetricsObserver{
		acquireLatency: NewHistogram(PoolAcquireLatencyBuckets),
		dialLatency:    NewHistogram(PoolDialLatencyBuckets),
		logger:         cfg.Logger.Named("pool").With(Fields{"pool": cfg.PoolName}),
		poolName:       cfg.PoolName,
	}
}

// Ensure PoolMetricsObserver implements tunnel.PoolObserver.
var _ tunnel.PoolObserver = (*PoolMetricsObserver)(nil)

// OnAcquire implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnAcquire(waitDuration time.Duration, reused bool) {
	o.acquiresTotal.Add(1)
	o.acquireLatency.Observe(float64(waitDuration.Milliseconds()))
	o.connectionsInUse.Add(1)
	if reused {
		o.connectionsIdle.Add(-1)
	}

	o.logger.Debug("connection acquired", Fields{
		"wait_ms": waitDuration.Milliseconds(),
		"reused":  reused,
	})
}

// OnAcquireTimeout implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnAcquireTimeout() {
	o.acquireTimeoutsTotal.Add(1)
	o.logger.Warn("acquire timed out")
}

// OnRelease implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnRelease() {
	current := o.connectionsInUse.Add(-1)
	if current < 0 {
		o.connectionsInUse.Store(0)
	}
	o.connectionsIdle.Add(1)
	o.logger.Debug("connection released")
}

// OnConnectionCreated implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnConnectionCreated(dialDuration time.Duration) {
	o.connectionsCreated.Add(1)
	o.connectionsTotal.Add(1)
	o.dialLatency.Observe(float64(dialDuration.Milliseconds()))

	o.logger.Info("connection created", Fields{
		"dial_ms": dialDuration.Milliseconds(),
	})
}

// OnConnectionClosed implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnConnectionClosed(reason string) {
	o.connectionsClosed.Add(1)
	o.connectionsTotal.Add(-1)

	o.logger.Info("connection closed", Fields{
		"reason": reason,
	})
}

// OnHealthCheck implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnHealthCheck(healthy bool) {
	o.healthChecksTotal.Add(1)
	if !healthy {
		o.healthChecksFailed.Add(1)
		o.logger.Warn("health check failed")
	}
}

// OnPoolStats implements tunnel.PoolObserver.
func (o *PoolMetricsObserver) OnPoolStats(stats tunnel.PoolStatsSnapshot) {
	// Update gauges from authoritative stats
	o.connectionsTotal.Store(stats.ConnectionsTotal)
	o.connectionsIdle.Store(stats.ConnectionsIdle)
	o.connectionsInUse.Store(stats.ConnectionsInUse)
	o.waitingCount.Store(stats.WaitingCount)

	o.logger.Debug("pool stats", Fields{
		"total":      stats.ConnectionsTotal,
		"idle":       stats.ConnectionsIdle,
		"in_use":     stats.ConnectionsInUse,
		"waiting":    stats.WaitingCount,
		"acquires":   stats.AcquiresTotal,
		"timeouts":   stats.AcquireTimeoutsTotal,
		"created":    stats.ConnectionsCreated,
		"closed":     stats.ConnectionsClosed,
		"uptime_sec": stats.Uptime.Seconds(),
	})
}

// PoolMetricsSnapshot is a snapshot of pool metrics.
type PoolMetricsSnapshot struct {
	// Current state (gauges)
	ConnectionsTotal  int64
	ConnectionsIdle   int64
	ConnectionsInUse  int64
	WaitingCount      int64

	// Cumulative counters
	AcquiresTotal        uint64
	AcquireTimeoutsTotal uint64
	ConnectionsCreated   uint64
	ConnectionsClosed    uint64
	HealthChecksTotal    uint64
	HealthChecksFailed   uint64

	// Histogram summaries
	AcquireLatency HistogramSummary
	DialLatency    HistogramSummary

	// Pool identifier
	PoolName string
}

// Snapshot returns a point-in-time snapshot of pool metrics.
func (o *PoolMetricsObserver) Snapshot() PoolMetricsSnapshot {
	return PoolMetricsSnapshot{
		ConnectionsTotal:     o.connectionsTotal.Load(),
		ConnectionsIdle:      o.connectionsIdle.Load(),
		ConnectionsInUse:     o.connectionsInUse.Load(),
		WaitingCount:         o.waitingCount.Load(),
		AcquiresTotal:        o.acquiresTotal.Load(),
		AcquireTimeoutsTotal: o.acquireTimeoutsTotal.Load(),
		ConnectionsCreated:   o.connectionsCreated.Load(),
		ConnectionsClosed:    o.connectionsClosed.Load(),
		HealthChecksTotal:    o.healthChecksTotal.Load(),
		HealthChecksFailed:   o.healthChecksFailed.Load(),
		AcquireLatency:       o.acquireLatency.Summary(),
		DialLatency:          o.dialLatency.Summary(),
		PoolName:             o.poolName,
	}
}

// Reset clears all metrics (useful for testing).
func (o *PoolMetricsObserver) Reset() {
	o.connectionsTotal.Store(0)
	o.connectionsIdle.Store(0)
	o.connectionsInUse.Store(0)
	o.waitingCount.Store(0)
	o.acquiresTotal.Store(0)
	o.acquireTimeoutsTotal.Store(0)
	o.connectionsCreated.Store(0)
	o.connectionsClosed.Store(0)
	o.healthChecksTotal.Store(0)
	o.healthChecksFailed.Store(0)
	o.acquireLatency.Reset()
	o.dialLatency.Reset()
}
