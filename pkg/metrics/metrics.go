// Package metrics provides observability primitives for the quantum-go VPN library.
//
// The package includes:
//   - Counter, Gauge, and Histogram metric types
//   - Prometheus-compatible metrics export
//   - OpenTelemetry tracing support
//   - Structured logging with levels
//   - Health check functionality
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Collector aggregates metrics from tunnel sessions and transports.
type Collector struct {
	// Session metrics
	sessionsActive   atomic.Uint64
	sessionsTotal    atomic.Uint64
	sessionsFailed   atomic.Uint64
	handshakeLatency *Histogram

	// Traffic metrics
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	packetsSent   atomic.Uint64
	packetsRecv   atomic.Uint64

	// Security metrics
	replayAttacksBlocked atomic.Uint64
	authFailures         atomic.Uint64
	rekeysInitiated      atomic.Uint64
	rekeysCompleted      atomic.Uint64
	rekeysFailed         atomic.Uint64

	// Error metrics
	encryptErrors  atomic.Uint64
	decryptErrors  atomic.Uint64
	protocolErrors atomic.Uint64

	// Performance histograms
	encryptLatency *Histogram
	decryptLatency *Histogram

	// Creation time for uptime tracking
	createdAt time.Time

	// Labels for this collector instance
	labels Labels
}

// Labels represents key-value pairs for metric labeling.
type Labels map[string]string

// NewCollector creates a new metrics collector.
func NewCollector(labels Labels) *Collector {
	if labels == nil {
		labels = make(Labels)
	}

	return &Collector{
		handshakeLatency: NewHistogram(HandshakeLatencyBuckets),
		encryptLatency:   NewHistogram(LatencyBuckets),
		decryptLatency:   NewHistogram(LatencyBuckets),
		createdAt:        time.Now(),
		labels:           labels,
	}
}

// Default bucket configurations for histograms.
var (
	// HandshakeLatencyBuckets for handshake duration (milliseconds).
	HandshakeLatencyBuckets = []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

	// LatencyBuckets for encrypt/decrypt operations (microseconds).
	LatencyBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000}
)

// --- Session Metrics ---

// SessionStarted increments active and total session counters.
func (c *Collector) SessionStarted() {
	c.sessionsActive.Add(1)
	c.sessionsTotal.Add(1)
}

// SessionEnded decrements active session counter.
func (c *Collector) SessionEnded() {
	for {
		current := c.sessionsActive.Load()
		if current == 0 {
			return
		}
		if c.sessionsActive.CompareAndSwap(current, current-1) {
			return
		}
	}
}

// SessionFailed records a failed session attempt.
func (c *Collector) SessionFailed() {
	c.sessionsFailed.Add(1)
}

// RecordHandshakeLatency records a handshake duration.
func (c *Collector) RecordHandshakeLatency(d time.Duration) {
	c.handshakeLatency.Observe(float64(d.Milliseconds()))
}

// --- Traffic Metrics ---

// RecordBytesSent adds to the bytes sent counter.
func (c *Collector) RecordBytesSent(n uint64) {
	c.bytesSent.Add(n)
}

// RecordBytesReceived adds to the bytes received counter.
func (c *Collector) RecordBytesReceived(n uint64) {
	c.bytesReceived.Add(n)
}

// RecordPacketSent increments packets sent counter.
func (c *Collector) RecordPacketSent() {
	c.packetsSent.Add(1)
}

// RecordPacketReceived increments packets received counter.
func (c *Collector) RecordPacketReceived() {
	c.packetsRecv.Add(1)
}

// --- Security Metrics ---

// RecordReplayBlocked increments the replay attack counter.
func (c *Collector) RecordReplayBlocked() {
	c.replayAttacksBlocked.Add(1)
}

// RecordAuthFailure increments the authentication failure counter.
func (c *Collector) RecordAuthFailure() {
	c.authFailures.Add(1)
}

// RecordRekeyInitiated records a rekey initiation.
func (c *Collector) RecordRekeyInitiated() {
	c.rekeysInitiated.Add(1)
}

// RecordRekeyCompleted records a successful rekey completion.
func (c *Collector) RecordRekeyCompleted() {
	c.rekeysCompleted.Add(1)
}

// RecordRekeyFailed records a failed rekey attempt.
func (c *Collector) RecordRekeyFailed() {
	c.rekeysFailed.Add(1)
}

// --- Error Metrics ---

// RecordEncryptError increments encryption error counter.
func (c *Collector) RecordEncryptError() {
	c.encryptErrors.Add(1)
}

// RecordDecryptError increments decryption error counter.
func (c *Collector) RecordDecryptError() {
	c.decryptErrors.Add(1)
}

// RecordProtocolError increments protocol error counter.
func (c *Collector) RecordProtocolError() {
	c.protocolErrors.Add(1)
}

// --- Performance Metrics ---

// RecordEncryptLatency records encryption operation latency.
func (c *Collector) RecordEncryptLatency(d time.Duration) {
	c.encryptLatency.Observe(float64(d.Microseconds()))
}

// RecordDecryptLatency records decryption operation latency.
func (c *Collector) RecordDecryptLatency(d time.Duration) {
	c.decryptLatency.Observe(float64(d.Microseconds()))
}

// --- Snapshot ---

// Snapshot returns a point-in-time snapshot of all metrics.
type Snapshot struct {
	// Timestamp of the snapshot
	Timestamp time.Time

	// Uptime since collector creation
	Uptime time.Duration

	// Session metrics
	SessionsActive uint64
	SessionsTotal  uint64
	SessionsFailed uint64

	// Traffic metrics
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64

	// Security metrics
	ReplayAttacksBlocked uint64
	AuthFailures         uint64
	RekeysInitiated      uint64
	RekeysCompleted      uint64
	RekeysFailed         uint64

	// Error metrics
	EncryptErrors  uint64
	DecryptErrors  uint64
	ProtocolErrors uint64

	// Histogram summaries
	HandshakeLatency HistogramSummary
	EncryptLatency   HistogramSummary
	DecryptLatency   HistogramSummary

	// Labels
	Labels Labels
}

// Snapshot returns a point-in-time snapshot of all metrics.
func (c *Collector) Snapshot() Snapshot {
	return Snapshot{
		Timestamp:            time.Now(),
		Uptime:               time.Since(c.createdAt),
		SessionsActive:       c.sessionsActive.Load(),
		SessionsTotal:        c.sessionsTotal.Load(),
		SessionsFailed:       c.sessionsFailed.Load(),
		BytesSent:            c.bytesSent.Load(),
		BytesReceived:        c.bytesReceived.Load(),
		PacketsSent:          c.packetsSent.Load(),
		PacketsRecv:          c.packetsRecv.Load(),
		ReplayAttacksBlocked: c.replayAttacksBlocked.Load(),
		AuthFailures:         c.authFailures.Load(),
		RekeysInitiated:      c.rekeysInitiated.Load(),
		RekeysCompleted:      c.rekeysCompleted.Load(),
		RekeysFailed:         c.rekeysFailed.Load(),
		EncryptErrors:        c.encryptErrors.Load(),
		DecryptErrors:        c.decryptErrors.Load(),
		ProtocolErrors:       c.protocolErrors.Load(),
		HandshakeLatency:     c.handshakeLatency.Summary(),
		EncryptLatency:       c.encryptLatency.Summary(),
		DecryptLatency:       c.decryptLatency.Summary(),
		Labels:               c.labels,
	}
}

// Reset clears all metrics (useful for testing).
func (c *Collector) Reset() {
	c.sessionsActive.Store(0)
	c.sessionsTotal.Store(0)
	c.sessionsFailed.Store(0)
	c.bytesSent.Store(0)
	c.bytesReceived.Store(0)
	c.packetsSent.Store(0)
	c.packetsRecv.Store(0)
	c.replayAttacksBlocked.Store(0)
	c.authFailures.Store(0)
	c.rekeysInitiated.Store(0)
	c.rekeysCompleted.Store(0)
	c.rekeysFailed.Store(0)
	c.encryptErrors.Store(0)
	c.decryptErrors.Store(0)
	c.protocolErrors.Store(0)
	c.handshakeLatency.Reset()
	c.encryptLatency.Reset()
	c.decryptLatency.Reset()
	c.createdAt = time.Now()
}

// --- Global Collector ---

var (
	globalCollector     *Collector
	globalCollectorOnce sync.Once
)

// Global returns the global metrics collector.
// Creates one with default settings if not already initialized.
func Global() *Collector {
	globalCollectorOnce.Do(func() {
		globalCollector = NewCollector(Labels{"instance": "default"})
	})
	return globalCollector
}

// SetGlobal sets the global metrics collector.
// Should be called during initialization before any metrics are recorded.
func SetGlobal(c *Collector) {
	globalCollector = c
}
