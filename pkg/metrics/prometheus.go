package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
)

// PrometheusExporter exports metrics in Prometheus text format.
type PrometheusExporter struct {
	collector *Collector
	namespace string
}

type promWriter struct {
	w   io.Writer
	err error
}

func (pw *promWriter) writef(format string, args ...interface{}) {
	if pw.err != nil {
		return
	}
	_, pw.err = fmt.Fprintf(pw.w, format, args...)
}

// NewPrometheusExporter creates a new Prometheus exporter for the given collector.
// The namespace is prepended to all metric names (e.g., "quantum_vpn").
func NewPrometheusExporter(c *Collector, namespace string) *PrometheusExporter {
	return &PrometheusExporter{
		collector: c,
		namespace: namespace,
	}
}

// Handler returns an http.Handler that serves Prometheus metrics.
func (e *PrometheusExporter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		e.WriteMetrics(w)
	})
}

// WriteMetrics writes all metrics in Prometheus text format to the writer.
func (e *PrometheusExporter) WriteMetrics(w io.Writer) {
	pw := &promWriter{w: w}
	snap := e.collector.Snapshot()
	labels := e.formatLabels(snap.Labels)

	// --- Session Metrics ---
	e.writeHelp(pw, "sessions_active", "Number of currently active sessions")
	e.writeType(pw, "sessions_active", "gauge")
	e.writeMetric(pw, "sessions_active", labels, float64(snap.SessionsActive))

	e.writeHelp(pw, "sessions_total", "Total number of sessions created")
	e.writeType(pw, "sessions_total", "counter")
	e.writeMetric(pw, "sessions_total", labels, float64(snap.SessionsTotal))

	e.writeHelp(pw, "sessions_failed_total", "Total number of failed session attempts")
	e.writeType(pw, "sessions_failed_total", "counter")
	e.writeMetric(pw, "sessions_failed_total", labels, float64(snap.SessionsFailed))

	// --- Traffic Metrics ---
	e.writeHelp(pw, "bytes_sent_total", "Total bytes sent")
	e.writeType(pw, "bytes_sent_total", "counter")
	e.writeMetric(pw, "bytes_sent_total", labels, float64(snap.BytesSent))

	e.writeHelp(pw, "bytes_received_total", "Total bytes received")
	e.writeType(pw, "bytes_received_total", "counter")
	e.writeMetric(pw, "bytes_received_total", labels, float64(snap.BytesReceived))

	e.writeHelp(pw, "packets_sent_total", "Total packets sent")
	e.writeType(pw, "packets_sent_total", "counter")
	e.writeMetric(pw, "packets_sent_total", labels, float64(snap.PacketsSent))

	e.writeHelp(pw, "packets_received_total", "Total packets received")
	e.writeType(pw, "packets_received_total", "counter")
	e.writeMetric(pw, "packets_received_total", labels, float64(snap.PacketsRecv))

	// --- Security Metrics ---
	e.writeHelp(pw, "replay_attacks_blocked_total", "Total replay attacks blocked")
	e.writeType(pw, "replay_attacks_blocked_total", "counter")
	e.writeMetric(pw, "replay_attacks_blocked_total", labels, float64(snap.ReplayAttacksBlocked))

	e.writeHelp(pw, "auth_failures_total", "Total authentication failures")
	e.writeType(pw, "auth_failures_total", "counter")
	e.writeMetric(pw, "auth_failures_total", labels, float64(snap.AuthFailures))

	e.writeHelp(pw, "rekeys_initiated_total", "Total rekey operations initiated")
	e.writeType(pw, "rekeys_initiated_total", "counter")
	e.writeMetric(pw, "rekeys_initiated_total", labels, float64(snap.RekeysInitiated))

	e.writeHelp(pw, "rekeys_completed_total", "Total rekey operations completed successfully")
	e.writeType(pw, "rekeys_completed_total", "counter")
	e.writeMetric(pw, "rekeys_completed_total", labels, float64(snap.RekeysCompleted))

	e.writeHelp(pw, "rekeys_failed_total", "Total rekey operations that failed")
	e.writeType(pw, "rekeys_failed_total", "counter")
	e.writeMetric(pw, "rekeys_failed_total", labels, float64(snap.RekeysFailed))

	// --- Error Metrics ---
	e.writeHelp(pw, "encrypt_errors_total", "Total encryption errors")
	e.writeType(pw, "encrypt_errors_total", "counter")
	e.writeMetric(pw, "encrypt_errors_total", labels, float64(snap.EncryptErrors))

	e.writeHelp(pw, "decrypt_errors_total", "Total decryption errors")
	e.writeType(pw, "decrypt_errors_total", "counter")
	e.writeMetric(pw, "decrypt_errors_total", labels, float64(snap.DecryptErrors))

	e.writeHelp(pw, "protocol_errors_total", "Total protocol errors")
	e.writeType(pw, "protocol_errors_total", "counter")
	e.writeMetric(pw, "protocol_errors_total", labels, float64(snap.ProtocolErrors))

	// --- Rate Limit Metrics ---
	e.writeHelp(pw, "rate_limit_connections_total", "Total connections rejected due to rate limiting")
	e.writeType(pw, "rate_limit_connections_total", "counter")
	e.writeMetric(pw, "rate_limit_connections_total", labels, float64(snap.ConnectionRateLimits))

	e.writeHelp(pw, "rate_limit_handshakes_total", "Total handshakes rejected due to rate limiting")
	e.writeType(pw, "rate_limit_handshakes_total", "counter")
	e.writeMetric(pw, "rate_limit_handshakes_total", labels, float64(snap.HandshakeRateLimits))

	// --- Uptime ---
	e.writeHelp(pw, "uptime_seconds", "Time since the collector was created")
	e.writeType(pw, "uptime_seconds", "gauge")
	e.writeMetric(pw, "uptime_seconds", labels, snap.Uptime.Seconds())

	// --- Histograms ---
	e.writeHistogram(pw, "handshake_duration_milliseconds", "Handshake duration in milliseconds", labels, snap.HandshakeLatency)
	e.writeHistogram(pw, "encrypt_duration_microseconds", "Encryption duration in microseconds", labels, snap.EncryptLatency)
	e.writeHistogram(pw, "decrypt_duration_microseconds", "Decryption duration in microseconds", labels, snap.DecryptLatency)
}

// writeHelp writes a HELP line.
func (e *PrometheusExporter) writeHelp(pw *promWriter, name, help string) {
	pw.writef("# HELP %s_%s %s\n", e.namespace, name, help)
}

// writeType writes a TYPE line.
func (e *PrometheusExporter) writeType(pw *promWriter, name, typ string) {
	pw.writef("# TYPE %s_%s %s\n", e.namespace, name, typ)
}

// writeMetric writes a single metric line.
func (e *PrometheusExporter) writeMetric(pw *promWriter, name, labels string, value float64) {
	if labels != "" {
		pw.writef("%s_%s{%s} %g\n", e.namespace, name, labels, value)
	} else {
		pw.writef("%s_%s %g\n", e.namespace, name, value)
	}
}

// writeHistogram writes a histogram in Prometheus format.
func (e *PrometheusExporter) writeHistogram(pw *promWriter, name, help, labels string, h HistogramSummary) {
	e.writeHelp(pw, name, help)
	e.writeType(pw, name, "histogram")

	fullName := e.namespace + "_" + name

	// Write bucket counts
	for _, b := range h.Buckets {
		le := fmt.Sprintf("%g", b.UpperBound)
		if math.IsInf(b.UpperBound, 1) {
			le = "+Inf"
		}
		if labels != "" {
			pw.writef("%s_bucket{%s,le=\"%s\"} %d\n", fullName, labels, le, b.Count)
		} else {
			pw.writef("%s_bucket{le=\"%s\"} %d\n", fullName, le, b.Count)
		}
	}

	// Write sum and count
	if labels != "" {
		pw.writef("%s_sum{%s} %g\n", fullName, labels, h.Sum)
		pw.writef("%s_count{%s} %d\n", fullName, labels, h.Count)
	} else {
		pw.writef("%s_sum %g\n", fullName, h.Sum)
		pw.writef("%s_count %d\n", fullName, h.Count)
	}
}

// formatLabels converts Labels to Prometheus label format.
func (e *PrometheusExporter) formatLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		// Escape label values
		v := escapePromValue(labels[k])
		parts = append(parts, fmt.Sprintf("%s=\"%s\"", k, v))
	}

	return strings.Join(parts, ",")
}

// escapePromValue escapes a string for use as a Prometheus label value.
func escapePromValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// WritePoolMetrics writes pool metrics in Prometheus text format to the writer.
func (e *PrometheusExporter) WritePoolMetrics(w io.Writer, pool *PoolMetricsObserver) {
	if pool == nil {
		return
	}

	pw := &promWriter{w: w}
	snap := pool.Snapshot()
	labels := e.formatLabels(Labels{"pool": snap.PoolName})

	// --- Pool Gauges ---
	e.writeHelp(pw, "pool_connections_total", "Total number of connections in the pool")
	e.writeType(pw, "pool_connections_total", "gauge")
	e.writeMetric(pw, "pool_connections_total", labels, float64(snap.ConnectionsTotal))

	e.writeHelp(pw, "pool_connections_idle", "Number of idle connections in the pool")
	e.writeType(pw, "pool_connections_idle", "gauge")
	e.writeMetric(pw, "pool_connections_idle", labels, float64(snap.ConnectionsIdle))

	e.writeHelp(pw, "pool_connections_in_use", "Number of in-use connections in the pool")
	e.writeType(pw, "pool_connections_in_use", "gauge")
	e.writeMetric(pw, "pool_connections_in_use", labels, float64(snap.ConnectionsInUse))

	e.writeHelp(pw, "pool_waiting_count", "Number of goroutines waiting for a connection")
	e.writeType(pw, "pool_waiting_count", "gauge")
	e.writeMetric(pw, "pool_waiting_count", labels, float64(snap.WaitingCount))

	// --- Pool Counters ---
	e.writeHelp(pw, "pool_acquires_total", "Total number of successful connection acquires")
	e.writeType(pw, "pool_acquires_total", "counter")
	e.writeMetric(pw, "pool_acquires_total", labels, float64(snap.AcquiresTotal))

	e.writeHelp(pw, "pool_acquire_timeouts_total", "Total number of acquire timeouts")
	e.writeType(pw, "pool_acquire_timeouts_total", "counter")
	e.writeMetric(pw, "pool_acquire_timeouts_total", labels, float64(snap.AcquireTimeoutsTotal))

	e.writeHelp(pw, "pool_connections_created_total", "Total number of connections created")
	e.writeType(pw, "pool_connections_created_total", "counter")
	e.writeMetric(pw, "pool_connections_created_total", labels, float64(snap.ConnectionsCreated))

	e.writeHelp(pw, "pool_connections_closed_total", "Total number of connections closed")
	e.writeType(pw, "pool_connections_closed_total", "counter")
	e.writeMetric(pw, "pool_connections_closed_total", labels, float64(snap.ConnectionsClosed))

	e.writeHelp(pw, "pool_health_checks_total", "Total number of health checks performed")
	e.writeType(pw, "pool_health_checks_total", "counter")
	e.writeMetric(pw, "pool_health_checks_total", labels, float64(snap.HealthChecksTotal))

	e.writeHelp(pw, "pool_health_checks_failed_total", "Total number of failed health checks")
	e.writeType(pw, "pool_health_checks_failed_total", "counter")
	e.writeMetric(pw, "pool_health_checks_failed_total", labels, float64(snap.HealthChecksFailed))

	// --- Pool Histograms ---
	e.writeHistogram(pw, "pool_acquire_duration_milliseconds", "Time to acquire a connection in milliseconds", labels, snap.AcquireLatency)
	e.writeHistogram(pw, "pool_dial_duration_milliseconds", "Time to establish new connection in milliseconds", labels, snap.DialLatency)
}

// --- Convenience Functions ---

// ServePrometheus starts an HTTP server serving Prometheus metrics.
// This is a convenience function for simple use cases.
func ServePrometheus(addr string, c *Collector, namespace string) error {
	exp := NewPrometheusExporter(c, namespace)
	mux := http.NewServeMux()
	mux.Handle("/metrics", exp.Handler())
	server := newHTTPServer(addr, mux)
	return server.ListenAndServe()
}
