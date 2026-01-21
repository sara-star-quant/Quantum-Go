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
	snap := e.collector.Snapshot()
	labels := e.formatLabels(snap.Labels)

	// --- Session Metrics ---
	e.writeHelp(w, "sessions_active", "Number of currently active sessions")
	e.writeType(w, "sessions_active", "gauge")
	e.writeMetric(w, "sessions_active", labels, float64(snap.SessionsActive))

	e.writeHelp(w, "sessions_total", "Total number of sessions created")
	e.writeType(w, "sessions_total", "counter")
	e.writeMetric(w, "sessions_total", labels, float64(snap.SessionsTotal))

	e.writeHelp(w, "sessions_failed_total", "Total number of failed session attempts")
	e.writeType(w, "sessions_failed_total", "counter")
	e.writeMetric(w, "sessions_failed_total", labels, float64(snap.SessionsFailed))

	// --- Traffic Metrics ---
	e.writeHelp(w, "bytes_sent_total", "Total bytes sent")
	e.writeType(w, "bytes_sent_total", "counter")
	e.writeMetric(w, "bytes_sent_total", labels, float64(snap.BytesSent))

	e.writeHelp(w, "bytes_received_total", "Total bytes received")
	e.writeType(w, "bytes_received_total", "counter")
	e.writeMetric(w, "bytes_received_total", labels, float64(snap.BytesReceived))

	e.writeHelp(w, "packets_sent_total", "Total packets sent")
	e.writeType(w, "packets_sent_total", "counter")
	e.writeMetric(w, "packets_sent_total", labels, float64(snap.PacketsSent))

	e.writeHelp(w, "packets_received_total", "Total packets received")
	e.writeType(w, "packets_received_total", "counter")
	e.writeMetric(w, "packets_received_total", labels, float64(snap.PacketsRecv))

	// --- Security Metrics ---
	e.writeHelp(w, "replay_attacks_blocked_total", "Total replay attacks blocked")
	e.writeType(w, "replay_attacks_blocked_total", "counter")
	e.writeMetric(w, "replay_attacks_blocked_total", labels, float64(snap.ReplayAttacksBlocked))

	e.writeHelp(w, "auth_failures_total", "Total authentication failures")
	e.writeType(w, "auth_failures_total", "counter")
	e.writeMetric(w, "auth_failures_total", labels, float64(snap.AuthFailures))

	e.writeHelp(w, "rekeys_initiated_total", "Total rekey operations initiated")
	e.writeType(w, "rekeys_initiated_total", "counter")
	e.writeMetric(w, "rekeys_initiated_total", labels, float64(snap.RekeysInitiated))

	e.writeHelp(w, "rekeys_completed_total", "Total rekey operations completed successfully")
	e.writeType(w, "rekeys_completed_total", "counter")
	e.writeMetric(w, "rekeys_completed_total", labels, float64(snap.RekeysCompleted))

	e.writeHelp(w, "rekeys_failed_total", "Total rekey operations that failed")
	e.writeType(w, "rekeys_failed_total", "counter")
	e.writeMetric(w, "rekeys_failed_total", labels, float64(snap.RekeysFailed))

	// --- Error Metrics ---
	e.writeHelp(w, "encrypt_errors_total", "Total encryption errors")
	e.writeType(w, "encrypt_errors_total", "counter")
	e.writeMetric(w, "encrypt_errors_total", labels, float64(snap.EncryptErrors))

	e.writeHelp(w, "decrypt_errors_total", "Total decryption errors")
	e.writeType(w, "decrypt_errors_total", "counter")
	e.writeMetric(w, "decrypt_errors_total", labels, float64(snap.DecryptErrors))

	e.writeHelp(w, "protocol_errors_total", "Total protocol errors")
	e.writeType(w, "protocol_errors_total", "counter")
	e.writeMetric(w, "protocol_errors_total", labels, float64(snap.ProtocolErrors))

	// --- Uptime ---
	e.writeHelp(w, "uptime_seconds", "Time since the collector was created")
	e.writeType(w, "uptime_seconds", "gauge")
	e.writeMetric(w, "uptime_seconds", labels, snap.Uptime.Seconds())

	// --- Histograms ---
	e.writeHistogram(w, "handshake_duration_milliseconds", "Handshake duration in milliseconds", labels, snap.HandshakeLatency)
	e.writeHistogram(w, "encrypt_duration_microseconds", "Encryption duration in microseconds", labels, snap.EncryptLatency)
	e.writeHistogram(w, "decrypt_duration_microseconds", "Decryption duration in microseconds", labels, snap.DecryptLatency)
}

// writeHelp writes a HELP line.
func (e *PrometheusExporter) writeHelp(w io.Writer, name, help string) {
	fmt.Fprintf(w, "# HELP %s_%s %s\n", e.namespace, name, help)
}

// writeType writes a TYPE line.
func (e *PrometheusExporter) writeType(w io.Writer, name, typ string) {
	fmt.Fprintf(w, "# TYPE %s_%s %s\n", e.namespace, name, typ)
}

// writeMetric writes a single metric line.
func (e *PrometheusExporter) writeMetric(w io.Writer, name, labels string, value float64) {
	if labels != "" {
		fmt.Fprintf(w, "%s_%s{%s} %g\n", e.namespace, name, labels, value)
	} else {
		fmt.Fprintf(w, "%s_%s %g\n", e.namespace, name, value)
	}
}

// writeHistogram writes a histogram in Prometheus format.
func (e *PrometheusExporter) writeHistogram(w io.Writer, name, help, labels string, h HistogramSummary) {
	e.writeHelp(w, name, help)
	e.writeType(w, name, "histogram")

	fullName := e.namespace + "_" + name

	// Write bucket counts
	for _, b := range h.Buckets {
		le := fmt.Sprintf("%g", b.UpperBound)
		if math.IsInf(b.UpperBound, 1) {
			le = "+Inf"
		}
		if labels != "" {
			fmt.Fprintf(w, "%s_bucket{%s,le=\"%s\"} %d\n", fullName, labels, le, b.Count)
		} else {
			fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", fullName, le, b.Count)
		}
	}

	// Write sum and count
	if labels != "" {
		fmt.Fprintf(w, "%s_sum{%s} %g\n", fullName, labels, h.Sum)
		fmt.Fprintf(w, "%s_count{%s} %d\n", fullName, labels, h.Count)
	} else {
		fmt.Fprintf(w, "%s_sum %g\n", fullName, h.Sum)
		fmt.Fprintf(w, "%s_count %d\n", fullName, h.Count)
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

// --- Convenience Functions ---

// ServePrometheus starts an HTTP server serving Prometheus metrics.
// This is a convenience function for simple use cases.
func ServePrometheus(addr string, c *Collector, namespace string) error {
	exp := NewPrometheusExporter(c, namespace)
	http.Handle("/metrics", exp.Handler())
	return http.ListenAndServe(addr, nil)
}
