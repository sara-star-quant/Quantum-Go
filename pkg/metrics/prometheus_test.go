package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusExporterWriteMetrics(t *testing.T) {
	c := NewCollector(Labels{"instance": "test"})

	// Add some metrics
	c.SessionStarted()
	c.RecordBytesSent(1000)
	c.RecordHandshakeLatency(100 * time.Millisecond)

	exp := NewPrometheusExporter(c, "quantum_vpn")

	var buf bytes.Buffer
	exp.WriteMetrics(&buf)

	output := buf.String()

	// Check for expected metrics
	expectedMetrics := []string{
		"quantum_vpn_sessions_active",
		"quantum_vpn_sessions_total",
		"quantum_vpn_bytes_sent_total",
		"quantum_vpn_handshake_duration_milliseconds",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(output, metric) {
			t.Errorf("expected metric %q in output", metric)
		}
	}

	// Check for labels
	if !strings.Contains(output, `instance="test"`) {
		t.Error("expected label instance=\"test\" in output")
	}

	// Check for HELP and TYPE lines
	if !strings.Contains(output, "# HELP quantum_vpn_sessions_active") {
		t.Error("expected HELP line for sessions_active")
	}
	if !strings.Contains(output, "# TYPE quantum_vpn_sessions_active gauge") {
		t.Error("expected TYPE line for sessions_active")
	}
}

func TestPrometheusExporterHandler(t *testing.T) {
	c := NewCollector(nil)
	c.SessionStarted()

	exp := NewPrometheusExporter(c, "test")
	handler := exp.Handler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "test_sessions_active") {
		t.Error("expected sessions_active metric in response")
	}
}

func TestPrometheusExporterHistogram(t *testing.T) {
	c := NewCollector(nil)
	c.RecordHandshakeLatency(50 * time.Millisecond)
	c.RecordHandshakeLatency(150 * time.Millisecond)

	exp := NewPrometheusExporter(c, "test")

	var buf bytes.Buffer
	exp.WriteMetrics(&buf)

	output := buf.String()

	// Check for histogram bucket format
	if !strings.Contains(output, "_bucket{le=") {
		t.Error("expected histogram bucket format")
	}
	if !strings.Contains(output, "_sum") {
		t.Error("expected histogram sum")
	}
	if !strings.Contains(output, "_count") {
		t.Error("expected histogram count")
	}
	if !strings.Contains(output, `le="+Inf"`) {
		t.Error("expected +Inf bucket")
	}
}

func TestPrometheusExporterLabelEscaping(t *testing.T) {
	c := NewCollector(Labels{
		"path":    "/api/v1",
		"message": "hello \"world\"",
		"newline": "line1\nline2",
	})

	exp := NewPrometheusExporter(c, "test")

	var buf bytes.Buffer
	exp.WriteMetrics(&buf)

	output := buf.String()

	// Check proper escaping
	if strings.Contains(output, "\n\"") {
		t.Error("newline should be escaped in labels")
	}
	if strings.Contains(output, `"hello "world""`) {
		t.Error("quotes should be escaped in labels")
	}
}

func TestPrometheusExporterAllMetricTypes(t *testing.T) {
	c := NewCollector(nil)

	// Record all metric types
	c.SessionStarted()
	c.SessionEnded()
	c.SessionFailed()
	c.RecordBytesSent(100)
	c.RecordBytesReceived(200)
	c.RecordPacketSent()
	c.RecordPacketReceived()
	c.RecordReplayBlocked()
	c.RecordAuthFailure()
	c.RecordRekeyInitiated()
	c.RecordRekeyCompleted()
	c.RecordRekeyFailed()
	c.RecordEncryptError()
	c.RecordDecryptError()
	c.RecordProtocolError()
	c.RecordHandshakeLatency(100 * time.Millisecond)
	c.RecordEncryptLatency(10 * time.Microsecond)
	c.RecordDecryptLatency(15 * time.Microsecond)

	exp := NewPrometheusExporter(c, "quantum")

	var buf bytes.Buffer
	exp.WriteMetrics(&buf)

	output := buf.String()

	// All metrics should be present
	expectedMetrics := []string{
		"sessions_active",
		"sessions_total",
		"sessions_failed_total",
		"bytes_sent_total",
		"bytes_received_total",
		"packets_sent_total",
		"packets_received_total",
		"replay_attacks_blocked_total",
		"auth_failures_total",
		"rekeys_initiated_total",
		"rekeys_completed_total",
		"rekeys_failed_total",
		"encrypt_errors_total",
		"decrypt_errors_total",
		"protocol_errors_total",
		"uptime_seconds",
		"handshake_duration_milliseconds",
		"encrypt_duration_microseconds",
		"decrypt_duration_microseconds",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(output, "quantum_"+metric) {
			t.Errorf("missing metric: quantum_%s", metric)
		}
	}
}

func TestPrometheusExporterEmptyLabels(t *testing.T) {
	c := NewCollector(nil)
	c.SessionStarted()

	exp := NewPrometheusExporter(c, "test")

	var buf bytes.Buffer
	exp.WriteMetrics(&buf)

	output := buf.String()

	// With no labels, metrics should not have curly braces (except histograms)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "test_sessions_active") {
			if strings.Contains(line, "{") && !strings.Contains(line, "_bucket") {
				t.Errorf("gauge metric should not have labels: %s", line)
			}
		}
	}
}
