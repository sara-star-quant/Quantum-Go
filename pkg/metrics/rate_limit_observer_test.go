package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaskIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ipv4", "192.168.1.100", "192***100"},
		{"ipv4 short", "10.0.0.1", "10.***0.1"},
		{"ipv4 with port", "192.168.1.1:8443", "192***1.1"},
		{"ipv6", "2001:db8::1", "200***::1"},
		{"ipv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "200***334"},
		{"ipv6 with brackets and port", "[2001:db8::1]:8443", "200***::1"},
		{"ipv6 loopback", "::1", "***"},
		{"ipv4 loopback", "127.0.0.1", "127***0.1"},
		{"too short", "1.2", "***"},
		{"empty", "", "***"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskIP(tc.input)
			if got != tc.want {
				t.Errorf("maskIP(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRateLimitObserverRecordsMetrics(t *testing.T) {
	collector := NewCollector(nil)
	observer := NewRateLimitObserver(collector, NullLogger())

	observer.OnConnectionRateLimit("127.0.0.1")
	observer.OnHandshakeRateLimit("127.0.0.1")

	snap := collector.Snapshot()
	if snap.ConnectionRateLimits != 1 {
		t.Fatalf("expected ConnectionRateLimits to be 1, got %d", snap.ConnectionRateLimits)
	}
	if snap.HandshakeRateLimits != 1 {
		t.Fatalf("expected HandshakeRateLimits to be 1, got %d", snap.HandshakeRateLimits)
	}
}

func TestRateLimitObserverMasksIP(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(WithOutput(&buf), WithLevel(LevelWarn))
	collector := NewCollector(nil)
	observer := NewRateLimitObserver(collector, logger)

	rawIP := "192.168.1.100"
	observer.OnConnectionRateLimit(rawIP)
	observer.OnHandshakeRateLimit(rawIP)

	output := buf.String()

	// The raw IP must never appear in log output
	if strings.Contains(output, rawIP) {
		t.Errorf("raw IP %q found in log output:\n%s", rawIP, output)
	}

	// The masked form must appear
	masked := maskIP(rawIP) // "192***100"
	if !strings.Contains(output, masked) {
		t.Errorf("masked IP %q not found in log output:\n%s", masked, output)
	}
}

func TestRateLimitObserverEmptyIP(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(WithOutput(&buf), WithLevel(LevelWarn))
	collector := NewCollector(nil)
	observer := NewRateLimitObserver(collector, logger)

	// Empty IP should still log without remote_ip field
	observer.OnConnectionRateLimit("")
	observer.OnHandshakeRateLimit("")

	snap := collector.Snapshot()
	if snap.ConnectionRateLimits != 1 {
		t.Fatalf("expected ConnectionRateLimits to be 1, got %d", snap.ConnectionRateLimits)
	}
	if snap.HandshakeRateLimits != 1 {
		t.Fatalf("expected HandshakeRateLimits to be 1, got %d", snap.HandshakeRateLimits)
	}
}
