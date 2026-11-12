package metrics

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
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

// TestRateLimitObserverReportsHandshakeLoad wires a real stream Listener to the metrics
// observer: a stalled peer holds the only slot, the next connection is shed and counted, and
// closing the stalled peer returns the gauge to zero.
func TestRateLimitObserverReportsHandshakeLoad(t *testing.T) {
	collector := NewCollector(nil)
	ln, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := tunnel.DefaultTransportConfig()
	cfg.MaxPendingHandshakes = 1
	cfg.HandshakeTimeout = 10 * time.Second
	cfg.RateLimitObserver = NewRateLimitObserver(collector, nil)
	ln.SetConfig(cfg)
	go func() { _, _ = ln.Accept() }()

	wait := func(what string, ok func(Snapshot) bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(collector.Snapshot()); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: %+v", what, collector.Snapshot())
			}
		}
	}
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wait("one slot in use", func(s Snapshot) bool { return s.PendingHandshakes == 1 })
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	wait("one shed", func(s Snapshot) bool { return s.HandshakesShed == 1 })
	_ = first.Close()
	wait("slot released", func(s Snapshot) bool { return s.PendingHandshakes == 0 })
}
