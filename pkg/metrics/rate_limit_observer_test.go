package metrics

import "testing"

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
