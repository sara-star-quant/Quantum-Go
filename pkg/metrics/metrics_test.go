package metrics

import (
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	labels := Labels{"instance": "test"}
	c := NewCollector(labels)

	if c == nil {
		t.Fatal("expected non-nil collector")
	}

	snap := c.Snapshot()
	if snap.Labels["instance"] != "test" {
		t.Errorf("expected label instance=test, got %v", snap.Labels)
	}
}

func TestCollectorSessionMetrics(t *testing.T) {
	c := NewCollector(nil)

	// Test session start
	c.SessionStarted()
	c.SessionStarted()
	snap := c.Snapshot()
	if snap.SessionsActive != 2 {
		t.Errorf("expected 2 active sessions, got %d", snap.SessionsActive)
	}
	if snap.SessionsTotal != 2 {
		t.Errorf("expected 2 total sessions, got %d", snap.SessionsTotal)
	}

	// Test session end
	c.SessionEnded()
	snap = c.Snapshot()
	if snap.SessionsActive != 1 {
		t.Errorf("expected 1 active session, got %d", snap.SessionsActive)
	}
	if snap.SessionsTotal != 2 {
		t.Errorf("expected 2 total sessions, got %d", snap.SessionsTotal)
	}

	// Test session failed
	c.SessionFailed()
	snap = c.Snapshot()
	if snap.SessionsFailed != 1 {
		t.Errorf("expected 1 failed session, got %d", snap.SessionsFailed)
	}
}

func TestCollectorTrafficMetrics(t *testing.T) {
	c := NewCollector(nil)

	c.RecordBytesSent(1000)
	c.RecordBytesSent(500)
	c.RecordBytesReceived(2000)
	c.RecordPacketSent()
	c.RecordPacketSent()
	c.RecordPacketReceived()

	snap := c.Snapshot()
	if snap.BytesSent != 1500 {
		t.Errorf("expected 1500 bytes sent, got %d", snap.BytesSent)
	}
	if snap.BytesReceived != 2000 {
		t.Errorf("expected 2000 bytes received, got %d", snap.BytesReceived)
	}
	if snap.PacketsSent != 2 {
		t.Errorf("expected 2 packets sent, got %d", snap.PacketsSent)
	}
	if snap.PacketsRecv != 1 {
		t.Errorf("expected 1 packet received, got %d", snap.PacketsRecv)
	}
}

func TestCollectorSecurityMetrics(t *testing.T) {
	c := NewCollector(nil)

	c.RecordReplayBlocked()
	c.RecordAuthFailure()
	c.RecordRekeyInitiated()
	c.RecordRekeyCompleted()
	c.RecordRekeyFailed()

	snap := c.Snapshot()
	if snap.ReplayAttacksBlocked != 1 {
		t.Errorf("expected 1 replay blocked, got %d", snap.ReplayAttacksBlocked)
	}
	if snap.AuthFailures != 1 {
		t.Errorf("expected 1 auth failure, got %d", snap.AuthFailures)
	}
	if snap.RekeysInitiated != 1 {
		t.Errorf("expected 1 rekey initiated, got %d", snap.RekeysInitiated)
	}
	if snap.RekeysCompleted != 1 {
		t.Errorf("expected 1 rekey completed, got %d", snap.RekeysCompleted)
	}
	if snap.RekeysFailed != 1 {
		t.Errorf("expected 1 rekey failed, got %d", snap.RekeysFailed)
	}
}

func TestCollectorErrorMetrics(t *testing.T) {
	c := NewCollector(nil)

	c.RecordEncryptError()
	c.RecordDecryptError()
	c.RecordProtocolError()

	snap := c.Snapshot()
	if snap.EncryptErrors != 1 {
		t.Errorf("expected 1 encrypt error, got %d", snap.EncryptErrors)
	}
	if snap.DecryptErrors != 1 {
		t.Errorf("expected 1 decrypt error, got %d", snap.DecryptErrors)
	}
	if snap.ProtocolErrors != 1 {
		t.Errorf("expected 1 protocol error, got %d", snap.ProtocolErrors)
	}
}

func TestCollectorLatencyMetrics(t *testing.T) {
	c := NewCollector(nil)

	c.RecordHandshakeLatency(100 * time.Millisecond)
	c.RecordHandshakeLatency(200 * time.Millisecond)
	c.RecordEncryptLatency(10 * time.Microsecond)
	c.RecordDecryptLatency(15 * time.Microsecond)

	snap := c.Snapshot()
	if snap.HandshakeLatency.Count != 2 {
		t.Errorf("expected 2 handshake latency observations, got %d", snap.HandshakeLatency.Count)
	}
	if snap.HandshakeLatency.Mean != 150 {
		t.Errorf("expected mean handshake latency 150ms, got %.2f", snap.HandshakeLatency.Mean)
	}
	if snap.EncryptLatency.Count != 1 {
		t.Errorf("expected 1 encrypt latency observation, got %d", snap.EncryptLatency.Count)
	}
	if snap.DecryptLatency.Count != 1 {
		t.Errorf("expected 1 decrypt latency observation, got %d", snap.DecryptLatency.Count)
	}
}

func TestCollectorReset(t *testing.T) {
	c := NewCollector(nil)

	c.SessionStarted()
	c.RecordBytesSent(1000)
	c.RecordReplayBlocked()

	snap := c.Snapshot()
	if snap.SessionsActive != 1 || snap.BytesSent != 1000 {
		t.Fatal("metrics not recorded")
	}

	c.Reset()

	snap = c.Snapshot()
	if snap.SessionsActive != 0 {
		t.Errorf("expected 0 active sessions after reset, got %d", snap.SessionsActive)
	}
	if snap.BytesSent != 0 {
		t.Errorf("expected 0 bytes sent after reset, got %d", snap.BytesSent)
	}
	if snap.ReplayAttacksBlocked != 0 {
		t.Errorf("expected 0 replay blocked after reset, got %d", snap.ReplayAttacksBlocked)
	}
}

func TestCollectorUptime(t *testing.T) {
	c := NewCollector(nil)
	time.Sleep(10 * time.Millisecond)

	snap := c.Snapshot()
	if snap.Uptime < 10*time.Millisecond {
		t.Errorf("expected uptime >= 10ms, got %v", snap.Uptime)
	}
}

func TestGlobalCollector(t *testing.T) {
	// Get global collector
	g := Global()
	if g == nil {
		t.Fatal("expected non-nil global collector")
	}

	// Should return same instance
	g2 := Global()
	if g != g2 {
		t.Error("expected same global collector instance")
	}

	// Set custom global
	custom := NewCollector(Labels{"custom": "true"})
	SetGlobal(custom)

	// Note: Due to sync.Once, this won't change the global in normal use
	// This test just verifies the setter doesn't panic
}

func TestCollectorConcurrency(t *testing.T) {
	c := NewCollector(nil)

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				c.SessionStarted()
				c.RecordBytesSent(j)
				c.RecordHandshakeLatency(time.Duration(j) * time.Millisecond)
				c.SessionEnded()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	snap := c.Snapshot()
	if snap.SessionsTotal != 1000 {
		t.Errorf("expected 1000 total sessions, got %d", snap.SessionsTotal)
	}
	if snap.SessionsActive != 0 {
		t.Errorf("expected 0 active sessions, got %d", snap.SessionsActive)
	}
}
