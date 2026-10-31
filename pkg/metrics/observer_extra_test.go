package metrics

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func newTestObserver(buf *bytes.Buffer, role string) (*TunnelObserver, *Collector) {
	c := NewCollector(Labels{"test": "observer"})
	return NewTunnelObserver(TunnelObserverConfig{
		Collector: c,
		Logger:    TestLogger(buf),
		SessionID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Role:      role,
	}), c
}

func TestTunnelObserverSessionLifecycle(t *testing.T) {
	var buf bytes.Buffer
	o, c := newTestObserver(&buf, "initiator")

	o.OnSessionStart()
	if s := c.Snapshot(); s.SessionsActive != 1 || s.SessionsTotal != 1 {
		t.Fatalf("after start: active=%d total=%d", s.SessionsActive, s.SessionsTotal)
	}
	o.OnSessionEnd()
	if s := c.Snapshot(); s.SessionsActive != 0 {
		t.Fatalf("after end: active=%d, want 0", s.SessionsActive)
	}
	o.OnSessionFailed(errors.New("boom"))
	if s := c.Snapshot(); s.SessionsFailed != 1 {
		t.Fatalf("SessionsFailed=%d, want 1", s.SessionsFailed)
	}

	out := buf.String()
	for _, want := range []string{"session started", "session ended", "session failed", "boom", "0102030405060708"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "090a") {
		t.Error("session id was not truncated to 8 bytes")
	}
}

func TestTunnelObserverHandshakeEncryptDecrypt(t *testing.T) {
	var buf bytes.Buffer
	for _, role := range []string{"initiator", "responder"} {
		o, c := newTestObserver(&buf, role)

		_, done := o.OnHandshakeStart(context.Background())
		done(nil)
		_, done = o.OnHandshakeStart(context.Background())
		done(errors.New("handshake broke"))
		if n := c.Snapshot().HandshakeLatency.Count; n != 2 {
			t.Fatalf("%s: %d handshake latencies recorded, want 2", role, n)
		}

		_, done = o.OnEncrypt(context.Background(), 100)
		done(nil)
		_, done = o.OnEncrypt(context.Background(), 100)
		done(errors.New("seal"))
		s := c.Snapshot()
		if s.BytesSent != 100 || s.PacketsSent != 1 || s.EncryptErrors != 1 {
			t.Fatalf("%s encrypt: bytes=%d packets=%d errors=%d", role, s.BytesSent, s.PacketsSent, s.EncryptErrors)
		}

		_, done = o.OnDecrypt(context.Background(), 60)
		done(nil)
		_, done = o.OnDecrypt(context.Background(), 60)
		done(errors.New("open"))
		s = c.Snapshot()
		if s.BytesReceived != 60 || s.PacketsRecv != 1 || s.DecryptErrors != 1 {
			t.Fatalf("%s decrypt: bytes=%d packets=%d errors=%d", role, s.BytesReceived, s.PacketsRecv, s.DecryptErrors)
		}
	}
}

func TestTunnelObserverSecurityAndRekey(t *testing.T) {
	var buf bytes.Buffer
	o, c := newTestObserver(&buf, "responder")

	o.OnReplayDetected()
	o.OnAuthFailure()
	o.OnProtocolError(errors.New("bad frame"))
	_, done := o.OnRekeyStart(context.Background())
	done(nil)
	_, done = o.OnRekeyStart(context.Background())
	done(errors.New("rekey broke"))

	s := c.Snapshot()
	if s.ReplayAttacksBlocked != 1 || s.AuthFailures != 1 || s.ProtocolErrors != 1 {
		t.Fatalf("security counters: replay=%d auth=%d proto=%d", s.ReplayAttacksBlocked, s.AuthFailures, s.ProtocolErrors)
	}
	if s.RekeysInitiated != 2 || s.RekeysCompleted != 1 || s.RekeysFailed != 1 {
		t.Fatalf("rekey counters: started=%d completed=%d failed=%d", s.RekeysInitiated, s.RekeysCompleted, s.RekeysFailed)
	}
	if o.Logger() == nil {
		t.Fatal("Logger() returned nil")
	}
}

func TestInstrumentedSessionWrapsAndPropagatesErrors(t *testing.T) {
	var buf bytes.Buffer
	o, c := newTestObserver(&buf, "initiator")
	is := NewInstrumentedSession(o)

	if err := is.WrapEncrypt(context.Background(), 10, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := errors.New("fn failed")
	if err := is.WrapDecrypt(context.Background(), 10, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("WrapDecrypt returned %v, want %v", err, want)
	}
	s := c.Snapshot()
	if s.PacketsSent != 1 || s.DecryptErrors != 1 {
		t.Fatalf("wrapped metrics: sent=%d decryptErrors=%d", s.PacketsSent, s.DecryptErrors)
	}
	if min(3, 5) != 3 || min(5, 3) != 3 {
		t.Fatal("min is wrong")
	}
}

func TestNewTunnelObserverDefaults(t *testing.T) {
	if o := NewTunnelObserver(TunnelObserverConfig{}); o == nil || o.Logger() == nil {
		t.Fatal("observer with an empty config must fall back to the globals")
	}
}

func TestPoolMetricsObserver(t *testing.T) {
	var buf bytes.Buffer
	o := NewPoolMetricsObserver(PoolMetricsObserverConfig{Logger: TestLogger(&buf), PoolName: "edge"})

	o.OnConnectionCreated(30 * time.Millisecond)
	o.OnConnectionCreated(40 * time.Millisecond)
	o.OnAcquire(5*time.Millisecond, false)
	o.OnAcquire(7*time.Millisecond, true)
	o.OnAcquireTimeout()
	o.OnRelease()
	o.OnHealthCheck(true)
	o.OnHealthCheck(false)
	o.OnConnectionClosed("idle")

	s := o.Snapshot()
	if s.PoolName != "edge" || s.ConnectionsCreated != 2 || s.ConnectionsClosed != 1 || s.ConnectionsTotal != 1 {
		t.Fatalf("connection counters wrong: %+v", s)
	}
	if s.AcquiresTotal != 2 || s.AcquireTimeoutsTotal != 1 || s.HealthChecksTotal != 2 || s.HealthChecksFailed != 1 {
		t.Fatalf("acquire/health counters wrong: %+v", s)
	}
	if s.AcquireLatency.Count != 2 || s.DialLatency.Count != 2 {
		t.Fatalf("histograms not fed: acquire=%d dial=%d", s.AcquireLatency.Count, s.DialLatency.Count)
	}

	// OnPoolStats replaces the gauges with the authoritative values.
	o.OnPoolStats(tunnel.PoolStatsSnapshot{ConnectionsTotal: 9, ConnectionsIdle: 4, ConnectionsInUse: 5, WaitingCount: 2})
	if s := o.Snapshot(); s.ConnectionsTotal != 9 || s.ConnectionsIdle != 4 || s.ConnectionsInUse != 5 || s.WaitingCount != 2 {
		t.Fatalf("OnPoolStats did not set the gauges: %+v", s)
	}

	// In-use never goes negative, even on a stray release.
	o.Reset()
	o.OnRelease()
	if s := o.Snapshot(); s.ConnectionsInUse != 0 || s.AcquiresTotal != 0 {
		t.Fatalf("after Reset and a stray release: %+v", s)
	}

	exp := NewPrometheusExporter(NewCollector(nil), "qt")
	var out bytes.Buffer
	exp.WritePoolMetrics(&out, nil) // nil pool writes nothing
	if out.Len() != 0 {
		t.Fatal("nil pool wrote output")
	}
	exp.WritePoolMetrics(&out, o)
	text := out.String()
	for _, want := range []string{"pool_connections_total", "pool_acquire_duration_milliseconds", `pool="edge"`} {
		if !strings.Contains(text, want) {
			t.Errorf("pool exposition missing %q", want)
		}
	}
}

func TestGlobalLoggerFunctionsAndPresets(t *testing.T) {
	var buf bytes.Buffer
	prev := GetLogger()
	defer SetLogger(prev)
	SetLogger(TestLogger(&buf))

	Debug("dbg-line")
	Info("info-line")
	Warn("warn-line")
	Error("err-line", Fields{"k": "v"})
	out := buf.String()
	for _, want := range []string{"dbg-line", "info-line", "warn-line", "err-line", "k"} {
		if !strings.Contains(out, want) {
			t.Errorf("global logger output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	l := TestLogger(&buf)
	l.Debug("d")
	l.Warn("w")
	l.Error("e")
	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Errorf("TestLogger emitted %d lines for debug, warn and error, want 3", got)
	}

	buf.Reset()
	p := ProductionLogger(&buf)
	p.Debug("hidden") // below info, dropped
	p.Info("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), `"shown"`) && !strings.Contains(buf.String(), "shown") {
		t.Errorf("ProductionLogger filtering/format wrong: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "{") {
		t.Errorf("ProductionLogger did not write JSON: %q", buf.String())
	}
}

func TestHealthChecks(t *testing.T) {
	if err := MemoryCheck(^uint64(0))(); err != nil {
		t.Fatalf("a huge threshold must pass: %v", err)
	}
	if err := MemoryCheck(1)(); err == nil {
		t.Fatal("a 1-byte threshold must fail")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ConnectivityCheck(addr, time.Second)(); err != nil {
		t.Fatalf("reachable address failed: %v", err)
	}
	_ = ln.Close()
	if err := ConnectivityCheck(addr, 200*time.Millisecond)(); err == nil {
		t.Fatal("a closed port must fail the connectivity check")
	}
}

func TestServersRejectBadAddress(t *testing.T) {
	// A malformed address fails at once, without binding anything.
	if err := ServePrometheus("not-an-address", NewCollector(nil), "qt"); err == nil {
		t.Fatal("ServePrometheus accepted a bad address")
	}
	if err := NewServer(ServerConfig{EnableHealth: true}).ListenAndServe("not-an-address"); err == nil {
		t.Fatal("Server.ListenAndServe accepted a bad address")
	}
	srv := newHTTPServer(":0", nil)
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("metrics server is missing timeouts: %+v", srv)
	}
}
