package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/metrics"
)

// forwardOps is what an operator needs to run a forwarder unattended: counts and readiness for
// the metrics endpoint, and a wait group so a shutdown can let open connections finish.
// It holds counts and durations only, never addresses or identities.
type forwardOps struct {
	collector *metrics.Collector
	// conns counts connections being served; Drain waits on it.
	conns sync.WaitGroup

	ready    atomic.Bool
	draining atomic.Bool

	active       atomic.Int64
	accepted     atomic.Int64
	refused      atomic.Int64
	dialFailed   atomic.Int64
	reloads      atomic.Int64
	reloadFailed atomic.Int64
	// lastReloadOK is 1 until a reload fails and again after one succeeds.
	lastReloadOK atomic.Int64
}

func newForwardOps() *forwardOps {
	o := &forwardOps{collector: metrics.NewCollector(metrics.Labels{})}
	o.lastReloadOK.Store(1)
	return o
}

// serving marks the start of one served connection and returns its end.
func (o *forwardOps) serving() (done func()) {
	o.accepted.Add(1)
	o.active.Add(1)
	o.conns.Add(1)
	return func() {
		o.active.Add(-1)
		o.conns.Done()
	}
}

// bytes feeds the library's byte counters when a connection ends (sent: toward the peer
// or the upstream's side as the caller defines it, received: back).
func (o *forwardOps) bytes(sent, received int64) {
	o.collector.RecordBytesSent(int(min(sent, int64(1<<31-1))))
	o.collector.RecordBytesReceived(int(min(received, int64(1<<31-1))))
}

// drain waits for open connections to finish, up to timeout, and reports whether they did.
// The accept loop must have ended first (forwarder.Drain closes the listener), so every
// conns.Add happens before conns.Wait.
func (o *forwardOps) drain(timeout time.Duration) bool {
	o.draining.Store(true)
	o.ready.Store(false)
	if timeout <= 0 {
		return o.active.Load() == 0
	}
	finished := make(chan struct{})
	go func() {
		o.conns.Wait()
		close(finished)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-finished:
		return true
	case <-timer.C:
		return false
	}
}

// metricsBind returns the address to bind for --metrics-addr. A bare ":port" binds loopback.
// A wildcard host is refused: exposing the endpoint on every interface has to be a deliberate
// choice of one interface, named.
func metricsBind(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return "", fmt.Errorf("--metrics-addr %s listens on every interface; name one address, such as 127.0.0.1:%s", addr, port)
	}
	return addr, nil
}

// metricsServer is the observability endpoint: Prometheus metrics, liveness and readiness.
type metricsServer struct {
	srv  *http.Server
	addr net.Addr
}

// startMetricsServer serves /metrics, /healthz and /readyz for ops on addr.
func startMetricsServer(addr, version string, ops *forwardOps) (*metricsServer, error) {
	bind, err := metricsBind(addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	// metricsBind cannot know every spelling of a wildcard ("0", "00", a name that resolves to
	// one), so judge the address the socket actually got.
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && tcp.IP.IsUnspecified() {
		_ = ln.Close()
		return nil, fmt.Errorf("--metrics-addr %s listens on every interface; name one address, such as 127.0.0.1:%d", addr, tcp.Port)
	}
	inner := metrics.NewServer(metrics.ServerConfig{
		Collector:        ops.collector,
		Version:          version,
		EnablePrometheus: true,
		EnableHealth:     true,
	})
	inner.AddHealthCheck("forwarder", func() error {
		if !ops.ready.Load() {
			if ops.draining.Load() {
				return errors.New("draining")
			}
			return errors.New("not ready")
		}
		return nil
	})
	mux := http.NewServeMux()
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.Handler().ServeHTTP(w, r)
		writeForwardMetrics(w, ops)
	}))
	mux.Handle("/healthz", inner.Handler())
	mux.Handle("/readyz", inner.Handler())
	s := &metricsServer{
		srv: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		},
		addr: ln.Addr(),
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *metricsServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func writeForwardMetrics(w io.Writer, o *forwardOps) {
	b2i := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	row := func(name, kind, help string, v int64) {
		_, _ = fmt.Fprintf(w, "# HELP quantum_tunnel_forward_%s %s\n# TYPE quantum_tunnel_forward_%s %s\nquantum_tunnel_forward_%s %d\n", name, help, name, kind, name, v)
	}
	row("connections_active", "gauge", "Connections being served now.", o.active.Load())
	row("connections_total", "counter", "Connections accepted for serving.", o.accepted.Load())
	row("handshakes_refused_total", "counter", "Handshakes refused: wrong key, rate limit, or a peer that is not a tunnel client.", o.refused.Load())
	row("dial_failures_total", "counter", "Failed dials of the upstream (server) or of the tunnel peer (client).", o.dialFailed.Load())
	row("key_reloads_total", "counter", "Successful key reloads.", o.reloads.Load())
	row("key_reload_failures_total", "counter", "Key reloads that failed and kept the previous keys.", o.reloadFailed.Load())
	row("last_key_reload_ok", "gauge", "1 when the last key reload succeeded or none has run, 0 when it failed.", o.lastReloadOK.Load())
	row("ready", "gauge", "1 when the listener is up and keys are loaded, 0 otherwise.", b2i(o.ready.Load()))
	row("draining", "gauge", "1 while a shutdown waits for open connections.", b2i(o.draining.Load()))
}
