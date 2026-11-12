package tunnel_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/metrics"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// waitUntil polls cond until it holds or one generous deadline passes.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func lifecyclePool(t *testing.T, addr string, edit func(*tunnel.PoolConfig)) *tunnel.Pool {
	t.Helper()
	cfg := tunnel.DefaultPoolConfig()
	cfg.TransportConfig.AllowUnauthenticated = true
	cfg.MinConns = 0
	cfg.MaxConns = 3
	cfg.HealthCheckInterval = 0
	if edit != nil {
		edit(&cfg)
	}
	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func TestPoolLifecycleAcquireTimeout(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	obs := &testPoolObserver{}
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) {
		c.MaxConns = 1
		c.WaitTimeout = 100 * time.Millisecond
		c.Observer = obs
	})

	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = held.Release() }()

	if _, err := pool.Acquire(context.Background()); !errors.Is(err, qerrors.ErrPoolTimeout) {
		t.Fatalf("second Acquire = %v, want ErrPoolTimeout", err)
	}
	if obs.timeoutCount.Load() != 1 {
		t.Fatalf("OnAcquireTimeout called %d times, want 1", obs.timeoutCount.Load())
	}
	if w := pool.Stats().WaitingCount; w != 0 {
		t.Fatalf("WaitingCount = %d after timeout, want 0", w)
	}
}

func TestPoolLifecycleCloseWhileWaiting(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) { c.MaxConns = 1 })

	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = held.Release() }()

	res := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(context.Background())
		res <- err
	}()
	waitUntil(t, "a waiter to queue", func() bool { return pool.Stats().WaitingCount == 1 })

	if err := pool.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-res:
		if !errors.Is(err, qerrors.ErrPoolClosed) {
			t.Fatalf("waiter got %v, want ErrPoolClosed", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("waiter still blocked after Close")
	}

	if _, err := pool.Acquire(context.Background()); !errors.Is(err, qerrors.ErrPoolClosed) {
		t.Fatalf("Acquire after Close = %v, want ErrPoolClosed", err)
	}
	if err := pool.Start(context.Background()); !errors.Is(err, qerrors.ErrPoolClosed) {
		t.Fatalf("Start after Close = %v, want ErrPoolClosed", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

func TestPoolLifecycleWaiterGetsReleasedConn(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) { c.MaxConns = 1 })

	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	got := make(chan *tunnel.PoolConn, 1)
	go func() {
		c, err := pool.Acquire(context.Background())
		if err != nil {
			t.Errorf("waiter Acquire: %v", err)
		}
		got <- c
	}()
	waitUntil(t, "a waiter to queue", func() bool { return pool.Stats().WaitingCount == 1 })

	if err := held.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case c := <-got:
		if c == nil {
			t.Fatal("waiter got no connection")
		}
		if pool.Size() != 1 || pool.InUseCount() != 1 || pool.IdleCount() != 0 {
			t.Fatalf("size=%d inUse=%d idle=%d, want 1/1/0", pool.Size(), pool.InUseCount(), pool.IdleCount())
		}
		_ = c.Release()
	case <-time.After(30 * time.Second):
		t.Fatal("waiter never received the released connection")
	}
}

// A connection closed as unhealthy frees capacity; a queued waiter must be able to
// dial a replacement rather than sit until its timeout.
func TestPoolLifecycleWaiterAfterUnhealthyClose(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) { c.MaxConns = 1 })

	held, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	res := make(chan error, 1)
	go func() {
		c, err := pool.Acquire(context.Background())
		if err == nil {
			_ = c.Release()
		}
		res <- err
	}()
	waitUntil(t, "a waiter to queue", func() bool { return pool.Stats().WaitingCount == 1 })

	if err := held.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("waiter after unhealthy close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter starved after the only connection was closed as unhealthy")
	}
}

func TestPoolLifecycleMaxLifetimeEvictsOnAcquire(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) { c.MaxLifetime = 50 * time.Millisecond })

	first, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	created := first.CreatedAt()
	_ = first.Release()
	time.Sleep(100 * time.Millisecond)

	second, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = second.Release() }()
	if !second.CreatedAt().After(created) {
		t.Fatal("expired connection was reused instead of replaced")
	}
	if err := second.Send([]byte("fresh")); err != nil {
		t.Fatalf("Send on replacement: %v", err)
	}
}

func TestPoolLifecycleHealthCheckEvictsAndReplenishes(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	obs := &testPoolObserver{}
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) {
		c.MinConns = 1
		c.IdleTimeout = 400 * time.Millisecond
		c.HealthCheckInterval = 20 * time.Millisecond
		c.Observer = obs
	})

	// The idle connection ages out, the checker closes it and dials a replacement
	// to hold MinConns. ConnectionsCreated and the observer callbacks both run before
	// the replacement is registered (and the close notification runs after the stats
	// update), so wait for every signal at once instead of asserting right after the
	// first one. The replacement stays idle for IdleTimeout before the next eviction,
	// which leaves a window wide enough for the poll to see the whole state.
	waitUntil(t, "a health check to evict the idle connection and register a replacement", func() bool {
		s := pool.Stats()
		return s.ConnectionsCreated >= 2 && s.HealthChecksFailed >= 1 &&
			obs.healthCheckCount.Load() > 0 && obs.connClosedCount.Load() > 0 &&
			pool.Size() >= 1
	})
}

func TestPoolLifecycleDialFailure(t *testing.T) {
	// A listener that is closed immediately leaves a port that refuses connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) {
		c.MinConns = 1 // Start must tolerate the failed pre-dial.
		c.DialTimeout = 2 * time.Second
	})
	if pool.Size() != 0 {
		t.Fatalf("Size = %d, want 0", pool.Size())
	}
	if _, err := pool.Acquire(context.Background()); err == nil {
		t.Fatal("Acquire against a dead address succeeded")
	}
	if pool.Size() != 0 {
		t.Fatalf("failed dial leaked a pool slot: Size = %d", pool.Size())
	}
}

func TestPoolLifecycleConcurrentStress(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	const maxConns = 3
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) { c.MaxConns = maxConns })

	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				c, err := pool.Acquire(context.Background())
				if err != nil {
					t.Errorf("Acquire: %v", err)
					return
				}
				if n := pool.Size(); n > maxConns {
					t.Errorf("pool grew to %d, max %d", n, maxConns)
				}
				if err := c.Send([]byte("x")); err != nil {
					t.Errorf("Send: %v", err)
				}
				if _, err := c.Receive(); err != nil {
					t.Errorf("Receive: %v", err)
				}
				if i%5 == 0 {
					_ = c.Close() // mix in unhealthy returns
				} else {
					_ = c.Release()
				}
			}
		}()
	}
	wg.Wait()

	if pool.InUseCount() != 0 {
		t.Fatalf("InUseCount = %d after all callers finished", pool.InUseCount())
	}
	if s := pool.Stats(); s.WaitingCount != 0 || s.ConnectionsInUse != 0 {
		t.Fatalf("stats leaked: waiting=%d inUse=%d", s.WaitingCount, s.ConnectionsInUse)
	}
}

func TestPoolMetricsObserverEndToEnd(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	obs := metrics.NewPoolMetricsObserver(metrics.PoolMetricsObserverConfig{PoolName: "e2e"})
	pool := lifecyclePool(t, addr, func(c *tunnel.PoolConfig) {
		c.MaxConns = 1
		c.WaitTimeout = 50 * time.Millisecond
		c.HealthCheckInterval = 20 * time.Millisecond
		c.Observer = obs
	})

	c, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := pool.Acquire(context.Background()); !errors.Is(err, qerrors.ErrPoolTimeout) {
		t.Fatalf("want ErrPoolTimeout, got %v", err)
	}
	_ = c.Release()
	again, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	_ = again.Close()

	waitUntil(t, "pool metrics to catch up", func() bool {
		s := obs.Snapshot()
		return s.HealthChecksTotal > 0 && s.ConnectionsClosed > 0
	})
	s := obs.Snapshot()
	if s.PoolName != "e2e" || s.ConnectionsCreated < 1 || s.AcquiresTotal != 2 || s.AcquireTimeoutsTotal != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
}
