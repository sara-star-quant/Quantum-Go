package tunnel_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// TestPoolConfig tests pool configuration validation.
func TestPoolConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("DefaultPoolConfig should be valid: %v", err)
		}
		if cfg.MinConns != 1 {
			t.Errorf("MinConns = %d, want 1", cfg.MinConns)
		}
		if cfg.MaxConns != 10 {
			t.Errorf("MaxConns = %d, want 10", cfg.MaxConns)
		}
	})

	t.Run("InvalidMinConns", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MinConns = -1
		if err := cfg.Validate(); err == nil {
			t.Error("Expected error for negative MinConns")
		}
	})

	t.Run("InvalidMaxConns", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MaxConns = -1
		if err := cfg.Validate(); err == nil {
			t.Error("Expected error for negative MaxConns")
		}
	})

	t.Run("MinExceedsMax", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MinConns = 10
		cfg.MaxConns = 5
		if err := cfg.Validate(); err == nil {
			t.Error("Expected error when MinConns > MaxConns")
		}
	})

	t.Run("ZeroMaxAllowed", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MaxConns = 0 // Unlimited
		cfg.MinConns = 100
		if err := cfg.Validate(); err != nil {
			t.Errorf("MaxConns=0 with high MinConns should be valid: %v", err)
		}
	})
}

// TestNewPool tests pool creation.
func TestNewPool(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MinConns = 0 // Don't pre-create connections in this test
		pool, err := tunnel.NewPool("tcp", "127.0.0.1:9999", cfg)
		if err != nil {
			t.Fatalf("NewPool failed: %v", err)
		}
		if pool == nil {
			t.Fatal("NewPool returned nil")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		cfg := tunnel.DefaultPoolConfig()
		cfg.MinConns = -1
		_, err := tunnel.NewPool("tcp", "127.0.0.1:9999", cfg)
		if err == nil {
			t.Error("Expected error for invalid config")
		}
	})
}

// TestPoolBasicFlow tests basic acquire/release flow with a real server.
func TestPoolBasicFlow(t *testing.T) {
	// Start a listener
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	// Server goroutine to accept connections
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}
			// Keep connection alive for pool reuse testing
			go func(c *tunnel.Tunnel) {
				for {
					data, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
					// Echo back
					if err := c.Send(data); err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	// Create pool
	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0 // Start with no connections
	cfg.MaxConns = 5
	cfg.HealthCheckInterval = 0 // Disable background checks for this test

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	if err := pool.Start(ctx); err != nil {
		t.Fatalf("Pool.Start failed: %v", err)
	}

	// Wait a bit for server to be ready
	time.Sleep(50 * time.Millisecond)

	// Acquire a connection
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Verify we can use it
	testData := []byte("Hello, Pool!")
	if err := conn.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	response, err := conn.Receive()
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	if string(response) != string(testData) {
		t.Errorf("Response = %q, want %q", response, testData)
	}

	// Release connection back to pool
	if err := conn.Release(); err != nil {
		t.Errorf("Release failed: %v", err)
	}

	// Verify pool size
	if pool.Size() != 1 {
		t.Errorf("Pool size = %d, want 1", pool.Size())
	}
	if pool.IdleCount() != 1 {
		t.Errorf("Idle count = %d, want 1", pool.IdleCount())
	}

	// Acquire again - should get the same connection (reused)
	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Second Acquire failed: %v", err)
	}

	// Use it
	if err := conn2.Send([]byte("Second message")); err != nil {
		t.Fatalf("Second Send failed: %v", err)
	}
	_, _ = conn2.Receive()

	// Release
	if err := conn2.Release(); err != nil {
		t.Errorf("Second Release failed: %v", err)
	}
}

// TestPoolConnectionReuse tests that connections are reused.
func TestPoolConnectionReuse(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()
	var acceptCount atomic.Int32

	// Count accepts
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			acceptCount.Add(1)
			go func(c *tunnel.Tunnel) {
				for {
					data, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
					_ = c.Send(data)
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 2
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Acquire and release multiple times
	for i := 0; i < 10; i++ {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		if err := conn.Send([]byte("test")); err != nil {
			t.Fatalf("Send %d failed: %v", i, err)
		}
		_, _ = conn.Receive()
		_ = conn.Release()
	}

	// Should have only created 1 connection (reused)
	if got := acceptCount.Load(); got != 1 {
		t.Errorf("Accept count = %d, want 1 (connection reuse)", got)
	}
}

// TestPoolMaxConnections tests pool respects max connections.
func TestPoolMaxConnections(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	// Accept connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 2
	cfg.WaitTimeout = 100 * time.Millisecond
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Acquire max connections
	var conns []*tunnel.PoolConn
	for i := 0; i < 2; i++ {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Pool should be at capacity
	if pool.Size() != 2 {
		t.Errorf("Pool size = %d, want 2", pool.Size())
	}
	if pool.IdleCount() != 0 {
		t.Errorf("Idle count = %d, want 0", pool.IdleCount())
	}

	// Next acquire should timeout
	_, err = pool.Acquire(ctx)
	if !qerrors.Is(err, qerrors.ErrPoolTimeout) {
		t.Errorf("Expected ErrPoolTimeout, got %v", err)
	}

	// Release one
	_ = conns[0].Release()

	// Now acquire should succeed
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after release failed: %v", err)
	}
	_ = conn.Release()

	// Release remaining
	for _, c := range conns[1:] {
		_ = c.Release()
	}
}

// TestPoolWaitTimeout tests timeout when pool is exhausted.
func TestPoolWaitTimeout(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.WaitTimeout = 50 * time.Millisecond
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Acquire the only connection
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	start := time.Now()
	_, err = pool.Acquire(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error")
	}
	if !qerrors.Is(err, qerrors.ErrPoolTimeout) {
		t.Errorf("Expected ErrPoolTimeout, got %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Timeout too quick: %v", elapsed)
	}

	_ = conn.Release()
}

// TestPoolTryAcquire tests non-blocking acquire.
func TestPoolTryAcquire(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// TryAcquire should create a connection
	conn, err := pool.TryAcquire()
	if err != nil {
		t.Fatalf("TryAcquire failed: %v", err)
	}

	// Second TryAcquire should fail immediately
	start := time.Now()
	_, err = pool.TryAcquire()
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected error from TryAcquire when pool exhausted")
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("TryAcquire should fail immediately, took %v", elapsed)
	}

	_ = conn.Release()
}

// TestPoolClose tests closing the pool.
func TestPoolClose(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 2
	cfg.MaxConns = 5
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Close the pool
	if err := pool.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Acquire should fail after close
	_, err = pool.Acquire(ctx)
	if !qerrors.Is(err, qerrors.ErrPoolClosed) {
		t.Errorf("Expected ErrPoolClosed after Close, got %v", err)
	}

	// Double close should be safe
	if err := pool.Close(); err != nil {
		t.Errorf("Double close should be safe, got %v", err)
	}
}

// TestPoolStats tests statistics collection.
func TestPoolStats(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					data, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
					_ = c.Send(data)
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 5
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Perform some operations
	for i := 0; i < 5; i++ {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		_ = conn.Send([]byte("test"))
		_, _ = conn.Receive()
		_ = conn.Release()
	}

	stats := pool.Stats()

	if stats.AcquiresTotal != 5 {
		t.Errorf("AcquiresTotal = %d, want 5", stats.AcquiresTotal)
	}
	if stats.ConnectionsCreated < 1 {
		t.Errorf("ConnectionsCreated = %d, want >= 1", stats.ConnectionsCreated)
	}
	if stats.Uptime <= 0 {
		t.Errorf("Uptime = %v, want > 0", stats.Uptime)
	}
}

// TestPoolConcurrentAccess tests concurrent acquire/release.
func TestPoolConcurrentAccess(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					data, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
					_ = c.Send(data)
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 5
	cfg.WaitTimeout = 5 * time.Second
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Concurrent workers
	numWorkers := 10
	numOps := 20
	var wg sync.WaitGroup
	errors := make(chan error, numWorkers*numOps)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				conn, err := pool.Acquire(ctx)
				if err != nil {
					errors <- err
					continue
				}
				msg := []byte("hello")
				if err := conn.Send(msg); err != nil {
					_ = conn.Close() // Close on error
					errors <- err
					continue
				}
				if _, err := conn.Receive(); err != nil {
					_ = conn.Close()
					errors <- err
					continue
				}
				_ = conn.Release()
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Count errors
	var errCount int
	for err := range errors {
		errCount++
		t.Logf("Error: %v", err)
	}

	if errCount > 0 {
		t.Errorf("Got %d errors in concurrent test", errCount)
	}

	stats := pool.Stats()
	t.Logf("Stats: Acquires=%d, Created=%d, Closed=%d, Peak=%d",
		stats.AcquiresTotal, stats.ConnectionsCreated,
		stats.ConnectionsClosed, stats.PeakConnections)
}

// TestPoolCloseMarksUnhealthy tests that Close() marks connection as unhealthy.
func TestPoolCloseMarksUnhealthy(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 2
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Acquire connection
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Close instead of Release (marks as unhealthy)
	_ = conn.Close()

	// Give time for cleanup
	time.Sleep(50 * time.Millisecond)

	// Pool should be empty
	if pool.Size() != 0 {
		t.Errorf("Pool size = %d, want 0 after Close()", pool.Size())
	}
}

// TestPoolDoubleRelease tests that double release is safe.
func TestPoolDoubleRelease(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 5
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// First release
	if err := conn.Release(); err != nil {
		t.Errorf("First release failed: %v", err)
	}

	// Double release should be safe (no-op)
	if err := conn.Release(); err != nil {
		t.Errorf("Double release should be safe, got: %v", err)
	}

	// Using connection after release should fail
	if err := conn.Send([]byte("test")); err == nil {
		t.Error("Expected error when using released connection")
	}
}

// TestPoolContextCancellation tests context cancellation during acquire.
func TestPoolContextCancellation(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					_, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.WaitTimeout = 10 * time.Second
	cfg.HealthCheckInterval = 0

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Acquire the only connection
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Try to acquire with a cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())

	var acquireErr error
	done := make(chan struct{})
	go func() {
		_, acquireErr = pool.Acquire(cancelCtx)
		close(done)
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	<-done

	if acquireErr != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", acquireErr)
	}

	_ = conn.Release()
}

// TestPoolObserver tests observer notifications.
func TestPoolObserver(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tunnel.Tunnel) {
				for {
					data, err := c.Receive()
					if err != nil {
						_ = c.Close()
						return
					}
					_ = c.Send(data)
				}
			}(conn)
		}
	}()

	// Create a counting observer
	observer := &testPoolObserver{}

	cfg := tunnel.DefaultPoolConfig()
	cfg.MinConns = 0
	cfg.MaxConns = 5
	cfg.HealthCheckInterval = 0
	cfg.Observer = observer

	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	_ = pool.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Perform operations
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	_ = conn.Send([]byte("test"))
	_, _ = conn.Receive()
	_ = conn.Release()

	// Check observer was called
	if observer.acquireCount.Load() != 1 {
		t.Errorf("OnAcquire called %d times, want 1", observer.acquireCount.Load())
	}
	if observer.releaseCount.Load() != 1 {
		t.Errorf("OnRelease called %d times, want 1", observer.releaseCount.Load())
	}
	if observer.connCreatedCount.Load() < 1 {
		t.Errorf("OnConnectionCreated called %d times, want >= 1", observer.connCreatedCount.Load())
	}
}

// testPoolObserver is a test implementation of PoolObserver.
type testPoolObserver struct {
	acquireCount      atomic.Int32
	releaseCount      atomic.Int32
	timeoutCount      atomic.Int32
	connCreatedCount  atomic.Int32
	connClosedCount   atomic.Int32
	healthCheckCount  atomic.Int32
}

func (o *testPoolObserver) OnAcquire(_ time.Duration, _ bool) {
	o.acquireCount.Add(1)
}

func (o *testPoolObserver) OnAcquireTimeout() {
	o.timeoutCount.Add(1)
}

func (o *testPoolObserver) OnRelease() {
	o.releaseCount.Add(1)
}

func (o *testPoolObserver) OnConnectionCreated(_ time.Duration) {
	o.connCreatedCount.Add(1)
}

func (o *testPoolObserver) OnConnectionClosed(_ string) {
	o.connClosedCount.Add(1)
}

func (o *testPoolObserver) OnHealthCheck(_ bool) {
	o.healthCheckCount.Add(1)
}

func (o *testPoolObserver) OnPoolStats(_ tunnel.PoolStatsSnapshot) {}
