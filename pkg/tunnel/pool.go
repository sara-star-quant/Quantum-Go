package tunnel

import (
	"context"
	"net"
	"sync"
	"time"

	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// Pool manages a pool of reusable Tunnel connections.
// It reduces the overhead of establishing new connections by reusing
// existing ones with established sessions.
type Pool struct {
	network string
	address string
	config  PoolConfig

	mu       sync.Mutex
	conns    []*pooledConn // All connections (idle + in-use)
	idle     []*pooledConn // Available connections (LIFO for cache locality)
	waiters  []chan *pooledConn
	closed   bool
	stats    *PoolStats

	healthCtx    context.Context
	healthCancel context.CancelFunc
	healthWg     sync.WaitGroup
}

// NewPool creates a new connection pool for the given network address.
// The pool is not started until Start is called.
func NewPool(network, address string, config PoolConfig) (*Pool, error) {
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Pool{
		network: network,
		address: address,
		config:  config,
		conns:   make([]*pooledConn, 0, config.MaxConns),
		idle:    make([]*pooledConn, 0, config.MaxConns),
		waiters: make([]chan *pooledConn, 0),
		stats:   newPoolStats(),
	}, nil
}

// Start initializes the pool and establishes minimum connections.
// It also starts background health checking if configured.
func (p *Pool) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return qerrors.ErrPoolClosed
	}
	p.mu.Unlock()

	// Pre-create minimum connections
	for i := 0; i < p.config.MinConns; i++ {
		pc, err := p.createConn(ctx)
		if err != nil {
			// Log but continue - we'll try again later
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, pc)
		p.idle = append(p.idle, pc)
		p.stats.setTotalCount(int64(len(p.conns)))
		p.stats.setIdleCount(int64(len(p.idle)))
		p.mu.Unlock()
	}

	// Start health checker if configured
	if p.config.HealthCheckInterval > 0 {
		p.healthCtx, p.healthCancel = context.WithCancel(context.Background())
		p.healthWg.Add(1)
		go p.healthChecker()
	}

	return nil
}

// Close closes all connections in the pool and prevents new acquires.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true

	// Cancel health checker
	if p.healthCancel != nil {
		p.healthCancel()
	}

	// Close all waiting channels
	for _, ch := range p.waiters {
		close(ch)
	}
	p.waiters = nil

	// Collect connections to close
	connsToClose := make([]*pooledConn, len(p.conns))
	copy(connsToClose, p.conns)
	p.conns = nil
	p.idle = nil
	p.mu.Unlock()

	// Wait for health checker to stop
	p.healthWg.Wait()

	// Close all connections outside the lock
	for _, pc := range connsToClose {
		_ = pc.tunnel.Close()
		if p.config.Observer != nil {
			p.config.Observer.OnConnectionClosed("pool_closed")
		}
	}

	return nil
}

// Acquire gets a connection from the pool, waiting up to WaitTimeout if necessary.
// The returned PoolConn must be released with Release() or closed with Close().
func (p *Pool) Acquire(ctx context.Context) (*PoolConn, error) {
	startTime := time.Now()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, qerrors.ErrPoolClosed
	}

	// Try to get an idle connection
	for len(p.idle) > 0 {
		// Pop from end (LIFO for better cache locality)
		pc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		// Quick health check
		if p.isHealthy(pc) {
			pc.inUse.Store(true)
			p.stats.recordAcquire(time.Since(startTime), true)
			p.mu.Unlock()

			if p.config.Observer != nil {
				p.config.Observer.OnAcquire(time.Since(startTime), true)
			}
			return newPoolConn(pc), nil
		}

		// Connection is unhealthy, close it
		p.removeConnLocked(pc)
		go func(pc *pooledConn) {
			_ = pc.tunnel.Close()
			if p.config.Observer != nil {
				p.config.Observer.OnConnectionClosed("unhealthy")
			}
		}(pc)
	}

	// Check if we can create a new connection
	if p.config.MaxConns == 0 || len(p.conns) < p.config.MaxConns {
		p.mu.Unlock()
		return p.createAndAcquire(ctx, startTime)
	}

	// Pool is exhausted, wait for a connection
	if p.config.WaitTimeout == 0 {
		p.mu.Unlock()
		p.stats.recordAcquireTimeout()
		if p.config.Observer != nil {
			p.config.Observer.OnAcquireTimeout()
		}
		return nil, qerrors.ErrPoolExhausted
	}

	// Create wait channel
	ch := make(chan *pooledConn, 1)
	p.waiters = append(p.waiters, ch)
	p.stats.incrementWaiting()
	p.mu.Unlock()

	// Wait with timeout
	timeout := p.config.WaitTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case pc := <-ch:
		p.stats.decrementWaiting()
		if pc == nil {
			// Channel closed, pool is closing
			return nil, qerrors.ErrPoolClosed
		}

		// Quick health check
		if !p.isHealthy(pc) {
			p.mu.Lock()
			p.removeConnLocked(pc)
			p.mu.Unlock()
			go func() {
				_ = pc.tunnel.Close()
				if p.config.Observer != nil {
					p.config.Observer.OnConnectionClosed("unhealthy")
				}
			}()
			// Try again recursively
			return p.Acquire(ctx)
		}

		pc.inUse.Store(true)
		p.stats.recordAcquire(time.Since(startTime), true)
		if p.config.Observer != nil {
			p.config.Observer.OnAcquire(time.Since(startTime), true)
		}
		return newPoolConn(pc), nil

	case <-timer.C:
		p.mu.Lock()
		p.removeWaiter(ch)
		p.mu.Unlock()
		p.stats.decrementWaiting()
		p.stats.recordAcquireTimeout()
		if p.config.Observer != nil {
			p.config.Observer.OnAcquireTimeout()
		}
		return nil, qerrors.ErrPoolTimeout

	case <-ctx.Done():
		p.mu.Lock()
		p.removeWaiter(ch)
		p.mu.Unlock()
		p.stats.decrementWaiting()
		p.stats.recordAcquireTimeout()
		if p.config.Observer != nil {
			p.config.Observer.OnAcquireTimeout()
		}
		return nil, ctx.Err()
	}
}

// TryAcquire attempts to get a connection without waiting.
// Returns ErrPoolExhausted if no connection is available.
func (p *Pool) TryAcquire() (*PoolConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	// Use a zero WaitTimeout to not wait
	p.mu.Lock()
	origTimeout := p.config.WaitTimeout
	p.config.WaitTimeout = 0
	p.mu.Unlock()

	conn, err := p.Acquire(ctx)

	p.mu.Lock()
	p.config.WaitTimeout = origTimeout
	p.mu.Unlock()

	return conn, err
}

// Stats returns the current pool statistics.
func (p *Pool) Stats() PoolStatsSnapshot {
	return p.stats.Snapshot()
}

// Size returns the current total number of connections (idle + in-use).
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// IdleCount returns the current number of idle connections.
func (p *Pool) IdleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

// InUseCount returns the current number of in-use connections.
func (p *Pool) InUseCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns) - len(p.idle)
}

// release returns a connection to the pool.
func (p *Pool) release(pc *pooledConn) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		// Pool is closed, just close the connection
		go func() {
			_ = pc.tunnel.Close()
		}()
		return nil
	}

	pc.inUse.Store(false)

	// If unhealthy, close it
	if pc.unhealthy.Load() {
		p.removeConnLocked(pc)
		p.stats.recordConnectionClosed(false)
		go func() {
			_ = pc.tunnel.Close()
			if p.config.Observer != nil {
				p.config.Observer.OnConnectionClosed("marked_unhealthy")
			}
		}()
		return nil
	}

	// Check if there are waiters
	if len(p.waiters) > 0 {
		ch := p.waiters[0]
		p.waiters = p.waiters[1:]
		pc.inUse.Store(true) // Mark as in use before handing off
		ch <- pc
		return nil
	}

	// Return to idle pool
	p.idle = append(p.idle, pc)
	p.stats.recordRelease()

	if p.config.Observer != nil {
		p.config.Observer.OnRelease()
	}

	return nil
}

// createAndAcquire creates a new connection and returns it.
func (p *Pool) createAndAcquire(ctx context.Context, startTime time.Time) (*PoolConn, error) {
	pc, err := p.createConn(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = pc.tunnel.Close()
		return nil, qerrors.ErrPoolClosed
	}

	pc.inUse.Store(true)
	p.conns = append(p.conns, pc)
	p.stats.setTotalCount(int64(len(p.conns)))
	p.stats.recordAcquire(time.Since(startTime), false)
	p.mu.Unlock()

	if p.config.Observer != nil {
		p.config.Observer.OnAcquire(time.Since(startTime), false)
	}

	return newPoolConn(pc), nil
}

// createConn creates a new tunnel connection.
func (p *Pool) createConn(ctx context.Context) (*pooledConn, error) {
	dialStart := time.Now()

	// Create dialer with timeout
	var d net.Dialer
	if p.config.DialTimeout > 0 {
		d.Timeout = p.config.DialTimeout
	}

	conn, err := d.DialContext(ctx, p.network, p.address)
	if err != nil {
		return nil, err
	}

	// Create session as initiator
	session, err := NewSession(RoleInitiator)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Perform handshake
	if err := InitiatorHandshake(session, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Create transport
	transport, err := NewTransport(session, conn, p.config.TransportConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	tunnel := &Tunnel{Transport: transport}
	pc := newPooledConn(tunnel, p)

	dialDuration := time.Since(dialStart)
	p.stats.recordConnectionCreated(dialDuration)

	if p.config.Observer != nil {
		p.config.Observer.OnConnectionCreated(dialDuration)
	}

	return pc, nil
}

// isHealthy performs a quick health check on a connection.
func (p *Pool) isHealthy(pc *pooledConn) bool {
	// Check if marked unhealthy
	if pc.unhealthy.Load() {
		return false
	}

	// Check max lifetime
	if p.config.MaxLifetime > 0 && pc.age() > p.config.MaxLifetime {
		return false
	}

	// Check idle timeout
	if p.config.IdleTimeout > 0 && pc.idleTime() > p.config.IdleTimeout {
		return false
	}

	// Check session state
	session := pc.tunnel.Session()
	if session == nil {
		return false
	}

	state := session.State()
	return state == SessionStateEstablished || state == SessionStateRekeying
}

// removeConnLocked removes a connection from the pool (must hold lock).
func (p *Pool) removeConnLocked(pc *pooledConn) {
	// Remove from conns
	for i, c := range p.conns {
		if c == pc {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}

	// Remove from idle if present
	for i, c := range p.idle {
		if c == pc {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			break
		}
	}

	p.stats.setTotalCount(int64(len(p.conns)))
	p.stats.setIdleCount(int64(len(p.idle)))
}

// removeWaiter removes a wait channel from the waiters list.
func (p *Pool) removeWaiter(ch chan *pooledConn) {
	for i, w := range p.waiters {
		if w == ch {
			p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
			return
		}
	}
}

// healthChecker runs periodic health checks on idle connections.
func (p *Pool) healthChecker() {
	defer p.healthWg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.healthCtx.Done():
			return
		case <-ticker.C:
			p.runHealthCheck()
		}
	}
}

// runHealthCheck checks all idle connections and removes unhealthy ones.
func (p *Pool) runHealthCheck() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}

	// Check idle connections
	var unhealthy []*pooledConn
	newIdle := make([]*pooledConn, 0, len(p.idle))

	for _, pc := range p.idle {
		healthy := p.isHealthy(pc)

		if p.config.Observer != nil {
			p.config.Observer.OnHealthCheck(healthy)
		}
		p.stats.recordHealthCheck(healthy)

		if healthy {
			newIdle = append(newIdle, pc)
		} else {
			unhealthy = append(unhealthy, pc)
		}
	}

	p.idle = newIdle
	for _, pc := range unhealthy {
		p.removeConnLocked(pc)
	}

	p.stats.setIdleCount(int64(len(p.idle)))
	p.mu.Unlock()

	// Close unhealthy connections outside the lock
	for _, pc := range unhealthy {
		_ = pc.tunnel.Close()
		if p.config.Observer != nil {
			p.config.Observer.OnConnectionClosed("health_check_failed")
		}
	}

	// Try to maintain minimum connections
	p.mu.Lock()
	deficit := p.config.MinConns - len(p.conns)
	p.mu.Unlock()

	if deficit > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), p.config.DialTimeout)
		defer cancel()

		for i := 0; i < deficit; i++ {
			pc, err := p.createConn(ctx)
			if err != nil {
				break
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				_ = pc.tunnel.Close()
				return
			}
			p.conns = append(p.conns, pc)
			p.idle = append(p.idle, pc)
			p.stats.setTotalCount(int64(len(p.conns)))
			p.stats.setIdleCount(int64(len(p.idle)))
			p.mu.Unlock()
		}
	}

	// Report stats to observer
	if p.config.Observer != nil {
		p.config.Observer.OnPoolStats(p.stats.Snapshot())
	}
}
