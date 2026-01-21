package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

// pooledConn is an internal representation of a connection in the pool.
// It tracks metadata needed for connection management.
type pooledConn struct {
	tunnel    *Tunnel
	pool      *Pool
	createdAt time.Time
	lastUsed  time.Time
	useMu     sync.Mutex // Protects lastUsed updates
	inUse     atomic.Bool
	unhealthy atomic.Bool
}

// newPooledConn creates a new pooled connection wrapper.
func newPooledConn(tunnel *Tunnel, pool *Pool) *pooledConn {
	now := time.Now()
	return &pooledConn{
		tunnel:    tunnel,
		pool:      pool,
		createdAt: now,
		lastUsed:  now,
	}
}

// markUsed updates the last used timestamp.
func (pc *pooledConn) markUsed() {
	pc.useMu.Lock()
	pc.lastUsed = time.Now()
	pc.useMu.Unlock()
}

// getLastUsed returns the last used time safely.
func (pc *pooledConn) getLastUsed() time.Time {
	pc.useMu.Lock()
	defer pc.useMu.Unlock()
	return pc.lastUsed
}

// age returns how old the connection is.
func (pc *pooledConn) age() time.Duration {
	return time.Since(pc.createdAt)
}

// idleTime returns how long the connection has been idle.
func (pc *pooledConn) idleTime() time.Duration {
	return time.Since(pc.getLastUsed())
}

// PoolConn is the public handle returned to users from Acquire.
// It wraps a Tunnel and provides Release/Close methods.
type PoolConn struct {
	pc       *pooledConn
	released atomic.Bool
}

// newPoolConn creates a new PoolConn handle for a pooled connection.
func newPoolConn(pc *pooledConn) *PoolConn {
	return &PoolConn{pc: pc}
}

// Tunnel returns the underlying Tunnel for this connection.
// Returns nil if the connection has been released or closed.
func (c *PoolConn) Tunnel() *Tunnel {
	if c.released.Load() {
		return nil
	}
	return c.pc.tunnel
}

// Send sends data through the tunnel.
// This is a convenience method that delegates to the underlying Tunnel.
func (c *PoolConn) Send(data []byte) error {
	if c.released.Load() {
		return ErrConnReleased
	}
	return c.pc.tunnel.Send(data)
}

// Receive receives data from the tunnel.
// This is a convenience method that delegates to the underlying Tunnel.
func (c *PoolConn) Receive() ([]byte, error) {
	if c.released.Load() {
		return nil, ErrConnReleased
	}
	return c.pc.tunnel.Receive()
}

// SendPing sends a keepalive ping through the tunnel.
func (c *PoolConn) SendPing() error {
	if c.released.Load() {
		return ErrConnReleased
	}
	return c.pc.tunnel.SendPing()
}

// Release returns the connection to the pool for reuse.
// The connection should be in a healthy state when released.
// After calling Release, the PoolConn should not be used.
func (c *PoolConn) Release() error {
	if !c.released.CompareAndSwap(false, true) {
		return nil // Already released, idempotent
	}
	c.pc.markUsed()
	return c.pc.pool.release(c.pc)
}

// Close marks the connection as unhealthy and removes it from the pool.
// Use this instead of Release when the connection encountered an error
// or is in an unknown state.
func (c *PoolConn) Close() error {
	if !c.released.CompareAndSwap(false, true) {
		return nil // Already released/closed
	}
	c.pc.unhealthy.Store(true)
	return c.pc.pool.release(c.pc)
}

// Session returns the underlying Session for this connection.
func (c *PoolConn) Session() *Session {
	if c.released.Load() {
		return nil
	}
	return c.pc.tunnel.Session()
}

// LocalAddr returns the local network address.
func (c *PoolConn) LocalAddr() string {
	if c.released.Load() || c.pc.tunnel == nil {
		return ""
	}
	return c.pc.tunnel.LocalAddr().String()
}

// RemoteAddr returns the remote network address.
func (c *PoolConn) RemoteAddr() string {
	if c.released.Load() || c.pc.tunnel == nil {
		return ""
	}
	return c.pc.tunnel.RemoteAddr().String()
}

// CreatedAt returns when the connection was established.
func (c *PoolConn) CreatedAt() time.Time {
	return c.pc.createdAt
}

// ErrConnReleased is returned when trying to use a released connection.
var ErrConnReleased = &poolError{msg: "pool: connection already released"}

// poolError is a simple error type for pool-related errors.
type poolError struct {
	msg string
}

func (e *poolError) Error() string {
	return e.msg
}
