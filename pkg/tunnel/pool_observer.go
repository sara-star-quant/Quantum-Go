package tunnel

import "time"

// PoolObserver provides hooks for pool lifecycle and statistics events.
// Implementations should be lightweight; callbacks may run on hot paths.
type PoolObserver interface {
	// OnAcquire is called when a connection is acquired from the pool.
	OnAcquire(waitDuration time.Duration, reused bool)

	// OnAcquireTimeout is called when Acquire times out waiting for a connection.
	OnAcquireTimeout()

	// OnRelease is called when a connection is released back to the pool.
	OnRelease()

	// OnConnectionCreated is called when a new connection is established.
	OnConnectionCreated(dialDuration time.Duration)

	// OnConnectionClosed is called when a connection is removed from the pool.
	OnConnectionClosed(reason string)

	// OnHealthCheck is called when a health check is performed.
	OnHealthCheck(healthy bool)

	// OnPoolStats is called periodically with current pool statistics.
	// This can be used for monitoring and alerting.
	OnPoolStats(stats PoolStatsSnapshot)
}

// NoOpPoolObserver is a no-op implementation of PoolObserver.
// Use this when metrics are not needed.
type NoOpPoolObserver struct{}

var _ PoolObserver = (*NoOpPoolObserver)(nil)

// OnAcquire implements PoolObserver.
func (NoOpPoolObserver) OnAcquire(time.Duration, bool) {}

// OnAcquireTimeout implements PoolObserver.
func (NoOpPoolObserver) OnAcquireTimeout() {}

// OnRelease implements PoolObserver.
func (NoOpPoolObserver) OnRelease() {}

// OnConnectionCreated implements PoolObserver.
func (NoOpPoolObserver) OnConnectionCreated(time.Duration) {}

// OnConnectionClosed implements PoolObserver.
func (NoOpPoolObserver) OnConnectionClosed(string) {}

// OnHealthCheck implements PoolObserver.
func (NoOpPoolObserver) OnHealthCheck(bool) {}

// OnPoolStats implements PoolObserver.
func (NoOpPoolObserver) OnPoolStats(PoolStatsSnapshot) {}
