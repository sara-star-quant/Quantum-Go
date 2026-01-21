package tunnel

import (
	"errors"
	"time"
)

// PoolConfig holds configuration for the connection pool.
type PoolConfig struct {
	// MinConns is the minimum number of connections to maintain.
	// The pool will try to keep at least this many idle connections.
	// Default: 1
	MinConns int

	// MaxConns is the maximum number of connections allowed.
	// When 0, there is no limit (use with caution).
	// Default: 10
	MaxConns int

	// IdleTimeout closes idle connections after this duration.
	// 0 disables idle timeout (not recommended).
	// Default: 5 minutes
	IdleTimeout time.Duration

	// MaxLifetime is the maximum lifetime of a connection.
	// Connections older than this are closed even if in use.
	// 0 disables max lifetime.
	// Default: 30 minutes
	MaxLifetime time.Duration

	// HealthCheckInterval is the interval between health checks.
	// Health checks verify pooled connections are still valid.
	// 0 disables periodic health checks (on-acquire checks still run).
	// Default: 30 seconds
	HealthCheckInterval time.Duration

	// WaitTimeout is how long Acquire waits for a connection when pool is exhausted.
	// 0 means return immediately with ErrPoolExhausted.
	// Default: 30 seconds
	WaitTimeout time.Duration

	// DialTimeout is the timeout for establishing new connections.
	// Default: 10 seconds
	DialTimeout time.Duration

	// TransportConfig is the configuration for new tunnel connections.
	TransportConfig TransportConfig

	// Observer receives pool lifecycle and statistics events.
	// Optional - if nil, events are not reported.
	Observer PoolObserver
}

// DefaultPoolConfig returns a PoolConfig with sensible defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MinConns:            1,
		MaxConns:            10,
		IdleTimeout:         5 * time.Minute,
		MaxLifetime:         30 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		WaitTimeout:         30 * time.Second,
		DialTimeout:         10 * time.Second,
		TransportConfig:     DefaultTransportConfig(),
	}
}

// Validate checks the configuration for errors.
func (c *PoolConfig) Validate() error {
	if c.MinConns < 0 {
		return errors.New("pool: MinConns cannot be negative")
	}
	if c.MaxConns < 0 {
		return errors.New("pool: MaxConns cannot be negative")
	}
	if c.MaxConns > 0 && c.MinConns > c.MaxConns {
		return errors.New("pool: MinConns cannot exceed MaxConns")
	}
	if c.IdleTimeout < 0 {
		return errors.New("pool: IdleTimeout cannot be negative")
	}
	if c.MaxLifetime < 0 {
		return errors.New("pool: MaxLifetime cannot be negative")
	}
	if c.HealthCheckInterval < 0 {
		return errors.New("pool: HealthCheckInterval cannot be negative")
	}
	if c.WaitTimeout < 0 {
		return errors.New("pool: WaitTimeout cannot be negative")
	}
	if c.DialTimeout < 0 {
		return errors.New("pool: DialTimeout cannot be negative")
	}
	return nil
}

// applyDefaults fills in zero values with defaults.
func (c *PoolConfig) applyDefaults() {
	defaults := DefaultPoolConfig()

	if c.MinConns == 0 {
		c.MinConns = defaults.MinConns
	}
	if c.MaxConns == 0 {
		c.MaxConns = defaults.MaxConns
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaults.IdleTimeout
	}
	if c.MaxLifetime == 0 {
		c.MaxLifetime = defaults.MaxLifetime
	}
	if c.HealthCheckInterval == 0 {
		c.HealthCheckInterval = defaults.HealthCheckInterval
	}
	if c.WaitTimeout == 0 {
		c.WaitTimeout = defaults.WaitTimeout
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = defaults.DialTimeout
	}
}
