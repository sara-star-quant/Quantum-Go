# Configuration

Quantum-Go uses the `TransportConfig` struct to tune performance, security, and operational behavior.

## TransportConfig

```go
type TransportConfig struct {
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    RateLimit    RateLimitConfig
}
```

### Basic Settings

```go
config := tunnel.DefaultTransportConfig()

// Timeouts for underlying network operations
config.ReadTimeout = 30 * time.Second
config.WriteTimeout = 30 * time.Second
```

### Rate Limiting (v0.0.6+)

Protect your server from DoS attacks and resource exhaustion:

```go
// Max concurrent connections allowed per IP
config.RateLimit.MaxConnectionsPerIP = 100

// Global handshake rate limit (tokens per second)
config.RateLimit.HandshakeRateLimit = 5.0 

// Burst allowance for handshakes
config.RateLimit.HandshakeBurst = 10
```

## Session Resumption

Quantum-Go automatically supports secure session resumption using encrypted tickets.

- **Mechanism**: RFC 5077-style tickets.
- **Trigger**: Following a successful full handshake, the server issues a ticket.
- **Benefit**: Abbreviated handshake skips the heavy CH-KEM exchange while maintaining forward secrecy.
- **Client Side**: Handled automatically if the client reuses the `Session` context or ticket cache (future feature).
