package tunnel

// RateLimitObserver receives notifications when rate limits are hit.
type RateLimitObserver interface {
	// OnConnectionRateLimit is called when a connection is rejected due to per-IP limits.
	OnConnectionRateLimit(remoteIP string)
	// OnHandshakeRateLimit is called when a handshake is rejected due to global limits.
	OnHandshakeRateLimit(remoteIP string)
}
