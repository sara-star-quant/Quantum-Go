package tunnel

// HandshakeLoadObserver is an optional extension of RateLimitObserver. When the observer set in
// TransportConfig.RateLimitObserver also implements it, the stream Listener reports how many
// handshakes are in flight and when it sheds a connection because MaxPendingHandshakes is
// reached. The calls are events, not a running total, so an observer keeps an exact gauge by
// adding on start and subtracting on finish.
type HandshakeLoadObserver interface {
	// OnHandshakeStarted is called when a connection takes a handshake slot.
	OnHandshakeStarted()
	// OnHandshakeFinished is called when that handshake ends, whatever its outcome.
	OnHandshakeFinished()
	// OnHandshakeShed is called when a connection is closed on arrival because every slot is taken.
	OnHandshakeShed(remoteIP string)
}

// RateLimitObserver receives notifications when rate limits are hit.
type RateLimitObserver interface {
	// OnConnectionRateLimit is called when a connection is rejected due to per-IP limits.
	OnConnectionRateLimit(remoteIP string)
	// OnHandshakeRateLimit is called when a handshake is rejected due to global limits.
	OnHandshakeRateLimit(remoteIP string)
}
