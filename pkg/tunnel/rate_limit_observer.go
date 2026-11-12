package tunnel

// HandshakeLoadObserver is an optional extension of RateLimitObserver. When the observer set in
// TransportConfig.RateLimitObserver also implements it, the stream Listener reports the slots
// MaxPendingHandshakes limits (a connection mid-handshake, or finished and waiting for Accept)
// and when it sheds a connection because every slot is taken. The calls are events, so an
// observer keeps an exact gauge by adding on start and subtracting on finish, and the gauge
// never exceeds the limit. A decorator that wraps an observer must forward these methods too,
// or the load events are lost. The calls run on the accept path, so they must not block.
// Stream listeners only: the datagram transport does not report them.
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
