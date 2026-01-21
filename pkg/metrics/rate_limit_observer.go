package metrics

import "github.com/pzverkov/quantum-go/pkg/tunnel"

// RateLimitObserver implements tunnel.RateLimitObserver and records rate limit events.
type RateLimitObserver struct {
	collector *Collector
	logger    *Logger
}

var _ tunnel.RateLimitObserver = (*RateLimitObserver)(nil)

// NewRateLimitObserver creates a rate limit observer that records metrics and logs events.
func NewRateLimitObserver(collector *Collector, logger *Logger) *RateLimitObserver {
	if collector == nil {
		collector = Global()
	}
	if logger == nil {
		logger = GetLogger()
	}

	return &RateLimitObserver{
		collector: collector,
		logger:    logger.Named("rate_limit"),
	}
}

// OnConnectionRateLimit records a connection rate limit event.
func (o *RateLimitObserver) OnConnectionRateLimit(remoteIP string) {
	o.collector.RecordConnectionRateLimit()
	if remoteIP != "" {
		o.logger.Warn("connection rate limit exceeded", Fields{"remote_ip": remoteIP})
		return
	}
	o.logger.Warn("connection rate limit exceeded")
}

// OnHandshakeRateLimit records a handshake rate limit event.
func (o *RateLimitObserver) OnHandshakeRateLimit(remoteIP string) {
	o.collector.RecordHandshakeRateLimit()
	if remoteIP != "" {
		o.logger.Warn("handshake rate limit exceeded", Fields{"remote_ip": remoteIP})
		return
	}
	o.logger.Warn("handshake rate limit exceeded")
}
