package metrics

import (
	"strings"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// maskIP partially redacts an IP address, keeping the first and last few
// characters visible (e.g. "192...168" or "2001:...::1"). For addresses
// shorter than 6 characters the full value is masked as "***".
func maskIP(ip string) string {
	// Strip port if present (host:port or [host]:port)
	host := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// Could be IPv6 or host:port -- only strip if it looks like a port suffix
		if bracket := strings.LastIndex(ip, "]"); bracket != -1 {
			// [IPv6]:port
			host = ip[1:bracket]
		} else if strings.Count(ip, ":") == 1 {
			// IPv4:port
			host = ip[:idx]
		}
	}

	if len(host) < 6 {
		return "***"
	}
	return host[:3] + "***" + host[len(host)-3:]
}

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
		o.logger.Warn("connection rate limit exceeded", Fields{"remote_ip": maskIP(remoteIP)})
		return
	}
	o.logger.Warn("connection rate limit exceeded")
}

// OnHandshakeRateLimit records a handshake rate limit event.
func (o *RateLimitObserver) OnHandshakeRateLimit(remoteIP string) {
	o.collector.RecordHandshakeRateLimit()
	if remoteIP != "" {
		o.logger.Warn("handshake rate limit exceeded", Fields{"remote_ip": maskIP(remoteIP)})
		return
	}
	o.logger.Warn("handshake rate limit exceeded")
}
