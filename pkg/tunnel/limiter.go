package tunnel

import (
	"sync"
	"time"
)

// IPRateLimiter tracks and limits the number of concurrent connections per IP.
type IPRateLimiter struct {
	mu          sync.Mutex
	connections map[string]int
	maxPerIP    int
}

// NewIPRateLimiter creates a new IPRateLimiter.
func NewIPRateLimiter(maxPerIP int) *IPRateLimiter {
	return &IPRateLimiter{
		connections: make(map[string]int),
		maxPerIP:    maxPerIP,
	}
}

// AllowConnection checks if the IP is allowed to establish a new connection.
// If allowed, it increments the connection count.
func (l *IPRateLimiter) AllowConnection(ip string) bool {
	if l.maxPerIP <= 0 {
		return true // No limit
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connections[ip] >= l.maxPerIP {
		return false
	}
	l.connections[ip]++
	return true
}

// ReleaseConnection decrements the connection count for the IP.
func (l *IPRateLimiter) ReleaseConnection(ip string) {
	if l.maxPerIP <= 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connections[ip] > 0 {
		l.connections[ip]--
		if l.connections[ip] == 0 {
			delete(l.connections, ip) // Cleanup to prevent map growth
		}
	}
}

// HandshakeLimiter limits the rate of handshakes using a token bucket algorithm.
type HandshakeLimiter struct {
	mu         sync.Mutex
	rate       float64 // Tokens per second
	burst      int     // Max bucket size
	tokens     float64 // Current tokens
	lastRefill time.Time
}

// NewHandshakeLimiter creates a new HandshakeLimiter.
func NewHandshakeLimiter(rate float64, burst int) *HandshakeLimiter {
	return &HandshakeLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// AllowHandshake checks if a handshake is allowed (consumes 1 token).
func (l *HandshakeLimiter) AllowHandshake() bool {
	if l.rate <= 0 {
		return true // No limit
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()

	// Refill tokens
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
	l.lastRefill = now

	// Consume token
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}
