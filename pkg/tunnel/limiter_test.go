package tunnel

import (
	"testing"
	"time"
)

func TestIPRateLimiter(t *testing.T) {
	// Allow 2 connections per IP
	limiter := NewIPRateLimiter(2)

	ip := "192.0.2.1"
	otherIP := "192.0.2.2"

	// 1. First connection allowed
	if !limiter.AllowConnection(ip) {
		t.Error("expected first connection to be allowed")
	}

	// 2. Second connection allowed
	if !limiter.AllowConnection(ip) {
		t.Error("expected second connection to be allowed")
	}

	// 3. Third connection blocked
	if limiter.AllowConnection(ip) {
		t.Error("expected third connection to be blocked")
	}

	// 4. Other IP allowed
	if !limiter.AllowConnection(otherIP) {
		t.Error("expected connection from other IP to be allowed")
	}

	// 5. Release one from first IP
	limiter.ReleaseConnection(ip)

	// 6. Should be allowed again
	if !limiter.AllowConnection(ip) {
		t.Error("expected connection to be allowed after release")
	}

	// 7. Test no limit
	noLimit := NewIPRateLimiter(0)
	for i := 0; i < 100; i++ {
		if !noLimit.AllowConnection(ip) {
			t.Error("expected connection to always be allowed with no limit")
		}
	}
}

func TestHandshakeLimiter(t *testing.T) {
	// Rate: 10/sec, Burst: 2
	limiter := NewHandshakeLimiter(10, 2)

	// 1. Consume burst
	if !limiter.AllowHandshake() {
		t.Error("expected 1st handshake (burst) to be allowed")
	}
	if !limiter.AllowHandshake() {
		t.Error("expected 2nd handshake (burst) to be allowed")
	}

	// 2. Should be blocked immediately
	if limiter.AllowHandshake() {
		t.Error("expected 3rd handshake (burst exceeded) to be blocked")
	}

	// 3. Wait for refill (1 token takes 0.1s)
	// We wait slightly more to be safe
	time.Sleep(110 * time.Millisecond)

	if !limiter.AllowHandshake() {
		t.Error("expected handshake to be allowed after token refill")
	}

	// 4. Test no limit
	noLimit := NewHandshakeLimiter(0, 0)
	for i := 0; i < 100; i++ {
		if !noLimit.AllowHandshake() {
			t.Error("expected handshake to always be allowed with no limit")
		}
	}
}
