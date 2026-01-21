package integration

import (
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

func TestConnectionRateLimit(t *testing.T) {
	// Configure server with MaxConnectionsPerIP = 1
	config := tunnel.DefaultTransportConfig()
	config.RateLimit.MaxConnectionsPerIP = 1
	config.RateLimit.HandshakeRateLimit = 0 // No limit for this test

	// Start server
	ln, err := tunnel.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()
	ln.SetConfig(config)

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Don't exit on error (e.g. rate limit error), just continue
				continue
			}
			// Keep connection alive for a bit
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()

	addr := ln.Addr().String()

	// 1. First connection should succeed
	conn1, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("First connection failed: %v", err)
	}
	defer func() { _ = conn1.Close() }()

	// 2. Second connection should fail (limited)
	// Note: Since we're connecting from localhost, IP is the same.
	// The server Accept should close the connection immediately.
	// Dial might succeed at TCP level but handshake or read/write should fail or close.
	conn2, err := tunnel.Dial("tcp", addr)
	// Dial performs handshake. If server closes connection during handshake (or before), Dial returns error.
	if err == nil {
		// If Dial succeeded, check if it gets closed quickly
		_, errRead := conn2.Receive()
		if errRead == nil {
			t.Error("Second connection should have been closed/rejected")
		}
		_ = conn2.Close()
	} else {
		// Error is expected
		t.Logf("Second connection rejected as expected: %v", err)
	}

	// 3. Wait for first connection to close/release
	_ = conn1.Close()
	time.Sleep(200 * time.Millisecond)

	// 4. Third connection should now succeed
	conn3, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Errorf("Third connection failed after release: %v", err)
	}
	if conn3 != nil {
		_ = conn3.Close()
	}
}

func TestHandshakeRateLimit(t *testing.T) {
	// Configure server with HandshakeRateLimit = 1/sec, Burst = 1
	config := tunnel.DefaultTransportConfig()
	config.RateLimit.HandshakeRateLimit = 1.0
	config.RateLimit.HandshakeBurst = 1

	// Start server
	ln, err := tunnel.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()
	ln.SetConfig(config)

	// Accept in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go func() {
				// Keep alive briefly
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()

	addr := ln.Addr().String()

	// 1. First handshake (consumes burst)
	conn1, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("First handshake failed: %v", err)
	}
	if conn1 != nil {
		defer func() { _ = conn1.Close() }()
	}

	// 2. Second handshake immediately (should be rate limited)
	conn2, err := tunnel.Dial("tcp", addr)
	if err == nil {
		// If Dial succeeds, the connection might be closed immediately after.
		// Dial waits for handshake completion. If server rejects before handshake finishes, Dial should fail.
		t.Error("Second handshake should have failed rate limiting")
		_ = conn2.Close()
	} else {
		t.Logf("Second handshake rejected as expected: %v", err)
	}

	// 3. Wait for refill (1.1s)
	time.Sleep(1100 * time.Millisecond)

	// 4. Third handshake should succeed
	conn3, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Errorf("Third handshake failed after refill: %v", err)
	}
	if conn3 != nil {
		_ = conn3.Close()
	}
}
