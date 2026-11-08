package main

import (
	"testing"
	"time"
)

func TestMeasureTunnelAndTCPDeliverEverything(t *testing.T) {
	const total = 4 << 20
	chunk := make([]byte, 8<<10)

	tun, err := measureTunnel(total, 30*time.Second, chunk)
	if err != nil {
		t.Fatalf("measureTunnel: %v", err)
	}
	if tun.received != tun.sent || tun.sent < total {
		t.Fatalf("tunnel sent %d received %d, want at least %d delivered intact", tun.sent, tun.received, total)
	}
	if tun.cipher != "AES-256-GCM" {
		t.Fatalf("negotiated cipher = %q, want AES-256-GCM", tun.cipher)
	}
	if tun.recvDur <= 0 || tun.recvMBps() <= 0 {
		t.Fatalf("no receive timing: %+v", tun)
	}

	plain, err := measureTCP(total, 30*time.Second, chunk)
	if err != nil {
		t.Fatalf("measureTCP: %v", err)
	}
	if plain.received != plain.sent || plain.sent < total {
		t.Fatalf("tcp sent %d received %d, want at least %d delivered intact", plain.sent, plain.received, total)
	}
}
