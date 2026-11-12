package tunnel_test

import (
	"errors"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// A peer that closes gracefully sends close_notify. The other side's Close must still release
// the socket, or a per-address connection slot leaks and the address is eventually locked out.
func TestCloseAfterPeerCloseReleasesTheConnection(t *testing.T) {
	ln, err := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := tunnel.DefaultTransportConfig()
	cfg.RateLimit = tunnel.RateLimitConfig{MaxConnectionsPerIP: 1}
	ln.SetConfig(cfg)
	accepted := make(chan *tunnel.Tunnel, 4)
	go func() {
		for {
			s, err := ln.Accept()
			if err != nil {
				continue
			}
			accepted <- s
		}
	}()

	client, err := tunnel.DialInsecure("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = client.Close() // sends close_notify

	server.SetReadTimeout(5 * time.Second)
	if _, err := server.Receive(); !errors.Is(err, tunnel.ErrTunnelClosed) {
		t.Fatalf("Receive after the peer closed returned %v, want ErrTunnelClosed", err)
	}
	_ = server.Close() // must release the socket and the per-address slot

	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		again, err := tunnel.DialInsecure("tcp", ln.Addr().String())
		if err == nil {
			_ = again.Close()
			return
		}
	}
	t.Fatal("the address stayed locked out after the server closed a tunnel the peer had closed")
}
