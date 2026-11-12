package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

func poolTo(t *testing.T, addr string, edit func(*TransportConfig)) *Pool {
	t.Helper()
	pc := DefaultPoolConfig()
	pc.MinConns = 0
	pc.TransportConfig.HandshakeTimeout = 3 * time.Second
	edit(&pc.TransportConfig)
	p, err := NewPool("tcp", addr, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func acquire(p *Pool) (*PoolConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.Acquire(ctx)
}

// A pooled connection must authenticate like a dialed one. The pool once built its session
// without the transport config, so a pool never sent its PSK and never checked its pin.
func TestPoolSendsItsPSK(t *testing.T) {
	serverCfg := DefaultTransportConfig()
	serverCfg.PSK, serverCfg.PSKIdentity = pskBytes(5), []byte("pool-1")
	serverCfg.RequirePSK = true
	serverCfg.HandshakeTimeout = 3 * time.Second
	ln, _ := acceptOne(t, serverCfg)

	good := poolTo(t, ln.Addr().String(), func(c *TransportConfig) {
		c.PSK, c.PSKIdentity = pskBytes(5), []byte("pool-1")
	})
	if _, err := acquire(good); err != nil {
		t.Fatalf("a pool holding the right PSK was refused: %v", err)
	}
	none := poolTo(t, ln.Addr().String(), func(*TransportConfig) {})
	if _, err := acquire(none); err == nil {
		t.Fatal("a pool with no PSK reached a server that requires one")
	}
}

func TestPoolChecksItsPinnedServerKey(t *testing.T) {
	suite := chkem.DefaultSuite()
	server, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := DefaultTransportConfig()
	serverCfg.StaticKeyPair = server
	serverCfg.HandshakeTimeout = 3 * time.Second
	ln, _ := acceptOne(t, serverCfg)

	right := poolTo(t, ln.Addr().String(), func(c *TransportConfig) { c.PinnedServerKey = server.PublicKey() })
	if _, err := acquire(right); err != nil {
		t.Fatalf("a pool pinning the right key was refused: %v", err)
	}
	wrong := poolTo(t, ln.Addr().String(), func(c *TransportConfig) { c.PinnedServerKey = other.PublicKey() })
	if _, err := acquire(wrong); err == nil {
		t.Fatal("a pool pinning the wrong key connected, so the pin is not enforced")
	}
}

func TestPoolHonorsTheKEMSuiteAllowlist(t *testing.T) {
	serverCfg := DefaultTransportConfig()
	serverCfg.HandshakeTimeout = 3 * time.Second
	ln, accepted := acceptOne(t, serverCfg)
	p := poolTo(t, ln.Addr().String(), func(c *TransportConfig) { c.AllowedKEMSuites = []chkem.SuiteID{xw} })
	if _, err := acquire(p); err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	t.Cleanup(func() { _ = s.Close() })
	if got := s.Peer().Suite; got != xw {
		t.Fatalf("pooled connection negotiated %v, want x-wing from the allowlist", got)
	}
}
