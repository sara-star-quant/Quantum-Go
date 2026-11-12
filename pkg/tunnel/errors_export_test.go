package tunnel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// These tests use only the public names and std errors.Is, as an outside caller must.

func TestExportedErrorsUnsupportedKEMSuite(t *testing.T) {
	cfg := tunnel.DefaultTransportConfig()
	cfg.AllowUnauthenticated = true
	cfg.KEMSuite = 0x7FFF
	if _, err := tunnel.DialWithConfig("tcp", "127.0.0.1:1", cfg); !errors.Is(err, tunnel.ErrUnsupportedKEMSuite) {
		t.Fatalf("err = %v, want tunnel.ErrUnsupportedKEMSuite", err)
	}
}

func TestExportedErrorsInvalidPSK(t *testing.T) {
	cfg := tunnel.DefaultTransportConfig()
	cfg.PSK, cfg.PSKIdentity = []byte("short"), []byte("id")
	if _, err := tunnel.DialWithConfig("tcp", "127.0.0.1:1", cfg); !errors.Is(err, tunnel.ErrInvalidPSK) {
		t.Fatalf("err = %v, want tunnel.ErrInvalidPSK", err)
	}
}

func TestExportedErrorsPoolClosed(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	cfg := tunnel.DefaultPoolConfig()
	cfg.TransportConfig.AllowUnauthenticated = true
	pool, err := tunnel.NewPool("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
	if _, err := pool.Acquire(context.Background()); !errors.Is(err, tunnel.ErrPoolClosed) {
		t.Fatalf("err = %v, want tunnel.ErrPoolClosed", err)
	}
}

func TestExportedErrorsServerKeyMismatch(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.StaticKeyPair = serverKP
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PinnedServerKey = otherKP.PublicKey() // pins the wrong key
	clientErr, _ := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if !errors.Is(clientErr, tunnel.ErrServerKeyMismatch) {
		t.Fatalf("err = %v, want tunnel.ErrServerKeyMismatch", clientErr)
	}
}

func TestExportedChkemErrors(t *testing.T) {
	if _, err := chkem.ParsePublicKey([]byte{1, 2, 3}); !errors.Is(err, chkem.ErrInvalidPublicKey) {
		t.Fatalf("ParsePublicKey: %v, want chkem.ErrInvalidPublicKey", err)
	}
	if _, err := chkem.ParseCiphertext([]byte{1, 2, 3}); !errors.Is(err, chkem.ErrInvalidCiphertext) {
		t.Fatalf("ParseCiphertext: %v, want chkem.ErrInvalidCiphertext", err)
	}
}
