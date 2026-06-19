package tunnel_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// runStaticAuthHandshake drives one stream handshake with the given server and
// client configs and returns the client-side Dial error (nil on success). It
// also reports whether the server accepted a session.
func runStaticAuthHandshake(t *testing.T, serverCfg, clientCfg tunnel.TransportConfig) (clientErr error, serverAccepted bool) {
	t.Helper()

	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	listener.SetConfig(serverCfg)
	defer func() { _ = listener.Close() }()
	addr := listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err == nil && conn != nil {
			serverAccepted = true
			_ = conn.Close()
		}
	}()

	time.Sleep(50 * time.Millisecond)
	client, err := tunnel.DialWithConfig("tcp", addr, clientCfg)
	if err != nil {
		wg.Wait()
		return err, serverAccepted
	}
	_ = client.Close()
	wg.Wait()
	return nil, serverAccepted
}

func TestStaticAuthSuccess(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.StaticKeyPair = serverKP
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PinnedServerKey = serverKP.PublicKey()

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if clientErr != nil {
		t.Fatalf("authenticated handshake failed: %v", clientErr)
	}
	if !accepted {
		t.Error("server did not accept an authenticated session")
	}
}

func TestStaticAuthWrongPinRejected(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	// A different key the client wrongly pins (could be an impostor's key).
	otherKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.StaticKeyPair = serverKP
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PinnedServerKey = otherKP.PublicKey()

	clientErr, _ := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if !errors.Is(clientErr, qerrors.ErrServerKeyMismatch) {
		t.Fatalf("wrong pin: got %v, want ErrServerKeyMismatch", clientErr)
	}
}

func TestStaticAuthServerNotConfiguredRejected(t *testing.T) {
	// Client pins a key, but the server has no static identity (or a MitM stripped
	// the static ciphertext). The client must fail closed.
	pinKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	serverCfg := tunnel.DefaultTransportConfig() // no StaticKeyPair
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PinnedServerKey = pinKP.PublicKey()

	clientErr, _ := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if !errors.Is(clientErr, qerrors.ErrServerKeyMismatch) {
		t.Fatalf("server-not-configured: got %v, want ErrServerKeyMismatch", clientErr)
	}
}

func TestStaticAuthUnauthenticatedRegression(t *testing.T) {
	// Neither side configures static keys: the handshake must still succeed
	// (opt-in, no behavior change for existing callers).
	clientErr, accepted := runStaticAuthHandshake(t, tunnel.DefaultTransportConfig(), tunnel.DefaultTransportConfig())
	if clientErr != nil {
		t.Fatalf("unauthenticated handshake failed: %v", clientErr)
	}
	if !accepted {
		t.Error("server did not accept an unauthenticated session")
	}
}

func TestStaticAuthServerServesUnpinnedClient(t *testing.T) {
	// A server with a static identity still serves clients that do not pin it
	// (unauthenticated). The static leg is opt-in from the client side.
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.StaticKeyPair = serverKP

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, tunnel.DefaultTransportConfig())
	if clientErr != nil {
		t.Fatalf("unpinned client against static-key server failed: %v", clientErr)
	}
	if !accepted {
		t.Error("server did not accept an unpinned client")
	}
}
