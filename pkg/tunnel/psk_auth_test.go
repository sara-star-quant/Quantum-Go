package tunnel_test

import (
	"bytes"
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func pskOfByte(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestPSKMutualAuthSuccess(t *testing.T) {
	psk := pskOfByte(0xAB)
	id := []byte("edge-01")
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.PSK = psk
	serverCfg.PSKIdentity = id
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PSK = psk
	clientCfg.PSKIdentity = id

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if clientErr != nil {
		t.Fatalf("PSK mutual handshake failed: %v", clientErr)
	}
	if !accepted {
		t.Error("server did not accept a PSK-authenticated session")
	}
}

func TestPSKMismatchRejected(t *testing.T) {
	id := []byte("edge-01")
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.PSK = pskOfByte(0x01)
	serverCfg.PSKIdentity = id
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PSK = pskOfByte(0x02) // different key, same identity
	clientCfg.PSKIdentity = id

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if clientErr == nil {
		t.Fatal("mismatched PSK was accepted")
	}
	if accepted {
		t.Error("server established a session under a mismatched PSK")
	}
}

func TestPSKClientOnlyRejected(t *testing.T) {
	// Client folds a PSK; the server has none, so the Finished MACs diverge.
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PSK = pskOfByte(0xAB)
	clientCfg.PSKIdentity = []byte("edge-01")

	clientErr, accepted := runStaticAuthHandshake(t, tunnel.DefaultTransportConfig(), clientCfg)
	if clientErr == nil {
		t.Fatal("PSK client against a no-PSK server was accepted")
	}
	if accepted {
		t.Error("no-PSK server established a session for a PSK client")
	}
}

func TestPSKIdentityMismatchRejected(t *testing.T) {
	psk := pskOfByte(0xAB)
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.PSK = psk
	serverCfg.PSKIdentity = []byte("edge-01")
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PSK = psk
	clientCfg.PSKIdentity = []byte("edge-99") // same key, wrong identity

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if clientErr == nil {
		t.Fatal("PSK identity mismatch was accepted")
	}
	if accepted {
		t.Error("server folded a PSK despite an identity mismatch")
	}
}

func TestPSKCombinedWithStaticKey(t *testing.T) {
	// Static-key pinning and PSK together: both legs fold (defense in depth).
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	psk := pskOfByte(0xCD)
	id := []byte("edge-01")

	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.StaticKeyPair = serverKP
	serverCfg.PSK = psk
	serverCfg.PSKIdentity = id
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PinnedServerKey = serverKP.PublicKey()
	clientCfg.PSK = psk
	clientCfg.PSKIdentity = id

	clientErr, accepted := runStaticAuthHandshake(t, serverCfg, clientCfg)
	if clientErr != nil {
		t.Fatalf("static+PSK handshake failed: %v", clientErr)
	}
	if !accepted {
		t.Error("server did not accept a static+PSK session")
	}
}

func TestPSKInvalidConfigRejected(t *testing.T) {
	// A short key is a configuration error on the dialing side.
	clientCfg := tunnel.DefaultTransportConfig()
	clientCfg.PSK = make([]byte, 16) // wrong size
	clientCfg.PSKIdentity = []byte("edge-01")

	_, err := tunnel.DialWithConfig("tcp", "127.0.0.1:1", clientCfg)
	if !errors.Is(err, qerrors.ErrInvalidPSK) {
		t.Fatalf("short PSK: got %v, want ErrInvalidPSK", err)
	}

	// An empty identity with a key set is equally invalid.
	clientCfg.PSK = pskOfByte(0xAB)
	clientCfg.PSKIdentity = nil
	_, err = tunnel.DialWithConfig("tcp", "127.0.0.1:1", clientCfg)
	if !errors.Is(err, qerrors.ErrInvalidPSK) {
		t.Fatalf("empty identity: got %v, want ErrInvalidPSK", err)
	}
}
