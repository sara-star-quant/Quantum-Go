package tunnel

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// pubDgramPair dials a datagram connection over real loopback sockets using only the
// public API. It returns the client conn, the server conn (nil if the dial failed)
// and the dial error.
func pubDgramPair(t *testing.T, serverOpts, clientOpts []DatagramEndpointOption) (client, server *DatagramConn, serverAddr net.Addr, err error) {
	t.Helper()
	start := func(opts []DatagramEndpointOption) (*DatagramEndpoint, net.PacketConn) {
		sock, lerr := net.ListenPacket("udp", "127.0.0.1:0")
		if lerr != nil {
			t.Fatalf("listen: %v", lerr)
		}
		ep, nerr := NewDatagramEndpoint(sock, append([]DatagramEndpointOption{WithAllowUnauthenticated()}, opts...)...)
		if nerr != nil {
			t.Fatalf("NewDatagramEndpoint: %v", nerr)
		}
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 50 * time.Millisecond
		ep.maxRetries = 40
		go ep.Serve()
		t.Cleanup(func() { _ = ep.Close() })
		return ep, sock
	}
	srvEP, srvSock := start(serverOpts)
	cliEP, _ := start(clientOpts)

	type accepted struct {
		c *DatagramConn
	}
	acc := make(chan accepted, 1)
	go func() {
		c, aerr := srvEP.Accept()
		if aerr != nil {
			acc <- accepted{}
			return
		}
		acc <- accepted{c}
	}()

	client, err = DialDatagram(cliEP, srvSock.LocalAddr())
	if err != nil {
		return nil, nil, srvSock.LocalAddr(), err
	}
	select {
	case a := <-acc:
		server = a.c
	case <-time.After(30 * time.Second):
		t.Fatal("responder did not surface a session")
	}
	return client, server, srvSock.LocalAddr(), nil
}

func echoOnce(t *testing.T, from, to *DatagramConn, msg string) {
	t.Helper()
	if err := from.Send([]byte(msg)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := make(chan []byte, 1)
	go func() {
		p, _ := to.Recv()
		got <- p
	}()
	select {
	case p := <-got:
		if string(p) != msg {
			t.Fatalf("got %q, want %q", p, msg)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("datagram not delivered")
	}
}

func TestPublicOptionsPinnedServerKey(t *testing.T) {
	kp, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	other, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	t.Run("matching pin completes", func(t *testing.T) {
		client, server, addr, err := pubDgramPair(t,
			[]DatagramEndpointOption{WithStaticIdentity(kp), WithRequireStaticAuth()},
			[]DatagramEndpointOption{WithPinnedServerKey(kp.PublicKey())})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		echoOnce(t, client, server, "pinned")
		echoOnce(t, server, client, "pinned back")
		if client.RemoteAddr().String() != addr.String() {
			t.Fatalf("client RemoteAddr = %v, want %v", client.RemoteAddr(), addr)
		}
		if server.RemoteAddr() == nil || server.RemoteAddr().String() == addr.String() {
			t.Fatalf("server RemoteAddr = %v, want the client's address", server.RemoteAddr())
		}
	})

	t.Run("wrong pin is rejected", func(t *testing.T) {
		_, _, _, err := pubDgramPair(t,
			[]DatagramEndpointOption{WithStaticIdentity(kp)},
			[]DatagramEndpointOption{WithPinnedServerKey(other.PublicKey())})
		if !errors.Is(err, qerrors.ErrServerKeyMismatch) {
			t.Fatalf("got %v, want ErrServerKeyMismatch", err)
		}
	})

	t.Run("pin against an unauthenticated server is rejected", func(t *testing.T) {
		_, _, _, err := pubDgramPair(t, nil,
			[]DatagramEndpointOption{WithPinnedServerKey(kp.PublicKey())})
		if !errors.Is(err, qerrors.ErrServerKeyMismatch) {
			t.Fatalf("got %v, want ErrServerKeyMismatch", err)
		}
	})
}

func TestPublicOptionsPSKLookup(t *testing.T) {
	good := make([]byte, constants.PSKSize)
	for i := range good {
		good[i] = byte(i + 1)
	}
	var lookups atomic.Int32
	lookup := func(identity []byte) []byte {
		lookups.Add(1)
		if string(identity) == "alice" {
			return good
		}
		return nil
	}
	serverOpts := []DatagramEndpointOption{WithPSKLookup(lookup), WithRequirePSK()}

	t.Run("known identity completes", func(t *testing.T) {
		client, server, _, err := pubDgramPair(t, serverOpts,
			[]DatagramEndpointOption{WithPSK([]byte("alice"), good)})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		echoOnce(t, client, server, "psk")
		if lookups.Load() == 0 {
			t.Fatal("WithPSKLookup callback was never consulted")
		}
	})

	t.Run("unknown identity fails", func(t *testing.T) {
		_, _, _, err := pubDgramPair(t, serverOpts,
			[]DatagramEndpointOption{WithPSK([]byte("mallory"), good)})
		if err == nil {
			t.Fatal("dial with an unknown PSK identity succeeded")
		}
	})
}

func TestPublicOptionsDatagramOffload(t *testing.T) {
	// Offload is a no-op off Linux and on kernels without UDP_GRO, so this checks the
	// option never breaks the data path on any platform.
	opt := []DatagramEndpointOption{WithDatagramOffload()}
	client, server, _, err := pubDgramPair(t, opt, opt)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	echoOnce(t, client, server, "offload")
	echoOnce(t, server, client, "offload back")
}
