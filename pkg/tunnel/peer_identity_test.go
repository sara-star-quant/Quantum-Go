package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

func pskBytes(base byte) []byte {
	k := make([]byte, constants.PSKSize)
	for i := range k {
		k[i] = base + byte(i)
	}
	return k
}

// acceptOne starts a stream listener with the given config, accepts one tunnel in the
// background and returns the listener plus a channel for the accepted tunnel.
func acceptOne(t *testing.T, cfg TransportConfig) (*Listener, chan *Tunnel) {
	t.Helper()
	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ln.SetConfig(cfg)
	accepted := make(chan *Tunnel, 1)
	go func() {
		for {
			tun, err := ln.Accept()
			if err != nil {
				continue // a refused handshake: keep listening
			}
			accepted <- tun
			return
		}
	}()
	return ln, accepted
}

func TestPeerIdentityStream(t *testing.T) {
	table := map[string][]byte{"alice": pskBytes(1), "bob": pskBytes(50)}
	serverCfg := DefaultTransportConfig()
	serverCfg.PSKLookup = func(id []byte) []byte { return table[string(id)] }
	serverCfg.RequirePSK = true

	for name, key := range table {
		ln, accepted := acceptOne(t, serverCfg)
		cfg := DefaultTransportConfig()
		cfg.PSK, cfg.PSKIdentity = key, []byte(name)
		client, err := DialWithConfig("tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		t.Cleanup(func() { _ = client.Close() })

		server := <-accepted
		t.Cleanup(func() { _ = server.Close() })
		peer := server.Peer()
		if string(peer.Identity) != name {
			t.Fatalf("server saw identity %q, want %q", peer.Identity, name)
		}
		if peer.RemoteAddr == nil || peer.Suite == 0 {
			t.Fatalf("peer info incomplete: %+v", peer)
		}
		if got := client.Peer().Identity; got != nil {
			t.Fatalf("a client learned an identity %q for the server; want nil", got)
		}
		// The accessor returns a copy: changing it must not change the session.
		peer.Identity[0] ^= 0xFF
		if string(server.Peer().Identity) != name {
			t.Fatal("Peer exposed the session's own identity bytes")
		}
	}
}

func TestPeerIdentityEmptyWithoutPSK(t *testing.T) {
	ln, accepted := acceptOne(t, DefaultTransportConfig())
	client, err := DialWithConfig("tcp", ln.Addr().String(), DefaultTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	if id := server.Peer().Identity; id != nil {
		t.Fatalf("an unauthenticated peer got identity %q", id)
	}
}

func TestPeerIdentityDatagram(t *testing.T) {
	key := pskBytes(7)
	lookup := func(id []byte) []byte {
		if string(id) == "alice" {
			return key
		}
		return nil
	}
	client, server, _, err := pubDgramPair(t,
		[]DatagramEndpointOption{WithPSKLookup(lookup), WithRequirePSK()},
		[]DatagramEndpointOption{WithPSK([]byte("alice"), key)})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(server.Peer().Identity); got != "alice" {
		t.Fatalf("datagram server saw identity %q, want alice", got)
	}
	if client.Peer().Identity != nil {
		t.Fatal("a datagram client learned an identity")
	}
}

// The identity is a claim until the peer's Finished verifies. A client that names a known
// identity with the wrong key must leave no identity behind on the server session.
func TestPeerIdentityNotRecordedWhenFinishedFails(t *testing.T) {
	cConn, sConn := net.Pipe()
	defer func() { _ = cConn.Close() }()
	defer func() { _ = sConn.Close() }()

	server, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	server.PSKLookup = func(id []byte) []byte {
		if string(id) == "alice" {
			return pskBytes(1)
		}
		return nil
	}
	client, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	client.PSK, client.PSKIdentity = pskBytes(99), []byte("alice") // right name, wrong key

	_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
	_ = sConn.SetDeadline(time.Now().Add(10 * time.Second))
	srvErr := make(chan error, 1)
	go func() { srvErr <- ResponderHandshake(server, sConn) }()
	_ = InitiatorHandshake(client, cConn)
	if err := <-srvErr; err == nil {
		t.Fatal("the responder accepted a client with the wrong key")
	}
	if id := server.PeerIdentity(); id != nil {
		t.Fatalf("a failed handshake recorded identity %q", id)
	}
}
