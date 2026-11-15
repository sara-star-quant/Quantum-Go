package tunnel

import (
	"bytes"
	"testing"
)

func TestPSKFingerprint(t *testing.T) {
	a, b := PSKFingerprint(pskBytes(1)), PSKFingerprint(pskBytes(2))
	if len(a) != 8 || len(b) != 8 {
		t.Fatalf("fingerprints are %d and %d bytes, want 8", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two different keys share a fingerprint")
	}
	if !bytes.Equal(a, PSKFingerprint(pskBytes(1))) {
		t.Fatal("the fingerprint of one key changed between calls")
	}
	if bytes.Equal(a, pskBytes(1)[:8]) {
		t.Fatal("the fingerprint is a prefix of the key")
	}
}

// A server session carries the fingerprint of the key the peer proved, so a server can find
// sessions whose key was removed or replaced. A client carries none.
func TestPeerKeyIDStream(t *testing.T) {
	table := map[string][]byte{"alice": pskBytes(1), "bob": pskBytes(50)}
	serverCfg := DefaultTransportConfig()
	serverCfg.PSKLookup = func(id []byte) []byte { return table[string(id)] }
	serverCfg.RequirePSK = true
	seen := map[string][]byte{}
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
		got := server.Peer().KeyID
		if !bytes.Equal(got, PSKFingerprint(key)) {
			t.Fatalf("%s: KeyID %x, want %x", name, got, PSKFingerprint(key))
		}
		if client.Peer().KeyID != nil {
			t.Fatal("a client learned a key ID for the server")
		}
		seen[name] = got
	}
	if bytes.Equal(seen["alice"], seen["bob"]) {
		t.Fatal("two identities with different keys have the same KeyID")
	}
}

func TestPeerKeyIDDatagram(t *testing.T) {
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
	if !bytes.Equal(server.Peer().KeyID, PSKFingerprint(key)) {
		t.Fatal("the datagram server's KeyID is not the fingerprint of the proved key")
	}
	if client.Peer().KeyID != nil {
		t.Fatal("a datagram client learned a key ID")
	}
}
