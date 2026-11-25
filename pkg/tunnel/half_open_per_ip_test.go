package tunnel

import (
	"fmt"
	"testing"
)

func newCappedRegistry(perIP int) *connRegistry {
	r := newConnRegistry(1000)
	r.maxPerIP = perIP
	return r
}

func reserve(r *connRegistry, source string) bool {
	_, ok := r.reserveSource(source, func() *datagramSession { return &datagramSession{} })
	return ok
}

// The cookie proves that a source can receive at its address. It does not limit how many
// handshakes one real address may hold, so one host can take a slot per source port until the
// global ceiling is full. With a per-address cap set, one address holds at most that many.
func TestPerAddressHalfOpenCap(t *testing.T) {
	r := newCappedRegistry(3)
	for port := 4000; port < 4003; port++ {
		if !reserve(r, fmt.Sprintf("198.51.100.7:%d", port)) {
			t.Fatalf("port %d: a handshake below the cap was refused", port)
		}
	}
	if reserve(r, "198.51.100.7:4003") {
		t.Fatal("a fourth handshake from one address was admitted past the cap of three")
	}
	if !reserve(r, "198.51.100.8:4000") {
		t.Fatal("another address was refused because of the first one")
	}
	if got := r.halfOpenLoad(); got != 4 {
		t.Fatalf("half-open load = %d, want 4", got)
	}
}

func TestPerAddressCapFreesOnRelease(t *testing.T) {
	r := newCappedRegistry(1)
	const src = "198.51.100.7:4000"
	ds, ok := r.reserveSource(src, func() *datagramSession { return &datagramSession{} })
	if !ok {
		t.Fatal("first handshake refused")
	}
	if reserve(r, "198.51.100.7:4001") {
		t.Fatal("a second handshake from the address was admitted at a cap of one")
	}
	r.releaseSource(src, ds)
	if !reserve(r, "198.51.100.7:4001") {
		t.Fatal("the slot was not freed for the address after the release")
	}
}

// An IPv6 /64 is one address for this purpose: a host can pick any address inside its prefix.
func TestPerAddressCapGroupsAnIPv6Prefix(t *testing.T) {
	r := newCappedRegistry(2)
	if !reserve(r, "[2001:db8:1:2::1]:4000") || !reserve(r, "[2001:db8:1:2::ffff]:4000") {
		t.Fatal("handshakes below the cap were refused")
	}
	if reserve(r, "[2001:db8:1:2:abcd::1]:4000") {
		t.Fatal("a third address in the same /64 was admitted past the cap")
	}
	if !reserve(r, "[2001:db8:1:3::1]:4000") {
		t.Fatal("a different /64 was refused")
	}
}

// Zero means no cap, the default: behavior is unchanged.
func TestPerAddressCapOffByDefault(t *testing.T) {
	r := newCappedRegistry(0)
	for port := 4000; port < 4100; port++ {
		if !reserve(r, fmt.Sprintf("198.51.100.7:%d", port)) {
			t.Fatalf("port %d refused with no cap set", port)
		}
	}
}

// The option reaches the endpoint's registry: three hellos from one address on different ports
// leave two handshakes half open at a cap of two.
func TestWithMaxHalfOpenPerIPLimitsAnEndpoint(t *testing.T) {
	ep, err := NewDatagramEndpoint(&captureConn{}, WithAllowUnauthenticated(), WithMaxHalfOpenPerIP(2))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	for i := range 3 {
		src := udp("198.51.100.7", 4000+i)
		if err := ep.routeDatagram(src, clientHelloFrame(t, uint32(i+1), 0, 200, 200, nil)); err != nil {
			t.Fatalf("route %d: %v", i, err)
		}
	}
	if got := ep.registry.halfOpenLoad(); got != 2 {
		t.Fatalf("half-open load = %d, want 2 at a per-address cap of 2", got)
	}
}
