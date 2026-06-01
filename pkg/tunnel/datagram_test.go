package tunnel

import (
	"net"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// mustEndpoint builds a DatagramEndpoint for tests, failing on the CSPRNG-only
// construction error so call sites stay terse.
func mustEndpoint(t *testing.T, conn net.PacketConn) *DatagramEndpoint {
	t.Helper()
	ep, err := NewDatagramEndpoint(conn)
	if err != nil {
		t.Fatalf("NewDatagramEndpoint: %v", err)
	}
	return ep
}

func TestConnRegistryAddAssignsUniqueNonZeroIndices(t *testing.T) {
	r := newConnRegistry(constants.DatagramMaxHalfOpenFloor)
	const n = 1000
	seen := make(map[uint32]*datagramSession, n)

	for i := 0; i < n; i++ {
		ds := &datagramSession{}
		idx, err := r.add(ds)
		if err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
		if idx == 0 {
			t.Fatal("index 0 is reserved and must never be assigned")
		}
		if ds.index != idx {
			t.Fatalf("session index %d != returned %d", ds.index, idx)
		}
		if _, dup := seen[idx]; dup {
			t.Fatalf("duplicate index %d assigned", idx)
		}
		seen[idx] = ds
	}
	if got := r.count(); got != n {
		t.Fatalf("count: got %d, want %d", got, n)
	}
}

func TestConnRegistryLookupAndRemove(t *testing.T) {
	r := newConnRegistry(constants.DatagramMaxHalfOpenFloor)
	ds := &datagramSession{}
	idx, err := r.add(ds)
	if err != nil {
		t.Fatal(err)
	}

	if got := r.lookup(idx); got != ds {
		t.Fatalf("lookup(%d): got %p, want %p", idx, got, ds)
	}
	if got := r.lookup(idx ^ 0xFFFFFFFF); got != nil {
		t.Fatal("lookup of an unregistered index must return nil")
	}

	r.remove(idx)
	if got := r.lookup(idx); got != nil {
		t.Fatal("lookup after remove must return nil")
	}
	r.remove(idx) // idempotent
	if r.count() != 0 {
		t.Fatalf("count after remove: got %d, want 0", r.count())
	}
}

func TestConnRegistryHalfOpenCap(t *testing.T) {
	const ceiling = 4
	r := newConnRegistry(ceiling)
	const src = "203.0.113.7:51820"

	// The ceiling is global, not per-source. tryAddHalfOpen is the direct primitive
	// (reserveSource dedups in production), so it bumps the global counter each call.
	for i := 0; i < ceiling; i++ {
		if !r.tryAddHalfOpen(src) {
			t.Fatalf("half-open %d should be admitted (ceiling %d)", i, ceiling)
		}
	}
	if r.tryAddHalfOpen(src) {
		t.Fatal("half-open over the global ceiling must be rejected")
	}
	// A different source does NOT get its own budget: the ceiling is global.
	if r.tryAddHalfOpen("198.51.100.9:51820") {
		t.Fatal("the half-open ceiling is global; a distinct source must not bypass it")
	}

	// Releasing one slot lets exactly one more in.
	r.releaseHalfOpen(src)
	if !r.tryAddHalfOpen(src) {
		t.Fatal("after release, one more half-open should be admitted")
	}
	if r.tryAddHalfOpen(src) {
		t.Fatal("still at the ceiling after a single release")
	}
}

func TestRouteDatagram(t *testing.T) {
	e := mustEndpoint(t, nil) // routeDatagram does not touch the conn
	src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}

	// Too-short datagram: the type peek rejects it.
	if err := e.routeDatagram(src, []byte{0x02}); err == nil {
		t.Fatal("short datagram should be rejected")
	}

	// DATA frame for an unknown connection index drops without error or new state.
	dataFrame := protocol.EncodeDatagramData(
		protocol.DatagramHeader{RecvIndex: 12345, Seq: 1}, []byte("ciphertext"))
	if err := e.routeDatagram(src, dataFrame); err != nil {
		t.Fatalf("data frame for unknown index should drop, got %v", err)
	}
	if e.registry.count() != 0 {
		t.Fatal("routing must not create session state for an unknown index")
	}

	// A single-fragment HANDSHAKE frame routes to the reassembler.
	hsFrame, err := protocol.EncodeDatagramHandshake(protocol.DatagramHandshakeHeader{
		SenderIndex: 7,
		MsgType:     protocol.MessageTypeClientHello,
		FragLength:  5,
		TotalLength: 5,
	}, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.routeDatagram(src, hsFrame); err != nil {
		t.Fatalf("handshake frame routing: %v", err)
	}
}

func TestConnRegistryReleaseHalfOpenNeverNegative(t *testing.T) {
	const ceiling = 4
	r := newConnRegistry(ceiling)
	const src = "192.0.2.1:1"
	// Release with no prior add must not underflow halfOpenTotal (the per-source map
	// no-ops at 0), and the registry must then still accept the full ceiling.
	r.releaseHalfOpen(src)
	for i := 0; i < ceiling; i++ {
		if !r.tryAddHalfOpen(src) {
			t.Fatalf("admit %d after spurious release", i)
		}
	}
}
