package tunnel

import (
	"net"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func udp(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func TestAddrEqual(t *testing.T) {
	a := udp("203.0.113.1", 5000)
	if !addrEqual(a, udp("203.0.113.1", 5000)) {
		t.Fatal("identical UDP addresses must compare equal")
	}
	if addrEqual(a, udp("203.0.113.1", 5001)) {
		t.Fatal("different ports must compare unequal")
	}
	if addrEqual(a, udp("203.0.113.2", 5000)) {
		t.Fatal("different IPs must compare unequal")
	}
	if addrEqual(nil, a) || addrEqual(a, nil) {
		t.Fatal("nil must not equal a real address")
	}
	if !addrEqual(nil, nil) {
		t.Fatal("nil must equal nil")
	}
	// Non-UDP addrs fall back to String().
	if !addrEqual(memAddr{name: "x"}, memAddr{name: "x"}) {
		t.Fatal("equal memAddrs must compare equal")
	}
}

// dataFrameFrom seals a DATA frame from `from` targeting connection index idx at
// sequence seq, returning the wire bytes the receive loop would see.
func dataFrameFrom(t *testing.T, from *Session, idx uint32, seq uint64, payload []byte) []byte {
	t.Helper()
	header := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
		Type:      protocol.DatagramFrameData,
		Epoch:     from.datagramSendEpoch(),
		RecvIndex: idx,
		Seq:       seq,
	})
	ct, err := from.DatagramSeal(header, seq, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return append(header, ct...)
}

// registerEstablished registers an established responder-side session in e's
// registry whose peer is the initiator session, anchored at addr.
func registerEstablished(t *testing.T, e *DatagramEndpoint, addr net.Addr) (idx uint32, peer *Session, ds *datagramSession) {
	t.Helper()
	initiator, responder := datagramSessionPair(t)
	ds = &datagramSession{
		session: responder,
		recvCh:  make(chan []byte, 8),
		closed:  make(chan struct{}),
	}
	ds.setPeerAddr(addr)
	idx, err := e.registry.add(ds)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return idx, initiator, ds
}

func TestRoamingFollowsAuthenticatedFrame(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	start := udp("198.51.100.1", 4000)
	idx, peer, ds := registerEstablished(t, e, start)

	// A fresh authenticated frame from a new source moves the session there.
	moved := udp("203.0.113.9", 7000)
	if err := e.routeDatagram(moved, dataFrameFrom(t, peer, idx, 1, []byte("one"))); err != nil {
		t.Fatalf("route: %v", err)
	}
	if got := ds.currentPeerAddr(); !addrEqual(got, moved) {
		t.Fatalf("peerAddr = %v after authenticated roam, want %v", got, moved)
	}
	// The payload was still delivered.
	select {
	case <-ds.recvCh:
	default:
		t.Fatal("roamed frame was not delivered to the application")
	}
}

func TestRoamingIgnoresReplayedFrame(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	start := udp("198.51.100.1", 4000)
	idx, peer, ds := registerEstablished(t, e, start)

	frame := dataFrameFrom(t, peer, idx, 1, []byte("one"))
	if err := e.routeDatagram(start, frame); err != nil {
		t.Fatalf("route: %v", err)
	}
	if got := ds.currentPeerAddr(); !addrEqual(got, start) {
		t.Fatalf("peerAddr = %v after first frame, want %v", got, start)
	}

	// Replaying the exact same (already-seen) frame from an attacker address must
	// fail the replay window and therefore NOT move the session.
	attacker := udp("203.0.113.66", 9999)
	if err := e.routeDatagram(attacker, frame); err != nil {
		t.Fatalf("route replay: %v", err)
	}
	if got := ds.currentPeerAddr(); !addrEqual(got, start) {
		t.Fatalf("replayed frame moved peerAddr to %v; must stay %v", got, start)
	}
}

func TestRoamingIgnoresForgedFrame(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	start := udp("198.51.100.1", 4000)
	idx, peer, ds := registerEstablished(t, e, start)

	// A frame whose ciphertext is corrupt fails AEAD Open, so the session must not
	// move and the replay window must not advance.
	frame := dataFrameFrom(t, peer, idx, 5, []byte("real"))
	frame[len(frame)-1] ^= 0xff // tamper the tag
	attacker := udp("203.0.113.66", 9999)
	if err := e.routeDatagram(attacker, frame); err != nil {
		t.Fatalf("route forged: %v", err)
	}
	if got := ds.currentPeerAddr(); !addrEqual(got, start) {
		t.Fatalf("forged frame moved peerAddr to %v; must stay %v", got, start)
	}

	// A subsequent genuine frame at seq 5 from the real peer still authenticates
	// (the forged attempt did not consume the sequence) and roams.
	good := udp("203.0.113.9", 7000)
	if err := e.routeDatagram(good, dataFrameFrom(t, peer, idx, 5, []byte("real"))); err != nil {
		t.Fatalf("route good: %v", err)
	}
	if got := ds.currentPeerAddr(); !addrEqual(got, good) {
		t.Fatalf("peerAddr = %v after genuine roam, want %v", got, good)
	}
}

func TestRoamingNoChangeSameSource(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	start := udp("198.51.100.1", 4000)
	idx, peer, ds := registerEstablished(t, e, start)

	before := ds.currentPeerAddr()
	for seq := uint64(1); seq <= 3; seq++ {
		if err := e.routeDatagram(start, dataFrameFrom(t, peer, idx, seq, []byte("x"))); err != nil {
			t.Fatalf("route: %v", err)
		}
	}
	// Same-source traffic must not churn the stored pointer's identity.
	if got := ds.currentPeerAddr(); !addrEqual(got, before) {
		t.Fatalf("same-source traffic changed peerAddr to %v, want %v", got, before)
	}
}
