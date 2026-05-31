package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// dgramPair establishes a connected DatagramConn pair over an in-memory transport
// with the given fault rates. The handshake runs over the faulty pipe; data-plane
// assertions in the caller decide whether to use a clean or faulty pipe.
func dgramPair(t *testing.T, seed uint64, drop, dup, reorder float64) (client, server *DatagramConn, epA, epB *DatagramEndpoint) {
	t.Helper()
	connA, connB := memPipe(seed, drop, dup, reorder)
	epA = mustEndpoint(t, connA)
	epB = mustEndpoint(t, connB)
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 2 * time.Millisecond
		ep.rtoMax = 20 * time.Millisecond
	}
	go epA.Serve()
	go epB.Serve()

	type res struct {
		c   *DatagramConn
		err error
	}
	dialCh := make(chan res, 1)
	go func() {
		c, err := DialDatagram(epA, connB.addr)
		dialCh <- res{c, err}
	}()

	acceptCh := make(chan *DatagramConn, 1)
	go func() {
		c, err := epB.Accept()
		if err == nil {
			acceptCh <- c
		}
	}()

	select {
	case c := <-acceptCh:
		server = c
	case <-time.After(5 * time.Second):
		t.Fatal("responder did not accept a session")
	}
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("dial: %v", r.err)
		}
		client = r.c
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not complete")
	}
	return client, server, epA, epB
}

func TestDatagramConnRoundTrip(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 1, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	cases := []struct {
		name     string
		from, to *DatagramConn
		payload  string
	}{
		{"client->server", client, server, "hello from client"},
		{"server->client", server, client, "hello from server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.from.Send([]byte(tc.payload)); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := recvWithTimeout(t, tc.to)
			if !bytes.Equal(got, []byte(tc.payload)) {
				t.Fatalf("got %q want %q", got, tc.payload)
			}
		})
	}
}

// TestDatagramConnUnderReorderDup sends many unique payloads over a pipe that
// duplicates and reorders (but does not drop), and asserts every unique payload is
// delivered exactly once: reordering is tolerated and duplicates are suppressed by
// the replay window.
func TestDatagramConnUnderReorderDup(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 7, 0, 0.3, 0.3)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	const n = 50
	for i := 0; i < n; i++ {
		if err := client.Send([]byte(fmt.Sprintf("msg-%03d", i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// The fault model reorders by holding a packet until the next one arrives, so a
	// held tail packet needs a follow-up to flush it (data frames are not
	// retransmitted). Nudge with throwaway "flush-" packets when delivery stalls;
	// they carry distinct keys and are ignored by the unique-payload accounting.
	flushes := 0
	flush := func() {
		_ = client.Send([]byte(fmt.Sprintf("flush-%d", flushes)))
		flushes++
	}
	flush()

	seen := make(map[string]int)
	deadline := time.After(5 * time.Second)
	for countMsgs(seen) < n {
		select {
		case b := <-server.ds.recvCh:
			seen[string(b)]++
		case <-time.After(50 * time.Millisecond):
			if flushes > 200 {
				t.Fatalf("only received %d/%d unique payloads", countMsgs(seen), n)
			}
			flush()
		case <-deadline:
			t.Fatalf("only received %d/%d unique payloads", countMsgs(seen), n)
		}
	}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("msg-%03d", i)
		if seen[key] == 0 {
			t.Fatalf("missing payload %q", key)
		}
		if seen[key] > 1 {
			t.Fatalf("duplicate delivery of %q (%d times)", key, seen[key])
		}
	}
}

// TestDatagramReplayRejectedOverWire captures a valid DATA frame and re-injects it
// through the receive path; the replay must be dropped (no second delivery).
func TestDatagramReplayRejectedOverWire(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 3, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	// Build a DATA frame exactly as Send would, but capture the bytes.
	seq := client.ds.session.nextDatagramSeq()
	header := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
		Type:      protocol.DatagramFrameData,
		Epoch:     client.ds.session.datagramSendEpoch(),
		RecvIndex: client.ds.peerIndex,
		Seq:       seq,
	})
	ct, err := client.ds.session.DatagramSeal(header, seq, []byte("once"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	frame := append(header, ct...)

	// First delivery succeeds.
	if err := epB.routeDatagram(epA.conn.LocalAddr(), append([]byte(nil), frame...)); err != nil {
		t.Fatalf("route 1: %v", err)
	}
	if got := recvWithTimeout(t, server); !bytes.Equal(got, []byte("once")) {
		t.Fatalf("got %q want %q", got, "once")
	}
	// Replay is dropped: nothing delivered.
	if err := epB.routeDatagram(epA.conn.LocalAddr(), append([]byte(nil), frame...)); err != nil {
		t.Fatalf("route 2: %v", err)
	}
	select {
	case b := <-server.ds.recvCh:
		t.Fatalf("replay was delivered: %q", b)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDatagramSendOversize(t *testing.T) {
	client, _, epA, epB := dgramPair(t, 4, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	if err := client.Send(make([]byte, constants.DatagramMaxDataPayload)); err != nil {
		t.Fatalf("send at max payload should succeed: %v", err)
	}
	err := client.Send(make([]byte, constants.DatagramMaxDataPayload+1))
	if !errors.Is(err, qerrors.ErrMessageTooLarge) {
		t.Fatalf("oversize send: got %v want ErrMessageTooLarge", err)
	}
}

func TestDatagramCloseAuth(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 5, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	srcAddr := epA.conn.LocalAddr()

	// A forged CLOSE (valid header, garbage tag) for the server's index must NOT
	// tear the session down.
	forged := protocol.EncodeDatagramHeader(protocol.DatagramHeader{
		Type:      protocol.DatagramFrameClose,
		Epoch:     0,
		RecvIndex: client.ds.peerIndex, // the index the server demuxes on
		Seq:       9999,
	})
	forged = append(forged, bytes.Repeat([]byte{0xAB}, constants.AESTagSize)...)
	if err := epB.routeDatagram(srcAddr, forged); err != nil {
		t.Fatalf("route forged close: %v", err)
	}
	if epB.registry.lookup(server.ds.index) == nil {
		t.Fatal("forged CLOSE tore the session down")
	}

	// A genuine Close from the client tears the server session down.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for epB.registry.lookup(server.ds.index) != nil {
		select {
		case <-deadline:
			t.Fatal("authenticated CLOSE did not tear the session down")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestDatagramIdleReap drives the reaper goroutine directly: a registered,
// established session with stale activity is torn down within a few tick periods.
func TestDatagramIdleReap(t *testing.T) {
	connA, _ := memPipe(6, 0, 0, 0)
	ep := mustEndpoint(t, connA)
	ep.idleTimeout = 40 * time.Millisecond
	defer func() { _ = ep.Close() }()

	s, _ := datagramSessionPair(t)
	s.lastActivityNanos.Store(time.Now().Add(-time.Hour).UnixNano()) // long idle
	ds := &datagramSession{session: s, recvCh: make(chan []byte, 1), closed: make(chan struct{})}
	if _, err := ep.registry.add(ds); err != nil {
		t.Fatalf("register: %v", err)
	}

	go ep.reapIdle()

	// teardown removes from the registry before signalling closed, so waiting on
	// ds.closed guarantees both have happened (no race on observing removal first).
	select {
	case <-ds.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle session was not reaped")
	}
	if ep.registry.lookup(ds.index) != nil {
		t.Fatal("reaped session is still registered")
	}
}

// countMsgs counts delivered keys that are real payloads (prefix "msg-"), ignoring
// the throwaway flush packets used to drain the reordering hold-back.
func countMsgs(seen map[string]int) int {
	n := 0
	for k := range seen {
		if len(k) >= 4 && k[:4] == "msg-" {
			n++
		}
	}
	return n
}

func recvWithTimeout(t *testing.T, c *DatagramConn) []byte {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b, err := c.Recv()
		ch <- res{b, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("recv: %v", r.err)
		}
		return r.b
	case <-time.After(3 * time.Second):
		t.Fatal("recv timed out")
		return nil
	}
}
