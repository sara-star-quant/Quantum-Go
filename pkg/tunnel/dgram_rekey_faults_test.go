package tunnel

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func memConn(ep *DatagramEndpoint) *memPacketConn { return ep.conn.(*memPacketConn) }

// deliver sends payload until the peer receives it, tolerating a lossy data plane. It
// fails the test if no copy arrives, or if anything other than payload arrives.
func deliver(t *testing.T, from, to *DatagramConn, payload string) {
	t.Helper()
	got := make(chan []byte, 64)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			p, err := to.Recv()
			if err != nil {
				return
			}
			select {
			case got <- p:
			case <-stop:
				return
			}
		}
	}()
	for range 60 {
		if err := from.Send([]byte(payload)); err != nil {
			t.Fatalf("send: %v", err)
		}
		select {
		case p := <-got:
			if !bytes.Equal(p, []byte(payload)) {
				t.Fatalf("received %q, want %q", p, payload)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("%q never arrived", payload)
}

func epochs(a, b *DatagramConn) (uint8, uint8) {
	return a.Session().datagramSendEpoch(), b.Session().datagramSendEpoch()
}

func waitEpoch(t *testing.T, c *DatagramConn, want uint8) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for c.Session().datagramSendEpoch() != want {
		if time.Now().After(deadline) {
			t.Fatalf("epoch = %d, want %d", c.Session().datagramSendEpoch(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The first RekeyInit, or the first RekeyResponse, is lost; the retransmit completes it.
func TestDatagramRekeyTargetedLoss(t *testing.T) {
	for name, tc := range map[string]struct {
		msg      protocol.MessageType
		fromSide func(a, b *DatagramEndpoint) *DatagramEndpoint
	}{
		"RekeyInit lost":     {protocol.MessageTypeDatagramRekeyInit, func(a, _ *DatagramEndpoint) *DatagramEndpoint { return a }},
		"RekeyResponse lost": {protocol.MessageTypeDatagramRekeyResponse, func(_, b *DatagramEndpoint) *DatagramEndpoint { return b }},
	} {
		t.Run(name, func(t *testing.T) {
			client, server, epA, epB := dgramPair(t, 31, 0, 0, 0)
			defer func() { _ = epA.Close(); _ = epB.Close() }()
			memConn(tc.fromSide(epA, epB)).fault.dropFirst = tc.msg

			if err := client.Rekey(); err != nil {
				t.Fatalf("Rekey: %v", err)
			}
			waitEpoch(t, server, 1)
			if c, s := epochs(client, server); c != 1 || s != 1 {
				t.Fatalf("epochs = %d/%d, want 1/1", c, s)
			}
			sendRecv(t, client, server, "after")
			sendRecv(t, server, client, "after back")
		})
	}
}

// Across seeded loss, duplication and reordering of every datagram, a rekey either
// completes or reports failure, and retrying always converges: both peers end on the
// same epoch and data flows both ways. A failed attempt must never leave the pair unable
// to talk.
func TestDatagramRekeyConvergesUnderFaults(t *testing.T) {
	profiles := []struct{ drop, dup, reorder float64 }{
		{0.2, 0.1, 0.15},
		{0.4, 0.2, 0.3},
		{0, 0.5, 0.5},
	}
	for pi, p := range profiles {
		for seed := uint64(1); seed <= 8; seed++ {
			t.Run(fmt.Sprintf("profile%d/seed%d", pi, seed), func(t *testing.T) {
				client, server, epA, epB := dgramPair(t, seed*7+uint64(pi), p.drop, p.dup, p.reorder)
				defer func() { _ = epA.Close(); _ = epB.Close() }()

				done := false
				for attempt := 0; attempt < 5 && !done; attempt++ {
					done = client.Rekey() == nil
				}
				if !done {
					t.Fatal("rekey never completed in 5 attempts")
				}
				c, _ := epochs(client, server)
				if c == 0 {
					t.Fatal("client did not advance")
				}
				waitEpoch(t, server, c)
				deliver(t, client, server, "c->s")
				deliver(t, server, client, "s->c")
			})
		}
	}
}

// The epoch is one byte. Rotating past 255 wraps to 0 and traffic keeps flowing.
func TestDatagramRekeyEpochRollover(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 41, 0, 0, 0)
	defer func() { _ = epA.Close(); _ = epB.Close() }()
	const rekeys = 260
	for i := range rekeys {
		if err := client.Rekey(); err != nil {
			t.Fatalf("rekey %d: %v", i+1, err)
		}
		waitEpoch(t, server, uint8((i+1)%256))
	}
	if c, s := epochs(client, server); c != rekeys%256 || s != rekeys%256 {
		t.Fatalf("epochs = %d/%d, want %d", c, s, rekeys%256)
	}
	sendRecv(t, client, server, "past rollover")
	sendRecv(t, server, client, "past rollover back")
}

// Captured rekey frames replayed later, including during another rekey, are ignored: each
// rekey advances each side exactly once.
func TestDatagramRekeyReplayedFramesIgnored(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 51, 0, 0, 0)
	defer func() { _ = epA.Close(); _ = epB.Close() }()

	var mu sync.Mutex
	var inits, resps [][]byte
	capture := func(into *[][]byte) func([]byte) {
		return func(data []byte) {
			if ft, err := protocol.PeekDatagramType(data); err != nil || ft != protocol.DatagramFrameHandshake {
				return
			}
			h, _, err := protocol.ParseDatagramHandshake(data)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch h.MsgType {
			case protocol.MessageTypeDatagramRekeyInit:
				inits = append(inits, append([]byte(nil), data...))
			case protocol.MessageTypeDatagramRekeyResponse:
				resps = append(resps, append([]byte(nil), data...))
			}
		}
	}
	memConn(epA).fault.tap = capture(&inits)
	memConn(epB).fault.tap = capture(&resps)

	if err := client.Rekey(); err != nil {
		t.Fatal(err)
	}
	waitEpoch(t, server, 1)
	mu.Lock()
	oldInits, oldResps := append([][]byte(nil), inits...), append([][]byte(nil), resps...)
	mu.Unlock()
	if len(oldInits) == 0 || len(oldResps) == 0 {
		t.Fatal("no rekey frames captured")
	}

	replay := func() {
		for _, f := range oldInits {
			memConn(epB).enqueue(memPacket{data: f, src: memConn(epA).addr})
		}
		for _, f := range oldResps {
			memConn(epA).enqueue(memPacket{data: f, src: memConn(epB).addr})
		}
		time.Sleep(100 * time.Millisecond) // let the receive loops process them
	}

	replay() // after the rekey completed
	if c, s := epochs(client, server); c != 1 || s != 1 {
		t.Fatalf("replay after rekey moved epochs to %d/%d", c, s)
	}

	// A second rekey with the first one's frames replayed alongside it.
	done := make(chan error, 1)
	go func() { done <- client.Rekey() }()
	for range 5 {
		replay()
	}
	if err := within(t, "second rekey", func() error { return <-done }); err != nil {
		t.Fatal(err)
	}
	waitEpoch(t, server, 2)
	replay()
	if c, s := epochs(client, server); c != 2 || s != 2 {
		t.Fatalf("epochs = %d/%d after replays, want 2/2", c, s)
	}
	sendRecv(t, client, server, "still works")
	sendRecv(t, server, client, "still works back")
}

// Packets sealed under the old epoch are accepted for the retention window after a
// rekey, then rejected.
func TestDatagramOldEpochAcceptedThenRejected(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 61, 0, 0, 0)
	defer func() { _ = epA.Close(); _ = epB.Close() }()

	cs := client.Session()
	idx := client.ds.peerIndex
	base := uint64(1000)
	early := dataFrameFrom(t, cs, idx, base+1, []byte("old epoch, in window"))
	late := dataFrameFrom(t, cs, idx, base+2, []byte("old epoch, expired"))

	if err := client.Rekey(); err != nil {
		t.Fatal(err)
	}
	waitEpoch(t, server, 1)
	inject := func(f []byte) { memConn(epB).enqueue(memPacket{data: f, src: memConn(epA).addr}) }

	inject(early)
	if got := recvWithTimeout(t, server); string(got) != "old epoch, in window" {
		t.Fatalf("in-window old-epoch packet = %q", got)
	}

	ss := server.Session()
	ss.mu.Lock()
	ss.dgramEpochs.prev.retireAfter = time.Now().Add(-time.Second)
	ss.mu.Unlock()

	inject(late)
	got := make(chan []byte, 1)
	go func() { p, _ := server.Recv(); got <- p }()
	select {
	case p := <-got:
		t.Fatalf("expired old-epoch packet delivered: %q", p)
	case <-time.After(300 * time.Millisecond):
	}
	// The live epoch is unaffected; the pending Recv above takes this message.
	if err := client.Send([]byte("current epoch")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if string(p) != "current epoch" {
			t.Fatalf("got %q", p)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("current-epoch packet not delivered")
	}
}

// Rekey against a peer that has gone away returns an error instead of hanging.
func TestDatagramRekeyAfterPeerCloseFailsClosed(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 71, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	epB.maxRetries = 3
	epA.maxRetries = 3
	_ = server.Close()
	_ = epB.Close()
	if err := within(t, "Rekey", func() error { return client.Rekey() }); err == nil {
		t.Fatal("Rekey against a closed peer reported success")
	}
}
