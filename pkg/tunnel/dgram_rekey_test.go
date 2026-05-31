package tunnel

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// sendRecv sends one payload from -> to and asserts it arrives intact.
func sendRecv(t *testing.T, from, to *DatagramConn, payload string) {
	t.Helper()
	if err := from.Send([]byte(payload)); err != nil {
		t.Fatalf("send %q: %v", payload, err)
	}
	got := recvWithTimeout(t, to)
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestDatagramRekeyExchange(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 11, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	// Data flows under epoch 0.
	sendRecv(t, client, server, "before-rekey c->s")
	sendRecv(t, server, client, "before-rekey s->c")

	if e := client.Session().datagramSendEpoch(); e != 0 {
		t.Fatalf("pre-rekey client epoch = %d, want 0", e)
	}

	if err := client.Rekey(); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	// Both sides advanced to epoch 1.
	if e := client.Session().datagramSendEpoch(); e != 1 {
		t.Fatalf("post-rekey client epoch = %d, want 1", e)
	}
	// The responder advances reactively; give the receive loop a moment if needed.
	deadline := time.After(time.Second)
	for server.Session().datagramSendEpoch() != 1 {
		select {
		case <-deadline:
			t.Fatalf("post-rekey server epoch = %d, want 1", server.Session().datagramSendEpoch())
		case <-time.After(2 * time.Millisecond):
		}
	}

	// Data flows under epoch 1 in both directions.
	sendRecv(t, client, server, "after-rekey c->s")
	sendRecv(t, server, client, "after-rekey s->c")
}

// TestDatagramRekeyAutoTrigger forces the current epoch to look nearly exhausted so
// the next Send schedules a background rekey, and verifies both sides advance.
func TestDatagramRekeyAutoTrigger(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 31, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	// Set startSeq so seq-startSeq wraps to >= the high-water mark on the next Send.
	s := client.Session()
	s.dgramEpochs.cur.startSeq = s.sendSeq.Load() - datagramRekeyHighWater

	sendRecv(t, client, server, "still epoch 0") // sealed before the trigger fires

	deadline := time.After(2 * time.Second)
	for client.Session().datagramSendEpoch() != 1 || server.Session().datagramSendEpoch() != 1 {
		select {
		case <-deadline:
			t.Fatalf("auto-rekey did not advance both sides: client=%d server=%d",
				client.Session().datagramSendEpoch(), server.Session().datagramSendEpoch())
		case <-time.After(2 * time.Millisecond):
		}
	}
	sendRecv(t, client, server, "after auto-rekey")
}

func TestDatagramRekeyOnlyInitiatorDrives(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 12, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()
	_ = client
	if err := server.Rekey(); err == nil {
		t.Fatal("responder Rekey should be rejected, got nil")
	}
}

// TestDatagramRekeyUnderLoss drives a rekey across a pipe that drops, duplicates,
// and reorders datagrams. Retransmission of the RekeyInit and the responder's
// verbatim replay of its cached response must still converge, and data must flow
// under the new epoch afterwards.
func TestDatagramRekeyUnderLoss(t *testing.T) {
	for seed := uint64(1); seed <= 8; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			client, server, epA, epB := dgramPair(t, seed, 0.2, 0.1, 0.15)
			defer func() { _ = epA.Close() }()
			defer func() { _ = epB.Close() }()

			if err := client.Rekey(); err != nil {
				t.Fatalf("rekey under loss: %v", err)
			}
			if e := client.Session().datagramSendEpoch(); e != 1 {
				t.Fatalf("client epoch = %d, want 1", e)
			}
			deadline := time.After(2 * time.Second)
			for server.Session().datagramSendEpoch() != 1 {
				select {
				case <-deadline:
					t.Fatal("server did not advance epoch under loss")
				case <-time.After(2 * time.Millisecond):
				}
			}
		})
	}
}

// TestDatagramRekeyResponderCacheNoDoubleAdvance verifies that retransmitted
// RekeyInits do not make the responder advance more than once: after a rekey, the
// responder is on epoch 1, and replaying the same RekeyInit must keep it on epoch 1
// (re-running Encapsulate would derive a different secret and desync the sides).
func TestDatagramRekeyResponderCacheNoDoubleAdvance(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 21, 0, 0, 0)
	defer func() { _ = epA.Close() }()
	defer func() { _ = epB.Close() }()

	if err := client.Rekey(); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	deadline := time.After(time.Second)
	for server.Session().datagramSendEpoch() != 1 {
		select {
		case <-deadline:
			t.Fatal("server did not advance to epoch 1")
		case <-time.After(2 * time.Millisecond):
		}
	}

	// A second rekey advances to epoch 2 exactly once.
	if err := client.Rekey(); err != nil {
		t.Fatalf("second rekey: %v", err)
	}
	deadline = time.After(time.Second)
	for server.Session().datagramSendEpoch() != 2 {
		select {
		case <-deadline:
			t.Fatalf("server epoch = %d, want 2", server.Session().datagramSendEpoch())
		case <-time.After(2 * time.Millisecond):
		}
	}
	sendRecv(t, client, server, "after-two-rekeys")
}
