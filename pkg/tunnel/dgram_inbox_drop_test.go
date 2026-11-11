package tunnel

import (
	"testing"
	"time"
)

// With no reader, every authenticated datagram that arrives is either queued in the
// inbox or counted as dropped, so the counters must add up exactly once traffic stops.
func TestDatagramInboxDropIsCounted(t *testing.T) {
	client, server, stop := dialEstablished(t)
	defer stop()
	sess := server.getSession()

	payload := make([]byte, 16)
	deadline := time.Now().Add(20 * time.Second)
	for sess.InboxDropped.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no drops counted after flooding a stalled reader; received %d", sess.PacketsRecv.Load())
		}
		for range 512 {
			if err := client.Send(payload); err != nil {
				t.Fatalf("send: %v", err)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for the receive loop to go quiet: two equal readings 100 ms apart.
	last := int64(-1)
	for i := 0; i < 100; i++ {
		cur := sess.PacketsRecv.Load()
		if cur == last {
			break
		}
		last = cur
		time.Sleep(100 * time.Millisecond)
	}

	queued, dropped, received := int64(len(server.recvCh)), sess.InboxDropped.Load(), sess.PacketsRecv.Load()
	if queued != int64(dataInboxCap) {
		t.Fatalf("inbox holds %d, want it full at %d", queued, dataInboxCap)
	}
	if received != queued+dropped {
		t.Fatalf("received %d, but %d queued plus %d dropped = %d", received, queued, dropped, queued+dropped)
	}
	if st := sess.Stats(); st.InboxDropped != dropped {
		t.Fatalf("Stats().InboxDropped = %d, want %d", st.InboxDropped, dropped)
	}
}
