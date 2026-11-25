package tunnel

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// The responder caches its RekeyResponse and replays it when the initiator retransmits the same
// RekeyInit, since the first response may have been lost. The replay must answer only a
// retransmit of the init it answered, byte for byte. Any other body under the same epoch is
// unauthenticated input, and answering it with a multi-kilobyte response lets a tiny forged
// packet trigger a large send toward the genuine peer.
func TestForgedRekeyInitDoesNotReplayTheCachedResponse(t *testing.T) {
	conn := &captureConn{}
	e := mustEndpoint(t, conn)
	addr := udp("198.51.100.1", 4000)
	_, initiator, ds := registerEstablished(t, e, addr)

	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body, epoch, err := initiator.buildDatagramRekeyInit(kp)
	if err != nil {
		t.Fatal(err)
	}

	writes := func() int { conn.mu.Lock(); defer conn.mu.Unlock(); return len(conn.written) }

	e.handleRekeyInit(ds, epoch, body)
	first := writes()
	if first == 0 {
		t.Fatal("the genuine RekeyInit was not answered")
	}

	// A retransmit of the same init replays the cached response.
	e.handleRekeyInit(ds, epoch, body)
	if got := writes(); got != 2*first {
		t.Fatalf("a retransmit must replay the %d cached frames: %d writes in total", first, got)
	}

	// A different body under the same epoch is not a retransmit. It must send nothing.
	forged := append([]byte(nil), body...)
	forged[len(forged)-1] ^= 0x01
	e.handleRekeyInit(ds, epoch, forged)
	e.handleRekeyInit(ds, epoch, []byte("short forged init"))
	if got := writes(); got != 2*first {
		t.Fatalf("a forged RekeyInit under the cached epoch triggered %d extra frames", got-2*first)
	}
}
