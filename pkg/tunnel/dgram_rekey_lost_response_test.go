package tunnel

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// If every RekeyResponse flight of one attempt is lost, the responder has already moved to the
// next epoch and cached its response. The initiator's next attempt must still complete once the
// network heals. It used to build a fresh init under the old epoch, which the responder either
// ignored (its cache is keyed by the epoch) or could not match to the cached response, so every
// later attempt timed out and the pair could never rekey again.
func TestDatagramRekeyRecoversAfterEveryResponseWasLost(t *testing.T) {
	client, server, epA, epB := dgramPair(t, 61, 0, 0, 0)
	defer func() { _ = epA.Close(); _ = epB.Close() }()
	epA.maxRetries = 3 // a short first attempt
	epA.rtoMax = 20 * time.Millisecond

	memConn(epB).fault.setDropAll(protocol.MessageTypeDatagramRekeyResponse)
	if err := client.Rekey(); err == nil {
		t.Fatal("the attempt with every response lost must time out")
	}
	memConn(epB).fault.setDropAll(0)

	epA.maxRetries = 40
	if err := client.Rekey(); err != nil {
		t.Fatalf("the retry after the network healed failed: %v", err)
	}
	waitEpoch(t, client, 1)
	waitEpoch(t, server, 1)
	sendRecv(t, client, server, "after the retry")
	sendRecv(t, server, client, "after the retry back")
}
