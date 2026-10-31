package tunnel

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// collector drains the server's receive queue concurrently with the sender, because
// recvCh is small and drops when full.
type collector struct {
	mu  sync.Mutex
	got [][]byte
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func startCollector(server *datagramSession) *collector {
	c := &collector{}
	go func() {
		for {
			select {
			case p := <-server.recvCh:
				c.mu.Lock()
				c.got = append(c.got, p)
				c.mu.Unlock()
			case <-server.closed:
				return
			}
		}
	}()
	return c
}

// waitFor blocks until the collector holds n payloads or the deadline passes.
func (c *collector) waitFor(n int) bool {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if c.count() >= n {
			return true
		}
	}
	return c.count() >= n
}

func makePayloads(sizes []int) [][]byte {
	ps := make([][]byte, len(sizes))
	for i, n := range sizes {
		ps[i] = bytes.Repeat([]byte{byte(i + 1)}, n)
	}
	return ps
}

// TestSendBatchDelivers checks SendBatch delivers every payload intact, with and
// without offload, for equal sizes, a short tail, mixed sizes and a batch larger
// than one segmented send.
func TestSendBatchDelivers(t *testing.T) {
	tail := func(n, size, last int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = size
		}
		s[n-1] = last
		return s
	}
	equal := func(n, size int) []int { return tail(n, size, size) }
	cases := map[string][]int{
		"single":        {500},
		"equal":         equal(10, 1000),
		"short tail":    tail(10, 1000, 300),
		"mixed":         {1000, 1000, 500, 1000, 1000, 200, 1000},
		"growing":       {100, 200, 300, 400},
		"over 64 segs":  equal(150, 200),
		"bytes limit":   equal(60, constants.DatagramMaxDataPayload-20),
		"tiny":          equal(20, 1),
		"alternating":   {900, 900, 100, 900, 900, 100},
		"full payloads": equal(8, constants.DatagramMaxDataPayload),
	}
	for _, offload := range []bool{false, true} {
		for name, sizes := range cases {
			t.Run(fmt.Sprintf("offload=%v/%s", offload, name), func(t *testing.T) {
				var opts []DatagramEndpointOption
				if offload {
					opts = append(opts, WithDatagramOffload())
				}
				client, server, stop := dialEstablished(t, opts...)
				defer stop()

				payloads := makePayloads(sizes)
				col := startCollector(server)
				// Send in chunks and wait for each to arrive, so the sender never
				// outruns the receive queue (UDP drops by design when it does).
				for off := 0; off < len(payloads); off += 32 {
					end := min(off+32, len(payloads))
					if err := client.SendBatch(payloads[off:end]); err != nil {
						t.Fatalf("SendBatch: %v", err)
					}
					if !col.waitFor(end) {
						t.Fatalf("received %d payloads, want %d", col.count(), end)
					}
				}
				for i := range payloads {
					if !bytes.Equal(col.got[i], payloads[i]) {
						t.Fatalf("payload %d differs (len %d, want %d)", i, len(col.got[i]), len(payloads[i]))
					}
				}
			})
		}
	}
}

func TestSendBatchRejectsOversizeAndEmpty(t *testing.T) {
	client, _, stop := dialEstablished(t)
	defer stop()
	if err := client.SendBatch(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	big := make([]byte, 100000)
	if err := client.SendBatch([][]byte{{1}, big}); err == nil {
		t.Fatal("oversize payload accepted")
	}
}

// TestSendBatchCountsAndSequences checks the session counters and that sequence
// numbers advance contiguously across a batch.
func TestSendBatchCountsAndSequences(t *testing.T) {
	client, server, stop := dialEstablished(t, WithDatagramOffload())
	defer stop()
	s := client.Session()
	before, packets, bytesBefore := s.sendSeq.Load(), s.PacketsSent.Load(), s.BytesSent.Load()

	payloads := makePayloads([]int{100, 100, 100, 100, 50})
	col := startCollector(server)
	if err := client.SendBatch(payloads); err != nil {
		t.Fatal(err)
	}
	if !col.waitFor(len(payloads)) {
		t.Fatalf("received %d payloads, want %d", col.count(), len(payloads))
	}
	if d := s.sendSeq.Load() - before; d != uint64(len(payloads)) {
		t.Errorf("sequence advanced by %d, want %d", d, len(payloads))
	}
	if d := s.PacketsSent.Load() - packets; d != int64(len(payloads)) {
		t.Errorf("PacketsSent advanced by %d, want %d", d, len(payloads))
	}
	if d := s.BytesSent.Load() - bytesBefore; d != 450 {
		t.Errorf("BytesSent advanced by %d, want 450", d)
	}
}
