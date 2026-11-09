package tunnel

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// Benchmarks for work an unauthenticated sender can make a node do, and for the
// documented hot paths. Run with: go test ./pkg/tunnel -run '^$' -bench 'Micro' -benchmem

var microAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4433}

func BenchmarkMicroCookieIssue(b *testing.B) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = cs.issue(microAddr)
	}
}

// Verifying a forged cookie is the cost of every unauthenticated retry under load.
func BenchmarkMicroCookieVerify(b *testing.B) {
	cs, err := newCookieSigner(nil)
	if err != nil {
		b.Fatal(err)
	}
	valid := cs.issue(microAddr)
	forged := append([]byte(nil), valid...)
	forged[len(forged)-1] ^= 1
	for name, c := range map[string][]byte{"valid": valid, "forged": forged} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				cs.verify(microAddr, c)
			}
		})
	}
}

// A sender can open reassembly state with one tiny fragment that declares the largest
// total length, forcing the buffer allocation; this is the cost per such fragment.
func BenchmarkMicroReassemblerAdversarialOpen(b *testing.B) {
	r := NewReassembler(0, 0, time.Minute)
	piece := []byte{1}
	h := frag(1, 0, constants.DatagramMaxHandshakeMessageSize, piece)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		h.SenderIndex = uint32(i)
		i++
		if _, _, err := r.Add("attacker", h, piece); err != nil {
			b.Fatal(err)
		}
	}
}

// Overlapping duplicates of one fragment must stay cheap.
func BenchmarkMicroReassemblerDuplicateFragment(b *testing.B) {
	r := NewReassembler(0, 0, time.Minute)
	piece := make([]byte, 1000)
	h := frag(1, 0, constants.DatagramMaxHandshakeMessageSize, piece)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := r.Add("peer", h, piece); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMicroDatagramReplayAdmissibleCheck(b *testing.B) {
	w := NewDatagramReplayWindow()
	b.ReportAllocs()
	var seq uint64
	for b.Loop() {
		seq++
		if w.Admissible(seq) {
			w.Check(seq)
		}
	}
}

func BenchmarkMicroDatagramHeader(b *testing.B) {
	h := protocol.DatagramHeader{Type: protocol.DatagramFrameData, Epoch: 1, RecvIndex: 0xabcdef, Seq: 42}
	frame := protocol.EncodeDatagramData(h, make([]byte, 64))
	b.Run("parse", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, _, err := protocol.ParseDatagramHeader(frame); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = protocol.EncodeDatagramHeader(h)
		}
	})
}

// Every received datagram does one registry lookup; many cores do it at once.
func BenchmarkMicroRegistryLookupParallel(b *testing.B) {
	reg := newConnRegistry(1024)
	var indexes []uint32
	for range 512 {
		ds := &datagramSession{}
		idx, err := reg.add(ds)
		if err != nil {
			b.Fatal(err)
		}
		indexes = append(indexes, idx)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if reg.lookup(indexes[i%len(indexes)]) == nil {
				b.Error("registered session not found")
				return
			}
			i++
		}
	})
}

// quietAllocs returns the allocations per call of f, retrying while the count is
// above limit. testing.AllocsPerRun counts mallocs from every goroutine in the
// process, so a previous test's closing connections or handshakes can inflate a single
// measurement; a genuine regression allocates in every attempt and still exceeds limit.
func quietAllocs(limit float64, f func()) float64 {
	best := math.MaxFloat64
	for attempt := 0; attempt < 20; attempt++ {
		if got := testing.AllocsPerRun(100, f); got < best {
			best = got
		}
		if best <= limit {
			break
		}
		time.Sleep(50 * time.Millisecond) // let a finite background burst drain
	}
	return best
}

// TestQuietAllocsToleratesBackgroundBurstButNotRegressions guards the helper: a finite
// burst of foreign allocations must not fail a zero-allocation function, and a function
// that really allocates must still be reported.
func TestQuietAllocsToleratesBackgroundBurstButNotRegressions(t *testing.T) {
	var sink []byte
	allocating := func() { sink = make([]byte, 64); _ = sink }

	done := make(chan struct{})
	go func() {
		defer close(done)
		end := time.Now().Add(150 * time.Millisecond)
		for time.Now().Before(end) {
			_ = make([]byte, 128)
		}
	}()
	if got := quietAllocs(0, func() {}); got != 0 {
		t.Fatalf("noop reported %v allocs during a background burst", got)
	}
	<-done
	if got := quietAllocs(0, allocating); got < 1 {
		t.Fatalf("allocating function reported %v allocs", got)
	}
}

// The docs claim a zero-allocation steady-state send; the one residual allocation is
// the AEAD nonce, which escapes through the cipher.AEAD interface. Pin that so the
// documentation cannot drift from the code.
func TestDatagramSendAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	c := benchDatagramConn(t)
	payload := make([]byte, 1200-constants.DatagramDataOverhead)
	if err := c.Send(payload); err != nil {
		t.Fatal(err)
	}
	if got := quietAllocs(0, func() { _ = c.Send(payload) }); got != 0 {
		t.Fatalf("steady-state Send allocates %v times per call, want 0", got)
	}
	batch := [][]byte{payload, payload, payload, payload}
	if err := c.SendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if got := quietAllocs(0, func() { _ = c.SendBatch(batch) }); got != 0 {
		t.Fatalf("steady-state SendBatch allocates %v times per call, want 0", got)
	}
}

func TestDatagramHotPathAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	frame := protocol.EncodeDatagramData(protocol.DatagramHeader{Type: protocol.DatagramFrameData, RecvIndex: 7, Seq: 1}, make([]byte, 64))
	if got := quietAllocs(0, func() { _, _, _ = protocol.ParseDatagramHeader(frame) }); got != 0 {
		t.Errorf("ParseDatagramHeader allocates %v times", got)
	}
	w := NewDatagramReplayWindow()
	var seq uint64
	if got := quietAllocs(0, func() {
		seq++
		if w.Admissible(seq) {
			w.Check(seq)
		}
	}); got != 0 {
		t.Errorf("replay window allocates %v times", got)
	}
	reg := newConnRegistry(16)
	idx, err := reg.add(&datagramSession{})
	if err != nil {
		t.Fatal(err)
	}
	if got := quietAllocs(0, func() { _ = reg.lookup(idx) }); got != 0 {
		t.Errorf("registry lookup allocates %v times", got)
	}
	a, b := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	if got := quietAllocs(0, func() { _ = addrEqual(a, b) }); got != 0 {
		t.Errorf("addrEqual allocates %v times", got)
	}
}
