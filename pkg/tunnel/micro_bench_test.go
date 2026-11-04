package tunnel

import (
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
	if got := testing.AllocsPerRun(200, func() { _ = c.Send(payload) }); got > 1 {
		t.Fatalf("steady-state Send allocates %v times per call, documented limit is 1 (the nonce)", got)
	}
}

func TestDatagramHotPathAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	frame := protocol.EncodeDatagramData(protocol.DatagramHeader{Type: protocol.DatagramFrameData, RecvIndex: 7, Seq: 1}, make([]byte, 64))
	if got := testing.AllocsPerRun(200, func() { _, _, _ = protocol.ParseDatagramHeader(frame) }); got != 0 {
		t.Errorf("ParseDatagramHeader allocates %v times", got)
	}
	w := NewDatagramReplayWindow()
	var seq uint64
	if got := testing.AllocsPerRun(200, func() {
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
	if got := testing.AllocsPerRun(200, func() { _ = reg.lookup(idx) }); got != 0 {
		t.Errorf("registry lookup allocates %v times", got)
	}
	a, b := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	if got := testing.AllocsPerRun(200, func() { _ = addrEqual(a, b) }); got != 0 {
		t.Errorf("addrEqual allocates %v times", got)
	}
}
