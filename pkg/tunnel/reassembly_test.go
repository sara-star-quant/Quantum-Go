package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func frag(sender uint32, off, total int, data []byte) protocol.DatagramHandshakeHeader {
	return protocol.DatagramHandshakeHeader{
		SenderIndex: sender,
		MsgType:     protocol.MessageTypeClientHello,
		FragOffset:  uint16(off),
		FragLength:  uint16(len(data)),
		TotalLength: uint16(total),
	}
}

func TestReassembler_Complete(t *testing.T) {
	r := NewReassembler(4, 4096, time.Second)
	full := []byte("ABCDEFGHIJKLMNOP")
	a, b := full[:6], full[6:]

	_, done, err := r.Add("src", frag(1, 0, len(full), a), a)
	if err != nil || done {
		t.Fatalf("first fragment: done=%v err=%v", done, err)
	}
	msg, done, err := r.Add("src", frag(1, 6, len(full), b), b)
	if err != nil || !done {
		t.Fatalf("second fragment: done=%v err=%v", done, err)
	}
	if string(msg) != string(full) {
		t.Fatalf("reassembled %q want %q", msg, full)
	}
}

func TestReassembler_OutOfOrderAndDuplicate(t *testing.T) {
	r := NewReassembler(4, 4096, time.Second)
	full := []byte("0123456789")
	a, b, c := full[0:4], full[4:7], full[7:10]

	if _, done, _ := r.Add("s", frag(1, 7, len(full), c), c); done {
		t.Fatal("unexpectedly complete after one fragment")
	}
	if _, done, _ := r.Add("s", frag(1, 0, len(full), a), a); done {
		t.Fatal("unexpectedly complete after two fragments")
	}
	// Duplicate of an already-received fragment must not complete or corrupt.
	if _, done, _ := r.Add("s", frag(1, 7, len(full), c), c); done {
		t.Fatal("duplicate fragment completed message prematurely")
	}
	msg, done, err := r.Add("s", frag(1, 4, len(full), b), b)
	if err != nil || !done {
		t.Fatalf("final fragment: done=%v err=%v", done, err)
	}
	if string(msg) != string(full) {
		t.Fatalf("reassembled %q want %q", msg, full)
	}
}

func TestReassembler_RejectsOversize(t *testing.T) {
	r := NewReassembler(4, 16, time.Second)
	data := []byte("x")
	h := frag(1, 0, 17, data) // total 17 > max 16
	if _, _, err := r.Add("s", h, data); err == nil {
		t.Fatal("expected oversize rejection")
	}
}

func TestReassembler_PerSourceCapEvicts(t *testing.T) {
	r := NewReassembler(2, 4096, time.Second)
	// Three distinct in-progress messages from one source, cap is 2.
	for i := uint32(1); i <= 3; i++ {
		data := []byte("ab")
		h := frag(i, 0, 10, data) // 10-byte total, only 2 delivered -> stays open
		if _, done, err := r.Add("s", h, data); err != nil || done {
			t.Fatalf("sender %d: done=%v err=%v", i, done, err)
		}
	}
	r.mu.Lock()
	n := len(r.bySource["s"])
	r.mu.Unlock()
	if n > 2 {
		t.Fatalf("per-source buffers = %d, want <= 2", n)
	}
}

func TestReassembler_GlobalSourceCap(t *testing.T) {
	r := NewReassembler(4, 4096, time.Second)
	r.maxSources = 3
	data := []byte("ab")

	// Fill the global cap with distinct sources, each holding an open message.
	for i := 0; i < 3; i++ {
		src := "src" + string(rune('A'+i))
		if _, done, err := r.Add(src, frag(1, 0, 10, data), data); err != nil || done {
			t.Fatalf("source %s: done=%v err=%v", src, done, err)
		}
	}
	// A new, distinct source beyond the cap is rejected (spoofed-source flood guard).
	if _, _, err := r.Add("srcZ", frag(1, 0, 10, data), data); err == nil {
		t.Fatal("expected global source-cap rejection for a new source")
	}
	// An already-tracked source can still make progress on its in-flight messages.
	if _, done, err := r.Add("srcA", frag(2, 0, 10, data), data); err != nil || done {
		t.Fatalf("existing source must still be served: done=%v err=%v", done, err)
	}
}

func TestReassembler_Timeout(t *testing.T) {
	r := NewReassembler(4, 4096, 5*time.Second)
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }

	data := []byte("ab")
	if _, done, err := r.Add("s", frag(1, 0, 10, data), data); err != nil || done {
		t.Fatalf("setup fragment: done=%v err=%v", done, err)
	}
	// Advance past the timeout; the next Add triggers eviction of stale state.
	now = now.Add(6 * time.Second)
	other := []byte("cd")
	if _, done, err := r.Add("s", frag(2, 0, 10, other), other); err != nil || done {
		t.Fatalf("post-timeout fragment: done=%v err=%v", done, err)
	}
	r.mu.Lock()
	_, stillThere := r.bySource["s"][reasmKey{sender: 1, msg: protocol.MessageTypeClientHello, total: 10}]
	r.mu.Unlock()
	if stillThere {
		t.Fatal("expired reassembly buffer was not evicted")
	}
}

func TestReassembler_OverlappingFragmentsAndDrop(t *testing.T) {
	r := NewReassembler(4, 4096, time.Second)
	full := make([]byte, 200)
	for i := range full {
		full[i] = byte(i)
	}
	// Overlap across a 64-bit coverage word boundary, then close the gap.
	a, b, c := full[0:70], full[60:130], full[130:200]
	for _, f := range []struct {
		off  int
		data []byte
	}{{0, a}, {60, b}} {
		if _, done, err := r.Add("s", frag(1, f.off, len(full), f.data), f.data); err != nil || done {
			t.Fatalf("fragment at %d: done=%v err=%v", f.off, done, err)
		}
	}
	msg, done, err := r.Add("s", frag(1, 130, len(full), c), c)
	if err != nil || !done || string(msg) != string(full) {
		t.Fatalf("overlap reassembly: done=%v err=%v equal=%v", done, err, string(msg) == string(full))
	}

	// Drop discards in-progress state for a source.
	if _, _, err := r.Add("d", frag(2, 0, len(full), a), a); err != nil {
		t.Fatal(err)
	}
	if r.sourceCount() != 1 {
		t.Fatalf("sourceCount = %d, want 1", r.sourceCount())
	}
	r.Drop("d")
	if r.sourceCount() != 0 {
		t.Fatalf("sourceCount after Drop = %d, want 0", r.sourceCount())
	}
}

// Expired state must not count toward cookie pressure or complete late, even when no new
// fragment has arrived to trigger a sweep.
func TestReassembler_ExpiryWithoutTraffic(t *testing.T) {
	r := NewReassembler(4, 1500, 5*time.Second)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	full := bytes.Repeat([]byte{7}, 100)
	if _, _, err := r.Add("s", frag(1, 0, len(full), full[:50]), full[:50]); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if n := r.sourceCount(); n != 0 {
		t.Fatalf("sourceCount after timeout = %d, want 0", n)
	}
}

// With the sweep throttled, a buffer past its timeout still must not complete.
func TestReassembler_ThrottledSweepStillExpires(t *testing.T) {
	r := NewReassembler(4, 1500, 8*time.Second)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	full := bytes.Repeat([]byte{7}, 100)
	if _, _, err := r.Add("a", frag(1, 0, len(full), full[:50]), full[:50]); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Second)
	r.lastSweep = now // the sweep just ran, so only the lookup check can expire "a"
	if _, done, err := r.Add("a", frag(1, 50, len(full), full[50:]), full[50:]); err != nil || done {
		t.Fatalf("expired buffer completed: done=%v err=%v", done, err)
	}
}

// A HelloRetryRequest handshake sends two ClientHellos of different sizes under one sender and
// type. A late duplicate of the first hello's fragment must not block the retried second one.
func TestReassembler_SameTypeDifferentSizeDoNotCollide(t *testing.T) {
	r := NewReassembler(4, 4096, 10*time.Second)
	first := make([]byte, 300)
	second := make([]byte, 200)
	for i := range first {
		first[i] = 0xAA
	}
	for i := range second {
		second[i] = byte(i)
	}

	// One stale fragment of the first hello arrives and stays partial.
	if _, done, err := r.Add("s", frag(1, 0, len(first), first[:100]), first[:100]); err != nil || done {
		t.Fatalf("stale fragment: done=%v err=%v", done, err)
	}
	// The retried hello arrives in two fragments and must complete with its own bytes.
	if _, done, err := r.Add("s", frag(1, 0, len(second), second[:120]), second[:120]); err != nil || done {
		t.Fatalf("second hello, first fragment: done=%v err=%v", done, err)
	}
	got, done, err := r.Add("s", frag(1, 120, len(second), second[120:]), second[120:])
	if err != nil || !done {
		t.Fatalf("second hello, last fragment: done=%v err=%v", done, err)
	}
	if !bytes.Equal(got, second) {
		t.Fatal("the retried hello reassembled with bytes from the stale one")
	}
}

// sourceCount runs for every handshake frame, because the cookie gate asks whether the endpoint is
// under pressure before it looks at anything else. It must not rescan every source and buffer on
// each call: with a thousand held sources that scan cost 48 microseconds a packet, enough for a
// modest flood to hold the reassembler lock and starve real handshakes. The fake clock advances a
// millisecond per read, so a thousand calls span one second, and a sweep every quarter of the
// 10 second timeout means at most one sweep in that span.
func TestReassembler_SourceCountDoesNotSweepPerCall(t *testing.T) {
	r := NewReassembler(4, 4096, 10*time.Second)
	clock := time.Unix(1_000, 0)
	r.now = func() time.Time { clock = clock.Add(time.Millisecond); return clock }
	a := []byte{1}
	if _, _, err := r.Add("src", frag(1, 0, 16, a), a); err != nil {
		t.Fatal(err)
	}

	sweeps, last := 0, r.lastSweep
	for range 1000 {
		r.sourceCount()
		if !r.lastSweep.Equal(last) {
			sweeps++
			last = r.lastSweep
		}
	}
	if sweeps > 1 {
		t.Fatalf("sourceCount swept %d times in 1000 calls over one second, want at most 1", sweeps)
	}
}
