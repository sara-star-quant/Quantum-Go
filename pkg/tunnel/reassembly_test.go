package tunnel

import (
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
	_, stillThere := r.bySource["s"][reasmKey{sender: 1, msg: protocol.MessageTypeClientHello}]
	r.mu.Unlock()
	if stillThere {
		t.Fatal("expired reassembly buffer was not evicted")
	}
}
