package tunnel

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// handleDataTo fills the caller's buffer: no allocation when it has room.
func TestHandleDataToAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	tx, rx := inplaceSessionPair(t)
	tr := &Transport{session: rx, codec: protocol.NewCodec()}
	frames := make([][]byte, 0, 8192)
	for i := 0; i < 8192; i++ {
		f, _, err := tx.encryptFrameTo(nil, bytes.Repeat([]byte{byte(i)}, 1400), nil)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	buf := make([]byte, 0, 2048)
	i := 0
	got := quietAllocs(0, func() {
		out, err := tr.handleDataTo(buf[:0], frames[i])
		if err != nil || len(out) != 1400 || out[0] != byte(i) {
			t.Fatalf("record %d: len %d err %v", i, len(out), err)
		}
		i++
	})
	if got != 0 {
		t.Fatalf("handleDataTo allocates %v times per record with a sized buffer, want 0", got)
	}
}

// ReceiveInto appends to dst, reuses its backing array, and skips control messages.
func TestReceiveIntoReusesBufferAndAppends(t *testing.T) {
	sender, receiver, cleanup := benchStreamPair(t)
	defer cleanup()
	go func() {
		_ = sender.SendPing() // control traffic between data records must not reach the caller
		_ = sender.Send([]byte("alpha"))
		_ = sender.Send(bytes.Repeat([]byte("b"), 3000))
	}()

	buf := make([]byte, 0, 4096)
	out, err := receiver.ReceiveInto(buf[:0])
	if err != nil || string(out) != "alpha" {
		t.Fatalf("first: %q, %v", out, err)
	}
	if &out[0] != &buf[:1][0] {
		t.Fatal("ReceiveInto did not reuse the caller's buffer")
	}

	prefix := append(buf[:0:0], "hdr:"...)
	out, err = receiver.ReceiveInto(prefix)
	if err != nil || !bytes.HasPrefix(out, []byte("hdr:")) || len(out) != 4+3000 {
		t.Fatalf("append semantics: len %d err %v", len(out), err)
	}
}

// A failed receive leaves the caller's buffer contents alone.
func TestReceiveIntoErrorKeepsDst(t *testing.T) {
	sender, receiver, cleanup := benchStreamPair(t)
	_ = sender
	cleanup() // closes both ends: the next read fails
	dst := []byte("keep")
	out, err := receiver.ReceiveInto(dst)
	if err == nil {
		t.Fatal("expected an error from a closed connection")
	}
	if string(out) != "keep" {
		t.Fatalf("dst changed on error: %q", out)
	}
}
