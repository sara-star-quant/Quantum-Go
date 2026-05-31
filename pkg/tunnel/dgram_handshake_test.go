package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func TestFragmentHandshake_RoundTrip(t *testing.T) {
	// A message larger than one datagram must split and reassemble exactly.
	msg := make([]byte, 1644) // ~ ClientHello size, exceeds the 1200 MTU
	for i := range msg {
		msg[i] = byte(i)
	}
	base := protocol.DatagramHandshakeHeader{
		DatagramHeader: protocol.DatagramHeader{RecvIndex: 7, Seq: 100},
		SenderIndex:    42,
		MsgType:        protocol.MessageTypeClientHello,
	}

	frames, err := fragmentHandshake(base, msg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected multiple fragments for %d bytes, got %d", len(msg), len(frames))
	}

	// Reassemble in reverse order to exercise reordering tolerance.
	r := NewReassembler(4, 8192, time.Second)
	var out []byte
	var done bool
	for i := len(frames) - 1; i >= 0; i-- {
		if len(frames[i]) > constants.DatagramMTU {
			t.Fatalf("frame %d is %d bytes, over MTU %d", i, len(frames[i]), constants.DatagramMTU)
		}
		h, frag, perr := protocol.ParseDatagramHandshake(frames[i])
		if perr != nil {
			t.Fatalf("frame %d parse: %v", i, perr)
		}
		out, done, err = r.Add("peer", h, frag)
		if err != nil {
			t.Fatalf("frame %d reassemble: %v", i, err)
		}
	}
	if !done {
		t.Fatal("reassembly did not complete")
	}
	if !bytes.Equal(out, msg) {
		t.Fatal("reassembled message differs from the original")
	}
}

func TestFragmentHandshake_SingleFragment(t *testing.T) {
	base := protocol.DatagramHandshakeHeader{MsgType: protocol.MessageTypeClientHello}
	frames, err := fragmentHandshake(base, []byte("short message"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("a small message should be one frame, got %d", len(frames))
	}
}

func TestFragmentHandshake_RejectsEmptyAndOversize(t *testing.T) {
	base := protocol.DatagramHandshakeHeader{MsgType: protocol.MessageTypeClientHello}
	if _, err := fragmentHandshake(base, nil, false); err == nil {
		t.Fatal("an empty message must be rejected")
	}
	big := make([]byte, constants.DatagramMaxHandshakeMessageSize+1)
	if _, err := fragmentHandshake(base, big, false); err == nil {
		t.Fatal("an oversize message must be rejected")
	}
}
