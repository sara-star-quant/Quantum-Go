package protocol

import (
	"bytes"
	"testing"
)

// TestParseDatagramHandshake_TrailingPadding verifies the parser accepts a frame
// carrying trailing padding after the fragment payload (optional
// anti-fingerprinting padding) and returns exactly the unpadded fragment, leaving
// the padding out of the reassembled message and the handshake transcript.
func TestParseDatagramHandshake_TrailingPadding(t *testing.T) {
	frag := []byte("fragment-payload")
	h := DatagramHandshakeHeader{
		DatagramHeader: DatagramHeader{Seq: 9},
		SenderIndex:    0xAABBCCDD,
		MsgType:        MessageTypeClientHello,
		FragLength:     uint16(len(frag)),
		TotalLength:    uint16(len(frag)),
	}
	frame, err := EncodeDatagramHandshake(h, frag)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Append trailing zero padding, as fragmentHandshake does when padding is on.
	padded := append(append([]byte(nil), frame...), make([]byte, 64)...)

	gotH, gotFrag, err := ParseDatagramHandshake(padded)
	if err != nil {
		t.Fatalf("parse padded frame: %v", err)
	}
	if gotH.FragLength != h.FragLength || gotH.TotalLength != h.TotalLength {
		t.Fatalf("length fields changed by padding: got frag=%d total=%d", gotH.FragLength, gotH.TotalLength)
	}
	if !bytes.Equal(gotFrag, frag) {
		t.Fatalf("padded fragment not sliced to FragLength: got %q want %q", gotFrag, frag)
	}

	// An unpadded frame must still parse identically (backward compatible).
	gotH2, gotFrag2, err := ParseDatagramHandshake(frame)
	if err != nil {
		t.Fatalf("parse unpadded frame: %v", err)
	}
	if !bytes.Equal(gotFrag2, frag) || gotH2.FragLength != h.FragLength {
		t.Fatal("unpadded frame did not round-trip unchanged")
	}
}

// TestParseDatagramHandshake_RejectsUnderrun verifies a frame whose present bytes
// are fewer than FragLength claims is still rejected (padding tolerance only
// accepts EXTRA trailing bytes, never a short fragment).
func TestParseDatagramHandshake_RejectsUnderrun(t *testing.T) {
	frag := []byte("0123456789")
	h := DatagramHandshakeHeader{
		MsgType:     MessageTypeClientHello,
		FragLength:  uint16(len(frag)),
		TotalLength: uint16(len(frag)),
	}
	frame, err := EncodeDatagramHandshake(h, frag)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Drop the last 3 fragment bytes so present bytes < FragLength.
	if _, _, err := ParseDatagramHandshake(frame[:len(frame)-3]); err == nil {
		t.Fatal("expected rejection when present bytes are fewer than FragLength")
	}
}
