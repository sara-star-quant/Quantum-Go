package protocol

import (
	"bytes"
	"testing"
)

func TestDatagramData_RoundTrip(t *testing.T) {
	h := DatagramHeader{Epoch: 3, RecvIndex: 0xDEADBEEF, Seq: 0x0102030405060708}
	ct := []byte("encrypted-bytes-plus-tag")
	frame := EncodeDatagramData(h, ct)

	if got, err := PeekDatagramType(frame); err != nil || got != DatagramFrameData {
		t.Fatalf("PeekDatagramType = %v, %v; want DATA", got, err)
	}

	gotH, body, err := ParseDatagramHeader(frame)
	if err != nil {
		t.Fatalf("ParseDatagramHeader: %v", err)
	}
	if gotH.Type != DatagramFrameData || gotH.Epoch != h.Epoch ||
		gotH.RecvIndex != h.RecvIndex || gotH.Seq != h.Seq {
		t.Fatalf("header mismatch: got %+v want %+v", gotH, h)
	}
	if !bytes.Equal(body, ct) {
		t.Fatalf("body mismatch: got %q want %q", body, ct)
	}
	if !bytes.Equal(DatagramAAD(frame), frame[:DatagramHeaderSize]) {
		t.Fatal("AAD is not the common header")
	}
}

func TestDatagramHandshake_RoundTrip(t *testing.T) {
	frag := []byte("fragment-payload")
	h := DatagramHandshakeHeader{
		DatagramHeader: DatagramHeader{Epoch: 0, RecvIndex: 0, Seq: 7},
		SenderIndex:    0x11223344,
		MsgType:        MessageTypeClientHello,
		FragOffset:     0,
		FragLength:     uint16(len(frag)),
		TotalLength:    uint16(len(frag) * 2),
	}
	frame, err := EncodeDatagramHandshake(h, frag)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got, _ := PeekDatagramType(frame); got != DatagramFrameHandshake {
		t.Fatalf("type = %v want HANDSHAKE", got)
	}

	gotH, gotFrag, err := ParseDatagramHandshake(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotH.SenderIndex != h.SenderIndex || gotH.MsgType != h.MsgType ||
		gotH.FragOffset != h.FragOffset || gotH.FragLength != h.FragLength ||
		gotH.TotalLength != h.TotalLength {
		t.Fatalf("handshake header mismatch: got %+v want %+v", gotH, h)
	}
	if !bytes.Equal(gotFrag, frag) {
		t.Fatalf("fragment mismatch: got %q want %q", gotFrag, frag)
	}
	if len(gotH.Cookie) != 0 {
		t.Fatalf("cookie should be empty when none is set, got %d bytes", len(gotH.Cookie))
	}
}

func TestDatagramHandshake_CookieRoundTrip(t *testing.T) {
	frag := []byte("x")
	cookie := []byte("test-cookie")
	h := DatagramHandshakeHeader{
		DatagramHeader: DatagramHeader{Seq: 1},
		MsgType:        MessageTypeClientHello,
		FragLength:     uint16(len(frag)),
		TotalLength:    uint16(len(frag)),
		Cookie:         cookie,
	}
	frame, err := EncodeDatagramHandshake(h, frag)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotH, gotFrag, err := ParseDatagramHandshake(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(gotH.Cookie, cookie) {
		t.Fatalf("cookie mismatch: got %q want %q", gotH.Cookie, cookie)
	}
	if !bytes.Equal(gotFrag, frag) {
		t.Fatalf("fragment mismatch after cookie: got %q want %q", gotFrag, frag)
	}
}

func TestDatagramHandshake_Rejects(t *testing.T) {
	// FragOffset+FragLength beyond TotalLength must be rejected.
	frag := []byte("0123456789")
	h := DatagramHandshakeHeader{
		DatagramHeader: DatagramHeader{},
		MsgType:        MessageTypeClientHello,
		FragOffset:     5,
		FragLength:     uint16(len(frag)),
		TotalLength:    8, // 5+10 > 8
	}
	frame, err := EncodeDatagramHandshake(h, frag)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := ParseDatagramHandshake(frame); err == nil {
		t.Fatal("expected rejection of fragment exceeding total length")
	}

	// Truncated frame must be rejected, not panic.
	if _, _, err := ParseDatagramHandshake(frame[:DatagramHeaderSize+2]); err == nil {
		t.Fatal("expected rejection of truncated handshake frame")
	}
	if _, err := PeekDatagramType(frame[:3]); err == nil {
		t.Fatal("expected rejection of too-short datagram")
	}
}
