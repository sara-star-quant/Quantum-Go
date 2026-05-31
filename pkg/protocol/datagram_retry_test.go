package protocol

import (
	"bytes"
	"testing"
)

func TestRetryRoundTrip(t *testing.T) {
	cookie := []byte("opaque-stateless-cookie-bytes")
	frame := EncodeDatagramRetry(0xA1B2C3D4, cookie)

	ft, err := PeekDatagramType(frame)
	if err != nil {
		t.Fatalf("PeekDatagramType: %v", err)
	}
	if ft != DatagramFrameRetry {
		t.Fatalf("frame type = %#x, want %#x", ft, DatagramFrameRetry)
	}

	idx, got, err := ParseDatagramRetry(frame)
	if err != nil {
		t.Fatalf("ParseDatagramRetry: %v", err)
	}
	if idx != 0xA1B2C3D4 {
		t.Fatalf("recvIndex = %#x, want 0xA1B2C3D4", idx)
	}
	if !bytes.Equal(got, cookie) {
		t.Fatalf("cookie = %q, want %q", got, cookie)
	}
}

func TestRetryRejectsWrongType(t *testing.T) {
	// A DATA frame must not parse as RETRY.
	data := EncodeDatagramData(DatagramHeader{RecvIndex: 1, Seq: 1}, []byte("ct"))
	if _, _, err := ParseDatagramRetry(data); err == nil {
		t.Fatal("ParseDatagramRetry accepted a non-RETRY frame")
	}
}

func TestRetryRejectsShort(t *testing.T) {
	if _, _, err := ParseDatagramRetry([]byte{0x04, 0x00}); err == nil {
		t.Fatal("ParseDatagramRetry accepted a truncated header")
	}
}

func TestRetryEmptyCookie(t *testing.T) {
	frame := EncodeDatagramRetry(7, nil)
	idx, cookie, err := ParseDatagramRetry(frame)
	if err != nil {
		t.Fatalf("ParseDatagramRetry: %v", err)
	}
	if idx != 7 || len(cookie) != 0 {
		t.Fatalf("got idx=%d cookieLen=%d, want idx=7 cookieLen=0", idx, len(cookie))
	}
}
