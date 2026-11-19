package protocol

import (
	"bytes"
	"testing"
)

// The in-place data header must decode back to the sequence number and payload that went in.
func TestAppendDataHeaderRoundTripsThroughDecodeData(t *testing.T) {
	c := NewCodec()
	payload := []byte("sealed payload")
	frame := c.AppendDataHeader([]byte{}, 42, len(payload))
	frame = append(frame, payload...)

	seq, got, err := c.DecodeData(frame)
	if err != nil || seq != 42 || !bytes.Equal(got, payload) {
		t.Fatalf("DecodeData = %d, %q, %v; want 42 and the payload", seq, got, err)
	}
	// The length field drives stream framing, so read the frame back through the stream reader with a
	// trailing byte: a wrong length either cuts the frame short or swallows the extra byte.
	stream := bytes.NewReader(append(append([]byte{}, frame...), 0xFF))
	read, err := c.ReadMessage(stream)
	if err != nil || !bytes.Equal(read, frame) || stream.Len() != 1 {
		t.Fatalf("ReadMessage = %d bytes, %v, %d left; want the whole frame and one byte left", len(read), err, stream.Len())
	}
	// It must also append to existing bytes, not overwrite them.
	prefixed := c.AppendDataHeader([]byte("keep"), 1, 0)
	if !bytes.HasPrefix(prefixed, []byte("keep")) {
		t.Fatal("AppendDataHeader overwrote the bytes before it")
	}
}

// ReadMessageInto must return the same message as the allocating reader, reuse a large enough
// buffer, and grow a small one.
func TestReadMessageIntoReusesAndGrowsTheBuffer(t *testing.T) {
	c := NewCodec()
	msg, err := c.EncodeData(7, []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}

	big := make([]byte, 0, 4096)
	got, err := c.ReadMessageInto(bytes.NewReader(msg), big)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("large buffer: %v, equal=%v", err, bytes.Equal(got, msg))
	}
	if &got[0] != &big[:1][0] {
		t.Error("a large enough buffer was not reused")
	}

	got, err = c.ReadMessageInto(bytes.NewReader(msg), make([]byte, 0, 2))
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("small buffer: %v, equal=%v", err, bytes.Equal(got, msg))
	}
	if _, err := c.ReadMessageInto(bytes.NewReader(msg[:3]), nil); err == nil {
		t.Error("a truncated message read without an error")
	}
}

// The datagram header encoders must agree with the parser, and the data-frame appender must set
// the data type whatever the caller put in the header.
func TestDatagramHeaderEncodersAgreeWithTheParser(t *testing.T) {
	want := DatagramHeader{Type: DatagramFrameData, Epoch: 3, RecvIndex: 0xABCD1234, Seq: 1 << 40}

	got, rest, err := ParseDatagramHeader(EncodeDatagramHeader(want))
	if err != nil || got != want || len(rest) != 0 {
		t.Fatalf("EncodeDatagramHeader round trip = %+v, %d bytes left, %v", got, len(rest), err)
	}

	in := want
	in.Type = DatagramFrameHandshake // AppendDatagramDataHeader must override it
	got, _, err = ParseDatagramHeader(AppendDatagramDataHeader(nil, in))
	if err != nil || got != want {
		t.Fatalf("AppendDatagramDataHeader round trip = %+v, %v; want %+v", got, err, want)
	}
}
