package fuzz

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// FuzzDecodeHelloRetryRequest feeds the HelloRetryRequest decoder, which an off-path
// or active attacker can reach before authentication.
func FuzzDecodeHelloRetryRequest(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{byte(protocol.MessageTypeHelloRetryRequest), 0, 0, 0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = protocol.NewCodec().DecodeHelloRetryRequest(data)
	})
}

// FuzzDecodeFinished checks the Finished decoder never panics, and that a message
// it accepts re-encodes to the same verify data.
func FuzzDecodeFinished(f *testing.F) {
	c := protocol.NewCodec()
	if seed, err := c.EncodeFinished(protocol.MessageTypeClientFinished, make([]byte, 32)); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		vd, err := c.DecodeFinished(data)
		if err != nil {
			return
		}
		if _, err := c.EncodeFinished(protocol.MessageTypeClientFinished, vd); err != nil {
			t.Fatalf("accepted verify data does not re-encode: %v", err)
		}
	})
}

// FuzzDecodeRekey covers both rekey decoders (outer message and inner payload).
func FuzzDecodeRekey(f *testing.F) {
	c := protocol.NewCodec()
	if seed, err := c.EncodeRekey(7, make([]byte, 40)); err == nil {
		f.Add(seed)
	}
	if seed, err := c.EncodeRekeyPayload(make([]byte, 32), 9); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = c.DecodeRekey(data)
		_, _, _ = c.DecodeRekeyPayload(data)
	})
}

// FuzzParseDatagramHeader exercises the data-frame header parser that every received
// datagram reaches first; a header it accepts must re-encode and parse back the same.
func FuzzParseDatagramHeader(f *testing.F) {
	f.Add(protocol.AppendDatagramDataHeader(nil, protocol.DatagramHeader{Epoch: 1, RecvIndex: 9, Seq: 77}))
	f.Add([]byte{0x01})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = protocol.PeekDatagramType(data)
		h, _, err := protocol.ParseDatagramHeader(data)
		if err != nil {
			return
		}
		again, _, err := protocol.ParseDatagramHeader(protocol.AppendDatagramDataHeader(nil, h))
		if err != nil || again.Epoch != h.Epoch || again.RecvIndex != h.RecvIndex || again.Seq != h.Seq {
			t.Fatalf("header round trip mismatch: %+v -> %+v (%v)", h, again, err)
		}
	})
}
