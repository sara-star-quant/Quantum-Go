package fuzz

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// FuzzParseDatagramRetry exercises the RETRY frame parser an off-path attacker can
// reach: a malformed RETRY must never panic, and a well-formed one must round-trip.
func FuzzParseDatagramRetry(f *testing.F) {
	f.Add(protocol.EncodeDatagramRetry(0, nil))
	f.Add(protocol.EncodeDatagramRetry(0x01020304, []byte("cookie")))
	f.Add([]byte{0x04})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		idx, cookie, err := protocol.ParseDatagramRetry(data)
		if err != nil {
			return
		}
		// A successful parse must re-encode to a frame that parses back identically.
		reenc := protocol.EncodeDatagramRetry(idx, cookie)
		idx2, cookie2, err := protocol.ParseDatagramRetry(reenc)
		if err != nil {
			t.Fatalf("re-parse of a valid RETRY failed: %v", err)
		}
		if idx2 != idx || string(cookie2) != string(cookie) {
			t.Fatalf("RETRY round-trip mismatch: (%d,%q) != (%d,%q)", idx2, cookie2, idx, cookie)
		}
	})
}

// FuzzParseDatagramHandshake exercises the handshake-frame parser, including the
// cookie-bearing path used by the anti-DoS gate. Malformed input must never panic.
func FuzzParseDatagramHandshake(f *testing.F) {
	seed, _ := protocol.EncodeDatagramHandshake(protocol.DatagramHandshakeHeader{
		SenderIndex: 7,
		MsgType:     protocol.MessageTypeClientHello,
		FragLength:  5,
		TotalLength: 5,
		Cookie:      []byte("a-cookie"),
	}, []byte("hello"))
	f.Add(seed)
	f.Add([]byte{0x01})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, fragment, err := protocol.ParseDatagramHandshake(data)
		if err != nil {
			return
		}
		// Invariants the parser must guarantee on success.
		if int(h.FragLength) != len(fragment) {
			t.Fatalf("FragLength %d != fragment len %d", h.FragLength, len(fragment))
		}
		if int(h.FragOffset)+int(h.FragLength) > int(h.TotalLength) {
			t.Fatalf("fragment exceeds total: off=%d len=%d total=%d",
				h.FragOffset, h.FragLength, h.TotalLength)
		}
	})
}
