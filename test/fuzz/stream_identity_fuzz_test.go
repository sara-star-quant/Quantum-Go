package fuzz

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// FuzzReadMessage feeds the stream framing reader, the first code an unauthenticated TCP peer
// reaches. Both readers must agree, and an accepted message must be exactly header plus payload.
func FuzzReadMessage(f *testing.F) {
	c := protocol.NewCodec()
	if seed, err := c.EncodeFinished(protocol.MessageTypeClientFinished, make([]byte, 32)); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(nil))
	f.Add([]byte{1, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := c.ReadMessage(bytes.NewReader(data))
		into, err2 := c.ReadMessageInto(bytes.NewReader(data), nil)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("readers disagree: %v vs %v", err, err2)
		}
		if err != nil {
			return
		}
		if !bytes.Equal(msg, into) {
			t.Fatal("readers returned different messages")
		}
		if len(msg) > len(data) {
			t.Fatalf("read %d bytes from %d", len(msg), len(data))
		}
	})
}

// FuzzParseStaticKeys covers the suite-tagged pin and identity parsers that load operator
// supplied key files, plus the X-Wing public key parser.
func FuzzParseStaticKeys(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = chkem.ParseTaggedKeyPair(data)
		_, _ = chkem.ParseTaggedPublicKey(data)
		_, _ = crypto.ParseXWingPublicKey(data)
	})
}
