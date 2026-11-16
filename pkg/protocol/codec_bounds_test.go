package protocol

import (
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// hello builds a hello message of the given type whose payload is payloadLen bytes: the current
// version, 32 random bytes, then a session-ID length byte, then zeros. extraCap leaves spare
// capacity after the message, as a reused read buffer does.
func hello(typ MessageType, payloadLen int, sessionIDLen byte, extraCap int) []byte {
	msg := make([]byte, HeaderSize+payloadLen, HeaderSize+payloadLen+extraCap)
	msg[0] = byte(typ)
	msg[1], msg[2], msg[3], msg[4] = byte(payloadLen>>24), byte(payloadLen>>16), byte(payloadLen>>8), byte(payloadLen)
	msg[HeaderSize] = Current.Major
	msg[HeaderSize+1] = Current.Minor
	msg[HeaderSize+2+32] = sessionIDLen
	return msg
}

// A session-ID length that runs past the payload must be refused, not sliced: a server reads this
// message from a stranger before any authentication, and a client reads it from a server that
// may be hostile. The panic this guards against ended the whole process.
func TestHelloSessionIDLengthIsBoundedByThePayload(t *testing.T) {
	c := NewCodec()
	decoders := map[string]struct {
		typ    MessageType
		decode func([]byte) error
	}{
		"ClientHello": {MessageTypeClientHello, func(d []byte) error { _, err := c.DecodeClientHello(d); return err }},
		"ServerHello": {MessageTypeServerHello, func(d []byte) error { _, err := c.DecodeServerHello(d); return err }},
	}
	const payloadLen = 60
	const remaining = payloadLen - (2 + 32 + 1) // bytes left after the session-ID length byte
	for name, d := range decoders {
		for _, extraCap := range []int{0, 512} {
			for n := 0; n <= 255; n++ {
				err := d.decode(hello(d.typ, payloadLen, byte(n), extraCap))
				if n > remaining && !errors.Is(err, qerrors.ErrInvalidMessage) {
					t.Fatalf("%s: session ID length %d with %d payload bytes left (cap +%d): got %v, want ErrInvalidMessage", name, n, remaining, extraCap, err)
				}
			}
		}
	}
}
