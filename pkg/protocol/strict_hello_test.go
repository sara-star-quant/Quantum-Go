package protocol_test

import (
	"encoding/binary"
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// resized returns enc with its payload cut by drop bytes (negative: extended with
// extra) and the header length fixed, so only the field layout is malformed.
func resized(enc []byte, drop int, extra []byte) []byte {
	out := append([]byte(nil), enc[:len(enc)-drop]...)
	out = append(out, extra...)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(out)-protocol.HeaderSize))
	return out
}

// A hello parses exactly or fails, and a higher minor version may append fields.
func TestClientHelloStrictLayout(t *testing.T) {
	codec := protocol.NewCodec()
	enc, err := codec.EncodeClientHello(validClientHello(t))
	if err != nil {
		t.Fatal(err)
	}
	higher := append([]byte(nil), enc...)
	higher[protocol.HeaderSize+1] = protocol.Current.Minor + 1

	cases := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"exact", enc, true},
		{"missing the PSK flag", resized(enc, 1, nil), false},
		{"missing both flags", resized(enc, 2, nil), false},
		{"one trailing byte", resized(enc, 0, []byte{0}), false},
		{"trailing junk", resized(enc, 0, []byte("junk")), false},
		{"higher minor, exact", higher, true},
		{"higher minor with an unknown field", resized(higher, 0, []byte{9, 9}), true},
	}
	for _, tc := range cases {
		_, err := codec.DecodeClientHello(tc.data)
		if tc.ok && err != nil {
			t.Errorf("%s: rejected: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, qerrors.ErrInvalidMessage) {
			t.Errorf("%s: got %v, want ErrInvalidMessage", tc.name, err)
		}
	}
}

func TestClientHelloRejectsEmptySuiteList(t *testing.T) {
	h := validClientHello(t)
	h.KEMSuites = nil
	if _, err := protocol.NewCodec().EncodeClientHello(h); !errors.Is(err, qerrors.ErrInvalidMessage) {
		t.Fatalf("empty KEMSuites encoded: %v", err)
	}
}

func TestClientHelloOtherMajorReportsTheVersion(t *testing.T) {
	codec := protocol.NewCodec()
	enc, err := codec.EncodeClientHello(validClientHello(t))
	if err != nil {
		t.Fatal(err)
	}
	other := resized(enc, 0, []byte("different layout"))
	other[protocol.HeaderSize] = protocol.Current.Major + 1
	if _, err := codec.DecodeClientHello(other); !errors.Is(err, qerrors.ErrUnsupportedVersion) {
		t.Fatalf("got %v, want ErrUnsupportedVersion", err)
	}
}
