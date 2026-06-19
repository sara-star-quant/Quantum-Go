package protocol_test

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// TestClientHelloVariableKeySizeRoundTrips confirms the length-prefixed wire carries
// a key share of a non-v1 size (X-Wing's 1216 bytes here), proving the codec no longer
// hardcodes the CH-KEM-v1 size.
func TestClientHelloVariableKeySizeRoundTrips(t *testing.T) {
	codec := protocol.NewCodec()
	const xwingPubKeySize = 1216
	pub := make([]byte, xwingPubKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	m := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         make([]byte, 32),
		KEMSuite:       0x0002,
		KEMSuites:      []uint16{0x0002, 0x0001},
		CHKEMPublicKey: pub,
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}
	enc, err := codec.EncodeClientHello(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := codec.DecodeClientHello(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec.CHKEMPublicKey) != xwingPubKeySize {
		t.Errorf("public key length: got %d, want %d", len(dec.CHKEMPublicKey), xwingPubKeySize)
	}
}

// TestClientHelloLengthPrefixOverRead rejects a key-share length prefix that claims
// more bytes than the payload holds, so a malformed length cannot over-read.
func TestClientHelloLengthPrefixOverRead(t *testing.T) {
	codec := protocol.NewCodec()
	m := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         make([]byte, 32),
		KEMSuite:       uint16(chkemv1ID()),
		KEMSuites:      []uint16{uint16(chkemv1ID())},
		CHKEMPublicKey: make([]byte, constants.CHKEMPublicKeySize),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}
	enc, err := codec.EncodeClientHello(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Inflate the key-share length prefix to 0xFFFF. The prefix sits right after
	// version(2)+random(32)+sessionIDLen(1)+kemSuite(2)+kemCount(1)+suite(2).
	off := protocol.HeaderSize + 2 + 32 + 1 + 2 + 1 + 2
	enc[off] = 0xFF
	enc[off+1] = 0xFF
	if _, err := codec.DecodeClientHello(enc); err == nil {
		t.Fatal("expected error for an over-long key-share length prefix")
	}
}

// TestVersionMismatchRejected confirms a peer at a different major version is rejected
// (IsCompatible is major-only), so a 4.x hello fails against this 5.0 build.
func TestVersionMismatchRejected(t *testing.T) {
	older := protocol.Version{Major: protocol.Current.Major - 1, Minor: 0}
	if older.IsCompatible(protocol.Current) {
		t.Fatalf("version %s should be incompatible with %s", older, protocol.Current)
	}
}

func chkemv1ID() uint16 { return 0x0001 }
