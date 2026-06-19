package protocol_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func validClientHello(t *testing.T) *protocol.ClientHello {
	t.Helper()
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	random := make([]byte, 32)
	_ = crypto.SecureRandom(random)
	return &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         random,
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}
}

func TestClientHelloStaticCiphertextRoundTrip(t *testing.T) {
	codec := protocol.NewCodec()

	// Absent: the presence flag is written but the field stays empty.
	plain := validClientHello(t)
	enc, err := codec.EncodeClientHello(plain)
	if err != nil {
		t.Fatalf("encode (no static ct): %v", err)
	}
	dec, err := codec.DecodeClientHello(enc)
	if err != nil {
		t.Fatalf("decode (no static ct): %v", err)
	}
	if len(dec.CHKEMStaticCiphertext) != 0 {
		t.Errorf("expected empty static ct, got %d bytes", len(dec.CHKEMStaticCiphertext))
	}

	// Present: a full-size static ciphertext round-trips byte-for-byte.
	withCT := validClientHello(t)
	ct := make([]byte, constants.CHKEMCiphertextSize)
	for i := range ct {
		ct[i] = byte(i)
	}
	withCT.CHKEMStaticCiphertext = ct
	enc2, err := codec.EncodeClientHello(withCT)
	if err != nil {
		t.Fatalf("encode (with static ct): %v", err)
	}
	// The authenticated ClientHello is exactly the static block larger.
	if len(enc2) != len(enc)+constants.CHKEMCiphertextSize {
		t.Errorf("size delta: got %d, want %d", len(enc2)-len(enc), constants.CHKEMCiphertextSize)
	}
	dec2, err := codec.DecodeClientHello(enc2)
	if err != nil {
		t.Fatalf("decode (with static ct): %v", err)
	}
	if !bytes.Equal(dec2.CHKEMStaticCiphertext, ct) {
		t.Error("static ciphertext did not round-trip")
	}
}

func TestClientHelloStaticCiphertextWrongSizeRejected(t *testing.T) {
	codec := protocol.NewCodec()
	m := validClientHello(t)
	m.CHKEMStaticCiphertext = make([]byte, 100) // not 0 and not CHKEMCiphertextSize
	if _, err := codec.EncodeClientHello(m); err == nil {
		t.Error("expected Validate to reject a wrong-size static ciphertext")
	}
}

func TestClientHelloStaticCiphertextDecodeBounds(t *testing.T) {
	codec := protocol.NewCodec()

	// Take a valid unauthenticated ClientHello and flip its trailing presence
	// byte to "present" without appending the 1600-byte body. The decoder must
	// reject it (bounds check), not panic.
	enc, err := codec.EncodeClientHello(validClientHello(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tampered := append([]byte(nil), enc...)
	tampered[len(tampered)-1] = 1 // claim a static ct is present
	if _, err := codec.DecodeClientHello(tampered); err == nil {
		t.Error("expected ErrInvalidMessage for present flag with truncated body")
	}

	// An unknown flag value (not 1) is treated as absent, not an error.
	tampered2 := append([]byte(nil), enc...)
	tampered2[len(tampered2)-1] = 2
	dec, err := codec.DecodeClientHello(tampered2)
	if err != nil {
		t.Fatalf("decode with flag=2 should succeed: %v", err)
	}
	if len(dec.CHKEMStaticCiphertext) != 0 {
		t.Error("flag=2 should not populate the static ciphertext")
	}
}
