package chkem_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

func TestGenerateStaticKeyPairRoundTrip(t *testing.T) {
	kp, seed, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	if len(seed) != chkem.StaticKeySeedSize {
		t.Fatalf("seed length: got %d, want %d", len(seed), chkem.StaticKeySeedSize)
	}

	// Reconstructing from the seed reproduces the same public pin.
	rebuilt, err := chkem.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	if !bytes.Equal(kp.PublicKey().Bytes(), rebuilt.PublicKey().Bytes()) {
		t.Error("reconstructed public key differs from the original (pin would not survive a restart)")
	}

	// The reconstructed private key actually works: a fresh exchange round-trips.
	ct, ssEnc, err := chkem.Encapsulate(rebuilt.PublicKey(), chkem.RoleResponder)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ssDec, err := chkem.Decapsulate(ct, rebuilt, chkem.RoleInitiator)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Error("reconstructed key pair failed a round-trip")
	}
}

func TestParseKeyPairRejectsBadSeed(t *testing.T) {
	if _, err := chkem.ParseKeyPair(make([]byte, chkem.StaticKeySeedSize-1)); err == nil {
		t.Error("expected error for short seed")
	}
	if _, err := chkem.ParseKeyPair(nil); err == nil {
		t.Error("expected error for nil seed")
	}
}

func TestGenerateStaticKeyPairDistinct(t *testing.T) {
	_, s1, _ := chkem.GenerateStaticKeyPair()
	_, s2, _ := chkem.GenerateStaticKeyPair()
	if bytes.Equal(s1, s2) {
		t.Error("two generated static seeds are identical")
	}
}
