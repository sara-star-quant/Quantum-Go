package chkem

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// TestXWingSuiteRoundTrip exercises the X-Wing suite through the Suite interface:
// generate, serialize/parse the public key and ciphertext, and encapsulate then
// decapsulate to a matching 32-byte secret.
func TestXWingSuiteRoundTrip(t *testing.T) {
	s, ok := GetSuite(SuiteXWing)
	if !ok {
		t.Fatal("X-Wing suite is not registered")
	}
	if s.PublicKeySize() != constants.XWingPublicKeySize ||
		s.CiphertextSize() != constants.XWingCiphertextSize ||
		s.SeedSize() != constants.XWingSeedSize {
		t.Fatalf("unexpected sizes: pub=%d ct=%d seed=%d", s.PublicKeySize(), s.CiphertextSize(), s.SeedSize())
	}

	kp, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubBytes := kp.PublicKey().Bytes()
	if len(pubBytes) != constants.XWingPublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(pubBytes), constants.XWingPublicKeySize)
	}

	pub, err := s.ParsePublicKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	ct, ss, err := s.Encapsulate(pub, RoleResponder)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ss) != constants.CHKEMSharedSecretSize {
		t.Fatalf("shared secret length = %d, want %d", len(ss), constants.CHKEMSharedSecretSize)
	}

	ct2, err := s.ParseCiphertext(ct.Bytes())
	if err != nil {
		t.Fatalf("ParseCiphertext: %v", err)
	}
	ss2, err := s.Decapsulate(ct2, kp, RoleInitiator)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("decapsulated secret does not match")
	}
}

// TestXWingStaticKeyPairDeterministic confirms a static X-Wing identity round-trips
// from its seed to the same public pin.
func TestXWingStaticKeyPairDeterministic(t *testing.T) {
	s, _ := GetSuite(SuiteXWing)
	kp, seed, err := s.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	if len(seed) != constants.XWingSeedSize {
		t.Fatalf("seed length = %d, want %d", len(seed), constants.XWingSeedSize)
	}
	kp2, err := s.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	if !bytes.Equal(kp.PublicKey().Bytes(), kp2.PublicKey().Bytes()) {
		t.Fatal("static key pair did not reconstruct the same public pin from its seed")
	}
}

// TestSupportedSuitesIncludesXWing confirms the registry advertises X-Wing after v1.
func TestSupportedSuitesIncludesXWing(t *testing.T) {
	ids := SupportedSuites()
	if len(ids) < 2 || ids[0] != SuiteCHKEMv1 || ids[1] != SuiteXWing {
		t.Fatalf("SupportedSuites = %v, want [CH-KEM-v1, X-Wing]", ids)
	}
}
