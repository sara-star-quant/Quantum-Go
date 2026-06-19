package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

func mkSecret(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestDeriveAuthenticatedSecret(t *testing.T) {
	eph := mkSecret(0x11)
	static := mkSecret(0x22)

	out, err := crypto.DeriveAuthenticatedSecret(eph, static)
	if err != nil {
		t.Fatalf("DeriveAuthenticatedSecret: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("output length: got %d, want 32", len(out))
	}

	// Deterministic.
	out2, _ := crypto.DeriveAuthenticatedSecret(eph, static)
	if !bytes.Equal(out, out2) {
		t.Error("not deterministic for identical inputs")
	}

	// Differs from the bare ephemeral secret (the fold actually mixes).
	if bytes.Equal(out, eph) {
		t.Error("output equals the ephemeral secret; static secret not mixed in")
	}

	// Order-sensitive: swapping the two inputs changes the output.
	swapped, _ := crypto.DeriveAuthenticatedSecret(static, eph)
	if bytes.Equal(out, swapped) {
		t.Error("output is not order-sensitive")
	}

	// Forward-secrecy evidence: the same static secret with a different ephemeral
	// secret yields a different master secret.
	other, _ := crypto.DeriveAuthenticatedSecret(mkSecret(0x33), static)
	if bytes.Equal(out, other) {
		t.Error("different ephemeral secret produced the same master secret")
	}
}

func TestDeriveAuthenticatedSecretRejectsWrongLength(t *testing.T) {
	good := mkSecret(0x01)
	if _, err := crypto.DeriveAuthenticatedSecret(good[:16], good); err == nil {
		t.Error("expected error for short ephemeral secret")
	}
	if _, err := crypto.DeriveAuthenticatedSecret(good, good[:31]); err == nil {
		t.Error("expected error for short static secret")
	}
}
