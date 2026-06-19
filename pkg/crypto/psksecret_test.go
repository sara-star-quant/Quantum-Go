package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

func TestDerivePSKSecret(t *testing.T) {
	master := mkSecret(0x11)
	psk := mkSecret(0x22)

	out, err := crypto.DerivePSKSecret(master, psk)
	if err != nil {
		t.Fatalf("DerivePSKSecret: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("output length: got %d, want 32", len(out))
	}

	// Deterministic.
	out2, _ := crypto.DerivePSKSecret(master, psk)
	if !bytes.Equal(out, out2) {
		t.Error("not deterministic for identical inputs")
	}

	// The fold actually mixes the PSK.
	if bytes.Equal(out, master) {
		t.Error("output equals the master secret; PSK not mixed in")
	}

	// A different PSK yields a different secret (mutual-auth separation).
	other, _ := crypto.DerivePSKSecret(master, mkSecret(0x33))
	if bytes.Equal(out, other) {
		t.Error("different PSK produced the same secret")
	}

	// Forward secrecy: the same PSK with a different master secret differs.
	fs, _ := crypto.DerivePSKSecret(mkSecret(0x44), psk)
	if bytes.Equal(out, fs) {
		t.Error("different master secret produced the same secret")
	}

	// Domain separation from the static-key fold: same inputs, different secret.
	auth, _ := crypto.DeriveAuthenticatedSecret(master, psk)
	if bytes.Equal(out, auth) {
		t.Error("PSK fold collides with the static-key fold for identical inputs")
	}
}

func TestDerivePSKSecretRejectsWrongLength(t *testing.T) {
	good := mkSecret(0x01)
	if _, err := crypto.DerivePSKSecret(good[:16], good); err == nil {
		t.Error("expected error for short master secret")
	}
	if _, err := crypto.DerivePSKSecret(good, good[:31]); err == nil {
		t.Error("expected error for short PSK")
	}
}
