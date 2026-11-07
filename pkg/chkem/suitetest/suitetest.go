// Package suitetest is the conformance battery every chkem.Suite must pass.
// Built-in suites run it in this repo; authors of external suites should run it
// before calling chkem.RegisterSuite.
package suitetest

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// RoleBinder is an optional interface. A suite that returns true binds the caller
// role into its shared secret, so Run also checks reflection resistance.
type RoleBinder interface{ BindsRole() bool }

// Run exercises s and fails t on any violation.
func Run(t *testing.T, s chkem.Suite) {
	t.Helper()

	kp, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	defer kp.Zeroize()
	if kp.Suite() != s.ID() || kp.PublicKey().Suite() != s.ID() {
		t.Fatalf("key pair carries suite %#x/%#x, want %#x", kp.Suite(), kp.PublicKey().Suite(), s.ID())
	}

	pub := kp.PublicKey()
	if got := len(pub.Bytes()); got != s.PublicKeySize() {
		t.Fatalf("public key is %d bytes, PublicKeySize says %d", got, s.PublicKeySize())
	}
	parsed, err := s.ParsePublicKey(pub.Bytes())
	if err != nil || !bytes.Equal(parsed.Bytes(), pub.Bytes()) {
		t.Fatalf("public key does not round trip: %v", err)
	}
	for _, n := range []int{0, s.PublicKeySize() - 1, s.PublicKeySize() + 1} {
		if _, err := s.ParsePublicKey(make([]byte, n)); err == nil {
			t.Errorf("ParsePublicKey accepted %d bytes", n)
		}
	}

	ct, secret, err := s.Encapsulate(pub, chkem.RoleResponder)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("shared secret is %d bytes, want 32", len(secret))
	}
	if got := len(ct.Bytes()); got != s.CiphertextSize() {
		t.Fatalf("ciphertext is %d bytes, CiphertextSize says %d", got, s.CiphertextSize())
	}
	pct, err := s.ParseCiphertext(ct.Bytes())
	if err != nil || !bytes.Equal(pct.Bytes(), ct.Bytes()) {
		t.Fatalf("ciphertext does not round trip: %v", err)
	}
	for _, n := range []int{0, s.CiphertextSize() - 1, s.CiphertextSize() + 1} {
		if _, err := s.ParseCiphertext(make([]byte, n)); err == nil {
			t.Errorf("ParseCiphertext accepted %d bytes", n)
		}
	}

	got, err := s.Decapsulate(pct, kp, chkem.RoleInitiator)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("decapsulated secret differs from encapsulated: %v", err)
	}

	// A flipped ciphertext bit must never yield the original secret (an error or an
	// implicit-rejection secret are both acceptable).
	for _, bit := range []int{0, s.CiphertextSize()*8/2 + 1, s.CiphertextSize()*8 - 1} {
		raw := ct.Bytes()
		raw[bit/8] ^= 1 << (bit % 8)
		bad, err := s.ParseCiphertext(raw)
		if err != nil {
			continue
		}
		if out, err := s.Decapsulate(bad, kp, chkem.RoleInitiator); err == nil && bytes.Equal(out, secret) {
			t.Errorf("flipped ciphertext bit %d still yields the original secret", bit)
		}
	}

	// A different key pair must not recover the secret.
	other, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair: %v", err)
	}
	defer other.Zeroize()
	if out, err := s.Decapsulate(pct, other, chkem.RoleInitiator); err == nil && bytes.Equal(out, secret) {
		t.Error("wrong key pair recovered the secret")
	}

	if rb, ok := s.(RoleBinder); ok && rb.BindsRole() {
		if out, err := s.Decapsulate(pct, kp, chkem.RoleResponder); err == nil && bytes.Equal(out, secret) {
			t.Error("suite claims role binding but the wrong role recovered the secret")
		}
	}

	// A static identity rebuilds the same public key from its seed.
	sk, seed, err := s.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	defer sk.Zeroize()
	if len(seed) != s.SeedSize() {
		t.Fatalf("seed is %d bytes, SeedSize says %d", len(seed), s.SeedSize())
	}
	again, err := s.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	defer again.Zeroize()
	if !bytes.Equal(again.PublicKey().Bytes(), sk.PublicKey().Bytes()) {
		t.Error("seed does not reproduce the public key")
	}
	if _, err := s.ParseKeyPair(seed[:len(seed)-1]); err == nil {
		t.Error("ParseKeyPair accepted a short seed")
	}

	// Nil inputs fail with an error and never panic.
	if _, _, err := s.Encapsulate(nil, chkem.RoleResponder); err == nil {
		t.Error("Encapsulate accepted a nil public key")
	}
	if _, err := s.Decapsulate(nil, kp, chkem.RoleInitiator); err == nil {
		t.Error("Decapsulate accepted a nil ciphertext")
	}
	if _, err := s.Decapsulate(pct, nil, chkem.RoleInitiator); err == nil {
		t.Error("Decapsulate accepted a nil key pair")
	}

	// Values from a different suite are rejected, not reinterpreted.
	for _, id := range chkem.SupportedSuites() {
		if id == s.ID() {
			continue
		}
		o, ok := chkem.GetSuite(id)
		if !ok {
			continue
		}
		okp, err := o.GenerateKeyPair()
		if err != nil {
			t.Fatalf("suite %#x GenerateKeyPair: %v", id, err)
		}
		oct, _, err := o.Encapsulate(okp.PublicKey(), chkem.RoleResponder)
		if err != nil {
			t.Fatalf("suite %#x Encapsulate: %v", id, err)
		}
		if _, _, err := s.Encapsulate(okp.PublicKey(), chkem.RoleResponder); err == nil {
			t.Errorf("Encapsulate accepted a suite %#x public key", id)
		}
		if _, err := s.Decapsulate(oct, kp, chkem.RoleInitiator); err == nil {
			t.Errorf("Decapsulate accepted a suite %#x ciphertext", id)
		}
		if _, err := s.Decapsulate(pct, okp, chkem.RoleInitiator); err == nil {
			t.Errorf("Decapsulate accepted a suite %#x key pair", id)
		}
		okp.Zeroize()
		break
	}
}
