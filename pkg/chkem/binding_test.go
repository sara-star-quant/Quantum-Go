package chkem

import (
	"bytes"
	"testing"
)

// These tests check the CH-KEM-v1 key combination against the binding properties of Cremers, Dax
// and Medinger ("Keeping Up with the KEMs", ACM CCS 2024), in the honest-key (HON) and leaked-key
// (LEAK) forms: the shared key K binds the ciphertexts (X-BIND-K-CT) and the public keys
// (X-BIND-K-PK). They call combineKey directly with the component secrets held equal, which is the
// situation a collision attack creates, and vary one bound value at a time. The malicious-key (MAL)
// forms are out of scope: the handshake never lets an adversary choose our key pairs.

// combineInputs holds every value combineKey takes, with realistic sizes.
type combineInputs struct {
	x25519Secret, mlkemSecret []byte
	pkX25519, pkMLKEM         []byte
	ctX25519, ctMLKEM         []byte
	version                   []byte
	role                      Role
}

func filledBytes(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func baseInputs() combineInputs {
	return combineInputs{
		x25519Secret: filledBytes(32, 0x01),
		mlkemSecret:  filledBytes(32, 0x02),
		pkX25519:     filledBytes(32, 0x03),
		pkMLKEM:      filledBytes(1568, 0x04),
		ctX25519:     filledBytes(32, 0x05),
		ctMLKEM:      filledBytes(1568, 0x06),
		version:      []byte{0x06, 0x00},
		role:         RoleResponder,
	}
}

func (c combineInputs) clone() combineInputs {
	for _, f := range []*[]byte{&c.x25519Secret, &c.mlkemSecret, &c.pkX25519, &c.pkMLKEM, &c.ctX25519, &c.ctMLKEM, &c.version} {
		*f = append([]byte(nil), *f...)
	}
	return c
}

func (c combineInputs) key(t *testing.T) []byte {
	t.Helper()
	k, err := combineKey(c.x25519Secret, c.mlkemSecret, c.pkX25519, c.pkMLKEM, c.ctX25519, c.ctMLKEM, c.version, c.role)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCombinerIsDeterministicAndFillsTheKey(t *testing.T) {
	a, b := baseInputs().key(t), baseInputs().key(t)
	if !bytes.Equal(a, b) {
		t.Fatal("the same inputs derived different keys")
	}
	if len(a) != 32 || bytes.Equal(a, make([]byte, 32)) {
		t.Fatalf("key = %x, want 32 non-zero bytes", a)
	}
}

// With the component secrets equal, changing any one bound value must change K. The first byte
// and the last byte of the large values both change it, so a derivation that hashes only a prefix
// of a key or ciphertext fails. Every variation must also differ from every other, so two inputs
// cannot map to the same key.
func TestCombinerKeyBindsEveryBoundValue(t *testing.T) {
	flipFirst := func(b []byte) { b[0] ^= 0x80 }
	flipLast := func(b []byte) { b[len(b)-1] ^= 0x01 }
	cases := []struct {
		name   string
		change func(*combineInputs)
	}{
		{"X-BIND-K-PK: X25519 public key, first byte", func(c *combineInputs) { flipFirst(c.pkX25519) }},
		{"X-BIND-K-PK: X25519 public key, last byte", func(c *combineInputs) { flipLast(c.pkX25519) }},
		{"X-BIND-K-PK: ML-KEM public key, first byte", func(c *combineInputs) { flipFirst(c.pkMLKEM) }},
		{"X-BIND-K-PK: ML-KEM public key, last byte", func(c *combineInputs) { flipLast(c.pkMLKEM) }},
		{"X-BIND-K-CT: X25519 ephemeral key, first byte", func(c *combineInputs) { flipFirst(c.ctX25519) }},
		{"X-BIND-K-CT: X25519 ephemeral key, last byte", func(c *combineInputs) { flipLast(c.ctX25519) }},
		{"X-BIND-K-CT: ML-KEM ciphertext, first byte", func(c *combineInputs) { flipFirst(c.ctMLKEM) }},
		{"X-BIND-K-CT: ML-KEM ciphertext, last byte", func(c *combineInputs) { flipLast(c.ctMLKEM) }},
		{"protocol version", func(c *combineInputs) { flipLast(c.version) }},
		{"role", func(c *combineInputs) { c.role = RoleInitiator }},
		{"X25519 component secret", func(c *combineInputs) { flipFirst(c.x25519Secret) }},
		{"ML-KEM component secret", func(c *combineInputs) { flipFirst(c.mlkemSecret) }},
	}
	base := baseInputs().key(t)
	seen := map[string]string{string(base): "the base inputs"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInputs().clone()
			tc.change(&in)
			k := in.key(t)
			if bytes.Equal(k, base) {
				t.Fatalf("changing the %s left the key unchanged: the key does not bind it", tc.name)
			}
			if other, dup := seen[string(k)]; dup {
				t.Fatalf("changing the %s gave the same key as %s", tc.name, other)
			}
			seen[string(k)] = tc.name
		})
	}
}

// Moving a byte across the boundary of two adjacent inputs must change K. A derivation that
// concatenated them without lengths would give the same key for both splits.
func TestCombinerFramingSeparatesAdjacentValues(t *testing.T) {
	base := baseInputs()
	want := base.key(t)

	pk := base.clone()
	pk.pkX25519, pk.pkMLKEM = pk.pkX25519[:31], append(append([]byte(nil), base.pkX25519[31:]...), base.pkMLKEM...)
	if bytes.Equal(pk.key(t), want) {
		t.Error("moving a byte from the X25519 public key into the ML-KEM public key kept the key")
	}

	ct := base.clone()
	ct.ctX25519, ct.ctMLKEM = ct.ctX25519[:31], append(append([]byte(nil), base.ctX25519[31:]...), base.ctMLKEM...)
	if bytes.Equal(ct.key(t), want) {
		t.Error("moving a byte from the X25519 ephemeral key into the ML-KEM ciphertext kept the key")
	}

	pkct := base.clone()
	pkct.pkMLKEM, pkct.ctX25519 = pkct.pkMLKEM[:1567], append(append([]byte(nil), base.pkMLKEM[1567:]...), base.ctX25519...)
	if bytes.Equal(pkct.key(t), want) {
		t.Error("moving a byte from the ML-KEM public key into the X25519 ephemeral key kept the key")
	}
}

// Through the public API: a ciphertext made for one key pair, decapsulated under another key pair
// or under the wrong role, must not give the encapsulator's key. This is the re-encapsulation
// setting of section 3 of the paper at the level of one KEM, for honest keys.
func TestDecapsulateUnderAnotherKeyPairOrRoleGivesAnotherKey(t *testing.T) {
	a, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct, sent, err := Encapsulate(a.PublicKey(), RoleResponder)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decapsulate(ct, a, RoleInitiator)
	if err != nil || !bytes.Equal(got, sent) {
		t.Fatalf("the intended recipient got %x, %v; want the encapsulator's key", got, err)
	}
	if other, err := Decapsulate(ct, b, RoleInitiator); err != nil || bytes.Equal(other, sent) {
		t.Fatalf("another key pair got %x, %v; want a different key and no error", other, err)
	}
	if wrong, err := Decapsulate(ct, a, RoleResponder); err != nil || bytes.Equal(wrong, sent) {
		t.Fatalf("the wrong role got %x, %v; want a different key and no error", wrong, err)
	}
}
