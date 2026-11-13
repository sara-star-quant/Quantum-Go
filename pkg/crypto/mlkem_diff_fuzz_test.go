package crypto_test

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/kemtest"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// fit returns b cut or zero-extended to exactly n bytes.
func fit(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// FuzzMLKEMDifferential checks that every implementation of ML-KEM-1024 in this repository
// agrees: the standard library (crypto/mlkem, imported directly so the result does not depend on
// the build tag), circl (through internal/kemtest) and the library's own wrapper. For fuzzed
// seeds and coins they must derive the same public key, decapsulate the same ciphertext to the
// same secret, implicitly reject a tampered ciphertext to the same unrelated secret, and agree
// on whether a mutated public key is well formed.
func FuzzMLKEMDifferential(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x01}, 64), bytes.Repeat([]byte{0x02}, 32), uint16(0), byte(0x01))
	f.Add(make([]byte, 64), make([]byte, 32), uint16(1567), byte(0xFF))
	f.Add(bytes.Repeat([]byte{0xFF}, 64), bytes.Repeat([]byte{0xA5}, 32), uint16(1535), byte(0x80))
	f.Add([]byte("seed"), []byte("coins"), uint16(700), byte(0x10))

	f.Fuzz(func(t *testing.T, seedIn, coinsIn []byte, flipPos uint16, flipMask byte) {
		seed, coins := fit(seedIn, 64), fit(coinsIn, 32)

		std, err := stdmlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			t.Fatalf("standard library rejected a 64-byte seed: %v", err)
		}
		stdPK := std.EncapsulationKey().Bytes()
		circlPK, err := kemtest.PublicKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("circl key from seed: %v", err)
		}
		if !bytes.Equal(stdPK, circlPK) {
			t.Fatal("standard library and circl derive different public keys from one seed")
		}
		kp, err := crypto.NewMLKEMKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("wrapper key from seed: %v", err)
		}
		if !bytes.Equal(kp.PublicKeyBytes(), stdPK) {
			t.Fatal("the wrapper derives a different public key from the standard library")
		}

		// One ciphertext, three decapsulations.
		ct, ss, err := kemtest.EncapsulateWithSeed(circlPK, coins)
		if err != nil {
			t.Fatalf("circl encapsulate: %v", err)
		}
		agree := func(name string, got []byte, err error, want []byte) {
			t.Helper()
			if err != nil {
				t.Fatalf("%s decapsulate: %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s decapsulates to a different secret", name)
			}
		}
		gotStd, err := std.Decapsulate(ct)
		agree("standard library", gotStd, err, ss)
		gotCircl, err := kemtest.DecapsulateFromSeed(seed, ct)
		agree("circl", gotCircl, err, ss)
		gotWrap, err := crypto.MLKEMDecapsulate(kp.DecapsulationKey, ct)
		agree("wrapper", gotWrap, err, ss)

		// Implicit rejection: a tampered ciphertext decapsulates to the same pseudorandom
		// secret everywhere, and not to the original one.
		if flipMask != 0 {
			bad := append([]byte(nil), ct...)
			bad[int(flipPos)%len(bad)] ^= flipMask
			rStd, err := std.Decapsulate(bad)
			if err != nil {
				t.Fatalf("standard library errored on a tampered ciphertext: %v", err)
			}
			rCircl, err := kemtest.DecapsulateFromSeed(seed, bad)
			agree("circl (tampered)", rCircl, err, rStd)
			rWrap, err := crypto.MLKEMDecapsulate(kp.DecapsulationKey, bad)
			agree("wrapper (tampered)", rWrap, err, rStd)
			if bytes.Equal(rStd, ss) {
				t.Fatal("a tampered ciphertext produced the original secret")
			}
		}

		// A mutated public key is accepted or refused by every implementation alike.
		pk := append([]byte(nil), stdPK...)
		pk[int(flipPos)%len(pk)] ^= flipMask
		_, stdErr := stdmlkem.NewEncapsulationKey1024(pk)
		_, wrapErr := crypto.ParseMLKEMPublicKey(pk)
		circlOK := kemtest.AcceptsPublicKey(pk)
		if (stdErr == nil) != circlOK || (wrapErr == nil) != circlOK {
			t.Fatalf("public key acceptance differs: standard library %v, circl %v, wrapper %v", stdErr == nil, circlOK, wrapErr == nil)
		}
	})
}
