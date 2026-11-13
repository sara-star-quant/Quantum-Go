package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/kemtest"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// The standard library and circl must derive the same ML-KEM-1024 key from a seed and agree
// on a ciphertext made with fixed coins, so the production path stays byte-compatible with
// the independent implementation that makes the conformance vectors.
func TestMLKEMStdlibMatchesCircl(t *testing.T) {
	for i := 0; i < 8; i++ {
		seed := make([]byte, 64)
		for j := range seed {
			seed[j] = byte(i*37 + j)
		}
		kp, err := crypto.NewMLKEMKeyPairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := kemtest.PublicKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kp.PublicKeyBytes(), pk) {
			t.Fatalf("seed %d: the public keys differ", i)
		}
		coins := bytes.Repeat([]byte{byte(i + 1)}, 32)
		ct, ss, err := kemtest.EncapsulateWithSeed(pk, coins)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.MLKEMDecapsulate(kp.DecapsulationKey, ct)
		if err != nil || !bytes.Equal(got, ss) {
			t.Fatalf("seed %d: stdlib decapsulation of a circl ciphertext differs: %v", i, err)
		}
	}
}

func TestKemtestRejectsABadSeed(t *testing.T) {
	if _, _, err := kemtest.EncapsulateWithSeed(make([]byte, 1568), make([]byte, 31)); err == nil {
		t.Fatal("a 31-byte seed was accepted")
	}
}
