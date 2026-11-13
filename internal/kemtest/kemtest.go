// Package kemtest holds deterministic ML-KEM-1024 encapsulation for known-answer tests.
// The standard library's crypto/mlkem draws its own coins and has no seeded encapsulation,
// so the vectors need an independent implementation. Only test code imports this package,
// and the default build uses circl directly, so this package only adds the seeded entry points.
package kemtest

import (
	"bytes"
	"errors"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// PublicKeyFromSeed derives the ML-KEM-1024 public key from a 64-byte key-generation seed
// (d || z), for cross-checking the standard library's derivation.
func PublicKeyFromSeed(seed []byte) ([]byte, error) {
	pk, _, err := mlkem1024.GenerateKeyPair(bytes.NewReader(seed))
	if err != nil {
		return nil, err
	}
	out := make([]byte, mlkem1024.PublicKeySize)
	pk.Pack(out)
	return out, nil
}

// EncapsulateWithSeed is ML-KEM-1024 encapsulation with caller-supplied coins (32 bytes).
// It returns the ciphertext and the 32-byte shared secret.
func EncapsulateWithSeed(publicKey, seed []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(seed) != mlkem1024.EncapsulationSeedSize {
		return nil, nil, errors.New("kemtest: encapsulation seed must be 32 bytes")
	}
	pk := new(mlkem1024.PublicKey)
	if err := pk.Unpack(publicKey); err != nil {
		return nil, nil, err
	}
	ct := make([]byte, mlkem1024.CiphertextSize)
	ss := make([]byte, mlkem1024.SharedKeySize)
	pk.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}
