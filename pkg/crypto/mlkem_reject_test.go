package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// A decapsulation whose ciphertext comparison skips part of the ciphertext accepts a modified
// ciphertext as valid and turns any accept or reject signal into a plaintext-checking oracle
// (CVE-2026-10097 in wolfSSL compared 1,536 of the 1,568 bytes). This pins the property for the
// production path: changing any single byte of a valid ciphertext gives a different key, and
// the same different key every time, never an error and never the honest key.
func requireRejectionAtEveryByte(t *testing.T, decap func([]byte) ([]byte, error), ct, honest []byte) []int {
	t.Helper()
	var bad []int
	for i := range ct {
		for _, mask := range []byte{0x01, 0x80} {
			mod := bytes.Clone(ct)
			mod[i] ^= mask
			k1, err := decap(mod)
			if err != nil || len(k1) != len(honest) || bytes.Equal(k1, honest) {
				bad = append(bad, i)
				break
			}
			if k2, err := decap(mod); err != nil || !bytes.Equal(k1, k2) {
				bad = append(bad, i)
				break
			}
		}
	}
	return bad
}

func TestMLKEMRejectsEveryModifiedCiphertextByte(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct, honest, err := crypto.MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		t.Fatal(err)
	}
	decap := func(c []byte) ([]byte, error) { return crypto.MLKEMDecapsulate(kp.DecapsulationKey, c) }
	if got, err := decap(ct); err != nil || !bytes.Equal(got, honest) {
		t.Fatalf("the unmodified ciphertext must decapsulate to the honest key: %v", err)
	}
	if bad := requireRejectionAtEveryByte(t, decap, ct, honest); len(bad) != 0 {
		t.Fatalf("modified ciphertext bytes at %d positions were not rejected, first at %d", len(bad), bad[0])
	}
}

// Negative control: a decapsulation that compares only the first 1,536 bytes, as the wolfSSL
// bug did, must fail the same property, or the test above could not catch the bug class.
func TestRejectionCheckCatchesAPrefixOnlyComparison(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct, honest, err := crypto.MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		t.Fatal(err)
	}
	const compared = 1536
	prefixOnly := func(c []byte) ([]byte, error) {
		if bytes.Equal(c[:compared], ct[:compared]) {
			return bytes.Clone(honest), nil
		}
		return crypto.MLKEMDecapsulate(kp.DecapsulationKey, c)
	}
	bad := requireRejectionAtEveryByte(t, prefixOnly, ct, honest)
	if want := len(ct) - compared; len(bad) != want {
		t.Fatalf("the prefix-only fake should fail at %d positions, failed at %d", want, len(bad))
	}
}
