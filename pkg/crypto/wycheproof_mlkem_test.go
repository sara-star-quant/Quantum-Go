package crypto

import (
	"bytes"
	"testing"
)

const wycheproofMLKEM1024SHA256 = "17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a"

// Project Wycheproof's ML-KEM-1024 vectors give expected answers from outside this repository,
// for the build that uses circl and for the FIPS build that uses the Go standard library.
// A valid case must reproduce the public key and the shared secret; the malleable-ciphertext
// cases are valid because implicit rejection must return the vector's pseudo-random secret
// instead of an error. An invalid case (a short seed, a ciphertext of the wrong length) must
// be refused.
func TestWycheproofMLKEM1024(t *testing.T) {
	f := loadWycheproof(t, "mlkem_1024_test.json", wycheproofMLKEM1024SHA256)
	var valid, invalid, implicitRejection int
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			id := int(tc["tcId"].(float64))
			result := tc["result"].(string)
			seed, ct := wycheproofHex(t, tc, "seed"), wycheproofHex(t, tc, "c")
			kp, err := NewMLKEMKeyPairFromSeed(seed)
			switch result {
			case "invalid":
				invalid++
				if err == nil {
					if _, err = MLKEMDecapsulate(kp.DecapsulationKey, ct); err == nil {
						t.Errorf("tcId %d (%v): an invalid case was accepted", id, tc["comment"])
					}
				}
			case "valid":
				valid++
				if err != nil {
					t.Errorf("tcId %d: key from seed: %v", id, err)
					continue
				}
				if ek, ok := tc["ek"].(string); ok && ek != "" && !bytes.Equal(kp.EncapsulationKey.Bytes(), wycheproofHex(t, tc, "ek")) {
					t.Errorf("tcId %d: public key differs from the vector", id)
				}
				ss, err := MLKEMDecapsulate(kp.DecapsulationKey, ct)
				if err != nil {
					t.Errorf("tcId %d: decapsulate: %v", id, err)
					continue
				}
				if !bytes.Equal(ss, wycheproofHex(t, tc, "K")) {
					t.Errorf("tcId %d: shared secret differs from the vector", id)
				}
				for _, fl := range tc["flags"].([]any) {
					if fl == "MalleableCiphertext" {
						implicitRejection++
					}
				}
			default:
				t.Errorf("tcId %d: unexpected result %q", id, result)
			}
		}
	}
	// The hash pins the file, so these counts pin the parser: a loop that skips cases fails here.
	if valid != 162 || invalid != 40 || implicitRejection != 9 {
		t.Fatalf("ran valid=%d invalid=%d implicit-rejection=%d, want 162, 40 and 9", valid, invalid, implicitRejection)
	}
}
