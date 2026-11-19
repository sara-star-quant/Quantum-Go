package crypto

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

const wycheproofX25519SHA256 = "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d"

// Wycheproof's X25519 vectors cover the cases that break careless implementations: points on the
// twist, low-order and non-canonical public keys, and scalar edge cases. Every valid case and every
// acceptable case except the low-order ones must reproduce the shared secret. A low-order public key
// makes the shared secret all zero, and the wrapper must refuse it, because a zero secret would
// leave the classical leg of the hybrid key with no entropy.
func TestWycheproofX25519(t *testing.T) {
	f := loadWycheproof(t, "x25519_test.json", wycheproofX25519SHA256)
	var valid, matched, zeroRefused int
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			id := int(tc["tcId"].(float64))
			result := tc["result"].(string)
			zero := false
			for _, fl := range tc["flags"].([]any) {
				zero = zero || fl == "ZeroSharedSecret"
			}
			pub, err := ParseX25519PublicKey(wycheproofHex(t, tc, "public"))
			if err != nil {
				t.Errorf("tcId %d: parse public key: %v", id, err)
				continue
			}
			priv, err := ecdh.X25519().NewPrivateKey(wycheproofHex(t, tc, "private"))
			if err != nil {
				t.Errorf("tcId %d: private key: %v", id, err)
				continue
			}
			ss, err := X25519(priv, pub)
			switch {
			case zero:
				if err == nil {
					t.Errorf("tcId %d (%v): a low-order public key produced a shared secret", id, tc["comment"])
					continue
				}
				zeroRefused++
			case err != nil:
				t.Errorf("tcId %d (%v): refused a case that must succeed: %v", id, tc["comment"], err)
			case !bytes.Equal(ss, wycheproofHex(t, tc, "shared")):
				t.Errorf("tcId %d (%v): shared secret differs from the vector", id, tc["comment"])
			default:
				matched++
			}
			if result == "valid" {
				valid++
			}
		}
	}
	// 264 valid and 254 acceptable cases, 31 of the acceptable ones with a zero shared secret.
	if valid != 264 || matched != 264+223 || zeroRefused != 31 {
		t.Fatalf("ran valid=%d matched=%d zero-refused=%d, want 264, 487 and 31", valid, matched, zeroRefused)
	}
}
