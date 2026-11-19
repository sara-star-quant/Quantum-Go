package crypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// wycheproofAEADCounts is what a run must have exercised, so a loop that skips cases fails.
type wycheproofAEADCounts struct{ valid, invalid, refusedKey, refusedNonce int }

// Wycheproof's AEAD vectors for the two cipher suites, driven through the wrapper's explicit-nonce
// methods. The wrapper takes 256-bit keys and 96-bit nonces only. Inside that envelope a valid case
// must open to the message and seal back to the same ciphertext and tag, and an invalid case, a
// modified tag above all, must fail to open. Outside it the wrapper must refuse, not guess: a key of
// another size cannot build a cipher, and a nonce of another size gets ErrInvalidNonce even when the
// vector calls the case valid.
func TestWycheproofAEAD(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		sha    string
		suite  constants.CipherSuite
		counts wycheproofAEADCounts
	}{
		{"AES-256-GCM", "aes_gcm_test.json", "985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7",
			constants.CipherSuiteAES256GCM, wycheproofAEADCounts{valid: 39, invalid: 27, refusedKey: 211, refusedNonce: 39}},
		{"ChaCha20-Poly1305", "chacha20_poly1305_test.json", "fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d",
			constants.CipherSuiteChaCha20Poly1305, wycheproofAEADCounts{valid: 256, invalid: 60, refusedKey: 0, refusedNonce: 9}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := loadWycheproof(t, c.file, c.sha)
			if FIPSMode() && !c.suite.IsFIPSApproved() {
				// The FIPS build must not build this cipher at all, whatever the vector says.
				if _, err := NewAEAD(c.suite, make([]byte, 32)); !errors.Is(err, qerrors.ErrCipherSuiteNotFIPSApproved) {
					t.Fatalf("FIPS build: NewAEAD(%s) = %v, want ErrCipherSuiteNotFIPSApproved", c.name, err)
				}
				t.Skipf("%s is not available in the FIPS build", c.name)
			}
			var got wycheproofAEADCounts
			for _, g := range f.TestGroups {
				for _, tc := range g.Tests {
					id := int(tc["tcId"].(float64))
					result := tc["result"].(string)
					key := wycheproofHex(t, tc, "key")
					a, err := NewAEAD(c.suite, key)
					if g.KeySize != 256 {
						if err == nil {
							t.Errorf("tcId %d: a %d-bit key built a cipher", id, g.KeySize)
						}
						got.refusedKey++
						continue
					}
					if err != nil {
						t.Errorf("tcId %d: NewAEAD: %v", id, err)
						continue
					}
					iv, aad, msg := wycheproofHex(t, tc, "iv"), wycheproofHex(t, tc, "aad"), wycheproofHex(t, tc, "msg")
					sealed := append(wycheproofHex(t, tc, "ct"), wycheproofHex(t, tc, "tag")...)
					if g.IvSize != 96 {
						if _, err := a.OpenWithNonce(iv, sealed, aad); !errors.Is(err, qerrors.ErrInvalidNonce) {
							t.Errorf("tcId %d: a %d-bit nonce gave %v, want ErrInvalidNonce", id, g.IvSize, err)
						}
						if _, err := a.SealWithNonce(iv, msg, aad); !errors.Is(err, qerrors.ErrInvalidNonce) {
							t.Errorf("tcId %d: sealing with a %d-bit nonce gave %v, want ErrInvalidNonce", id, g.IvSize, err)
						}
						got.refusedNonce++
						continue
					}
					pt, err := a.OpenWithNonce(iv, sealed, aad)
					switch result {
					case "valid":
						got.valid++
						if err != nil || !bytes.Equal(pt, msg) {
							t.Errorf("tcId %d (%v): open = %x, %v; want the vector's message", id, tc["comment"], pt, err)
						}
						if again, err := a.SealWithNonce(iv, msg, aad); err != nil || !bytes.Equal(again, sealed) {
							t.Errorf("tcId %d (%v): seal does not reproduce the vector's ciphertext and tag", id, tc["comment"])
						}
					case "invalid":
						got.invalid++
						if err == nil {
							t.Errorf("tcId %d (%v): an invalid case opened", id, tc["comment"])
						}
					default:
						t.Errorf("tcId %d: unexpected result %q", id, result)
					}
				}
			}
			if got != c.counts {
				t.Fatalf("ran %+v, want %+v", got, c.counts)
			}
		})
	}
}
