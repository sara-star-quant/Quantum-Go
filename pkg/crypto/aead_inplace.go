package crypto

import (
	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// SealWithNonceTo encrypts plaintext under nonce and appends the ciphertext and
// authentication tag to dst, returning the extended slice. Unlike SealWithNonce
// (which allocates a fresh slice per call), the caller supplies dst: pass a slice
// with spare capacity (for the datagram path, the frame buffer already holding the
// header) and the result reuses that backing array with no allocation. dst and
// plaintext must not overlap.
//
// To build a datagram frame in place, pass dst = header (len 14, cap >= 14 +
// len(plaintext) + Overhead) so the returned slice is header||ciphertext||tag and
// the AEAD AAD is that same header.
func (a *AEAD) SealWithNonceTo(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != constants.AESNonceSize {
		return nil, qerrors.ErrInvalidNonce
	}
	return a.cipher.Seal(dst, nonce, plaintext, additionalData), nil
}

// OpenWithNonceTo decrypts ciphertext under nonce and appends the plaintext to
// dst, returning the extended slice. Unlike OpenWithNonce it does not allocate
// when dst has spare capacity. The decrypted plaintext is written after any
// existing dst contents; pass dst[:0] over a reusable buffer to overwrite. dst and
// ciphertext must not overlap.
func (a *AEAD) OpenWithNonceTo(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != constants.AESNonceSize {
		return nil, qerrors.ErrInvalidNonce
	}
	if len(ciphertext) < constants.AESTagSize {
		return nil, qerrors.ErrCiphertextTooShort
	}
	pt, err := a.cipher.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, qerrors.ErrAuthenticationFailed
	}
	return pt, nil
}
