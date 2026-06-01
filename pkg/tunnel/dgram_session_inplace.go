// Package tunnel - dgram_session_inplace.go adds zero-allocation variants of the
// datagram seal/open primitives. They mirror DatagramSeal/DatagramOpen but append
// into a caller-supplied buffer (via the crypto package's *WithNonceTo methods)
// instead of allocating a fresh slice per call, so the datagram send hot path can
// reuse one frame buffer per connection. The allocating variants remain for
// callers that do not own a reusable buffer.
package tunnel

import (
	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// DatagramSealTo seals plaintext for the current epoch under nonce = sendPrefix ||
// seq, authenticating aad, and appends ciphertext||tag to dst, returning the
// extended slice. To build a frame in place pass dst = the header bytes (whose
// content must equal aad) backed by an array with spare capacity, so the result is
// header||ciphertext||tag with no allocation. See DatagramSeal for the semantics.
func (s *Session) DatagramSealTo(dst, aad []byte, seq uint64, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	cur := s.dgramEpochs.cur
	prefix := s.sendNoncePrefix
	s.mu.RUnlock()
	if cur == nil || cur.sendCipher == nil {
		return nil, qerrors.ErrInvalidState
	}
	if seq-cur.startSeq >= constants.MaxPacketsBeforeRekey {
		return nil, qerrors.ErrNonceExhausted
	}
	var nonce [constants.AESNonceSize]byte
	datagramNonce(nonce[:], prefix, seq)
	out, err := cur.sendCipher.SealWithNonceTo(dst, nonce[:], plaintext, aad)
	if err != nil {
		return nil, err
	}
	s.lastActivityNanos.Store(coarseTimeNanos())
	return out, nil
}

// DatagramOpenTo decrypts ciphertext for the epoch named in the frame header and
// appends the plaintext to dst, returning the extended slice. It mirrors
// DatagramOpen but does not allocate when dst has spare capacity. The caller still
// performs the replay-window check.
func (s *Session) DatagramOpenTo(dst []byte, epoch uint8, seq uint64, ciphertext, aad []byte) ([]byte, error) {
	s.mu.RLock()
	cipher := s.datagramRecvCipherLocked(epoch)
	prefix := s.recvNoncePrefix
	s.mu.RUnlock()
	if cipher == nil {
		return nil, qerrors.ErrAuthenticationFailed
	}
	var nonce [constants.AESNonceSize]byte
	datagramNonce(nonce[:], prefix, seq)
	pt, err := cipher.OpenWithNonceTo(dst, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, err
	}
	s.lastActivityNanos.Store(coarseTimeNanos())
	return pt, nil
}
