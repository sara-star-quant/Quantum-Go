// Package tunnel - dgram_session.go holds the datagram-specific crypto state and
// recv/send primitives on Session. It is deliberately separate from the stream
// path in session.go: the datagram path derives nonces, selects the receive
// cipher by an explicit per-frame epoch, and never touches the stream
// sendCipher/recvCipher promote/discard logic. The only shared state it reads is
// the master secret and the sequence counter.
package tunnel

import (
	"encoding/binary"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// datagramEpoch is the cipher pair for one rekey epoch. The epoch byte travels in
// every datagram header (authenticated, in the AAD) and selects the receive
// cipher, so the datagram path needs no in-order trial decryption.
type datagramEpoch struct {
	epoch       uint8
	sendCipher  *crypto.AEAD
	recvCipher  *crypto.AEAD
	startSeq    uint64    // send sequence at which this epoch became current
	retireAfter time.Time // zero for the current epoch; set when demoted to prev
}

// datagramEpochState holds the two live epochs: the current one and, briefly
// after a rekey, the previous one (retained for DatagramPrevEpochRetainSeconds so
// packets still in flight under the old key keep decrypting). Only adjacent
// epochs are ever live; a second rekey within the retain window overwrites prev.
type datagramEpochState struct {
	cur  *datagramEpoch
	prev *datagramEpoch
}

// InitializeDatagramKeys derives traffic keys and datagram nonce prefixes from the
// master secret and seeds epoch 0. It mirrors InitializeKeys' key derivation but
// additionally sets up the datagram-only state; it is called by the datagram
// handshake instead of InitializeKeys so the stream path is never affected.
func (s *Session) InitializeDatagramKeys(masterSecret []byte, cipherSuite constants.CipherSuite) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Load() == int32(SessionStateClosed) {
		return qerrors.ErrTunnelClosed
	}
	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return qerrors.ErrInvalidKeySize
	}

	s.masterSecret = make([]byte, len(masterSecret))
	copy(s.masterSecret, masterSecret)
	s.CipherSuite = cipherSuite

	sendCipher, recvCipher, err := s.deriveDatagramCiphers(masterSecret, cipherSuite)
	if err != nil {
		return err
	}

	initiatorPrefix, responderPrefix, err := crypto.DeriveDatagramNoncePrefixes(masterSecret)
	if err != nil {
		return err
	}
	if s.Role == RoleInitiator {
		s.sendNoncePrefix = initiatorPrefix
		s.recvNoncePrefix = responderPrefix
	} else {
		s.sendNoncePrefix = responderPrefix
		s.recvNoncePrefix = initiatorPrefix
	}

	// Keep the stream cipher fields consistent so generic accessors still work;
	// the datagram path itself reads through dgramEpochs.
	s.sendCipher = sendCipher
	s.recvCipher = recvCipher
	s.dgramEpochs = &datagramEpochState{
		cur: &datagramEpoch{epoch: 0, sendCipher: sendCipher, recvCipher: recvCipher, startSeq: 0},
	}
	s.dgramReplay = NewDatagramReplayWindow()
	s.lastActivityNanos.Store(time.Now().UnixNano())

	s.EstablishedAt = time.Now()
	s.SetState(SessionStateEstablished)
	return nil
}

// deriveDatagramCiphers builds the role-appropriate send/recv cipher pair from a
// master secret. Shared by InitializeDatagramKeys and AdvanceDatagramEpoch.
func (s *Session) deriveDatagramCiphers(masterSecret []byte, cipherSuite constants.CipherSuite) (send, recv *crypto.AEAD, err error) {
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(masterSecret)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.ZeroizeMultiple(initiatorKey, responderKey)

	var sendKey, recvKey []byte
	if s.Role == RoleInitiator {
		sendKey, recvKey = initiatorKey, responderKey
	} else {
		sendKey, recvKey = responderKey, initiatorKey
	}
	if send, err = crypto.NewAEAD(cipherSuite, sendKey); err != nil {
		return nil, nil, err
	}
	if recv, err = crypto.NewAEAD(cipherSuite, recvKey); err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

// nextDatagramSeq returns the next monotonic send sequence number. The sequence
// space is global and never reset across a rekey; the epoch (not the sequence)
// selects the key, so per-(key,nonce) uniqueness holds trivially.
func (s *Session) nextDatagramSeq() uint64 {
	return s.sendSeq.Add(1) - 1
}

// datagramSendEpoch returns the current send epoch.
func (s *Session) datagramSendEpoch() uint8 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dgramEpochs.cur.epoch
}

// buildAEADNonce builds the 12-byte AEAD nonce prefix || seq(8B BE) into dst
// (which must be 12 bytes). Shared by the stream and datagram transports, both of
// which derive the nonce rather than transmitting it.
func buildAEADNonce(dst, prefix []byte, seq uint64) {
	copy(dst[:constants.DatagramNoncePrefixSize], prefix)
	binary.BigEndian.PutUint64(dst[constants.DatagramNoncePrefixSize:], seq)
}

// DatagramSeal encrypts plaintext for the current epoch under nonce = sendPrefix ||
// seq, authenticating aad (the 14-byte frame header). It returns ciphertext||tag
// (the nonce is derived, not transmitted). The caller chooses seq via
// nextDatagramSeq and builds the header (whose epoch must equal datagramSendEpoch).
func (s *Session) DatagramSeal(aad []byte, seq uint64, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	cur := s.dgramEpochs.cur
	prefix := s.sendNoncePrefix
	s.mu.RUnlock()
	if cur == nil || cur.sendCipher == nil {
		return nil, qerrors.ErrInvalidState
	}
	cipher := cur.sendCipher
	// Hard cap on how many datagrams one epoch's key seals. The initiator starts a
	// background rekey well before this (datagramRekeyHighWater), so reaching the
	// cap means rekey could not complete; refuse rather than overrun the key's safe
	// usage limit.
	if seq-cur.startSeq >= constants.MaxPacketsBeforeRekey {
		return nil, qerrors.ErrNonceExhausted
	}

	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)
	ct, err := cipher.SealWithNonce(nonce[:], plaintext, aad)
	if err != nil {
		return nil, err
	}
	s.lastActivityNanos.Store(coarseTimeNanos())
	return ct, nil
}

// DatagramOpen decrypts ciphertext for the epoch named in the frame header,
// authenticating aad (the 14-byte header). It selects the current epoch's cipher,
// or the retained previous epoch's cipher if it is still live, and derives the
// nonce from recvPrefix || seq. It is a pure crypto op: the caller performs the
// replay-window check (see DatagramReplayWindow.Admissible/Check).
func (s *Session) DatagramOpen(epoch uint8, seq uint64, ciphertext, aad []byte) ([]byte, error) {
	s.mu.RLock()
	cipher := s.datagramRecvCipherLocked(epoch)
	prefix := s.recvNoncePrefix
	s.mu.RUnlock()
	if cipher == nil {
		return nil, qerrors.ErrAuthenticationFailed
	}

	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)
	pt, err := cipher.OpenWithNonce(nonce[:], ciphertext, aad)
	if err != nil {
		return nil, err
	}
	s.lastActivityNanos.Store(coarseTimeNanos())
	return pt, nil
}

// datagramRecvCipherLocked returns the receive cipher for epoch: the current
// epoch, or the previous epoch if it matches and has not yet been retired. The
// caller holds at least s.mu.RLock.
func (s *Session) datagramRecvCipherLocked(epoch uint8) *crypto.AEAD {
	es := s.dgramEpochs
	if es == nil {
		return nil
	}
	if es.cur != nil && es.cur.epoch == epoch {
		return es.cur.recvCipher
	}
	if es.prev != nil && es.prev.epoch == epoch && time.Now().Before(es.prev.retireAfter) {
		return es.prev.recvCipher
	}
	return nil
}

// AdvanceDatagramEpoch rotates to a new epoch built from newSecret: the current
// epoch becomes prev (retained for DatagramPrevEpochRetainSeconds so in-flight
// old-epoch packets keep decrypting), and a fresh epoch (epoch+1, mod 256) becomes
// current. It deliberately does NOT touch the stream rekey machinery
// (promotePendingRecvCipher / finalizeRekeyStateLocked / ActivateRekeySend); the
// explicit per-frame epoch makes trial decryption unnecessary.
//
// A second rekey within the retain window overwrites prev, so packets two epochs
// old are dropped; only adjacent epochs are guaranteed live.
func (s *Session) AdvanceDatagramEpoch(newSecret []byte) (uint8, error) {
	if len(newSecret) != constants.CHKEMSharedSecretSize {
		return 0, qerrors.ErrInvalidKeySize
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dgramEpochs == nil || s.dgramEpochs.cur == nil {
		return 0, qerrors.ErrInvalidState
	}

	send, recv, err := s.deriveDatagramCiphers(newSecret, s.CipherSuite)
	if err != nil {
		return 0, err
	}

	old := s.dgramEpochs.cur
	old.retireAfter = time.Now().Add(time.Duration(constants.DatagramPrevEpochRetainSeconds) * time.Second)
	newEpoch := old.epoch + 1
	s.dgramEpochs.prev = old
	s.dgramEpochs.cur = &datagramEpoch{epoch: newEpoch, sendCipher: send, recvCipher: recv, startSeq: s.sendSeq.Load()}

	// Adopt the new secret as the master secret for any subsequent rekey ratchet.
	s.masterSecret = make([]byte, len(newSecret))
	copy(s.masterSecret, newSecret)
	s.sendCipher = send
	s.recvCipher = recv
	return newEpoch, nil
}
