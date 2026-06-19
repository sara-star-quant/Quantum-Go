// Package tunnel - dgram_rekey.go is the reliable rekey transport for the
// datagram path. A rekey rotates the session to a new epoch with fresh forward
// secrecy, but the CH-KEM public key and ciphertext (~1.6 KB each) exceed the
// datagram MTU, so the exchange is a small fragmented sub-handshake reusing the
// handshake fragmenter and reassembler.
//
// The exchange is authenticated under the CURRENT epoch (an off-path party cannot
// forge it) and driven only by the handshake RoleInitiator, which avoids two
// sides rekeying at once. The responder answers reactively on the receive loop
// and caches its sealed response so a retransmitted RekeyInit is replayed
// verbatim - it must never re-run the randomized Encapsulate, which would derive
// a different secret and desync the epochs.
package tunnel

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

var errRekeyTimeout = errors.New("tunnel: datagram rekey timed out")

// datagramRekeyHighWater is the per-epoch send count at which the initiator starts
// a background rekey. It sits below the hard MaxPacketsBeforeRekey cap (enforced in
// DatagramSeal) so the rotation completes before the key budget is exhausted.
const datagramRekeyHighWater = constants.MaxPacketsBeforeRekey * 9 / 10

// datagramRekeyDue reports whether the current epoch has sealed enough datagrams to
// warrant a background rekey.
func (s *Session) datagramRekeyDue(seq uint64) bool {
	s.mu.RLock()
	cur := s.dgramEpochs.cur
	s.mu.RUnlock()
	if cur == nil {
		return false
	}
	return seq-cur.startSeq >= datagramRekeyHighWater
}

// --- Session rekey crypto (authenticated control messages) ---

// rekeyAAD binds a rekey control message to its type, epoch, and nonce sequence.
func rekeyAAD(msgType protocol.MessageType, epoch uint8, seq uint64) []byte {
	aad := make([]byte, 10)
	aad[0] = byte(msgType)
	aad[1] = epoch
	binary.BigEndian.PutUint64(aad[2:], seq)
	return aad
}

// sealRekeyControl seals a rekey payload under the current epoch's send cipher and
// returns the message body (nonceSeq(8B) || ciphertext) plus the epoch used (which
// the caller writes into the frame header). The nonce sequence is drawn from the
// global send counter so it never collides with a data-frame nonce; it is NOT
// replay-window-checked, since rekey retransmits reuse the same body verbatim.
func (s *Session) sealRekeyControl(msgType protocol.MessageType, payload []byte) (body []byte, epoch uint8, err error) {
	seq := s.nextDatagramSeq()
	s.mu.RLock()
	cur := s.dgramEpochs.cur
	prefix := s.sendNoncePrefix
	s.mu.RUnlock()
	if cur == nil || cur.sendCipher == nil {
		return nil, 0, qerrors.ErrInvalidState
	}
	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)
	ct, err := cur.sendCipher.SealWithNonce(nonce[:], payload, rekeyAAD(msgType, cur.epoch, seq))
	if err != nil {
		return nil, 0, err
	}
	body = make([]byte, 8+len(ct))
	binary.BigEndian.PutUint64(body, seq)
	copy(body[8:], ct)
	return body, cur.epoch, nil
}

// openRekeyControl authenticates and decrypts a rekey control body received under
// the named epoch.
func (s *Session) openRekeyControl(msgType protocol.MessageType, epoch uint8, body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, qerrors.ErrInvalidMessage
	}
	seq := binary.BigEndian.Uint64(body[:8])
	s.mu.RLock()
	cipher := s.datagramRecvCipherLocked(epoch)
	prefix := s.recvNoncePrefix
	s.mu.RUnlock()
	if cipher == nil {
		return nil, qerrors.ErrAuthenticationFailed
	}
	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)
	return cipher.OpenWithNonce(nonce[:], body[8:], rekeyAAD(msgType, epoch, seq))
}

// deriveNextDatagramSecret ratchets the current master secret with a fresh KEM
// secret to produce the next epoch's master secret.
func (s *Session) deriveNextDatagramSecret(fresh []byte) ([]byte, error) {
	s.mu.RLock()
	ms := s.masterSecret
	s.mu.RUnlock()
	return crypto.DeriveRekeySecret(ms, fresh)
}

// buildDatagramRekeyInit seals the initiator's fresh public key as a RekeyInit
// body and reports the epoch it was sealed under.
func (s *Session) buildDatagramRekeyInit(kp *chkem.KeyPair) (body []byte, epoch uint8, err error) {
	return s.sealRekeyControl(protocol.MessageTypeDatagramRekeyInit, kp.PublicKey().Bytes())
}

// respondToDatagramRekey processes a peer's RekeyInit body received under epoch:
// it authenticates the peer's public key, encapsulates to it, seals the ciphertext
// response under the SAME (still-current) epoch, then advances to the next epoch.
// Sealing before advancing is required so the initiator (still on the old epoch)
// can open the response. It returns the sealed response body and its epoch.
func (s *Session) respondToDatagramRekey(epoch uint8, initBody []byte) (respBody []byte, respEpoch uint8, err error) {
	pubBytes, err := s.openRekeyControl(protocol.MessageTypeDatagramRekeyInit, epoch, initBody)
	if err != nil {
		return nil, 0, err
	}
	pub, err := chkem.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, 0, err
	}
	ct, fresh, err := chkem.Encapsulate(pub, chkem.RoleResponder)
	if err != nil {
		return nil, 0, err
	}
	defer crypto.Zeroize(fresh)

	respBody, respEpoch, err = s.sealRekeyControl(protocol.MessageTypeDatagramRekeyResponse, ct.Bytes())
	if err != nil {
		return nil, 0, err
	}
	newSecret, err := s.deriveNextDatagramSecret(fresh)
	if err != nil {
		return nil, 0, err
	}
	defer crypto.Zeroize(newSecret)
	if _, err := s.AdvanceDatagramEpoch(newSecret); err != nil {
		return nil, 0, err
	}
	return respBody, respEpoch, nil
}

// completeDatagramRekey processes the responder's RekeyResponse on the initiator:
// it authenticates and decapsulates the ciphertext (under the epoch the init was
// sealed under), ratchets to the next secret, and advances the epoch.
func (s *Session) completeDatagramRekey(epoch uint8, respBody []byte, kp *chkem.KeyPair) error {
	ctBytes, err := s.openRekeyControl(protocol.MessageTypeDatagramRekeyResponse, epoch, respBody)
	if err != nil {
		return err
	}
	ct, err := chkem.ParseCiphertext(ctBytes)
	if err != nil {
		return err
	}
	fresh, err := chkem.Decapsulate(ct, kp, chkem.RoleInitiator)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(fresh)
	newSecret, err := s.deriveNextDatagramSecret(fresh)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(newSecret)
	_, err = s.AdvanceDatagramEpoch(newSecret)
	return err
}

// --- wire helpers ---

// fragmentRekey splits a rekey control body into datagram HANDSHAKE frames carrying
// the rekey message type and the sealing epoch. The reassembler keys fragments by
// (SenderIndex, MsgType), independent of the handshake, so rekey and handshake
// reassembly never collide. pad applies the same uniform-size padding as the
// handshake (rekey is the same PQ sub-handshake mid-session, so it has the same
// size fingerprint).
func fragmentRekey(ds *datagramSession, epoch uint8, msgType protocol.MessageType, body []byte, pad bool) ([][]byte, error) {
	base := protocol.DatagramHandshakeHeader{
		DatagramHeader: protocol.DatagramHeader{
			Type:      protocol.DatagramFrameHandshake,
			Epoch:     epoch,
			RecvIndex: ds.peerIndex,
		},
		SenderIndex: ds.index,
		MsgType:     msgType,
	}
	return fragmentHandshake(base, body, pad)
}

// --- initiator driver ---

// Rekey rotates the session to a new epoch with fresh forward secrecy. Only the
// handshake initiator may drive it; the call blocks until the exchange completes,
// times out, or the session closes. Concurrent calls return ErrRekeyInProgress.
func (c *DatagramConn) Rekey() error {
	s := c.ds.session
	if s.Role != RoleInitiator {
		return qerrors.ErrInvalidState
	}
	if !c.ds.beginRekey() {
		return qerrors.ErrRekeyInProgress
	}
	defer c.ds.endRekey()

	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		return err
	}
	defer kp.Zeroize()

	body, epoch, err := s.buildDatagramRekeyInit(kp)
	if err != nil {
		return err
	}
	frames, err := fragmentRekey(c.ds, epoch, protocol.MessageTypeDatagramRekeyInit, body, c.ep.padHandshake)
	if err != nil {
		return err
	}

	// Drain any stale response left from a prior attempt.
	select {
	case <-c.ds.rekeyInbox:
	default:
	}

	rto := c.ep.rtoInitial
	timer := time.NewTimer(0) // fire immediately to send the first flight
	defer timer.Stop()
	attempts := 0
	for {
		select {
		case <-timer.C:
			if attempts > constants.DatagramHandshakeMaxRetries {
				return errRekeyTimeout
			}
			peer := c.ds.currentPeerAddr() // re-read so a mid-rekey roam is followed
			c.ep.batch.writeAll(frames, peer)
			attempts++
			armTimer(timer, rto)
			if rto *= 2; rto > c.ep.rtoMax {
				rto = c.ep.rtoMax
			}
		case resp := <-c.ds.rekeyInbox:
			if err := s.completeDatagramRekey(epoch, resp, kp); err == nil {
				return nil
			}
			// A response that fails to authenticate is ignored; keep waiting.
		case <-c.ds.closed:
			return qerrors.ErrTunnelClosed
		case <-c.ep.done:
			return errEndpointClosed
		}
	}
}

// --- receive-loop integration ---

// handleRekey dispatches a fully reassembled rekey message to the responder logic
// (RekeyInit) or to the waiting initiator (RekeyResponse).
func (e *DatagramEndpoint) handleRekey(h protocol.DatagramHandshakeHeader, body []byte) {
	ds := e.registry.lookup(h.RecvIndex)
	if ds == nil || ds.session == nil {
		return
	}
	switch h.MsgType {
	case protocol.MessageTypeDatagramRekeyInit:
		e.handleRekeyInit(ds, h.Epoch, body)
	case protocol.MessageTypeDatagramRekeyResponse:
		if ds.rekeyInbox != nil {
			select {
			case ds.rekeyInbox <- body:
			default:
			}
		}
	}
}

// handleRekeyInit answers a RekeyInit as the responder. A retransmit of an
// already-answered rekey (same source epoch) replays the cached response frames;
// a fresh rekey is processed once and its response cached.
func (e *DatagramEndpoint) handleRekeyInit(ds *datagramSession, epoch uint8, body []byte) {
	ds.rekeyRespMu.Lock()
	defer ds.rekeyRespMu.Unlock()

	if ds.rekeyRespValid && ds.rekeyRespFrom == epoch {
		peer := ds.currentPeerAddr()
		e.batch.writeAll(ds.rekeyRespFrames, peer)
		return
	}
	// Only a rekey transitioning from the current epoch is processed; stale or
	// out-of-order inits are dropped.
	if epoch != ds.session.datagramSendEpoch() {
		return
	}
	respBody, respEpoch, err := ds.session.respondToDatagramRekey(epoch, body)
	if err != nil {
		return
	}
	frames, err := fragmentRekey(ds, respEpoch, protocol.MessageTypeDatagramRekeyResponse, respBody, e.padHandshake)
	if err != nil {
		return
	}
	ds.rekeyRespFrom = epoch
	ds.rekeyRespFrames = frames
	ds.rekeyRespValid = true
	peer := ds.currentPeerAddr()
	e.batch.writeAll(frames, peer)
}
