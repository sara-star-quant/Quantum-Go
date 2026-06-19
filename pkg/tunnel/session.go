// Package tunnel implements the CH-KEM tunnel with secure key exchange
// and encrypted data transport.
//
// The tunnel provides:
//   - Quantum-resistant key exchange using CH-KEM
//   - Authenticated encryption using AES-256-GCM or ChaCha20-Poly1305
//   - Forward secrecy through ephemeral keys
//   - Automatic rekeying to limit key exposure
//   - Replay protection through sequence numbers
package tunnel

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// SessionState represents the current state of the tunnel session.
type SessionState int32

const (
	// SessionStateNew indicates a fresh session not yet handshaked
	SessionStateNew SessionState = iota

	// SessionStateHandshaking indicates handshake is in progress
	SessionStateHandshaking

	// SessionStateEstablished indicates the tunnel is ready for data
	SessionStateEstablished

	// SessionStateRekeying indicates a rekey operation is in progress
	SessionStateRekeying

	// SessionStateClosed indicates the session has been terminated
	SessionStateClosed
)

// String returns a human-readable name for the session state.
func (s SessionState) String() string {
	switch s {
	case SessionStateNew:
		return "New"
	case SessionStateHandshaking:
		return "Handshaking"
	case SessionStateEstablished:
		return "Established"
	case SessionStateRekeying:
		return "Rekeying"
	case SessionStateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// Role indicates whether this endpoint is the initiator or responder.
type Role int

// Session role constants.
const (
	// RoleInitiator indicates this endpoint initiated the connection.
	RoleInitiator Role = iota
	// RoleResponder indicates this endpoint accepted the connection.
	RoleResponder
)

// Session represents a CH-KEM tunnel session.
type Session struct {
	// Unique session identifier
	ID []byte

	// Role of this endpoint
	Role Role

	// Current state
	state atomic.Int32

	// Protocol version negotiated
	Version protocol.Version

	// Selected cipher suite
	CipherSuite constants.CipherSuite

	// Local key pair for this session
	LocalKeyPair *chkem.KeyPair

	// Remote public key
	RemotePublicKey *chkem.PublicKey

	// StaticKeyPair is the responder's long-term identity for endpoint
	// authentication (server side). Nil means unauthenticated (default).
	StaticKeyPair *chkem.KeyPair

	// PinnedServerKey is the server static public key the initiator requires the
	// server to prove possession of (client side). Nil means unauthenticated.
	PinnedServerKey *chkem.PublicKey

	// RequireStaticAuth makes a responder reject any initiator that does not
	// authenticate it via static-key pinning (server side). Requires StaticKeyPair.
	RequireStaticAuth bool

	// PSK is a pre-shared key folded into the master secret for mutual
	// authentication. Both peers set it (PSKSize bytes). Nil means no PSK.
	PSK []byte

	// PSKIdentity is the label the initiator sends so the responder selects the
	// matching PSK. Set on both peers alongside PSK.
	PSKIdentity []byte

	// Master secret derived from CH-KEM
	masterSecret []byte

	// Traffic encryption ciphers
	sendCipher *crypto.AEAD
	recvCipher *crypto.AEAD

	// Sequence numbers
	sendSeq atomic.Uint64
	recvSeq atomic.Uint64 //nolint:unused // Reserved for future bidirectional validation

	// sendEpochStartSeq is the send sequence at which the current send cipher took
	// over. seq - sendEpochStartSeq is the per-epoch packet count, bounding how much
	// the current key seals (the stream nonce is derived, so the AEAD's own counter
	// no longer tracks this). Mirrors the datagram epoch startSeq.
	sendEpochStartSeq atomic.Uint64

	// Replay protection window
	replayWindow *ReplayWindow

	// Timestamps
	CreatedAt     time.Time
	EstablishedAt time.Time
	LastActivity  time.Time

	// Observability hooks
	observer Observer

	// Statistics
	BytesSent     atomic.Int64
	BytesReceived atomic.Int64
	PacketsSent   atomic.Int64
	PacketsRecv   atomic.Int64

	// Handshake transcript for key derivation
	transcriptHash []byte //nolint:unused // Reserved for future session verification

	// Rekey state
	rekeyInProgress     bool
	pendingRekeyKeyPair *chkem.KeyPair // New keypair for initiator
	pendingRekeySecret  []byte         // Pending shared secret for responder
	rekeyActivationSeq  uint64         // Sequence number when new keys activate
	pendingRecvCipher   *crypto.AEAD   // New receive cipher waiting for activation
	pendingSendCipher   *crypto.AEAD   // New send cipher waiting for activation (initiator)

	// Per-direction AEAD nonce prefixes. Both transports derive the nonce as
	// prefix || seq instead of transmitting it; the prefix is fixed for the session
	// (derived once from the initial master secret). See InitializeKeys (stream) and
	// InitializeDatagramKeys (datagram).
	sendNoncePrefix []byte
	recvNoncePrefix []byte

	// Datagram transport state (nil/unused on the TCP/stream path). The datagram
	// path selects the receive cipher by an explicit per-frame epoch (dgramEpochs)
	// instead of the stream trial-decrypt promote/discard, and tracks replay in a
	// wide, never-reset window (dgramReplay). See dgram_session.go.
	dgramEpochs       *datagramEpochState
	dgramReplay       *DatagramReplayWindow
	lastActivityNanos atomic.Int64

	// Mutex for state changes
	mu sync.RWMutex
}

// StreamReplayWindowSize is the stream replay window width in bits. It is widened
// from the original 64 so the filter tolerates deeper reordering before dropping
// packets as too old. Must be a multiple of 64.
const StreamReplayWindowSize = 1024

// ReplayWindow is the stream path's sliding-window replay filter. It reuses the
// same multi-word bitmap as the datagram path (see replay.go) so it tracks
// StreamReplayWindowSize sequence numbers instead of 64. Stream sequence numbers
// stay global and monotonic across a rekey, so the live receive path keeps this
// window across the trial-decrypt cipher promotion (promotePendingRecvCipher does
// not reset it). That persistence is what rejects a replay of the rekey-boundary
// packet, whose sequence the window already recorded.
type ReplayWindow struct {
	inner *DatagramReplayWindow
}

// NewReplayWindow creates a new replay protection window.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{inner: NewDatagramReplayWindowSize(StreamReplayWindowSize)}
}

// Check validates a sequence number against the replay window. It returns true if
// the sequence is fresh (not a replay and not older than the window) and records
// it, false otherwise.
func (rw *ReplayWindow) Check(seq uint64) bool {
	return rw.inner.Check(seq)
}

// NewSession creates a new session with the given role.
func NewSession(role Role) (*Session, error) {
	// Generate session ID
	sessionID, err := crypto.SecureRandomBytes(constants.SessionIDSize)
	if err != nil {
		return nil, err
	}

	// Generate local key pair
	keyPair, err := chkem.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	s := &Session{
		ID:           sessionID,
		Role:         role,
		LocalKeyPair: keyPair,
		replayWindow: NewReplayWindow(),
		CreatedAt:    time.Now(),
	}
	s.state.Store(int32(SessionStateNew))

	return s, nil
}

// State returns the current session state.
func (s *Session) State() SessionState {
	return SessionState(s.state.Load())
}

// SetState atomically sets the session state.
func (s *Session) SetState(state SessionState) {
	s.state.Store(int32(state))
}

// SetObserver sets an observer for session lifecycle and metrics.
// Should be called during initialization before any data is sent.
func (s *Session) SetObserver(observer Observer) {
	s.observer = observer
}

// InitializeKeys derives and sets up encryption keys from the master secret.
func (s *Session) InitializeKeys(masterSecret []byte, cipherSuite constants.CipherSuite) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Load() == int32(SessionStateClosed) {
		return qerrors.ErrTunnelClosed
	}

	if len(masterSecret) != constants.CHKEMSharedSecretSize {
		return qerrors.ErrInvalidKeySize
	}

	// Store master secret
	s.masterSecret = make([]byte, len(masterSecret))
	copy(s.masterSecret, masterSecret)
	s.CipherSuite = cipherSuite

	// Derive traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(masterSecret)
	if err != nil {
		return err
	}

	// Set up ciphers based on role
	var sendKey, recvKey []byte
	if s.Role == RoleInitiator {
		sendKey = initiatorKey
		recvKey = responderKey
	} else {
		sendKey = responderKey
		recvKey = initiatorKey
	}

	s.sendCipher, err = crypto.NewAEAD(cipherSuite, sendKey)
	if err != nil {
		return err
	}

	s.recvCipher, err = crypto.NewAEAD(cipherSuite, recvKey)
	if err != nil {
		return err
	}

	// Zeroize key material (sendKey/recvKey are aliases to initiatorKey/responderKey)
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

	// Derive the per-direction nonce prefixes. The stream no longer transmits the
	// AEAD nonce; it builds nonce = prefix || seq. The prefix is fixed for the
	// session (not re-derived on rekey), which is safe because seq is global and
	// monotonic, so the nonce never repeats.
	initiatorPrefix, responderPrefix, err := crypto.DeriveStreamNoncePrefixes(masterSecret)
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
	s.sendEpochStartSeq.Store(s.sendSeq.Load())

	s.EstablishedAt = time.Now()
	s.SetState(SessionStateEstablished)

	return nil
}

// Encrypt encrypts data for sending.
func (s *Session) Encrypt(plaintext []byte) ([]byte, uint64, error) {
	// Get the sequence number first
	seq := s.sendSeq.Add(1) - 1

	// The send cipher is switched to the new key explicitly at rekey time (initiator in
	// ProcessRekeyResponse; responder in ActivateRekeySend after its response is sent),
	// never lazily by sequence number — see the rekey trial-decryption design in Decrypt.
	// Read the cipher, nonce prefix, and epoch start together so the key-wear guard and
	// the derived nonce stay consistent with one another across a concurrent rekey.
	s.mu.RLock()
	cipher := s.sendCipher
	prefix := s.sendNoncePrefix
	startSeq := s.sendEpochStartSeq.Load()
	s.mu.RUnlock()

	observer := s.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnEncrypt(context.Background(), len(plaintext))
	}

	if cipher == nil {
		if observer != nil {
			observer.OnProtocolError(qerrors.ErrInvalidState)
		}
		if done != nil {
			done(qerrors.ErrInvalidState)
		}
		return nil, 0, qerrors.ErrInvalidState
	}

	// Hard cap on how many records this epoch's key seals. NeedsRekey starts a rekey
	// well before this; reaching the cap means it could not complete, so refuse rather
	// than overrun the key's safe usage limit. (The AEAD's own counter no longer tracks
	// this because the stream uses SealWithNonce.) The seq >= startSeq guard avoids a
	// uint64 underflow at the rekey boundary, where this seq was assigned just before a
	// concurrent rekey advanced sendEpochStartSeq (seq < startSeq, so per-epoch count 0).
	if seq >= startSeq && seq-startSeq >= constants.MaxPacketsBeforeRekey {
		if done != nil {
			done(qerrors.ErrNonceExhausted)
		}
		return nil, 0, qerrors.ErrNonceExhausted
	}

	// Use sequence number as additional authenticated data, and derive the AEAD nonce
	// as prefix || seq (not transmitted on the wire).
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, seq)

	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)
	ciphertext, err := cipher.SealWithNonce(nonce[:], plaintext, aad)
	if err != nil {
		if done != nil {
			done(err)
		}
		return nil, 0, err
	}
	if done != nil {
		done(nil)
	}

	s.BytesSent.Add(int64(len(plaintext)))
	s.PacketsSent.Add(1)
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()

	return ciphertext, seq, nil
}

// Decrypt decrypts received data.
func (s *Session) Decrypt(ciphertext []byte, seq uint64) ([]byte, error) {
	s.mu.RLock()
	cipher := s.recvCipher
	pendingCipher := s.pendingRecvCipher
	prefix := s.recvNoncePrefix
	s.mu.RUnlock()

	if cipher == nil {
		if s.observer != nil {
			s.observer.OnProtocolError(qerrors.ErrInvalidState)
		}
		return nil, qerrors.ErrInvalidState
	}

	// Check replay window
	if !s.replayWindow.Check(seq) {
		if s.observer != nil {
			s.observer.OnReplayDetected()
		}
		return nil, qerrors.ErrReplayDetected
	}

	observer := s.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnDecrypt(context.Background(), len(ciphertext))
	}

	// Use sequence number as additional authenticated data, and derive the AEAD nonce
	// as prefix || seq (the sender did not transmit it). The same nonce serves both the
	// current and the pending cipher; only the key differs.
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, seq)
	var nonce [constants.AESNonceSize]byte
	buildAEADNonce(nonce[:], prefix, seq)

	plaintext, err := cipher.OpenWithNonce(nonce[:], ciphertext, aad)
	if err != nil && pendingCipher != nil {
		// Rekey trial decryption: the peer may have switched to its new send key
		// before our matching receive key took over. Try the pending (new) cipher;
		// a successful Open means the peer has switched, so promote it as the live
		// receive cipher. On an in-order stream this happens exactly once, at the
		// old->new boundary. (Rekey state/master-secret finalization is independent
		// and already done at our own send-cipher switch.)
		if pt, perr := pendingCipher.OpenWithNonce(nonce[:], ciphertext, aad); perr == nil {
			s.promotePendingRecvCipher()
			plaintext, err = pt, nil
		}
	}
	if err != nil {
		if observer != nil {
			if qerrors.Is(err, qerrors.ErrAuthenticationFailed) {
				observer.OnAuthFailure()
			}
		}
		if done != nil {
			done(err)
		}
		return nil, err
	}
	if done != nil {
		done(nil)
	}

	s.BytesReceived.Add(int64(len(plaintext)))
	s.PacketsRecv.Add(1)
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()

	return plaintext, nil
}

// NeedsRekey returns true if the session should initiate rekeying.
func (s *Session) NeedsRekey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sendCipher == nil {
		return false
	}

	// Per-epoch key-wear: rekey before the current key seals too many records. The
	// stream derives its nonce (SealWithNonce), so the AEAD's own counter no longer
	// tracks this; use seq - sendEpochStartSeq like the datagram path.
	if s.sendSeq.Load()-s.sendEpochStartSeq.Load() >= datagramRekeyHighWater {
		return true
	}

	// Check byte limit
	if s.BytesSent.Load() >= constants.MaxBytesBeforeRekey {
		return true
	}

	// Check packet limit
	if s.PacketsSent.Load() >= constants.MaxPacketsBeforeRekey {
		return true
	}

	// Check time limit
	if time.Since(s.EstablishedAt).Seconds() >= float64(constants.MaxSessionDurationSeconds) {
		return true
	}

	return false
}

// Rekey performs a session rekey operation.
func (s *Session) Rekey(newMasterSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(newMasterSecret) != constants.CHKEMSharedSecretSize {
		return qerrors.ErrInvalidKeySize
	}

	// Derive new traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(newMasterSecret)
	if err != nil {
		return err
	}

	// Set up new ciphers
	var sendKey, recvKey []byte
	if s.Role == RoleInitiator {
		sendKey = initiatorKey
		recvKey = responderKey
	} else {
		sendKey = responderKey
		recvKey = initiatorKey
	}

	newSendCipher, err := crypto.NewAEAD(s.CipherSuite, sendKey)
	if err != nil {
		return err
	}

	newRecvCipher, err := crypto.NewAEAD(s.CipherSuite, recvKey)
	if err != nil {
		return err
	}

	// Atomically swap ciphers
	s.sendCipher = newSendCipher
	s.recvCipher = newRecvCipher
	s.sendEpochStartSeq.Store(s.sendSeq.Load())

	// Update master secret
	crypto.Zeroize(s.masterSecret)
	s.masterSecret = make([]byte, len(newMasterSecret))
	copy(s.masterSecret, newMasterSecret)

	// Zeroize key material (sendKey/recvKey are aliases to initiatorKey/responderKey)
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

	// Reset counters
	s.replayWindow = NewReplayWindow()
	s.EstablishedAt = time.Now()

	return nil
}

// ExportTicket creates an encrypted session ticket for resumption.
func (s *Session) ExportTicket(tm *TicketManager) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.State() != SessionStateEstablished {
		return nil, qerrors.ErrInvalidState
	}

	if s.masterSecret == nil {
		return nil, qerrors.ErrInvalidState
	}

	ticket := &SessionTicket{
		Version:      1,
		CipherSuite:  s.CipherSuite,
		MasterSecret: make([]byte, len(s.masterSecret)),
		CreatedAt:    s.EstablishedAt,
	}
	copy(ticket.MasterSecret, s.masterSecret)

	return tm.EncryptTicket(ticket)
}

// Resume restores a session from an encrypted ticket (called by responder).
// Returns the ticket's master secret (PSK) for mixing with a fresh KEM secret.
// Does NOT initialize traffic keys - that happens after the fresh KEM exchange.
func (s *Session) Resume(ticketBytes []byte, tm *TicketManager) ([]byte, error) {
	ticket, err := tm.DecryptTicket(ticketBytes)
	if err != nil {
		return nil, err
	}

	// Store cipher suite from ticket
	s.mu.Lock()
	s.CipherSuite = ticket.CipherSuite
	s.mu.Unlock()

	return ticket.MasterSecret, nil
}

// Close securely closes the session and zeroizes sensitive data.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.SetState(SessionStateClosed)

	// Zeroize sensitive data
	if s.masterSecret != nil {
		crypto.Zeroize(s.masterSecret)
		s.masterSecret = nil
	}

	if s.LocalKeyPair != nil {
		s.LocalKeyPair.Zeroize()
		s.LocalKeyPair = nil
	}

	s.sendCipher = nil
	s.recvCipher = nil
}

// Stats returns session statistics.
type Stats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsRecv   int64
	Duration      time.Duration
	State         SessionState
	CipherSuite   constants.CipherSuite
	FIPSMode      bool
}

// Stats returns current session statistics.
func (s *Session) Stats() Stats {
	return Stats{
		BytesSent:     s.BytesSent.Load(),
		BytesReceived: s.BytesReceived.Load(),
		PacketsSent:   s.PacketsSent.Load(),
		PacketsRecv:   s.PacketsRecv.Load(),
		Duration:      time.Since(s.CreatedAt),
		State:         s.State(),
		CipherSuite:   s.CipherSuite,
		FIPSMode:      crypto.FIPSMode(),
	}
}

// IsFIPSCompliant returns true if the session is using FIPS-compliant settings.
// This requires both FIPS mode to be enabled and a FIPS-approved cipher suite to be in use.
func (s *Session) IsFIPSCompliant() bool {
	return crypto.FIPSMode() && s.CipherSuite.IsFIPSApproved()
}

// --- Rekey Protocol Methods ---

// InitiateRekey starts a rekey operation (called by initiator).
// Returns the new public key to send to the responder and the activation sequence.
func (s *Session) InitiateRekey() ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rekeyInProgress {
		return nil, 0, qerrors.ErrRekeyInProgress
	}

	if s.State() != SessionStateEstablished {
		return nil, 0, qerrors.ErrInvalidState
	}

	// Generate new keypair for rekey
	newKeyPair, err := chkem.GenerateKeyPair()
	if err != nil {
		return nil, 0, err
	}

	// Set activation sequence to current + some buffer for in-flight packets
	activationSeq := s.sendSeq.Load() + 16

	s.rekeyInProgress = true
	s.pendingRekeyKeyPair = newKeyPair
	s.rekeyActivationSeq = activationSeq
	s.SetState(SessionStateRekeying)

	return newKeyPair.PublicKey().Bytes(), activationSeq, nil
}

// PrepareRekeyResponse processes an incoming rekey request (called by responder).
// Returns the ciphertext to send back to the initiator.
func (s *Session) PrepareRekeyResponse(newPublicKeyBytes []byte, activationSeq uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State() != SessionStateEstablished && s.State() != SessionStateRekeying {
		return nil, qerrors.ErrInvalidState
	}

	// Parse the new public key
	newPublicKey, err := chkem.ParsePublicKey(newPublicKeyBytes)
	if err != nil {
		return nil, err
	}

	// Encapsulate to the new public key
	ciphertext, freshSecret, err := chkem.Encapsulate(newPublicKey, chkem.RoleResponder)
	if err != nil {
		return nil, err
	}

	// Ratchet: mix current master secret with fresh KEM secret for forward secrecy
	newSecret, err := crypto.DeriveRekeySecret(s.masterSecret, freshSecret)
	if err != nil {
		return nil, err
	}
	crypto.Zeroize(freshSecret)

	// Derive new traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(newSecret)
	if err != nil {
		return nil, err
	}

	// Create new receive cipher (for receiving from initiator after activation)
	newRecvCipher, err := crypto.NewAEAD(s.CipherSuite, initiatorKey)
	if err != nil {
		return nil, err
	}

	// Create new send cipher
	newSendCipher, err := crypto.NewAEAD(s.CipherSuite, responderKey)
	if err != nil {
		return nil, err
	}

	// Store pending state (both ciphers activate at activation sequence)
	s.rekeyInProgress = true
	s.rekeyActivationSeq = activationSeq
	s.pendingRecvCipher = newRecvCipher
	s.pendingSendCipher = newSendCipher
	s.pendingRekeySecret = newSecret

	// Zeroize temporary keys
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

	s.SetState(SessionStateRekeying)

	return ciphertext.Bytes(), nil
}

// ProcessRekeyResponse completes a rekey operation (called by initiator).
func (s *Session) ProcessRekeyResponse(ciphertextBytes []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.rekeyInProgress || s.pendingRekeyKeyPair == nil {
		return qerrors.ErrInvalidState
	}

	// Parse ciphertext
	ciphertext, err := chkem.ParseCiphertext(ciphertextBytes)
	if err != nil {
		return err
	}

	// Decapsulate using pending keypair
	freshSecret, err := chkem.Decapsulate(ciphertext, s.pendingRekeyKeyPair, chkem.RoleInitiator)
	if err != nil {
		return err
	}

	// Ratchet: mix current master secret with fresh KEM secret for forward secrecy
	newSecret, err := crypto.DeriveRekeySecret(s.masterSecret, freshSecret)
	if err != nil {
		return err
	}
	crypto.Zeroize(freshSecret)

	// Derive new traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(newSecret)
	if err != nil {
		return err
	}

	// Create new ciphers
	newSendCipher, err := crypto.NewAEAD(s.CipherSuite, initiatorKey)
	if err != nil {
		return err
	}

	newRecvCipher, err := crypto.NewAEAD(s.CipherSuite, responderKey)
	if err != nil {
		return err
	}

	// The initiator switches its send cipher to the new key immediately: the rekey
	// request was sent and this response received under the old key, so all subsequent
	// application data must use the new key. The receive cipher is kept pending and
	// switched lazily via trial decryption once the responder's new-key traffic arrives.
	s.sendCipher = newSendCipher
	s.sendEpochStartSeq.Store(s.sendSeq.Load())
	s.pendingRecvCipher = newRecvCipher
	s.pendingRekeySecret = newSecret

	// Clean up pending keypair
	s.pendingRekeyKeyPair.Zeroize()
	s.pendingRekeyKeyPair = nil

	// Zeroize temporary keys
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

	// The send direction has switched, so the rekey handshake is complete for this
	// side: adopt the new master secret and clear rekey state. The receive cipher is
	// promoted separately, lazily, via trial decryption.
	s.finalizeRekeyStateLocked()

	return nil
}

// finalizeRekeyStateLocked adopts the pending rekey master secret and clears rekey
// handshake state. It does NOT touch the receive cipher (promoted separately via trial
// decryption in Decrypt). Caller must hold s.mu.
func (s *Session) finalizeRekeyStateLocked() {
	if s.pendingRekeySecret != nil {
		crypto.Zeroize(s.masterSecret)
		s.masterSecret = s.pendingRekeySecret
		s.pendingRekeySecret = nil
	}
	s.rekeyInProgress = false
	s.rekeyActivationSeq = 0
	s.EstablishedAt = time.Now()
	s.state.Store(int32(SessionStateEstablished))
}

// promotePendingRecvCipher switches the receive cipher to the pending (new) rekey cipher
// once the peer's new-key traffic is observed (via trial decryption). No-op if there is
// no pending receive cipher.
//
// The replay window is deliberately NOT reset here. Sequence numbers are global and
// monotonic across a rekey (sendSeq is never reset), so the existing window stays valid
// and continues to reject duplicates. Resetting it would re-arm a fresh window whose
// first Check accepts any sequence, letting an on-path attacker replay the boundary
// packet (whose sequence this Decrypt already recorded before promotion).
func (s *Session) promotePendingRecvCipher() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pendingRecvCipher == nil {
		return
	}
	s.recvCipher = s.pendingRecvCipher
	s.pendingRecvCipher = nil
}

// ActivatePendingKeys activates both pending rekey ciphers and finalizes rekey state in
// one step. The live transport path no longer calls this (it switches the send cipher
// explicitly and promotes the receive cipher lazily via trial decryption); it is
// retained for callers that want an immediate, combined activation.
func (s *Session) ActivatePendingKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.rekeyInProgress {
		return
	}

	// Switch both ciphers if pending.
	if s.pendingRecvCipher != nil {
		s.recvCipher = s.pendingRecvCipher
		s.pendingRecvCipher = nil
	}
	if s.pendingSendCipher != nil {
		s.sendCipher = s.pendingSendCipher
		s.pendingSendCipher = nil
		s.sendEpochStartSeq.Store(s.sendSeq.Load())
	}
	s.replayWindow = NewReplayWindow()

	// Adopt the new master secret and clear rekey handshake state.
	s.finalizeRekeyStateLocked()
}

// ActivateRekeySend switches the send cipher to the pending rekey send cipher.
//
// Called by the responder after its rekey response has been transmitted under the old
// key, so that subsequent application data uses the new key. The matching receive-side
// switch happens lazily via trial decryption in Decrypt (promotePendingRecvCipher). The
// initiator performs the equivalent send switch inline in ProcessRekeyResponse. No-op if
// there is no pending send cipher.
func (s *Session) ActivateRekeySend() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pendingSendCipher != nil {
		s.sendCipher = s.pendingSendCipher
		s.pendingSendCipher = nil
		s.sendEpochStartSeq.Store(s.sendSeq.Load())
	}

	// Send direction has switched to the new key, so the rekey handshake is complete
	// for this side. The receive cipher promotes lazily via trial decryption.
	s.finalizeRekeyStateLocked()
}

// IsRekeyInProgress returns true if a rekey operation is in progress.
func (s *Session) IsRekeyInProgress() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rekeyInProgress
}

// GetRekeyActivationSeq returns the sequence number at which new keys activate.
func (s *Session) GetRekeyActivationSeq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rekeyActivationSeq
}
