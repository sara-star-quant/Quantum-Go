// Package tunnel implements the CH-KEM VPN tunnel with secure key exchange
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/chkem"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/protocol"
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

const (
	RoleInitiator Role = iota
	RoleResponder
)

// Session represents a CH-KEM VPN tunnel session.
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

	// Master secret derived from CH-KEM
	masterSecret []byte

	// Traffic encryption ciphers
	sendCipher *crypto.AEAD
	recvCipher *crypto.AEAD

	// Sequence numbers
	sendSeq atomic.Uint64
	recvSeq atomic.Uint64 //nolint:unused // Reserved for future bidirectional validation

	// Replay protection window
	replayWindow *ReplayWindow

	// Timestamps
	CreatedAt     time.Time
	EstablishedAt time.Time
	LastActivity  time.Time

	// Observability hooks
	observer Observer

	// Statistics
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
	PacketsSent   atomic.Uint64
	PacketsRecv   atomic.Uint64

	// Handshake transcript for key derivation
	transcriptHash []byte //nolint:unused // Reserved for future session verification

	// Rekey state
	rekeyInProgress     bool
	pendingRekeyKeyPair *chkem.KeyPair // New keypair for initiator
	pendingRekeySecret  []byte         // Pending shared secret for responder
	rekeyActivationSeq  uint64         // Sequence number when new keys activate
	pendingRecvCipher   *crypto.AEAD   // New receive cipher waiting for activation
	pendingSendCipher   *crypto.AEAD   // New send cipher waiting for activation (initiator)

	// Mutex for state changes
	mu sync.RWMutex
}

// ReplayWindow implements a sliding window for replay attack protection.
type ReplayWindow struct {
	mu         sync.Mutex
	highSeq    uint64
	bitmap     uint64 // Bitmap for last 64 sequence numbers
	windowSize uint64
}

// NewReplayWindow creates a new replay protection window.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{
		highSeq:    0,
		bitmap:     0,
		windowSize: 64,
	}
}

// Check validates a sequence number against the replay window.
// Returns true if the sequence number is valid (not a replay).
func (rw *ReplayWindow) Check(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Sequence number is too old
	if seq+rw.windowSize <= rw.highSeq {
		return false
	}

	// Sequence number is within the window
	if seq <= rw.highSeq {
		diff := rw.highSeq - seq
		bit := uint64(1) << diff
		if rw.bitmap&bit != 0 {
			return false // Already received
		}
		rw.bitmap |= bit
		return true
	}

	// New highest sequence number
	if seq > rw.highSeq {
		diff := seq - rw.highSeq
		if diff >= rw.windowSize {
			rw.bitmap = 0
		} else {
			rw.bitmap <<= diff
		}
		rw.bitmap |= 1
		rw.highSeq = seq
	}

	return true
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

	// Zeroize key material
	crypto.ZeroizeMultiple(initiatorKey, responderKey, sendKey, recvKey)

	s.EstablishedAt = time.Now()
	s.SetState(SessionStateEstablished)

	return nil
}

// Encrypt encrypts data for sending.
func (s *Session) Encrypt(plaintext []byte) ([]byte, uint64, error) {
	// Get the sequence number first
	seq := s.sendSeq.Add(1) - 1

	// Check if we need to activate pending send cipher at this sequence
	s.checkAndActivateSendCipher(seq)

	// Now get the current send cipher (potentially just activated)
	s.mu.RLock()
	cipher := s.sendCipher
	s.mu.RUnlock()

	observer := s.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnEncrypt(context.Background(), uint64(len(plaintext)))
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

	// Use sequence number as additional authenticated data
	aad := make([]byte, 8)
	seqCopy := seq
	for i := 7; i >= 0; i-- {
		aad[i] = byte(seqCopy)
		seqCopy >>= 8
	}

	ciphertext, err := cipher.Seal(plaintext, aad)
	if err != nil {
		if done != nil {
			done(err)
		}
		return nil, 0, err
	}
	if done != nil {
		done(nil)
	}

	s.BytesSent.Add(uint64(len(plaintext)))
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
		_, done = observer.OnDecrypt(context.Background(), uint64(len(ciphertext)))
	}

	// Use sequence number as additional authenticated data
	aad := make([]byte, 8)
	seqCopy := seq
	for i := 7; i >= 0; i-- {
		aad[i] = byte(seqCopy)
		seqCopy >>= 8
	}

	plaintext, err := cipher.Open(ciphertext, aad)
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

	s.BytesReceived.Add(uint64(len(plaintext)))
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

	// Check nonce exhaustion
	if s.sendCipher.NeedsRekey() {
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

	// Update master secret
	crypto.Zeroize(s.masterSecret)
	s.masterSecret = make([]byte, len(newMasterSecret))
	copy(s.masterSecret, newMasterSecret)

	// Zeroize key material
	crypto.ZeroizeMultiple(initiatorKey, responderKey, sendKey, recvKey)

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
func (s *Session) Resume(ticketBytes []byte, tm *TicketManager) ([]byte, error) {
	ticket, err := tm.DecryptTicket(ticketBytes)
	if err != nil {
		return nil, err
	}

	// Initialize session state from ticket
	s.mu.Lock()
	s.CipherSuite = ticket.CipherSuite
	s.mu.Unlock()

	// Initialize traffic keys
	if err := s.InitializeKeys(ticket.MasterSecret, ticket.CipherSuite); err != nil {
		return nil, err
	}

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
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Duration      time.Duration
	State         SessionState
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
	}
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
	ciphertext, sharedSecret, err := chkem.Encapsulate(newPublicKey)
	if err != nil {
		return nil, err
	}

	// Derive new traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(sharedSecret)
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
	s.pendingRekeySecret = sharedSecret

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
	sharedSecret, err := chkem.Decapsulate(ciphertext, s.pendingRekeyKeyPair)
	if err != nil {
		return err
	}

	// Derive new traffic keys
	initiatorKey, responderKey, err := crypto.DeriveTrafficKeys(sharedSecret)
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

	// Store pending ciphers (will activate at activation sequence)
	s.pendingRecvCipher = newRecvCipher
	s.pendingSendCipher = newSendCipher
	s.pendingRekeySecret = sharedSecret

	// Clean up pending keypair
	s.pendingRekeyKeyPair.Zeroize()
	s.pendingRekeyKeyPair = nil

	// Zeroize temporary keys
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

	return nil
}

// ActivatePendingKeys activates pending keys after activation sequence is reached.
func (s *Session) ActivatePendingKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.rekeyInProgress {
		return
	}

	// Switch receive cipher if pending
	if s.pendingRecvCipher != nil {
		s.recvCipher = s.pendingRecvCipher
		s.pendingRecvCipher = nil
	}

	// Switch send cipher if pending
	if s.pendingSendCipher != nil {
		s.sendCipher = s.pendingSendCipher
		s.pendingSendCipher = nil
	}

	// Update master secret
	if s.pendingRekeySecret != nil {
		crypto.Zeroize(s.masterSecret)
		s.masterSecret = s.pendingRekeySecret
		s.pendingRekeySecret = nil
	}

	// Reset rekey state
	s.rekeyInProgress = false
	s.rekeyActivationSeq = 0
	s.replayWindow = NewReplayWindow()
	s.EstablishedAt = time.Now()

	s.SetState(SessionStateEstablished)
}

// checkAndActivateSendCipher checks if send cipher should be activated based on sequence number.
// When activation happens, it also activates pending keys on the receive side if available.
func (s *Session) checkAndActivateSendCipher(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rekeyInProgress && s.pendingSendCipher != nil && seq >= s.rekeyActivationSeq {
		// Switch send cipher
		s.sendCipher = s.pendingSendCipher
		s.pendingSendCipher = nil

		// Also switch receive cipher if pending
		if s.pendingRecvCipher != nil {
			s.recvCipher = s.pendingRecvCipher
			s.pendingRecvCipher = nil
		}

		// Update master secret
		if s.pendingRekeySecret != nil {
			crypto.Zeroize(s.masterSecret)
			s.masterSecret = s.pendingRekeySecret
			s.pendingRekeySecret = nil
		}

		// Complete the rekey
		s.rekeyInProgress = false
		s.rekeyActivationSeq = 0
		s.replayWindow = NewReplayWindow()
		s.EstablishedAt = time.Now()
		s.state.Store(int32(SessionStateEstablished))
	}
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
