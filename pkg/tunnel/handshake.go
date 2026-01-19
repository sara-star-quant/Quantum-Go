// handshake.go implements the CH-KEM handshake state machine.
//
// Handshake Protocol:
//
//	Initiator                              Responder
//	    |                                      |
//	    | -------- ClientHello --------------> |
//	    |   - version, random                  |
//	    |   - CH-KEM public key                |
//	    |   - cipher suites                    |
//	    |                                      |
//	    | <------- ServerHello --------------- |
//	    |   - version, random                  |
//	    |   - CH-KEM ciphertext                |
//	    |   - selected cipher suite            |
//	    |                                      |
//	    |   [Both derive shared secret]        |
//	    |                                      |
//	    | -------- ClientFinished -----------> |
//	    |   - verify_data (encrypted)          |
//	    |                                      |
//	    | <------- ServerFinished ------------ |
//	    |   - verify_data (encrypted)          |
//	    |                                      |
//	    |    === Tunnel Established ===        |
//
// Security Properties:
//   - Forward secrecy: Ephemeral keys used for each session
//   - Quantum resistance: CH-KEM hybrid key exchange
//   - Mutual authentication: Through verify_data exchange
//   - Replay protection: Random nonces in hello messages
package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/chkem"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

// HandshakeState represents the current state of the handshake.
type HandshakeState int

const (
	HandshakeStateInitial HandshakeState = iota
	HandshakeStateClientHelloSent
	HandshakeStateServerHelloSent
	HandshakeStateClientFinishedSent
	HandshakeStateComplete
	HandshakeStateFailed
)

// Handshake manages the CH-KEM handshake process.
type Handshake struct {
	session *Session
	codec   *protocol.Codec
	state   HandshakeState

	// Handshake-specific data
	clientRandom []byte
	serverRandom []byte

	// CH-KEM encapsulation result
	sharedSecret []byte

	// Handshake ciphers (derived from shared secret)
	sendCipher *crypto.AEAD
	recvCipher *crypto.AEAD

	// Transcript for verify_data computation
	transcript bytes.Buffer
}

// NewHandshake creates a new handshake for the given session.
func NewHandshake(session *Session) *Handshake {
	return &Handshake{
		session: session,
		codec:   protocol.NewCodec(),
		state:   HandshakeStateInitial,
	}
}

// --- Initiator Functions ---

// CreateClientHello generates the ClientHello message.
func (h *Handshake) CreateClientHello() ([]byte, error) {
	if h.state != HandshakeStateInitial {
		return nil, qerrors.ErrInvalidState
	}

	// Generate client random
	h.clientRandom = crypto.MustSecureRandomBytes(32)

	msg := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         h.clientRandom,
		SessionID:      nil, // New session
		CHKEMPublicKey: h.session.LocalKeyPair.PublicKey().Bytes(),
		CipherSuites:   protocol.SupportedCipherSuites(),
	}

	data, err := h.codec.EncodeClientHello(msg)
	if err != nil {
		return nil, err
	}

	// Add to transcript
	h.transcript.Write(data)

	h.state = HandshakeStateClientHelloSent
	h.session.SetState(SessionStateHandshaking)

	return data, nil
}

// ProcessServerHello processes the ServerHello message (initiator).
func (h *Handshake) ProcessServerHello(data []byte) error {
	if h.state != HandshakeStateClientHelloSent {
		return qerrors.ErrInvalidState
	}

	msg, err := h.codec.DecodeServerHello(data)
	if err != nil {
		return err
	}

	// Validate version compatibility
	if !msg.Version.IsCompatible(protocol.Current) {
		return qerrors.ErrUnsupportedVersion
	}

	// Store server random
	h.serverRandom = msg.Random

	// Parse ciphertext
	ct, err := chkem.ParseCiphertext(msg.CHKEMCiphertext)
	if err != nil {
		return err
	}

	// Decapsulate to get shared secret
	h.sharedSecret, err = chkem.Decapsulate(ct, h.session.LocalKeyPair)
	if err != nil {
		return err
	}

	// Add to transcript
	h.transcript.Write(data)

	// Store negotiated parameters
	h.session.ID = msg.SessionID
	h.session.Version = msg.Version
	h.session.CipherSuite = msg.CipherSuite

	// Derive handshake keys
	if err := h.deriveHandshakeKeys(); err != nil {
		return err
	}

	return nil
}

// CreateClientFinished generates the ClientFinished message.
func (h *Handshake) CreateClientFinished() ([]byte, error) {
	if h.sendCipher == nil {
		return nil, qerrors.ErrInvalidState
	}

	// Compute verify_data = SHAKE-256(transcript || "client finished")
	verifyData, err := crypto.DeriveKey(
		"CH-KEM-VPN-ClientFinished",
		h.transcript.Bytes(),
		32,
	)
	if err != nil {
		return nil, err
	}

	// Encode message
	plaintext, err := h.codec.EncodeFinished(protocol.MessageTypeClientFinished, verifyData)
	if err != nil {
		return nil, err
	}

	// Encrypt with handshake key
	ciphertext, err := h.sendCipher.Seal(plaintext, nil)
	if err != nil {
		return nil, err
	}

	// Add plaintext to transcript (before encryption)
	h.transcript.Write(plaintext)

	h.state = HandshakeStateClientFinishedSent

	return ciphertext, nil
}

// ProcessServerFinished processes the ServerFinished message (initiator).
func (h *Handshake) ProcessServerFinished(data []byte) error {
	if h.state != HandshakeStateClientFinishedSent {
		return qerrors.ErrInvalidState
	}

	// Decrypt with handshake key
	plaintext, err := h.recvCipher.Open(data, nil)
	if err != nil {
		return qerrors.NewProtocolError("handshake", qerrors.ErrAuthenticationFailed)
	}

	// Decode verify_data
	verifyData, err := h.codec.DecodeFinished(plaintext)
	if err != nil {
		return err
	}

	// Compute expected verify_data
	expectedVerifyData, err := crypto.DeriveKey(
		"CH-KEM-VPN-ServerFinished",
		h.transcript.Bytes(),
		32,
	)
	if err != nil {
		return err
	}

	// Verify
	if !crypto.ConstantTimeCompare(verifyData, expectedVerifyData) {
		return qerrors.NewProtocolError("handshake", qerrors.ErrAuthenticationFailed)
	}

	// Initialize session with traffic keys
	if err := h.session.InitializeKeys(h.sharedSecret, h.session.CipherSuite); err != nil {
		return err
	}

	h.state = HandshakeStateComplete

	// Cleanup
	h.cleanup()

	return nil
}

// --- Responder Functions ---

// ProcessClientHello processes the ClientHello message (responder).
func (h *Handshake) ProcessClientHello(data []byte) error {
	if h.state != HandshakeStateInitial {
		return qerrors.ErrInvalidState
	}

	msg, err := h.codec.DecodeClientHello(data)
	if err != nil {
		return err
	}

	// Validate version
	if !msg.Version.IsCompatible(protocol.Current) {
		return qerrors.ErrUnsupportedVersion
	}

	// Store client random
	h.clientRandom = msg.Random

	// Parse client's public key
	clientPublicKey, err := chkem.ParsePublicKey(msg.CHKEMPublicKey)
	if err != nil {
		return err
	}
	h.session.RemotePublicKey = clientPublicKey

	// Select cipher suite (first mutually supported)
	h.session.CipherSuite = selectCipherSuite(msg.CipherSuites)
	if !h.session.CipherSuite.IsSupported() {
		return qerrors.ErrUnsupportedCipherSuite
	}

	// Add to transcript
	h.transcript.Write(data)

	h.session.Version = msg.Version
	h.session.SetState(SessionStateHandshaking)

	return nil
}

// CreateServerHello generates the ServerHello message.
func (h *Handshake) CreateServerHello() ([]byte, error) {
	if h.session.RemotePublicKey == nil {
		return nil, qerrors.ErrInvalidState
	}

	// Generate server random
	h.serverRandom = crypto.MustSecureRandomBytes(32)

	// Encapsulate with client's public key
	ct, sharedSecret, err := chkem.Encapsulate(h.session.RemotePublicKey)
	if err != nil {
		return nil, err
	}
	h.sharedSecret = sharedSecret

	msg := &protocol.ServerHello{
		Version:         protocol.Current,
		Random:          h.serverRandom,
		SessionID:       h.session.ID,
		CHKEMCiphertext: ct.Bytes(),
		CipherSuite:     h.session.CipherSuite,
	}

	data, err := h.codec.EncodeServerHello(msg)
	if err != nil {
		return nil, err
	}

	// Add to transcript
	h.transcript.Write(data)

	// Derive handshake keys
	if err := h.deriveHandshakeKeys(); err != nil {
		return nil, err
	}

	h.state = HandshakeStateServerHelloSent

	return data, nil
}

// ProcessClientFinished processes the ClientFinished message (responder).
func (h *Handshake) ProcessClientFinished(data []byte) error {
	if h.state != HandshakeStateServerHelloSent {
		return qerrors.ErrInvalidState
	}

	// Decrypt with handshake key
	plaintext, err := h.recvCipher.Open(data, nil)
	if err != nil {
		return qerrors.NewProtocolError("handshake", qerrors.ErrAuthenticationFailed)
	}

	// Decode verify_data
	verifyData, err := h.codec.DecodeFinished(plaintext)
	if err != nil {
		return err
	}

	// Compute expected verify_data
	expectedVerifyData, err := crypto.DeriveKey(
		"CH-KEM-VPN-ClientFinished",
		h.transcript.Bytes(),
		32,
	)
	if err != nil {
		return err
	}

	// Verify
	if !crypto.ConstantTimeCompare(verifyData, expectedVerifyData) {
		return qerrors.NewProtocolError("handshake", qerrors.ErrAuthenticationFailed)
	}

	// Add plaintext to transcript
	h.transcript.Write(plaintext)

	return nil
}

// CreateServerFinished generates the ServerFinished message.
func (h *Handshake) CreateServerFinished() ([]byte, error) {
	if h.sendCipher == nil {
		return nil, qerrors.ErrInvalidState
	}

	// Compute verify_data
	verifyData, err := crypto.DeriveKey(
		"CH-KEM-VPN-ServerFinished",
		h.transcript.Bytes(),
		32,
	)
	if err != nil {
		return nil, err
	}

	// Encode message
	plaintext, err := h.codec.EncodeFinished(protocol.MessageTypeServerFinished, verifyData)
	if err != nil {
		return nil, err
	}

	// Encrypt with handshake key
	ciphertext, err := h.sendCipher.Seal(plaintext, nil)
	if err != nil {
		return nil, err
	}

	// Initialize session with traffic keys
	if err := h.session.InitializeKeys(h.sharedSecret, h.session.CipherSuite); err != nil {
		return nil, err
	}

	h.state = HandshakeStateComplete

	// Cleanup
	h.cleanup()

	return ciphertext, nil
}

// --- Helper Functions ---

// deriveHandshakeKeys derives encryption keys for the handshake phase.
func (h *Handshake) deriveHandshakeKeys() error {
	initiatorKey, responderKey, _, _, err := crypto.DeriveHandshakeKeys(h.sharedSecret)
	if err != nil {
		return err
	}

	// Set up ciphers based on role
	var sendKey, recvKey []byte
	if h.session.Role == RoleInitiator {
		sendKey = initiatorKey
		recvKey = responderKey
	} else {
		sendKey = responderKey
		recvKey = initiatorKey
	}

	h.sendCipher, err = crypto.NewAEAD(h.session.CipherSuite, sendKey)
	if err != nil {
		return err
	}

	h.recvCipher, err = crypto.NewAEAD(h.session.CipherSuite, recvKey)
	if err != nil {
		return err
	}

	// Zeroize key material
	crypto.ZeroizeMultiple(initiatorKey, responderKey, sendKey, recvKey)

	return nil
}

// selectCipherSuite selects the first mutually supported cipher suite.
func selectCipherSuite(offered []constants.CipherSuite) constants.CipherSuite {
	supported := protocol.SupportedCipherSuites()

	for _, o := range offered {
		for _, s := range supported {
			if o == s {
				return o
			}
		}
	}

	return 0 // No match
}

// cleanup zeroizes sensitive handshake data.
func (h *Handshake) cleanup() {
	if h.sharedSecret != nil {
		crypto.Zeroize(h.sharedSecret)
		h.sharedSecret = nil
	}
	if h.clientRandom != nil {
		crypto.Zeroize(h.clientRandom)
		h.clientRandom = nil
	}
	if h.serverRandom != nil {
		crypto.Zeroize(h.serverRandom)
		h.serverRandom = nil
	}
	h.sendCipher = nil
	h.recvCipher = nil
	h.transcript.Reset()
}

// State returns the current handshake state.
func (h *Handshake) State() HandshakeState {
	return h.state
}

// IsComplete returns true if the handshake completed successfully.
func (h *Handshake) IsComplete() bool {
	return h.state == HandshakeStateComplete
}

// writeEncryptedRecord writes an encrypted record with length framing.
// Format: [4-byte big-endian length][ciphertext]
func writeEncryptedRecord(w io.Writer, ciphertext []byte) error {
	// Write length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	// Write ciphertext
	_, err := w.Write(ciphertext)
	return err
}

// readEncryptedRecord reads an encrypted record with length framing.
func readEncryptedRecord(r io.Reader) ([]byte, error) {
	// Read length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)

	// Sanity check on length
	if length > protocol.MaxMessageSize {
		return nil, qerrors.ErrMessageTooLarge
	}

	// Read ciphertext
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// --- High-Level API ---

// InitiatorHandshake performs the complete handshake as initiator.
func InitiatorHandshake(session *Session, rw io.ReadWriter) error {
	h := NewHandshake(session)

	// Send ClientHello
	clientHello, err := h.CreateClientHello()
	if err != nil {
		return err
	}
	if _, err := rw.Write(clientHello); err != nil {
		return err
	}

	// Receive ServerHello
	serverHello, err := h.codec.ReadMessage(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessServerHello(serverHello); err != nil {
		return err
	}

	// Send ClientFinished (encrypted, with length framing)
	clientFinished, err := h.CreateClientFinished()
	if err != nil {
		return err
	}
	if err := writeEncryptedRecord(rw, clientFinished); err != nil {
		return err
	}

	// Receive ServerFinished (encrypted, with length framing)
	serverFinished, err := readEncryptedRecord(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessServerFinished(serverFinished); err != nil {
		return err
	}

	return nil
}

// ResponderHandshake performs the complete handshake as responder.
func ResponderHandshake(session *Session, rw io.ReadWriter) error {
	h := NewHandshake(session)

	// Receive ClientHello
	clientHello, err := h.codec.ReadMessage(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessClientHello(clientHello); err != nil {
		return err
	}

	// Send ServerHello
	serverHello, err := h.CreateServerHello()
	if err != nil {
		return err
	}
	if _, err := rw.Write(serverHello); err != nil {
		return err
	}

	// Receive ClientFinished (encrypted, with length framing)
	clientFinished, err := readEncryptedRecord(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessClientFinished(clientFinished); err != nil {
		return err
	}

	// Send ServerFinished (encrypted, with length framing)
	serverFinished, err := h.CreateServerFinished()
	if err != nil {
		return err
	}
	if err := writeEncryptedRecord(rw, serverFinished); err != nil {
		return err
	}

	return nil
}
