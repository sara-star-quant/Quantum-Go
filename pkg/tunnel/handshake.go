// Package tunnel implements the CH-KEM handshake state machine.
//
// This file (handshake.go) implements the handshake protocol:
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
	"context"
	"encoding/binary"
	"io"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// HandshakeState represents the current state of the handshake.
type HandshakeState int

// Handshake state machine states.
const (
	// HandshakeStateInitial is the starting state before any messages.
	HandshakeStateInitial HandshakeState = iota
	// HandshakeStateClientHelloSent indicates ClientHello was sent (initiator).
	HandshakeStateClientHelloSent
	// HandshakeStateServerHelloSent indicates ServerHello was sent (responder).
	HandshakeStateServerHelloSent
	// HandshakeStateClientFinishedSent indicates ClientFinished was sent.
	HandshakeStateClientFinishedSent
	// HandshakeStateComplete indicates the handshake completed successfully.
	HandshakeStateComplete
	// HandshakeStateFailed indicates the handshake failed.
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

	// staticSecret holds the static-key authentication secret between the static
	// CH-KEM leg (set in CreateClientHello on the client, ProcessClientHello on
	// the server) and the fold into sharedSecret before key derivation. Nil in
	// unauthenticated mode.
	staticSecret []byte

	// foldPSK records that both peers agreed on a pre-shared key (the client always
	// folds when configured; the server folds when the client's identity matches),
	// so foldPSKSecret mixes session.PSK into the master secret before key derivation.
	foldPSK bool

	// Handshake ciphers (derived from shared secret)
	sendCipher *crypto.AEAD
	recvCipher *crypto.AEAD

	// Transcript for verify_data computation
	transcript bytes.Buffer

	// HelloRetryRequest state. firstClientHello is the framed bytes of the first
	// ClientHello, kept so the RFC 8446 4.4.1 synthetic message hash can replace it
	// in the transcript on a retry. sendHRR (server) signals the driver to answer
	// the current ClientHello with a HelloRetryRequest for hrrSuite instead of a
	// ServerHello. hrrDone bounds the exchange to a single retry on both peers.
	firstClientHello []byte
	sendHRR          bool
	hrrSuite         chkem.SuiteID
	hrrDone          bool

	// Resumption state
	ticket        []byte         // Client ticket to send
	ticketSecret  []byte         // Initiator's secret for the ticket
	ticketManager *TicketManager // Server ticket manager to verify
	resumed       bool           // Whether this is a resumed session

	// datagram selects InitializeDatagramKeys (epoch-keyed, derived nonces) over
	// the stream InitializeKeys at completion. The datagram FSM sets it; the
	// stream path leaves it false and is byte-for-byte unchanged.
	datagram bool
}

// initializeSessionKeys installs traffic keys at handshake completion, choosing
// the datagram key setup (derived nonce prefixes + epoch 0) when this handshake
// runs over the datagram transport, and the stream setup otherwise.
func (h *Handshake) initializeSessionKeys() error {
	if h.datagram {
		return h.session.InitializeDatagramKeys(h.sharedSecret, h.session.CipherSuite)
	}
	return h.session.InitializeKeys(h.sharedSecret, h.session.CipherSuite)
}

// NewHandshake creates a new handshake for the given session.
func NewHandshake(session *Session) *Handshake {
	return &Handshake{
		session: session,
		codec:   protocol.NewCodec(),
		state:   HandshakeStateInitial,
	}
}

// SetTicket sets the session ticket for resumption (initiator).
func (h *Handshake) SetTicket(ticket, secret []byte) {
	h.ticket = ticket
	h.ticketSecret = secret
}

// SetTicketManager sets the ticket manager for resumption (responder).
func (h *Handshake) SetTicketManager(tm *TicketManager) {
	h.ticketManager = tm
}

// sendHandshakeAlert sends a handshake failure alert. Best effort.
func sendHandshakeAlert(rw io.ReadWriter, codec *protocol.Codec, code protocol.AlertCode, desc string) {
	msg := codec.EncodeAlert(protocol.AlertLevelFatal, code, desc)
	_, _ = rw.Write(msg)
}

// --- Initiator Functions ---

// CreateClientHello generates the ClientHello message.
func (h *Handshake) CreateClientHello() ([]byte, error) {
	if h.state != HandshakeStateInitial {
		return nil, qerrors.ErrInvalidState
	}

	// Generate client random. Keep it stable across a HelloRetryRequest retry so the
	// only difference between ClientHello1 and ClientHello2 is the KEM suite + share.
	if h.clientRandom == nil {
		h.clientRandom = crypto.MustSecureRandomBytes(32)
	}

	msg := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         h.clientRandom,
		SessionID:      h.ticket,
		KEMSuite:       uint16(h.session.kemSuite.ID()),
		KEMSuites:      supportedKEMSuiteIDs(),
		CHKEMPublicKey: h.session.LocalKeyPair.PublicKey().Bytes(),
		CipherSuites:   protocol.SupportedCipherSuites(),
	}

	// Static-key authentication: encapsulate to the pinned server static key so
	// only the holder of the matching private key can derive the same secret.
	if h.session.PinnedServerKey != nil {
		staticCT, staticSecret, err := h.session.kemSuite.Encapsulate(h.session.PinnedServerKey, chkem.RoleInitiator)
		if err != nil {
			return nil, err
		}
		h.staticSecret = staticSecret
		msg.CHKEMStaticCiphertext = staticCT.Bytes()
	}

	// PSK mutual authentication: advertise the identity so the server selects the
	// matching key, and fold our copy into the master secret before key derivation.
	if h.session.PSK != nil {
		msg.PSKIdentity = h.session.PSKIdentity
		h.foldPSK = true
	}

	data, err := h.codec.EncodeClientHello(msg)
	if err != nil {
		return nil, err
	}

	// Add to transcript, and remember the first ClientHello frame for the synthetic
	// message hash if a HelloRetryRequest follows.
	h.transcript.Write(data)
	if h.firstClientHello == nil {
		h.firstClientHello = data
	}

	h.state = HandshakeStateClientHelloSent
	h.session.SetState(SessionStateHandshaking)

	return data, nil
}

// ProcessHelloRetryRequest handles a HelloRetryRequest (initiator): adopt the KEM
// suite the server chose, regenerate the ephemeral key share in it, rewrite the
// transcript with the RFC 8446 4.4.1 synthetic message hash, and re-arm so the
// driver re-sends a ClientHello. Bounded to one retry.
func (h *Handshake) ProcessHelloRetryRequest(data []byte) error {
	if h.state != HandshakeStateClientHelloSent {
		return qerrors.ErrInvalidState
	}
	if h.hrrDone {
		return qerrors.ErrUnsupportedKEMSuite // a second HelloRetryRequest is not allowed
	}
	msg, err := h.codec.DecodeHelloRetryRequest(data)
	if err != nil {
		return err
	}
	if !msg.Version.IsCompatible(protocol.Current) {
		return qerrors.ErrUnsupportedVersion
	}
	suite, err := resolveKEMSuite(msg.KEMSuite)
	if err != nil {
		return err
	}
	// The retried suite must be one we offered, or the server is steering us off-list.
	if !offeredKEMSuite(msg.KEMSuite) {
		return qerrors.ErrUnsupportedKEMSuite
	}

	// Adopt the suite and regenerate the ephemeral key share in it.
	newKeyPair, err := suite.GenerateKeyPair()
	if err != nil {
		return err
	}
	if h.session.LocalKeyPair != nil {
		h.session.LocalKeyPair.Zeroize()
	}
	h.session.kemSuite = suite
	h.session.LocalKeyPair = newKeyPair

	// Synthetic transcript: SHA3-256(ClientHello1) || HelloRetryRequest, replacing the
	// raw ClientHello1, so the original advertisement is bound even across the retry.
	if err := h.replaceFirstHelloWithHash(data); err != nil {
		return err
	}
	h.hrrDone = true
	h.state = HandshakeStateInitial // re-arm CreateClientHello for the retried hello
	return nil
}

// replaceFirstHelloWithHash rewrites the transcript per RFC 8446 4.4.1: it resets
// it to SHA3-256(firstClientHello) followed by the HelloRetryRequest frame. The
// caller has already accumulated only ClientHello1 in the transcript.
func (h *Handshake) replaceFirstHelloWithHash(hrrFrame []byte) error {
	ch1Hash, err := crypto.TranscriptHash(h.firstClientHello)
	if err != nil {
		return err
	}
	h.transcript.Reset()
	h.transcript.Write(ch1Hash)
	h.transcript.Write(hrrFrame)
	return nil
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

	// The server must echo the KEM suite our key share used (no HelloRetryRequest
	// yet). A mismatch is a downgrade attempt; the transcript also binds the suite,
	// so this fails the Finished MAC regardless, but reject early and clearly.
	if msg.KEMSuite != uint16(h.session.kemSuite.ID()) {
		return qerrors.ErrUnsupportedKEMSuite
	}

	// Check if server accepted resumption
	if len(msg.SessionID) > 0 && h.ticket != nil && bytes.Equal(msg.SessionID, h.ticket) {
		h.resumed = true
	}

	// Store server random
	h.serverRandom = msg.Random

	// Always decapsulate (server always sends real ciphertext now)
	ct, err := h.session.kemSuite.ParseCiphertext(msg.CHKEMCiphertext)
	if err != nil {
		return err
	}

	freshSecret, err := h.session.kemSuite.Decapsulate(ct, h.session.LocalKeyPair, chkem.RoleInitiator)
	if err != nil {
		return err
	}

	if h.resumed {
		// PSK+KEM mode: mix ticket secret with fresh KEM secret
		h.sharedSecret, err = crypto.DeriveResumptionSecret(h.ticketSecret, freshSecret)
		if err != nil {
			return err
		}
		crypto.Zeroize(freshSecret)
	} else {
		h.sharedSecret = freshSecret
	}

	// Add to transcript
	h.transcript.Write(data)

	// Store negotiated parameters
	h.session.ID = msg.SessionID
	h.session.Version = msg.Version
	h.session.CipherSuite = msg.CipherSuite

	// Fold the static-key authentication secret into the master secret. The
	// ephemeral secret stays a mandatory input, so forward secrecy holds.
	if err := h.foldStaticSecret(); err != nil {
		return err
	}

	// Fold the PSK (mutual authentication) after any static fold, same order on
	// both peers.
	if err := h.foldPSKSecret(); err != nil {
		return err
	}

	// Derive handshake keys
	return h.deriveHandshakeKeys()
}

// CreateClientFinished generates the ClientFinished message.
func (h *Handshake) CreateClientFinished() ([]byte, error) {
	if h.sendCipher == nil {
		return nil, qerrors.ErrInvalidState
	}

	// Compute verify_data = SHAKE-256(sharedSecret || transcript || "client finished")
	// Including the shared secret proves both sides hold the same key material
	verifyData, err := crypto.DeriveKeyMultiple(
		"CH-KEM-Tunnel-ClientFinished",
		[][]byte{h.sharedSecret, h.transcript.Bytes()},
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

	// Compute expected verify_data with shared secret binding
	expectedVerifyData, err := crypto.DeriveKeyMultiple(
		"CH-KEM-Tunnel-ServerFinished",
		[][]byte{h.sharedSecret, h.transcript.Bytes()},
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
	if err := h.initializeSessionKeys(); err != nil {
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

	// Negotiate the KEM suite before any heavy crypto. If we do not support the suite
	// the client's key share uses, steer it with a HelloRetryRequest to a mutually
	// supported suite (once). If there is no overlap, or we already retried, fail closed.
	suite, err := resolveKEMSuite(msg.KEMSuite)
	if err != nil {
		if h.hrrDone {
			return err
		}
		mutual, ok := selectMutualKEMSuite(msg.KEMSuites)
		if !ok {
			return qerrors.ErrUnsupportedKEMSuite
		}
		// Short-circuit: do not process this hello's key share. Remember it for the
		// synthetic transcript hash and signal the driver to send a HelloRetryRequest.
		h.firstClientHello = data
		h.hrrSuite = mutual
		h.sendHRR = true
		return nil
	}
	h.session.kemSuite = suite

	// Store client random
	h.clientRandom = msg.Random

	// Check for resumption
	if len(msg.SessionID) > 0 && h.ticketManager != nil {
		secret, err := h.session.Resume(msg.SessionID, h.ticketManager)
		if err == nil {
			h.resumed = true
			h.ticketSecret = secret
			h.session.ID = msg.SessionID
		}
	}

	// Always parse client's public key (needed for fresh KEM exchange even during resumption)
	clientPublicKey, err := h.session.kemSuite.ParsePublicKey(msg.CHKEMPublicKey)
	if err != nil {
		return err
	}
	h.session.RemotePublicKey = clientPublicKey

	// If the server requires static-key authentication, reject any client that
	// sent no static ciphertext (unpinned, or a MitM that stripped the field).
	if h.session.RequireStaticAuth && len(msg.CHKEMStaticCiphertext) == 0 {
		return qerrors.ErrStaticAuthRequired
	}

	// Static-key authentication: if we hold a static identity and the client sent
	// a static ciphertext, decapsulate it. Only our static private key recovers
	// the secret the client encapsulated to our pinned public key. ML-KEM implicit
	// rejection means a wrong key yields a pseudo-random secret (no error/oracle);
	// the mismatch surfaces later as a Finished MAC failure.
	if h.session.StaticKeyPair != nil && len(msg.CHKEMStaticCiphertext) > 0 {
		staticCT, err := h.session.kemSuite.ParseCiphertext(msg.CHKEMStaticCiphertext)
		if err != nil {
			return err
		}
		staticSecret, err := h.session.kemSuite.Decapsulate(staticCT, h.session.StaticKeyPair, chkem.RoleResponder)
		if err != nil {
			return err
		}
		h.staticSecret = staticSecret
	}

	// PSK mutual authentication: fold our PSK only when the client advertised the
	// matching identity. An unknown or absent identity means no fold, so a client
	// that expected a PSK fails closed at the Finished MAC (no identity oracle).
	if h.session.PSK != nil && len(msg.PSKIdentity) > 0 &&
		bytes.Equal(msg.PSKIdentity, h.session.PSKIdentity) {
		h.foldPSK = true
	}

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

// CreateHelloRetryRequest builds the HelloRetryRequest the driver sends instead of
// ServerHello when ProcessClientHello signaled a KEM-suite mismatch. It applies the
// RFC 8446 4.4.1 synthetic transcript (hash of ClientHello1 + this HRR), so the
// retried exchange stays downgrade-bound. Valid only right after ProcessClientHello
// set sendHRR.
func (h *Handshake) CreateHelloRetryRequest() ([]byte, error) {
	if !h.sendHRR {
		return nil, qerrors.ErrInvalidState
	}
	data, err := h.codec.EncodeHelloRetryRequest(&protocol.HelloRetryRequest{
		Version:  protocol.Current,
		KEMSuite: uint16(h.hrrSuite),
	})
	if err != nil {
		return nil, err
	}
	if err := h.replaceFirstHelloWithHash(data); err != nil {
		return nil, err
	}
	h.sendHRR = false
	h.hrrDone = true
	return data, nil
}

// CreateServerHello generates the ServerHello message.
func (h *Handshake) CreateServerHello() ([]byte, error) {
	if h.session.RemotePublicKey == nil {
		return nil, qerrors.ErrInvalidState
	}

	// Generate server random
	h.serverRandom = crypto.MustSecureRandomBytes(32)

	// Always perform fresh KEM exchange (even during resumption for forward secrecy)
	ct, freshSecret, err := h.session.kemSuite.Encapsulate(h.session.RemotePublicKey, chkem.RoleResponder)
	if err != nil {
		return nil, err
	}
	ctBytes := ct.Bytes()

	if h.resumed {
		// PSK+KEM mode: mix ticket secret with fresh KEM secret
		h.sharedSecret, err = crypto.DeriveResumptionSecret(h.ticketSecret, freshSecret)
		if err != nil {
			return nil, err
		}
		crypto.Zeroize(freshSecret)
	} else {
		h.sharedSecret = freshSecret
	}

	msg := &protocol.ServerHello{
		Version:         protocol.Current,
		Random:          h.serverRandom,
		SessionID:       h.session.ID,
		KEMSuite:        uint16(h.session.kemSuite.ID()),
		CHKEMCiphertext: ctBytes,
		CipherSuite:     h.session.CipherSuite,
	}

	data, err := h.codec.EncodeServerHello(msg)
	if err != nil {
		return nil, err
	}

	// Add to transcript
	h.transcript.Write(data)

	// Fold the static-key authentication secret (set in ProcessClientHello) into
	// the master secret before deriving keys, matching the client.
	if err := h.foldStaticSecret(); err != nil {
		return nil, err
	}

	// Fold the PSK (set in ProcessClientHello on an identity match) in the same
	// order as the client.
	if err := h.foldPSKSecret(); err != nil {
		return nil, err
	}

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

	// Compute expected verify_data with shared secret binding
	expectedVerifyData, err := crypto.DeriveKeyMultiple(
		"CH-KEM-Tunnel-ClientFinished",
		[][]byte{h.sharedSecret, h.transcript.Bytes()},
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

	// Compute verify_data with shared secret binding
	verifyData, err := crypto.DeriveKeyMultiple(
		"CH-KEM-Tunnel-ServerFinished",
		[][]byte{h.sharedSecret, h.transcript.Bytes()},
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
	if err := h.initializeSessionKeys(); err != nil {
		return nil, err
	}

	h.state = HandshakeStateComplete

	// Cleanup
	h.cleanup()

	return ciphertext, nil
}

// --- Helper Functions ---

// foldStaticSecret mixes the static-key authentication secret into the master
// secret before handshake keys are derived. A no-op in unauthenticated mode.
// The ephemeral secret remains a mandatory input, preserving forward secrecy.
func (h *Handshake) foldStaticSecret() error {
	if h.staticSecret == nil {
		return nil
	}
	mixed, err := crypto.DeriveAuthenticatedSecret(h.sharedSecret, h.staticSecret)
	if err != nil {
		return err
	}
	h.sharedSecret = mixed
	crypto.Zeroize(h.staticSecret)
	h.staticSecret = nil
	return nil
}

// foldPSKSecret mixes the pre-shared key into the master secret for mutual
// authentication, after any static fold and before key derivation. A no-op unless
// both peers agreed on the PSK. The ephemeral secret stays a mandatory input, so
// forward secrecy holds even if the PSK later leaks. The PSK is long-term config,
// so it is not zeroized here.
func (h *Handshake) foldPSKSecret() error {
	if !h.foldPSK {
		return nil
	}
	mixed, err := crypto.DerivePSKSecret(h.sharedSecret, h.session.PSK)
	if err != nil {
		return err
	}
	h.sharedSecret = mixed
	return nil
}

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

	// Zeroize key material (sendKey/recvKey are aliases to initiatorKey/responderKey)
	crypto.ZeroizeMultiple(initiatorKey, responderKey)

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

// supportedKEMSuiteIDs returns the locally supported KEM suite ids as wire uint16s,
// for the ClientHello supported-suite list.
func supportedKEMSuiteIDs() []uint16 {
	ids := chkem.SupportedSuites()
	out := make([]uint16, len(ids))
	for i, id := range ids {
		out[i] = uint16(id)
	}
	return out
}

// resolveKEMSuite returns the registered suite for a wire id, or an error if this
// peer does not support it.
func resolveKEMSuite(wireID uint16) (chkem.Suite, error) {
	suite, ok := chkem.GetSuite(chkem.SuiteID(wireID))
	if !ok {
		return nil, qerrors.ErrUnsupportedKEMSuite
	}
	return suite, nil
}

// offeredKEMSuite reports whether wireID is one of the suites this peer supports
// (and therefore would have advertised), so a HelloRetryRequest cannot steer the
// client to a suite it never offered.
func offeredKEMSuite(wireID uint16) bool {
	for _, id := range chkem.SupportedSuites() {
		if uint16(id) == wireID {
			return true
		}
	}
	return false
}

// selectMutualKEMSuite picks the locally-supported suite (in this peer's preference
// order) that also appears in the client's advertised list, or false if there is no
// overlap. The server uses it to steer an unsupported client via HelloRetryRequest.
func selectMutualKEMSuite(clientSuites []uint16) (chkem.SuiteID, bool) {
	for _, local := range chkem.SupportedSuites() {
		for _, offered := range clientSuites {
			if uint16(local) == offered {
				return local, true
			}
		}
	}
	return 0, false
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
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext))) // #nosec G115 -- record ciphertext bounded by MaxMessageSize, fits uint32
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
// initiatorExchangeHellos sends the ClientHello, handles an optional
// HelloRetryRequest (one retry, resending the ClientHello in the server's suite),
// and processes the ServerHello. Shared by the fresh and resumption initiator drivers.
func initiatorExchangeHellos(h *Handshake, rw io.ReadWriter) error {
	clientHello, err := h.CreateClientHello()
	if err != nil {
		return err
	}
	if _, err := rw.Write(clientHello); err != nil {
		return err
	}

	msg, err := h.codec.ReadMessage(rw)
	if err != nil {
		return err
	}
	if protocol.MessageType(msg[0]) == protocol.MessageTypeHelloRetryRequest {
		if err := h.ProcessHelloRetryRequest(msg); err != nil {
			sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
			return err
		}
		retry, err := h.CreateClientHello()
		if err != nil {
			return err
		}
		if _, err := rw.Write(retry); err != nil {
			return err
		}
		if msg, err = h.codec.ReadMessage(rw); err != nil {
			return err
		}
	}

	if err := h.ProcessServerHello(msg); err != nil {
		sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
		return err
	}
	return nil
}

// responderExchangeHellos reads the ClientHello, sends a HelloRetryRequest if the
// client's KEM suite is unsupported (one retry), processes the resulting ClientHello,
// and sends the ServerHello. Shared by the fresh and resumption responder drivers.
func responderExchangeHellos(h *Handshake, rw io.ReadWriter) error {
	clientHello, err := h.codec.ReadMessage(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessClientHello(clientHello); err != nil {
		sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
		return err
	}
	if h.sendHRR {
		hrr, err := h.CreateHelloRetryRequest()
		if err != nil {
			return err
		}
		if _, err := rw.Write(hrr); err != nil {
			return err
		}
		retry, err := h.codec.ReadMessage(rw)
		if err != nil {
			return err
		}
		if err := h.ProcessClientHello(retry); err != nil {
			sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
			return err
		}
	}

	serverHello, err := h.CreateServerHello()
	if err != nil {
		return err
	}
	_, err = rw.Write(serverHello)
	return err
}

func InitiatorHandshake(session *Session, rw io.ReadWriter) error {
	observer := session.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnHandshakeStart(context.Background())
	}

	err := func() error {
		h := NewHandshake(session)

		// Exchange hellos (with an optional HelloRetryRequest) and process ServerHello.
		if err := initiatorExchangeHellos(h, rw); err != nil {
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

		// Receive ServerFinished (encrypted, with length framing). Past this point
		// a pinned client that fails has almost certainly hit a static-key
		// mismatch: the server could not derive matching handshake keys, so it
		// rejected our ClientFinished and we see an alert or a Finished mismatch.
		// Surface that as ErrServerKeyMismatch locally; the wire alert stays
		// generic so a prober learns nothing about the pin.
		serverFinished, err := readEncryptedRecord(rw)
		if err != nil {
			if h.session.PinnedServerKey != nil {
				return qerrors.ErrServerKeyMismatch
			}
			return err
		}
		if err := h.ProcessServerFinished(serverFinished); err != nil {
			sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
			if h.session.PinnedServerKey != nil {
				return qerrors.ErrServerKeyMismatch
			}
			return err
		}

		return nil
	}()

	if observer != nil {
		if err != nil {
			if qerrors.Is(err, qerrors.ErrAuthenticationFailed) {
				observer.OnAuthFailure()
			}
			if isProtocolError(err) {
				observer.OnProtocolError(err)
			}
		}
		if done != nil {
			done(err)
		}
	}

	return err
}

// ResponderHandshake performs the complete handshake as responder.
func ResponderHandshake(session *Session, rw io.ReadWriter) error {
	observer := session.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnHandshakeStart(context.Background())
	}

	err := func() error {
		h := NewHandshake(session)

		// Receive ClientHello (with an optional HelloRetryRequest) and send ServerHello.
		if err := responderExchangeHellos(h, rw); err != nil {
			return err
		}

		// Receive ClientFinished (encrypted, with length framing)
		clientFinished, err := readEncryptedRecord(rw)
		if err != nil {
			return err
		}
		if err := h.ProcessClientFinished(clientFinished); err != nil {
			sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
			return err
		}

		// Send ServerFinished (encrypted, with length framing)
		serverFinished, err := h.CreateServerFinished()
		if err != nil {
			return err
		}
		return writeEncryptedRecord(rw, serverFinished)
	}()

	if observer != nil {
		if err != nil {
			if qerrors.Is(err, qerrors.ErrAuthenticationFailed) {
				observer.OnAuthFailure()
			}
			if isProtocolError(err) {
				observer.OnProtocolError(err)
			}
		}
		if done != nil {
			done(err)
		}
	}

	return err
}

// InitiatorResumptionHandshake performs the complete handshake as initiator with resumption.
func InitiatorResumptionHandshake(session *Session, rw io.ReadWriter, ticket, secret []byte) error {
	observer := session.observer
	var done func(error)
	if observer != nil {
		_, done = observer.OnHandshakeStart(context.Background())
	}

	err := func() error {
		h := NewHandshake(session)
		h.SetTicket(ticket, secret)

		// Exchange hellos (with an optional HelloRetryRequest) and process ServerHello.
		if err := initiatorExchangeHellos(h, rw); err != nil {
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

		// Receive ServerFinished (encrypted, with length framing). Past this point
		// a pinned client that fails has almost certainly hit a static-key
		// mismatch: the server could not derive matching handshake keys, so it
		// rejected our ClientFinished and we see an alert or a Finished mismatch.
		// Surface that as ErrServerKeyMismatch locally; the wire alert stays
		// generic so a prober learns nothing about the pin.
		serverFinished, err := readEncryptedRecord(rw)
		if err != nil {
			if h.session.PinnedServerKey != nil {
				return qerrors.ErrServerKeyMismatch
			}
			return err
		}
		if err := h.ProcessServerFinished(serverFinished); err != nil {
			sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
			if h.session.PinnedServerKey != nil {
				return qerrors.ErrServerKeyMismatch
			}
			return err
		}

		return nil
	}()

	if observer != nil {
		if err != nil {
			if qerrors.Is(err, qerrors.ErrAuthenticationFailed) {
				observer.OnAuthFailure()
			}
			if isProtocolError(err) {
				observer.OnProtocolError(err)
			}
		}
		if done != nil {
			done(err)
		}
	}

	return err
}

// ResponderResumptionHandshake performs the complete handshake as responder with resumption.
func ResponderResumptionHandshake(session *Session, rw io.ReadWriter, tm *TicketManager) error {
	h := NewHandshake(session)
	h.SetTicketManager(tm)

	// Receive ClientHello (with an optional HelloRetryRequest) and send ServerHello.
	if err := responderExchangeHellos(h, rw); err != nil {
		return err
	}

	// Receive ClientFinished (encrypted, with length framing)
	clientFinished, err := readEncryptedRecord(rw)
	if err != nil {
		return err
	}
	if err := h.ProcessClientFinished(clientFinished); err != nil {
		sendHandshakeAlert(rw, h.codec, protocol.AlertCodeHandshakeFailure, "handshake failed")
		return err
	}

	// Send ServerFinished (encrypted, with length framing)
	serverFinished, err := h.CreateServerFinished()
	if err != nil {
		return err
	}
	return writeEncryptedRecord(rw, serverFinished)
}
