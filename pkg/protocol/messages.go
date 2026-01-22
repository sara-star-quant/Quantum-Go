// Package protocol defines protocol message types for the CH-KEM VPN handshake.
//
// This file (messages.go) implements the message flow:
//
//	Initiator                              Responder
//	    |                                      |
//	    | -------- ClientHello --------------> |
//	    |                                      |
//	    | <------- ServerHello --------------- |
//	    |                                      |
//	    | -------- ClientFinished -----------> |
//	    |                                      |
//	    | <------- ServerFinished ------------ |
//	    |                                      |
//	    |    === Tunnel Established ===        |
//
// All messages are length-prefixed with a 4-byte big-endian length field.
package protocol

import (
	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// MessageType identifies the type of protocol message.
type MessageType uint8

// Protocol message types for handshake, tunnel, and error signaling.
const (
	// MessageTypeClientHello initiates the handshake from the client.
	MessageTypeClientHello MessageType = 0x01
	// MessageTypeServerHello responds to ClientHello with server parameters.
	MessageTypeServerHello MessageType = 0x02
	// MessageTypeClientFinished confirms handshake completion from client.
	MessageTypeClientFinished MessageType = 0x03
	// MessageTypeServerFinished confirms handshake completion from server.
	MessageTypeServerFinished MessageType = 0x04

	// MessageTypeData carries encrypted application data.
	MessageTypeData MessageType = 0x10
	// MessageTypeRekey initiates a key rotation.
	MessageTypeRekey MessageType = 0x11
	// MessageTypePing requests a keepalive response.
	MessageTypePing MessageType = 0x12
	// MessageTypePong responds to a Ping.
	MessageTypePong MessageType = 0x13
	// MessageTypeClose signals graceful connection termination.
	MessageTypeClose MessageType = 0x14

	// MessageTypeAlert signals an error condition.
	MessageTypeAlert MessageType = 0xF0
)

// String returns a human-readable name for the message type.
func (mt MessageType) String() string {
	switch mt {
	case MessageTypeClientHello:
		return "ClientHello"
	case MessageTypeServerHello:
		return "ServerHello"
	case MessageTypeClientFinished:
		return "ClientFinished"
	case MessageTypeServerFinished:
		return "ServerFinished"
	case MessageTypeData:
		return "Data"
	case MessageTypeRekey:
		return "Rekey"
	case MessageTypePing:
		return "Ping"
	case MessageTypePong:
		return "Pong"
	case MessageTypeClose:
		return "Close"
	case MessageTypeAlert:
		return "Alert"
	default:
		return "Unknown"
	}
}

// AlertCode identifies specific error conditions.
type AlertCode uint8

// Alert codes identifying specific error conditions.
const (
	// AlertCodeUnexpectedMessage indicates an unexpected message was received.
	AlertCodeUnexpectedMessage AlertCode = 0x01
	// AlertCodeBadCiphertext indicates ciphertext validation failed.
	AlertCodeBadCiphertext AlertCode = 0x02
	// AlertCodeHandshakeFailure indicates the handshake could not complete.
	AlertCodeHandshakeFailure AlertCode = 0x03
	// AlertCodeUnsupportedVersion indicates no common protocol version.
	AlertCodeUnsupportedVersion AlertCode = 0x04
	// AlertCodeUnsupportedCipher indicates no common cipher suite.
	AlertCodeUnsupportedCipher AlertCode = 0x05
	// AlertCodeDecryptionFailed indicates decryption or MAC verification failed.
	AlertCodeDecryptionFailed AlertCode = 0x06
	// AlertCodeInternalError indicates an internal implementation error.
	AlertCodeInternalError AlertCode = 0x07
	// AlertCodeCloseNotify indicates graceful connection closure.
	AlertCodeCloseNotify AlertCode = 0x08
)

// ClientHello is sent by the initiator to begin the handshake.
type ClientHello struct {
	// Protocol version offered by the client
	Version Version

	// Random nonce for freshness (32 bytes)
	Random []byte

	// SessionID for session resumption (16 bytes, or empty for new session)
	SessionID []byte

	// Client's CH-KEM public key (1600 bytes)
	CHKEMPublicKey []byte

	// Supported cipher suites in preference order
	CipherSuites []constants.CipherSuite
}

// ServerHello is sent by the responder in response to ClientHello.
type ServerHello struct {
	// Protocol version selected by the server
	Version Version

	// Random nonce for freshness (32 bytes)
	Random []byte

	// SessionID assigned by server (16 bytes)
	SessionID []byte

	// CH-KEM ciphertext (1600 bytes)
	CHKEMCiphertext []byte

	// Selected cipher suite
	CipherSuite constants.CipherSuite
}

// ClientFinished confirms the handshake from the client side.
// This message is encrypted with the handshake keys.
type ClientFinished struct {
	// VerifyData is a MAC over the handshake transcript
	VerifyData []byte
}

// ServerFinished confirms the handshake from the server side.
// This message is encrypted with the handshake keys.
type ServerFinished struct {
	// VerifyData is a MAC over the handshake transcript
	VerifyData []byte
}

// DataMessage carries encrypted application data.
type DataMessage struct {
	// Sequence number for replay protection (8 bytes)
	Sequence uint64

	// Encrypted payload
	Payload []byte
}

// RekeyMessage initiates a key rotation.
type RekeyMessage struct {
	// New CH-KEM public key for forward secrecy
	NewPublicKey []byte

	// Sequence number at which new keys become active
	ActivationSequence uint64
}

// AlertLevel indicates the severity of the alert.
type AlertLevel uint8

// Alert severity levels.
const (
	// AlertLevelWarning indicates a non-fatal condition that may be recoverable.
	AlertLevelWarning AlertLevel = 0x01
	// AlertLevelFatal indicates an unrecoverable error requiring connection termination.
	AlertLevelFatal AlertLevel = 0x02
)

// AlertMessage signals an error condition or connection closure.
type AlertMessage struct {
	// Level of the alert (Warning or Fatal)
	Level AlertLevel

	// Alert code identifying the specific condition
	Code AlertCode

	// Optional description (max 256 bytes)
	Description string
}

// Validate checks if the AlertMessage is valid.
func (m *AlertMessage) Validate() error {
	if m.Level != AlertLevelWarning && m.Level != AlertLevelFatal {
		return qerrors.ErrInvalidMessage
	}
	if len(m.Description) > 256 {
		return qerrors.ErrInvalidMessage
	}
	return nil
}

// Validate checks if the ClientHello message is valid.
func (m *ClientHello) Validate() error {
	if !m.Version.IsCompatible(Current) {
		return qerrors.ErrUnsupportedVersion
	}
	if len(m.Random) != 32 {
		return qerrors.ErrInvalidMessage
	}
	if len(m.CHKEMPublicKey) != constants.CHKEMPublicKeySize {
		return qerrors.ErrInvalidPublicKey
	}
	if len(m.SessionID) > 2048 {
		return qerrors.ErrInvalidMessage
	}
	if len(m.CipherSuites) == 0 {
		return qerrors.ErrInvalidMessage
	}
	for _, cs := range m.CipherSuites {
		if !cs.IsSupported() {
			return qerrors.ErrUnsupportedCipherSuite
		}
	}
	return nil
}

// Validate checks if the ServerHello message is valid.
func (m *ServerHello) Validate() error {
	if !m.Version.IsCompatible(Current) {
		return qerrors.ErrUnsupportedVersion
	}
	if len(m.Random) != 32 {
		return qerrors.ErrInvalidMessage
	}
	if len(m.SessionID) > 2048 {
		return qerrors.ErrInvalidMessage
	}
	if len(m.CHKEMCiphertext) != constants.CHKEMCiphertextSize {
		return qerrors.ErrInvalidCiphertext
	}
	if !m.CipherSuite.IsSupported() {
		return qerrors.ErrUnsupportedCipherSuite
	}
	return nil
}

// Validate checks if the ClientFinished message is valid.
func (m *ClientFinished) Validate() error {
	if len(m.VerifyData) != 32 {
		return qerrors.ErrInvalidMessage
	}
	return nil
}

// Validate checks if the ServerFinished message is valid.
func (m *ServerFinished) Validate() error {
	if len(m.VerifyData) != 32 {
		return qerrors.ErrInvalidMessage
	}
	return nil
}

// HeaderSize is the size of the message header (type + length).
const HeaderSize = 5 // 1 byte type + 4 bytes length

// MaxMessageSize is the maximum size of a protocol message.
const MaxMessageSize = constants.MaxMessageSize
