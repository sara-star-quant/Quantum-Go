// codec.go implements serialization and deserialization of protocol messages.
//
// Wire Format:
//
// All messages follow this structure:
//
//	+------+--------+----------+
//	| Type | Length | Payload  |
//	| 1B   | 4B BE  | Variable |
//	+------+--------+----------+
//
// Length is big-endian uint32, not including header bytes.
//
// ClientHello Format:
//
//	+----------+--------+-----------+------------------+--------------+
//	| Version  | Random | SessionID | CHKEMPublicKey   | CipherSuites |
//	| 2B       | 32B    | 16B       | 1600B            | 2B * count   |
//	+----------+--------+-----------+------------------+--------------+
//
// ServerHello Format:
//
//	+----------+--------+-----------+------------------+-------------+
//	| Version  | Random | SessionID | CHKEMCiphertext  | CipherSuite |
//	| 2B       | 32B    | 16B       | 1600B            | 2B          |
//	+----------+--------+-----------+------------------+-------------+
package protocol

import (
	"encoding/binary"
	"io"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

// Codec provides message serialization and deserialization.
type Codec struct{}

// NewCodec creates a new protocol codec.
func NewCodec() *Codec {
	return &Codec{}
}

// EncodeClientHello serializes a ClientHello message.
func (c *Codec) EncodeClientHello(m *ClientHello) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	// Calculate payload size
	payloadSize := 2 + // version
		32 + // random
		1 + len(m.SessionID) + // session ID length + data
		constants.CHKEMPublicKeySize + // public key
		2 + 2*len(m.CipherSuites) // cipher suites count + data

	buf := make([]byte, HeaderSize+payloadSize)
	offset := 0

	// Header
	buf[offset] = byte(MessageTypeClientHello)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(payloadSize))
	offset += 4

	// Version
	buf[offset] = m.Version.Major
	buf[offset+1] = m.Version.Minor
	offset += 2

	// Random
	copy(buf[offset:], m.Random)
	offset += 32

	// SessionID (length-prefixed)
	buf[offset] = byte(len(m.SessionID))
	offset++
	copy(buf[offset:], m.SessionID)
	offset += len(m.SessionID)

	// CH-KEM public key
	copy(buf[offset:], m.CHKEMPublicKey)
	offset += constants.CHKEMPublicKeySize

	// Cipher suites
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(m.CipherSuites)))
	offset += 2
	for _, cs := range m.CipherSuites {
		binary.BigEndian.PutUint16(buf[offset:], uint16(cs))
		offset += 2
	}

	return buf, nil
}

// DecodeClientHello deserializes a ClientHello message.
func (c *Codec) DecodeClientHello(data []byte) (*ClientHello, error) {
	if len(data) < HeaderSize {
		return nil, qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeClientHello {
		return nil, qerrors.ErrInvalidMessage
	}

	payloadLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < HeaderSize+int(payloadLen) {
		return nil, qerrors.ErrInvalidMessage
	}

	// Minimum payload: version(2) + random(32) + sessionIDLen(1) + publicKey(1600) + cipherSuiteCount(2) + minCipherSuite(2) = 1639
	minPayloadLen := 2 + 32 + 1 + constants.CHKEMPublicKeySize + 2 + 2
	if int(payloadLen) < minPayloadLen {
		return nil, qerrors.ErrInvalidMessage
	}

	offset := HeaderSize
	m := &ClientHello{}

	// Version
	m.Version = Version{Major: data[offset], Minor: data[offset+1]}
	offset += 2

	// Random
	m.Random = make([]byte, 32)
	copy(m.Random, data[offset:offset+32])
	offset += 32

	// SessionID
	sessionIDLen := int(data[offset])
	offset++
	if sessionIDLen > 0 {
		m.SessionID = make([]byte, sessionIDLen)
		copy(m.SessionID, data[offset:offset+sessionIDLen])
		offset += sessionIDLen
	}

	// CH-KEM public key
	m.CHKEMPublicKey = make([]byte, constants.CHKEMPublicKeySize)
	copy(m.CHKEMPublicKey, data[offset:offset+constants.CHKEMPublicKeySize])
	offset += constants.CHKEMPublicKeySize

	// Cipher suites
	cipherSuiteCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	m.CipherSuites = make([]constants.CipherSuite, cipherSuiteCount)
	for i := range m.CipherSuites {
		m.CipherSuites[i] = constants.CipherSuite(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
}

// EncodeServerHello serializes a ServerHello message.
func (c *Codec) EncodeServerHello(m *ServerHello) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	payloadSize := 2 + // version
		32 + // random
		1 + len(m.SessionID) + // session ID length + data
		constants.CHKEMCiphertextSize + // ciphertext
		2 // cipher suite

	buf := make([]byte, HeaderSize+payloadSize)
	offset := 0

	// Header
	buf[offset] = byte(MessageTypeServerHello)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(payloadSize))
	offset += 4

	// Version
	buf[offset] = m.Version.Major
	buf[offset+1] = m.Version.Minor
	offset += 2

	// Random
	copy(buf[offset:], m.Random)
	offset += 32

	// SessionID (length-prefixed)
	buf[offset] = byte(len(m.SessionID))
	offset++
	copy(buf[offset:], m.SessionID)
	offset += len(m.SessionID)

	// CH-KEM ciphertext
	copy(buf[offset:], m.CHKEMCiphertext)
	offset += constants.CHKEMCiphertextSize

	// Cipher suite
	binary.BigEndian.PutUint16(buf[offset:], uint16(m.CipherSuite))

	return buf, nil
}

// DecodeServerHello deserializes a ServerHello message.
func (c *Codec) DecodeServerHello(data []byte) (*ServerHello, error) {
	if len(data) < HeaderSize {
		return nil, qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeServerHello {
		return nil, qerrors.ErrInvalidMessage
	}

	payloadLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < HeaderSize+int(payloadLen) {
		return nil, qerrors.ErrInvalidMessage
	}

	// Minimum payload: version(2) + random(32) + sessionIDLen(1) + ciphertext(1600) + cipherSuite(2) = 1637
	minPayloadLen := 2 + 32 + 1 + constants.CHKEMCiphertextSize + 2
	if int(payloadLen) < minPayloadLen {
		return nil, qerrors.ErrInvalidMessage
	}

	offset := HeaderSize
	m := &ServerHello{}

	// Version
	m.Version = Version{Major: data[offset], Minor: data[offset+1]}
	offset += 2

	// Random
	m.Random = make([]byte, 32)
	copy(m.Random, data[offset:offset+32])
	offset += 32

	// SessionID
	sessionIDLen := int(data[offset])
	offset++
	if sessionIDLen > 0 {
		m.SessionID = make([]byte, sessionIDLen)
		copy(m.SessionID, data[offset:offset+sessionIDLen])
		offset += sessionIDLen
	}

	// CH-KEM ciphertext
	m.CHKEMCiphertext = make([]byte, constants.CHKEMCiphertextSize)
	copy(m.CHKEMCiphertext, data[offset:offset+constants.CHKEMCiphertextSize])
	offset += constants.CHKEMCiphertextSize

	// Cipher suite
	m.CipherSuite = constants.CipherSuite(binary.BigEndian.Uint16(data[offset:]))

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
}

// EncodeFinished serializes a Finished message (client or server).
func (c *Codec) EncodeFinished(msgType MessageType, verifyData []byte) ([]byte, error) {
	if len(verifyData) != 32 {
		return nil, qerrors.ErrInvalidMessage
	}

	buf := make([]byte, HeaderSize+32)
	buf[0] = byte(msgType)
	binary.BigEndian.PutUint32(buf[1:], 32)
	copy(buf[HeaderSize:], verifyData)

	return buf, nil
}

// DecodeFinished deserializes a Finished message.
func (c *Codec) DecodeFinished(data []byte) ([]byte, error) {
	if len(data) < HeaderSize+32 {
		return nil, qerrors.ErrInvalidMessage
	}

	msgType := MessageType(data[0])
	if msgType != MessageTypeClientFinished && msgType != MessageTypeServerFinished {
		return nil, qerrors.ErrInvalidMessage
	}

	verifyData := make([]byte, 32)
	copy(verifyData, data[HeaderSize:HeaderSize+32])

	return verifyData, nil
}

// EncodeData serializes a data message.
func (c *Codec) EncodeData(seq uint64, payload []byte) ([]byte, error) {
	if len(payload) > constants.MaxPayloadSize {
		return nil, qerrors.ErrMessageTooLarge
	}

	payloadSize := 8 + len(payload)
	buf := make([]byte, HeaderSize+payloadSize)

	buf[0] = byte(MessageTypeData)
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize))
	binary.BigEndian.PutUint64(buf[HeaderSize:], seq)
	copy(buf[HeaderSize+8:], payload)

	return buf, nil
}

// DecodeData deserializes a data message.
func (c *Codec) DecodeData(data []byte) (uint64, []byte, error) {
	if len(data) < HeaderSize+8 {
		return 0, nil, qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeData {
		return 0, nil, qerrors.ErrInvalidMessage
	}

	seq := binary.BigEndian.Uint64(data[HeaderSize:])
	payload := data[HeaderSize+8:]

	return seq, payload, nil
}

// EncodeAlert serializes an alert message.
func (c *Codec) EncodeAlert(level AlertLevel, code AlertCode, description string) []byte {
	// Description length is stored in a single byte (max 255)
	if len(description) > 255 {
		description = description[:255]
	}

	payloadSize := 1 + 1 + 1 + len(description)
	buf := make([]byte, HeaderSize+payloadSize)

	buf[0] = byte(MessageTypeAlert)
	// payloadSize is max 258 bytes, so safe to cast
	//nolint:gosec // G115: payloadSize is bounded < 300
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize))
	buf[HeaderSize] = byte(level)
	buf[HeaderSize+1] = byte(code)
	buf[HeaderSize+2] = byte(len(description))
	copy(buf[HeaderSize+3:], description)

	return buf
}

// DecodeAlert deserializes an alert message.
func (c *Codec) DecodeAlert(data []byte) (AlertLevel, AlertCode, string, error) {
	if len(data) < HeaderSize+3 {
		return 0, 0, "", qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeAlert {
		return 0, 0, "", qerrors.ErrInvalidMessage
	}

	level := AlertLevel(data[HeaderSize])
	code := AlertCode(data[HeaderSize+1])
	descLen := int(data[HeaderSize+2])

	if len(data) < HeaderSize+3+descLen {
		return 0, 0, "", qerrors.ErrInvalidMessage
	}

	description := string(data[HeaderSize+3 : HeaderSize+3+descLen])

	return level, code, description, nil
}

// EncodeRekey serializes a rekey message.
// Format: NewPublicKey (1600B) + ActivationSequence (8B)
func (c *Codec) EncodeRekey(newPublicKey []byte, activationSeq uint64) ([]byte, error) {
	if len(newPublicKey) != constants.CHKEMPublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}

	payloadSize := constants.CHKEMPublicKeySize + 8
	buf := make([]byte, HeaderSize+payloadSize)

	buf[0] = byte(MessageTypeRekey)
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize))
	copy(buf[HeaderSize:], newPublicKey)
	binary.BigEndian.PutUint64(buf[HeaderSize+constants.CHKEMPublicKeySize:], activationSeq)

	return buf, nil
}

// DecodeRekey deserializes a rekey message.
func (c *Codec) DecodeRekey(data []byte) ([]byte, uint64, error) {
	minLen := HeaderSize + constants.CHKEMPublicKeySize + 8
	if len(data) < minLen {
		return nil, 0, qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeRekey {
		return nil, 0, qerrors.ErrInvalidMessage
	}

	newPublicKey := make([]byte, constants.CHKEMPublicKeySize)
	copy(newPublicKey, data[HeaderSize:HeaderSize+constants.CHKEMPublicKeySize])

	activationSeq := binary.BigEndian.Uint64(data[HeaderSize+constants.CHKEMPublicKeySize:])

	return newPublicKey, activationSeq, nil
}

// ReadMessage reads a complete message from the reader.
func (c *Codec) ReadMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint32(header[1:5])
	if payloadLen > MaxMessageSize {
		return nil, qerrors.ErrMessageTooLarge
	}

	msg := make([]byte, HeaderSize+payloadLen)
	copy(msg, header)

	if payloadLen > 0 {
		if _, err := io.ReadFull(r, msg[HeaderSize:]); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// GetMessageType returns the type of a serialized message.
func (c *Codec) GetMessageType(data []byte) (MessageType, error) {
	if len(data) < 1 {
		return 0, qerrors.ErrInvalidMessage
	}
	return MessageType(data[0]), nil
}
