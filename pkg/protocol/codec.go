// Package protocol implements serialization and deserialization of protocol messages.
//
// This file (codec.go) defines the wire format:
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
// ClientHello Format (KEMSuite/KEMSuites added in protocol 4.0; trailing optional
// static-ct and PSK-identity fields omitted here):
//
//	+---------+--------+-----------+----------+-----------+----------------+--------------+
//	| Version | Random | SessionID | KEMSuite | KEMSuites | CHKEMPublicKey | CipherSuites |
//	| 2B      | 32B    | 16B       | 2B       | 1B*2B*n   | 1600B (v1)     | 2B * count   |
//	+---------+--------+-----------+----------+-----------+----------------+--------------+
//
// ServerHello Format:
//
//	+---------+--------+-----------+----------+-----------------+-------------+
//	| Version | Random | SessionID | KEMSuite | CHKEMCiphertext | CipherSuite |
//	| 2B      | 32B    | 16B       | 2B       | 1600B (v1)      | 2B          |
//	+---------+--------+-----------+----------+-----------------+-------------+
package protocol

import (
	"encoding/binary"
	"io"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
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
		2 + 1 + 2*len(m.KEMSuites) + // kem suite + supported-suite count + list
		constants.CHKEMPublicKeySize + // public key
		2 + 2*len(m.CipherSuites) + // cipher suites count + data
		1 + len(m.CHKEMStaticCiphertext) + // static-ct presence flag + data
		1 + pskIdentityFieldLen(m.PSKIdentity) // psk-identity presence flag + (len + data)

	buf := make([]byte, HeaderSize+payloadSize)
	offset := 0

	// Header
	buf[offset] = byte(MessageTypeClientHello)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(payloadSize)) // #nosec G115 -- payloadSize bounded by MaxMessageSize (65536), fits uint32
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

	// KEM suite of the key share, then the supported-suite list (1-byte count + ids).
	binary.BigEndian.PutUint16(buf[offset:], m.KEMSuite)
	offset += 2
	buf[offset] = byte(len(m.KEMSuites)) // #nosec G115 -- suite count is single digits, fits uint8
	offset++
	for _, id := range m.KEMSuites {
		binary.BigEndian.PutUint16(buf[offset:], id)
		offset += 2
	}

	// CH-KEM public key
	copy(buf[offset:], m.CHKEMPublicKey)
	offset += constants.CHKEMPublicKeySize

	// Cipher suites
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(m.CipherSuites))) // #nosec G115 -- cipher suite count is single digits, fits uint16
	offset += 2
	for _, cs := range m.CipherSuites {
		binary.BigEndian.PutUint16(buf[offset:], uint16(cs))
		offset += 2
	}

	// Static-key authentication ciphertext (presence-flagged: 1 byte, then the
	// CHKEMCiphertextSize ct when present). Always write the flag so the field is
	// self-describing; older peers that stop after cipher suites ignore it.
	if len(m.CHKEMStaticCiphertext) > 0 {
		buf[offset] = 1
		offset++
		copy(buf[offset:], m.CHKEMStaticCiphertext)
		offset += constants.CHKEMCiphertextSize
	} else {
		buf[offset] = 0
		offset++
	}

	// PSK identity (presence-flagged: 1 byte, then a 1-byte length and the label
	// when present). Like the static field, additive and ignored by older peers.
	if len(m.PSKIdentity) > 0 {
		buf[offset] = 1
		offset++
		buf[offset] = byte(len(m.PSKIdentity))
		offset++
		copy(buf[offset:], m.PSKIdentity)
	} else {
		buf[offset] = 0
	}

	return buf, nil
}

// pskIdentityFieldLen returns the extra payload bytes a PSK identity contributes
// beyond its presence flag: a 1-byte length prefix plus the label when present.
func pskIdentityFieldLen(identity []byte) int {
	if len(identity) == 0 {
		return 0
	}
	return 1 + len(identity)
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
	// All field reads below must stay within the declared payload, not just
	// within len(data), so a malformed length field cannot over-read.
	payloadEnd := HeaderSize + int(payloadLen)

	// Minimum payload: version(2) + random(32) + sessionIDLen(1) + kemSuite(2) +
	// kemSuiteCount(1) + publicKey(1600) + cipherSuiteCount(2) + minCipherSuite(2).
	minPayloadLen := 2 + 32 + 1 + 2 + 1 + constants.CHKEMPublicKeySize + 2 + 2
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

	// KEM suite of the key share, then the supported-suite list.
	if offset+3 > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
	m.KEMSuite = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	kemSuiteCount := int(data[offset])
	offset++
	if offset+2*kemSuiteCount > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
	m.KEMSuites = make([]uint16, kemSuiteCount)
	for i := range m.KEMSuites {
		m.KEMSuites[i] = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	// CH-KEM public key
	if offset+constants.CHKEMPublicKeySize > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
	m.CHKEMPublicKey = make([]byte, constants.CHKEMPublicKeySize)
	copy(m.CHKEMPublicKey, data[offset:offset+constants.CHKEMPublicKeySize])
	offset += constants.CHKEMPublicKeySize

	// Cipher suites
	cipherSuiteCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+2*int(cipherSuiteCount) > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
	m.CipherSuites = make([]constants.CipherSuite, cipherSuiteCount)
	for i := range m.CipherSuites {
		m.CipherSuites[i] = constants.CipherSuite(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
	}

	// Static-key authentication ciphertext (presence-flagged). Older peers omit
	// the flag entirely, so only read it if a byte remains within the payload.
	if offset < payloadEnd {
		present := data[offset]
		offset++
		if present == 1 {
			if offset+constants.CHKEMCiphertextSize > payloadEnd {
				return nil, qerrors.ErrInvalidMessage
			}
			m.CHKEMStaticCiphertext = make([]byte, constants.CHKEMCiphertextSize)
			copy(m.CHKEMStaticCiphertext, data[offset:offset+constants.CHKEMCiphertextSize])
			offset += constants.CHKEMCiphertextSize
		}
	}

	// PSK identity (presence-flagged, length-prefixed). Additive after the static
	// field; older peers omit it, so only read it if a byte remains.
	if offset < payloadEnd {
		present := data[offset]
		offset++
		if present == 1 {
			if offset+1 > payloadEnd {
				return nil, qerrors.ErrInvalidMessage
			}
			idLen := int(data[offset])
			offset++
			if idLen == 0 || offset+idLen > payloadEnd {
				return nil, qerrors.ErrInvalidMessage
			}
			m.PSKIdentity = make([]byte, idLen)
			copy(m.PSKIdentity, data[offset:offset+idLen])
		}
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
		2 + // kem suite
		constants.CHKEMCiphertextSize + // ciphertext
		2 // cipher suite

	buf := make([]byte, HeaderSize+payloadSize)
	offset := 0

	// Header
	buf[offset] = byte(MessageTypeServerHello)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(payloadSize)) // #nosec G115 -- payloadSize bounded by MaxMessageSize (65536), fits uint32
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

	// Selected KEM suite
	binary.BigEndian.PutUint16(buf[offset:], m.KEMSuite)
	offset += 2

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
	payloadEnd := HeaderSize + int(payloadLen)

	// Minimum payload: version(2) + random(32) + sessionIDLen(1) + kemSuite(2) + ciphertext(1600) + cipherSuite(2)
	minPayloadLen := 2 + 32 + 1 + 2 + constants.CHKEMCiphertextSize + 2
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

	// Selected KEM suite
	if offset+2 > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
	m.KEMSuite = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// CH-KEM ciphertext
	if offset+constants.CHKEMCiphertextSize > payloadEnd {
		return nil, qerrors.ErrInvalidMessage
	}
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
// EncodeHelloRetryRequest serializes a HelloRetryRequest (version + KEM suite).
func (c *Codec) EncodeHelloRetryRequest(m *HelloRetryRequest) ([]byte, error) {
	const payloadSize = 2 + 2 // version + kem suite
	buf := make([]byte, HeaderSize+payloadSize)
	buf[0] = byte(MessageTypeHelloRetryRequest)
	binary.BigEndian.PutUint32(buf[1:], payloadSize)
	buf[HeaderSize] = m.Version.Major
	buf[HeaderSize+1] = m.Version.Minor
	binary.BigEndian.PutUint16(buf[HeaderSize+2:], m.KEMSuite)
	return buf, nil
}

// DecodeHelloRetryRequest deserializes a HelloRetryRequest.
func (c *Codec) DecodeHelloRetryRequest(data []byte) (*HelloRetryRequest, error) {
	if len(data) < HeaderSize+4 {
		return nil, qerrors.ErrInvalidMessage
	}
	if MessageType(data[0]) != MessageTypeHelloRetryRequest {
		return nil, qerrors.ErrInvalidMessage
	}
	return &HelloRetryRequest{
		Version:  Version{Major: data[HeaderSize], Minor: data[HeaderSize+1]},
		KEMSuite: binary.BigEndian.Uint16(data[HeaderSize+2:]),
	}, nil
}

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
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize)) // #nosec G115 -- payload guarded by MaxPayloadSize check above, fits uint32
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
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize)) // #nosec G115 -- alert payloadSize is bounded < 300, fits uint32
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

// EncodeRekeyPayload serializes the plaintext inner rekey payload.
// Format: NewPublicKey (1600B) + ActivationSequence (8B)
func (c *Codec) EncodeRekeyPayload(newPublicKey []byte, activationSeq uint64) ([]byte, error) {
	if len(newPublicKey) != constants.CHKEMPublicKeySize {
		return nil, qerrors.ErrInvalidPublicKey
	}

	buf := make([]byte, constants.CHKEMPublicKeySize+8)
	copy(buf, newPublicKey)
	binary.BigEndian.PutUint64(buf[constants.CHKEMPublicKeySize:], activationSeq)

	return buf, nil
}

// DecodeRekeyPayload deserializes the plaintext inner rekey payload.
func (c *Codec) DecodeRekeyPayload(data []byte) ([]byte, uint64, error) {
	minLen := constants.CHKEMPublicKeySize + 8
	if len(data) < minLen {
		return nil, 0, qerrors.ErrInvalidMessage
	}

	newPublicKey := make([]byte, constants.CHKEMPublicKeySize)
	copy(newPublicKey, data[:constants.CHKEMPublicKeySize])

	activationSeq := binary.BigEndian.Uint64(data[constants.CHKEMPublicKeySize:])

	return newPublicKey, activationSeq, nil
}

// EncodeRekey serializes an encrypted rekey message.
// Format: [Rekey(1B)] [Len(4B)] [Seq(8B)] [AEAD-Ciphertext]
func (c *Codec) EncodeRekey(seq uint64, ciphertext []byte) ([]byte, error) {
	payloadSize := 8 + len(ciphertext)
	buf := make([]byte, HeaderSize+payloadSize)

	buf[0] = byte(MessageTypeRekey)
	binary.BigEndian.PutUint32(buf[1:], uint32(payloadSize)) // #nosec G115 -- rekey payloadSize bounded by MaxMessageSize, fits uint32
	binary.BigEndian.PutUint64(buf[HeaderSize:], seq)
	copy(buf[HeaderSize+8:], ciphertext)

	return buf, nil
}

// DecodeRekey deserializes an encrypted rekey message.
// Returns the sequence number and ciphertext from the outer message.
func (c *Codec) DecodeRekey(data []byte) (uint64, []byte, error) {
	minLen := HeaderSize + 8
	if len(data) < minLen {
		return 0, nil, qerrors.ErrInvalidMessage
	}

	if MessageType(data[0]) != MessageTypeRekey {
		return 0, nil, qerrors.ErrInvalidMessage
	}

	seq := binary.BigEndian.Uint64(data[HeaderSize:])
	ciphertext := make([]byte, len(data)-(HeaderSize+8))
	copy(ciphertext, data[HeaderSize+8:])

	return seq, ciphertext, nil
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

// ReadMessageInto reads a complete message into buf, reusing it when it is large
// enough and reallocating (returning the new backing slice) otherwise. The returned
// slice aliases buf, so the caller MUST be done with it before the next
// ReadMessageInto call on the same buffer. It is the allocation-free hot-path twin of
// ReadMessage for a single-reader loop; ReadMessage stays for the handshake and any
// caller that needs an independent slice.
func (c *Codec) ReadMessageInto(r io.Reader, buf []byte) ([]byte, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint32(header[1:5])
	if payloadLen > MaxMessageSize {
		return nil, qerrors.ErrMessageTooLarge
	}

	total := HeaderSize + int(payloadLen)
	if cap(buf) < total {
		buf = make([]byte, total)
	}
	buf = buf[:total]
	copy(buf, header[:])

	if payloadLen > 0 {
		if _, err := io.ReadFull(r, buf[HeaderSize:]); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

// GetMessageType returns the type of a serialized message.
func (c *Codec) GetMessageType(data []byte) (MessageType, error) {
	if len(data) < 1 {
		return 0, qerrors.ErrInvalidMessage
	}
	return MessageType(data[0]), nil
}
