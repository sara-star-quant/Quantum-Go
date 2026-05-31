// Package protocol — datagram_codec.go defines the self-contained, per-datagram
// wire format used by the UDP/datagram transport. It is a separate wire format
// from the length-prefixed stream codec in codec.go: there is no cross-datagram
// length prefix (each datagram is one frame) and no transmitted nonce (the
// receiver derives the AEAD nonce from the per-session nonce prefix and the
// frame sequence number). There is no TCP<->UDP interop, by design.
//
// Common header (every datagram frame begins with this 14-byte header):
//
//		+-----------+-------+------------+--------+
//		| FrameType | Epoch | RecvIndex  | Seq    |
//		| 1B        | 1B    | 4B BE      | 8B BE  |
//		+-----------+-------+------------+--------+
//
//	  - FrameType selects DATA / HANDSHAKE / CLOSE / RETRY(reserved).
//	  - Epoch selects the receive cipher for DATA frames (see the datagram rekey
//	    design). It is carried in the clear but authenticated via the AEAD AAD,
//	    which is the entire 14-byte common header, so a flipped epoch is rejected.
//	  - RecvIndex is the random connection index the *receiver* assigned to the
//	    session; the sender echoes it so the receiver can demultiplex by index
//	    (not by source address). 0 means "unknown" (first ClientHello).
//	  - Seq is a globally monotonic, never-reset 64-bit counter. It is both the
//	    replay counter and the low 8 bytes of the AEAD nonce.
//
// DATA frame:  [common header] || AEAD ciphertext (incl. tag)
//
// HANDSHAKE frame: [common header] followed by a handshake extension and then a
// (possibly fragmented) handshake message payload:
//
//		+-------------+---------+------------+----------+-----------+-----------+----------+
//		| SenderIndex | MsgType | FragOffset | FragLen  | TotalLen  | CookieLen | Cookie   |
//		| 4B BE       | 1B      | 2B BE      | 2B BE    | 2B BE     | 1B        | variable |
//		+-------------+---------+------------+----------+-----------+-----------+----------+
//
//	  - SenderIndex is the connection index the *sender* assigned to the session.
//	  - MsgType identifies the logical handshake message (ClientHello, etc.); all
//	    fragments of one message share it.
//	  - FragOffset/FragLen/TotalLen drive app-layer reassembly of handshake
//	    messages that exceed the datagram MTU (the PQ Hellos are ~1.6 KB).
//	  - CookieLen/Cookie are reserved for a future stateless-retry/cookie
//	    (anti-DoS) hardening; CookieLen is 0 today, so adding it needs no wire change.
package protocol

import (
	"encoding/binary"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// DatagramFrameType identifies the kind of a datagram frame.
type DatagramFrameType uint8

// Datagram frame types.
const (
	// DatagramFrameHandshake carries a (possibly fragmented) handshake message.
	DatagramFrameHandshake DatagramFrameType = 0x01
	// DatagramFrameData carries AEAD-encrypted application data.
	DatagramFrameData DatagramFrameType = 0x02
	// DatagramFrameClose is a best-effort close notification.
	DatagramFrameClose DatagramFrameType = 0x03
	// DatagramFrameRetry is reserved for a future stateless retry/cookie exchange
	// (HelloRetryRequest style). It is defined now so adding that anti-DoS
	// hardening needs no wire change.
	DatagramFrameRetry DatagramFrameType = 0x04
)

// Datagram wire-format sizes.
const (
	// DatagramHeaderSize is the size of the common per-frame header in bytes.
	DatagramHeaderSize = 1 + 1 + 4 + 8 // type + epoch + recvIndex + seq
	// DatagramHandshakeExtSize is the size of the fixed part of the handshake
	// extension (excludes the variable-length cookie).
	DatagramHandshakeExtSize = 4 + 1 + 2 + 2 + 2 + 1 // sender + msgType + fragOff + fragLen + totalLen + cookieLen
)

// DatagramHeader is the common header carried by every datagram frame.
type DatagramHeader struct {
	Type      DatagramFrameType
	Epoch     uint8
	RecvIndex uint32
	Seq       uint64
}

// DatagramHandshakeHeader is the header of a HANDSHAKE frame.
type DatagramHandshakeHeader struct {
	DatagramHeader
	SenderIndex uint32
	MsgType     MessageType
	FragOffset  uint16
	FragLength  uint16
	TotalLength uint16
	Cookie      []byte // reserved for a future cookie/retry hardening; empty today
}

// PeekDatagramType returns the frame type of a raw datagram without fully
// parsing it. It is used to route an incoming datagram to the data or handshake
// path.
func PeekDatagramType(data []byte) (DatagramFrameType, error) {
	if len(data) < DatagramHeaderSize {
		return 0, qerrors.ErrInvalidMessage
	}
	return DatagramFrameType(data[0]), nil
}

// putDatagramHeader writes the 14-byte common header into buf (which must be at
// least DatagramHeaderSize long) and returns the number of bytes written.
func putDatagramHeader(buf []byte, h DatagramHeader) int {
	buf[0] = byte(h.Type)
	buf[1] = h.Epoch
	binary.BigEndian.PutUint32(buf[2:], h.RecvIndex)
	binary.BigEndian.PutUint64(buf[6:], h.Seq)
	return DatagramHeaderSize
}

// parseDatagramHeader reads the common header from data.
func parseDatagramHeader(data []byte) (DatagramHeader, error) {
	if len(data) < DatagramHeaderSize {
		return DatagramHeader{}, qerrors.ErrInvalidMessage
	}
	return DatagramHeader{
		Type:      DatagramFrameType(data[0]),
		Epoch:     data[1],
		RecvIndex: binary.BigEndian.Uint32(data[2:]),
		Seq:       binary.BigEndian.Uint64(data[6:]),
	}, nil
}

// ParseDatagramHeader reads the common header and returns it together with the
// remaining bytes (the frame body). The returned body aliases data.
func ParseDatagramHeader(data []byte) (DatagramHeader, []byte, error) {
	h, err := parseDatagramHeader(data)
	if err != nil {
		return DatagramHeader{}, nil, err
	}
	return h, data[DatagramHeaderSize:], nil
}

// EncodeDatagramHeader returns the 14-byte common header for h, preserving h.Type.
// The data path builds the header once with this, authenticates it as the AEAD
// AAD, and appends the ciphertext/tag itself (avoiding a redundant re-encode).
func EncodeDatagramHeader(h DatagramHeader) []byte {
	buf := make([]byte, DatagramHeaderSize)
	putDatagramHeader(buf, h)
	return buf
}

// EncodeDatagramData builds a DATA frame: the common header followed by the
// already-encrypted ciphertext. The AEAD AAD for the ciphertext must be the
// returned frame's first DatagramHeaderSize bytes (see DatagramAAD).
func EncodeDatagramData(h DatagramHeader, ciphertext []byte) []byte {
	h.Type = DatagramFrameData
	buf := make([]byte, DatagramHeaderSize+len(ciphertext))
	putDatagramHeader(buf, h)
	copy(buf[DatagramHeaderSize:], ciphertext)
	return buf
}

// DatagramAAD returns the additional-authenticated-data for a datagram frame:
// the common 14-byte header. It binds FrameType, Epoch, RecvIndex and Seq to
// the ciphertext. data must be at least DatagramHeaderSize long.
func DatagramAAD(data []byte) []byte {
	return data[:DatagramHeaderSize]
}

// EncodeDatagramHandshake builds a HANDSHAKE frame from h and the fragment
// payload. h.Type is forced to DatagramFrameHandshake.
func EncodeDatagramHandshake(h DatagramHandshakeHeader, fragment []byte) ([]byte, error) {
	if len(h.Cookie) > 255 {
		return nil, qerrors.ErrInvalidMessage
	}
	h.Type = DatagramFrameHandshake
	total := DatagramHeaderSize + DatagramHandshakeExtSize + len(h.Cookie) + len(fragment)
	buf := make([]byte, total)
	off := putDatagramHeader(buf, h.DatagramHeader)
	binary.BigEndian.PutUint32(buf[off:], h.SenderIndex)
	off += 4
	buf[off] = byte(h.MsgType)
	off++
	binary.BigEndian.PutUint16(buf[off:], h.FragOffset)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], h.FragLength)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], h.TotalLength)
	off += 2
	buf[off] = byte(len(h.Cookie))
	off++
	off += copy(buf[off:], h.Cookie)
	copy(buf[off:], fragment)
	return buf, nil
}

// ParseDatagramHandshake parses a HANDSHAKE frame and returns its header and the
// fragment payload. The returned fragment aliases data.
func ParseDatagramHandshake(data []byte) (DatagramHandshakeHeader, []byte, error) {
	base, err := parseDatagramHeader(data)
	if err != nil {
		return DatagramHandshakeHeader{}, nil, err
	}
	if base.Type != DatagramFrameHandshake {
		return DatagramHandshakeHeader{}, nil, qerrors.ErrInvalidMessage
	}
	off := DatagramHeaderSize
	if len(data) < off+DatagramHandshakeExtSize {
		return DatagramHandshakeHeader{}, nil, qerrors.ErrInvalidMessage
	}
	h := DatagramHandshakeHeader{DatagramHeader: base}
	h.SenderIndex = binary.BigEndian.Uint32(data[off:])
	off += 4
	h.MsgType = MessageType(data[off])
	off++
	h.FragOffset = binary.BigEndian.Uint16(data[off:])
	off += 2
	h.FragLength = binary.BigEndian.Uint16(data[off:])
	off += 2
	h.TotalLength = binary.BigEndian.Uint16(data[off:])
	off += 2
	cookieLen := int(data[off])
	off++
	if len(data) < off+cookieLen {
		return DatagramHandshakeHeader{}, nil, qerrors.ErrInvalidMessage
	}
	if cookieLen > 0 {
		h.Cookie = data[off : off+cookieLen]
		off += cookieLen
	}
	fragment := data[off:]
	// FragLength must describe exactly the fragment bytes present, and the
	// fragment must fit within the declared total message length.
	if int(h.FragLength) != len(fragment) {
		return DatagramHandshakeHeader{}, nil, qerrors.ErrInvalidMessage
	}
	if int(h.FragOffset)+int(h.FragLength) > int(h.TotalLength) {
		return DatagramHandshakeHeader{}, nil, qerrors.ErrInvalidMessage
	}
	return h, fragment, nil
}
