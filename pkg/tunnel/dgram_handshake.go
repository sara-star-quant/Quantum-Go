// Package tunnel - dgram_handshake.go drives the CH-KEM handshake over the
// connectionless datagram transport. Unlike the stream handshake it tolerates
// loss, reordering, and duplication, and it splits the large post-quantum
// handshake messages (the ~1.6 KB Hellos) across multiple datagrams.
//
// This file provides the send-side fragmenter, the inverse of the Reassembler.
// The retransmission state machine and the responder flight cache build on it.
package tunnel

import (
	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// maxHandshakeFragmentPayload is the largest handshake message slice that fits
// in one datagram after the common header and the handshake extension (and any
// cookie). It derives from the wire-format sizes in pkg/protocol so it stays
// correct if those change.
func maxHandshakeFragmentPayload(cookieLen int) int {
	return constants.DatagramMTU - protocol.DatagramHeaderSize - protocol.DatagramHandshakeExtSize - cookieLen
}

// fragmentHandshake splits a serialized handshake message into one or more
// datagram HANDSHAKE frames, each within the datagram MTU. base supplies the
// per-frame header fields (Epoch, RecvIndex, SenderIndex, MsgType, and an
// optional Cookie); fragmentHandshake fills FragOffset, FragLength, and
// TotalLength per fragment and assigns each frame a distinct, increasing
// sequence number starting at base.Seq. The frames reassemble in any order on
// the peer.
//
// When pad is set, each frame is zero-extended to exactly DatagramMTU. The
// padding sits after the fragment payload and is excluded from FragLength, so the
// receiver's parser slices it off before reassembly - it never enters the message
// or the handshake transcript. This makes every handshake datagram uniform-size
// (anti-fingerprinting); it does not equalize the number of datagrams per flight.
func fragmentHandshake(base protocol.DatagramHandshakeHeader, msg []byte, pad bool) ([][]byte, error) {
	total := len(msg)
	if total == 0 || total > constants.DatagramMaxHandshakeMessageSize {
		return nil, qerrors.ErrMessageTooLarge
	}
	maxFrag := maxHandshakeFragmentPayload(len(base.Cookie))
	if maxFrag <= 0 {
		return nil, qerrors.ErrInvalidMessage
	}

	frames := make([][]byte, 0, (total+maxFrag-1)/maxFrag)
	seq := base.Seq
	for off := 0; off < total; off += maxFrag {
		end := off + maxFrag
		if end > total {
			end = total
		}
		h := base
		h.Seq = seq
		h.FragOffset = uint16(off)
		h.FragLength = uint16(end - off)
		h.TotalLength = uint16(total)
		frame, err := protocol.EncodeDatagramHandshake(h, msg[off:end])
		if err != nil {
			return nil, err
		}
		if pad && len(frame) < constants.DatagramMTU {
			frame = append(frame, make([]byte, constants.DatagramMTU-len(frame))...)
		}
		frames = append(frames, frame)
		seq++
	}
	return frames, nil
}
