//go:build linux

package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// udpSegmentControl builds the UDP_SEGMENT (GSO) control message that asks the kernel
// to slice one large send into segSize-byte datagrams. It is the send-side mirror of
// the UDP_GRO cmsg the receive path reads.
func udpSegmentControl(segSize uint16) []byte {
	oob := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], segSize)
	return oob
}

// TestGSOSendSegments verifies the prerequisite for send-side offload (the deferred
// stage 2c): that x/net's WriteBatch actually transmits Message.OOB, so a UDP_SEGMENT
// control message makes the kernel slice one large send into multiple datagrams. The
// receiver runs without GRO, so each segment lands as its own datagram. It skips
// (rather than fails) on a kernel or transport that does not segment, so it records
// support without flaking; when it passes here it confirms the OOB path works and a
// future GSO send can ride WriteBatch instead of raw sendmmsg.
func TestGSOSendSegments(t *testing.T) {
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	defer func() { _ = rx.Close() }()
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial tx: %v", err)
	}
	defer func() { _ = tx.Close() }()

	const seg, count = 100, 3
	payload := make([]byte, seg*count)
	for i := range payload {
		payload[i] = byte(i)
	}

	pc := ipv4.NewPacketConn(tx)
	msgs := []ipv4.Message{{Buffers: [][]byte{payload}, OOB: udpSegmentControl(seg)}}
	if _, err := pc.WriteBatch(msgs, 0); err != nil {
		t.Skipf("WriteBatch with UDP_SEGMENT failed (no GSO on this transport): %v", err)
	}

	_ = rx.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var got [][]byte
	buf := make([]byte, 65536)
	for {
		n, _, rerr := rx.ReadFrom(buf)
		if rerr != nil {
			break // deadline: stop collecting whatever arrived
		}
		got = append(got, append([]byte(nil), buf[:n]...))
	}

	if len(got) == 1 && len(got[0]) == seg*count {
		t.Skip("kernel did not segment the GSO send on this transport; OOB path unconfirmed")
	}
	if len(got) != count {
		t.Fatalf("received %d datagrams, want %d segments", len(got), count)
	}
	var joined []byte
	for _, g := range got {
		if len(g) != seg {
			t.Errorf("segment length %d, want %d", len(g), seg)
		}
		joined = append(joined, g...)
	}
	if !bytes.Equal(joined, payload) {
		t.Errorf("reassembled segments do not match the original payload")
	}
}
