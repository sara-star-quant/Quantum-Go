//go:build linux

package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestWriteGSOFallsBackWhenDisabled checks a socket with segmentation turned off
// reports false and sends nothing, and that SendBatch still delivers through plain
// sends.
func TestWriteGSOFallsBackWhenDisabled(t *testing.T) {
	client, server, stop := dialEstablished(t, WithDatagramOffload())
	defer stop()

	lb, ok := client.ep.batch.(*linuxBatchIO)
	if !ok {
		t.Skip("endpoint is not on the Linux batch path")
	}
	lb.gso.Store(false)
	if lb.writeGSO(make([]byte, 400), 100, client.ds.currentPeerAddr()) {
		t.Fatal("writeGSO reported success while disabled")
	}

	payloads := makePayloads([]int{300, 300, 300, 300})
	col := startCollector(server)
	if err := client.SendBatch(payloads); err != nil {
		t.Fatal(err)
	}
	if !col.waitFor(len(payloads)) {
		t.Fatalf("received %d payloads through the fallback, want %d", col.count(), len(payloads))
	}
}

// TestWriteGSOSegmentsOnWire sends one segmented write straight at a UDP socket and
// checks the receiver sees separate datagrams. It skips where the kernel does not
// segment.
func TestWriteGSOSegmentsOnWire(t *testing.T) {
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rx.Close() }()
	tx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Close() }()

	b, ok := newBatchIO(tx, true).(*linuxBatchIO)
	if !ok || !b.gso.Load() {
		t.Skip("kernel does not accept UDP_SEGMENT")
	}
	const seg, count = 120, 4
	data := bytes.Repeat([]byte{7}, seg*count)
	if !b.writeGSO(data, seg, rx.LocalAddr()) {
		t.Skip("segmented send refused on this transport")
	}
	_ = rx.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < count; i++ {
		n, _, err := rx.ReadFrom(buf)
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if n != seg {
			t.Fatalf("segment %d has %d bytes, want %d", i, n, seg)
		}
	}
}

// TestUDPSegmentControlParses checks the hand-built control message is exactly what
// the kernel's own parser reads back: level UDP, type UDP_SEGMENT, the segment size.
func TestUDPSegmentControlParses(t *testing.T) {
	for _, size := range []uint16{1, 100, 1200, 65000} {
		msgs, err := unix.ParseSocketControlMessage(udpSegmentControl(size))
		if err != nil || len(msgs) != 1 {
			t.Fatalf("size %d: parse = %v, %d messages", size, err, len(msgs))
		}
		h := msgs[0].Header
		if h.Level != unix.SOL_UDP || h.Type != unix.UDP_SEGMENT {
			t.Fatalf("size %d: level=%d type=%d, want SOL_UDP/UDP_SEGMENT", size, h.Level, h.Type)
		}
		if len(msgs[0].Data) < 2 || binary.NativeEndian.Uint16(msgs[0].Data) != size {
			t.Fatalf("size %d: data %v does not carry the segment size", size, msgs[0].Data)
		}
	}
}
