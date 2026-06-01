//go:build linux

package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestSplitSegments covers the GRO re-split logic without a socket: a coalesced
// buffer splits into segSize-sized datagrams (final one short), and the degenerate
// sizes collapse to a single dispatch.
func TestSplitSegments(t *testing.T) {
	collect := func(data []byte, segSize int) [][]byte {
		var got [][]byte
		splitSegments(data, segSize, nil, func(_ net.Addr, p []byte) {
			got = append(got, append([]byte(nil), p...))
		})
		return got
	}

	cases := []struct {
		name    string
		data    []byte
		segSize int
		want    [][]byte
	}{
		{"no gro segSize zero", []byte("abcdef"), 0, [][]byte{[]byte("abcdef")}},
		{"segSize ge len", []byte("abc"), 8, [][]byte{[]byte("abc")}},
		{"exact multiple", []byte("aabbcc"), 2, [][]byte{[]byte("aa"), []byte("bb"), []byte("cc")}},
		{"short final segment", []byte("aabbc"), 2, [][]byte{[]byte("aa"), []byte("bb"), []byte("c")}},
		{"single byte segments", []byte("abc"), 1, [][]byte{[]byte("a"), []byte("b"), []byte("c")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := collect(c.data, c.segSize)
			if len(got) != len(c.want) {
				t.Fatalf("segments = %d, want %d (%q seg=%d)", len(got), len(c.want), c.data, c.segSize)
			}
			for i := range c.want {
				if !bytes.Equal(got[i], c.want[i]) {
					t.Errorf("segment %d = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestGROReceiveDelivers drives the UDP_GRO-enabled receive path over a real loopback
// socket: equal-size datagrams with distinct content all arrive intact, whether or
// not the kernel coalesced them (a coalesced burst re-splits at the segment size,
// recovering each datagram). Equal sizes are deliberate - GRO only coalesces same-size
// datagrams, so the split boundaries line up with the original datagrams.
func TestGROReceiveDelivers(t *testing.T) {
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

	bio := newBatchIO(rx, true)
	if _, ok := bio.(*linuxBatchIO); !ok {
		t.Fatalf("newBatchIO over *net.UDPConn = %T, want *linuxBatchIO", bio)
	}

	const n, size = 8, 100
	want := make([][]byte, n)
	for i := range want {
		want[i] = bytes.Repeat([]byte{byte('A' + i)}, size)
		if _, err := tx.Write(want[i]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got [][]byte
	for len(got) < n {
		if err := bio.recv(func(_ net.Addr, p []byte) {
			got = append(got, append([]byte(nil), p...)) // copy: payload is borrowed
		}); err != nil {
			t.Fatalf("recv after %d/%d datagrams: %v", len(got), n, err)
		}
	}

	for _, w := range want {
		if !containsBytes(got, w) {
			t.Errorf("datagram %q not delivered (got %d)", w[:4], len(got))
		}
	}
}
