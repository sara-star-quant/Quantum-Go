package tunnel_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// tagged builds a payload carrying (batch, index) so an echoed stream can be checked
// for order and contiguity.
func tagged(batch, idx uint32, size int) []byte {
	p := make([]byte, size)
	binary.BigEndian.PutUint32(p[0:], batch)
	binary.BigEndian.PutUint32(p[4:], idx)
	for i := 8; i < size; i++ {
		p[i] = byte(batch + idx + uint32(i))
	}
	return p
}

func TestStreamSendBatchOrderAndContent(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	c, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// 1500 records exceed one writev's 1024-vector limit; sizes vary across batches.
	var batches [][][]byte
	var want [][]byte
	for b, n := range []int{1, 7, 64, 1500} {
		batch := make([][]byte, n)
		for i := range batch {
			batch[i] = tagged(uint32(b), uint32(i), 8+(i%5)*300)
		}
		batches = append(batches, batch)
		want = append(want, batch...)
	}
	// Send from a goroutine: the echo server blocks on Send when we are not reading,
	// so sending about a megabyte before receiving anything could deadlock.
	sendErr := make(chan error, 1)
	go func() {
		for _, b := range batches {
			if err := c.SendBatch(b); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- nil
	}()
	for i, w := range want {
		got, err := c.Receive()
		if err != nil {
			t.Fatalf("Receive %d/%d: %v", i, len(want), err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("record %d differs: got %d bytes want %d", i, len(got), len(w))
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
}

// Records of one batch stay contiguous and in order even with concurrent senders.
func TestStreamSendBatchIsAtomicUnderConcurrency(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	c, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	const senders, batches, perBatch = 4, 20, 16
	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for b := 0; b < batches; b++ {
				id := uint32(s*batches + b)
				batch := make([][]byte, perBatch)
				for i := range batch {
					batch[i] = tagged(id, uint32(i), 64)
				}
				if err := c.SendBatch(batch); err != nil {
					t.Errorf("SendBatch: %v", err)
					return
				}
			}
		}(s)
	}

	total := senders * batches * perBatch
	var curBatch, nextIdx uint32 = ^uint32(0), 0
	for n := 0; n < total; n++ {
		got, err := c.Receive()
		if err != nil {
			t.Fatalf("Receive %d/%d: %v", n, total, err)
		}
		b, i := binary.BigEndian.Uint32(got[0:]), binary.BigEndian.Uint32(got[4:])
		if i == 0 {
			if nextIdx != 0 && nextIdx != perBatch {
				t.Fatalf("batch %d interleaved: previous batch ended at index %d", b, nextIdx)
			}
			curBatch, nextIdx = b, 0
		}
		if b != curBatch || i != nextIdx {
			t.Fatalf("record %d: batch %d index %d, want batch %d index %d (interleaved or reordered)", n, b, i, curBatch, nextIdx)
		}
		nextIdx++
	}
	wg.Wait()
}

func TestStreamSendBatchErrors(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()
	c, err := tunnel.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SendBatch(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	// One oversize payload rejects the whole batch before anything is written.
	bad := [][]byte{tagged(1, 0, 64), make([]byte, constants.MaxPayloadSize+1), tagged(1, 2, 64)}
	if err := c.SendBatch(bad); !errors.Is(err, tunnel.ErrMessageTooLarge) {
		t.Fatalf("oversize: %v, want ErrMessageTooLarge", err)
	}
	if err := c.Send(tagged(2, 0, 64)); err != nil {
		t.Fatal(err)
	}
	got, err := c.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(got) != 2 {
		t.Fatalf("a rejected batch leaked a record: first echo is batch %d", binary.BigEndian.Uint32(got))
	}

	_ = c.Close()
	if err := c.SendBatch([][]byte{tagged(3, 0, 64)}); !errors.Is(err, tunnel.ErrTunnelClosed) {
		t.Fatalf("closed: %v, want ErrTunnelClosed", err)
	}
}
