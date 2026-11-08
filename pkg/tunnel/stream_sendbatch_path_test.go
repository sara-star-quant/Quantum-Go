package tunnel

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestUseVectoredBatchThreshold(t *testing.T) {
	old := vectoredBatchMaxAvg
	defer func() { vectoredBatchMaxAvg = old }()
	mk := func(n, size int) [][]byte {
		b := make([][]byte, n)
		for i := range b {
			b[i] = make([]byte, size)
		}
		return b
	}
	vectoredBatchMaxAvg = 2048
	for _, c := range []struct {
		batch [][]byte
		want  bool
	}{
		{mk(8, 256), true}, {mk(8, 2048), true}, {mk(8, 2049), false}, {mk(8, 8192), false},
		{append(mk(7, 100), make([]byte, 20000)), false}, // one big record raises the average
	} {
		if got := useVectoredBatch(c.batch); got != c.want {
			t.Errorf("avg %d: got %v want %v", len(bytes.Join(c.batch, nil))/len(c.batch), got, c.want)
		}
	}
	vectoredBatchMaxAvg = math.MaxInt
	if !useVectoredBatch(mk(4, 60000)) {
		t.Error("MaxInt threshold must always pick the vectored write")
	}
}

func TestDefaultThresholdIsSane(t *testing.T) {
	if d := defaultVectoredBatchMaxAvg(); d < 1400 {
		t.Fatalf("default threshold %d would skip the common VPN record size", d)
	}
}

// Both write paths deliver every record, in order, intact.
func TestSendBatchBothPathsDeliverInOrder(t *testing.T) {
	old := vectoredBatchMaxAvg
	defer func() { vectoredBatchMaxAvg = old }()
	for name, thr := range map[string]int{"sequential": -1, "vectored": math.MaxInt} {
		t.Run(name, func(t *testing.T) {
			vectoredBatchMaxAvg = thr
			sender, receiver, cleanup := benchStreamPair(t)
			defer cleanup()
			const batches, per = 40, 12
			errc := make(chan error, 1)
			go func() {
				for b := 0; b < batches; b++ {
					batch := make([][]byte, per)
					for i := range batch {
						p := make([]byte, 64+(i%4)*900)
						binary.BigEndian.PutUint32(p[0:], uint32(b))
						binary.BigEndian.PutUint32(p[4:], uint32(i))
						batch[i] = p
					}
					if err := sender.SendBatch(batch); err != nil {
						errc <- err
						return
					}
				}
				errc <- nil
			}()
			for b := 0; b < batches; b++ {
				for i := 0; i < per; i++ {
					got, err := receiver.Receive()
					if err != nil {
						t.Fatalf("Receive batch %d idx %d: %v", b, i, err)
					}
					if binary.BigEndian.Uint32(got[0:]) != uint32(b) || binary.BigEndian.Uint32(got[4:]) != uint32(i) || len(got) != 64+(i%4)*900 {
						t.Fatalf("record %d/%d out of order or damaged", b, i)
					}
				}
			}
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		})
	}
}
