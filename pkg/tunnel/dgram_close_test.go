package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// A closed datagram session must not keep its epoch ciphers reachable, and every
// reader of the epoch state must fail cleanly instead of dereferencing nil.
func TestDatagramCloseDropsEpochCiphers(t *testing.T) {
	for _, rekeyed := range []bool{false, true} {
		name := "epoch0"
		if rekeyed {
			name = "after rekey (prev epoch live)"
		}
		t.Run(name, func(t *testing.T) {
			a, b := datagramSessionPair(t)
			if rekeyed {
				secret := make([]byte, constants.CHKEMSharedSecretSize)
				secret[0] = 1
				if _, err := a.AdvanceDatagramEpoch(secret); err != nil {
					t.Fatalf("advance: %v", err)
				}
			}
			header, ct := sealFrame(t, a, 7, []byte("before close"))
			a.Close()

			a.mu.RLock()
			epochs, send, recv := a.dgramEpochs, a.sendCipher, a.recvCipher
			a.mu.RUnlock()
			if epochs != nil || send != nil || recv != nil {
				t.Fatalf("closed session still references ciphers: epochs=%v send=%v recv=%v", epochs != nil, send != nil, recv != nil)
			}

			hdr := protocol.EncodeDatagramHeader(protocol.DatagramHeader{Type: protocol.DatagramFrameData, Epoch: a.datagramSendEpoch(), Seq: 8})
			if _, err := a.DatagramSeal(hdr, 8, []byte("x")); !errors.Is(err, qerrors.ErrInvalidState) {
				t.Errorf("DatagramSeal: got %v, want ErrInvalidState", err)
			}
			if _, err := a.DatagramSealTo(nil, hdr, 8, []byte("x"), nil); !errors.Is(err, qerrors.ErrInvalidState) {
				t.Errorf("DatagramSealTo: got %v, want ErrInvalidState", err)
			}
			if _, _, err := a.sealRekeyControl(protocol.MessageType(0), []byte("x")); !errors.Is(err, qerrors.ErrInvalidState) {
				t.Errorf("sealRekeyControl: got %v, want ErrInvalidState", err)
			}
			if _, err := a.AdvanceDatagramEpoch(make([]byte, constants.CHKEMSharedSecretSize)); !errors.Is(err, qerrors.ErrInvalidState) {
				t.Errorf("AdvanceDatagramEpoch: got %v, want ErrInvalidState", err)
			}
			// The frame was sealed by a before it closed, under the epoch it names.
			if _, err := a.DatagramOpen(0, 7, ct, header); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Errorf("DatagramOpen: got %v, want ErrTunnelClosed", err)
			}
			if _, err := a.DatagramOpenTo(nil, 0, 7, ct, header, nil); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Errorf("DatagramOpenTo: got %v, want ErrTunnelClosed", err)
			}
			if a.datagramRekeyDue(1 << 40) {
				t.Error("datagramRekeyDue reports a closed session as due")
			}
			a.Close() // idempotent

			// The peer is unaffected and still rejects a frame for an epoch it does not hold.
			if _, err := b.DatagramOpen(200, 7, ct, header); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
				t.Errorf("peer, unknown epoch: got %v, want ErrAuthenticationFailed", err)
			}
		})
	}
}

// Close races with sealing and opening; run under -race.
func TestDatagramCloseConcurrentWithTraffic(t *testing.T) {
	a, _ := datagramSessionPair(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for i := range 2000 {
				seq := uint64(i)
				hdr := protocol.EncodeDatagramHeader(protocol.DatagramHeader{Type: protocol.DatagramFrameData, Epoch: a.datagramSendEpoch(), Seq: seq})
				if ct, err := a.DatagramSeal(hdr, seq, []byte("x")); err == nil {
					_, _ = a.DatagramOpen(0, seq, ct, hdr)
				}
				_ = a.datagramRekeyDue(seq)
			}
		})
	}
	a.Close()
	wg.Wait()
}
