package tunnel

import (
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// An AEAD key gives an attacker a bounded number of forgery attempts before the integrity bound
// stops being negligible (RFC 9001 section 6.6 gives 2^36 failed packets for ChaCha20-Poly1305;
// the CFRG AEAD limits draft gives the formulas). A datagram session counts failed decryptions
// across all epochs and closes at the limit, so an on-path attacker cannot keep guessing forever.
func TestDatagramSessionClosesAtTheForgeryLimit(t *testing.T) {
	for _, viaTo := range []bool{false, true} {
		name := "DatagramOpen"
		if viaTo {
			name = "DatagramOpenTo"
		}
		t.Run(name, func(t *testing.T) {
			a, b := datagramSessionPair(t)
			const limit = 5
			b.authFailureLimit = limit

			header, ct := sealFrame(t, a, 7, []byte("genuine"))
			forged := append([]byte(nil), ct...)
			forged[0] ^= 0x01
			open := func(c []byte) ([]byte, error) {
				if viaTo {
					return b.DatagramOpenTo(nil, 0, 7, c, header, nil)
				}
				return b.DatagramOpen(0, 7, c, header)
			}

			for i := 1; i < limit; i++ {
				if _, err := open(forged); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
					t.Fatalf("forgery %d: got %v, want ErrAuthenticationFailed", i, err)
				}
			}
			if got, err := open(ct); err != nil || string(got) != "genuine" {
				t.Fatalf("below the limit the genuine frame must still open: %q %v", got, err)
			}
			// The limit-th failure closes the session. A genuine frame then fails as closed.
			if _, err := open(forged); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
				t.Fatalf("forgery at the limit: got %v, want ErrAuthenticationFailed", err)
			}
			if _, err := open(ct); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Fatalf("after the limit the session must be closed: got %v", err)
			}
		})
	}
}

// A frame for an epoch the session does not hold never reaches the AEAD, so it is not a
// decryption attempt and does not count toward the bound.
func TestUnknownEpochFramesDoNotSpendTheForgeryBudget(t *testing.T) {
	a, b := datagramSessionPair(t)
	b.authFailureLimit = 3
	header, ct := sealFrame(t, a, 7, []byte("genuine"))
	for range 10 {
		if _, err := b.DatagramOpen(200, 7, ct, header); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
			t.Fatalf("unknown epoch: got %v", err)
		}
	}
	if _, err := b.DatagramOpen(0, 7, ct, header); err != nil {
		t.Fatalf("unknown-epoch frames closed the session: %v", err)
	}
}

// A forged rekey control message is a decryption attempt under the same key, so it spends the
// same budget as a forged data frame.
func TestForgedRekeyControlSpendsTheForgeryBudget(t *testing.T) {
	a, b := datagramSessionPair(t)
	b.authFailureLimit = 2

	body, epoch, err := a.sealRekeyControl(protocol.MessageTypeDatagramRekeyInit, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), body...)
	forged[len(forged)-1] ^= 0x01

	if _, err := b.openRekeyControl(protocol.MessageTypeDatagramRekeyInit, epoch, forged); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
		t.Fatalf("first forgery: got %v, want ErrAuthenticationFailed", err)
	}
	if b.State() == SessionStateClosed {
		t.Fatal("the session closed below the limit")
	}
	if _, err := b.openRekeyControl(protocol.MessageTypeDatagramRekeyInit, epoch, forged); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
		t.Fatalf("second forgery: got %v, want ErrAuthenticationFailed", err)
	}
	if b.State() != SessionStateClosed {
		t.Fatal("forged rekey messages did not close the session at the limit")
	}
}

// Closing the session at the limit must also release the connection: the registry slot goes
// and readers blocked on the connection wake, as they do for an authenticated CLOSE.
func TestForgeryLimitTearsDownTheConnection(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	addr := udp("198.51.100.1", 4000)
	idx, peer, ds := registerEstablished(t, e, addr)
	ds.getSession().authFailureLimit = 3

	for i := range 3 {
		frame := dataFrameFrom(t, peer, idx, uint64(i+1), []byte("x"))
		frame[len(frame)-1] ^= 0xff
		if err := e.routeDatagram(addr, frame); err != nil {
			t.Fatalf("route %d: %v", i, err)
		}
	}
	select {
	case <-ds.closed:
	default:
		t.Fatal("the connection was not torn down after the session closed at the limit")
	}
	if e.registry.lookup(idx) != nil {
		t.Fatal("the registry still holds the connection after the limit")
	}
}
