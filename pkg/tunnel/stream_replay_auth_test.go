package tunnel

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// keyedSessionPair returns an initiator and a responder session keyed with the same master secret.
func keyedSessionPair(t *testing.T) (initiator, responder *Session) {
	t.Helper()
	master := make([]byte, constants.CHKEMSharedSecretSize)
	if err := crypto.SecureRandom(master); err != nil {
		t.Fatal(err)
	}
	var err error
	if initiator, err = NewSession(RoleInitiator); err != nil {
		t.Fatal(err)
	}
	responder = mustResponder(t)
	for _, s := range []*Session{initiator, responder} {
		if err := s.InitializeKeys(master, constants.CipherSuiteAES256GCM); err != nil {
			t.Fatal(err)
		}
	}
	return initiator, responder
}

// A frame that fails authentication must leave the replay window alone. Recording a sequence number
// before the tag is checked lets one forged frame, which anyone on the path can send, use up the
// number a genuine frame needs, or push the window so far ahead that every genuine frame looks too
// old. Datagram sessions already record only after authentication; the stream path must do the same.
func TestStreamForgedFrameDoesNotConsumeSequenceNumbers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		forgedSeq uint64
	}{
		{"same number as the next genuine frame", 0},
		{"far in the future", 5000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initiator, responder := keyedSessionPair(t)
			forged := bytes.Repeat([]byte{0xA5}, 16+constants.AESTagSize)
			if _, err := responder.Decrypt(forged, tc.forgedSeq); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
				t.Fatalf("forged frame: err = %v, want ErrAuthenticationFailed", err)
			}

			msg := []byte("genuine frame after the forgery")
			ct, seq, err := initiator.Encrypt(msg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := responder.Decrypt(ct, seq)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("genuine frame after a forged one: %q, %v; want it delivered", got, err)
			}
		})
	}
}

// Recording after authentication must still reject a genuine duplicate, including when several
// receivers see the same authentic frame at once: exactly one delivers it.
func TestStreamDuplicateGenuineFrameDeliversOnce(t *testing.T) {
	initiator, responder := keyedSessionPair(t)
	ct, seq, err := initiator.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	var delivered, replays atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			switch _, err := responder.Decrypt(ct, seq); {
			case err == nil:
				delivered.Add(1)
			case errors.Is(err, qerrors.ErrReplayDetected):
				replays.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if delivered.Load() != 1 || replays.Load() != 31 {
		t.Fatalf("delivered=%d replays=%d, want 1 and 31", delivered.Load(), replays.Load())
	}
}
