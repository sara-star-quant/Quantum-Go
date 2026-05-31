package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// datagramSessionPair returns an initiator and responder Session keyed from the
// same master secret via InitializeDatagramKeys, so their directional datagram
// ciphers and nonce prefixes agree.
func datagramSessionPair(t *testing.T) (initiator, responder *Session) {
	t.Helper()
	ms := bytes.Repeat([]byte{0x42}, constants.CHKEMSharedSecretSize)
	initiator, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	responder, err = NewSession(RoleResponder)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	if err := initiator.InitializeDatagramKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatalf("init initiator: %v", err)
	}
	if err := responder.InitializeDatagramKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatalf("init responder: %v", err)
	}
	return initiator, responder
}

// sealFrame builds a DATA frame header, seals plaintext under from's current
// epoch, and returns the header and ciphertext so a test can hand them to a recv
// path or tamper with them.
func sealFrame(t *testing.T, from *Session, seq uint64, plaintext []byte) (header, ct []byte) {
	t.Helper()
	header = protocol.EncodeDatagramHeader(protocol.DatagramHeader{
		Type:  protocol.DatagramFrameData,
		Epoch: from.datagramSendEpoch(),
		Seq:   seq,
	})
	ct, err := from.DatagramSeal(header, seq, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return header, ct
}

func TestDatagramSealOpenRoundTrip(t *testing.T) {
	initiator, responder := datagramSessionPair(t)

	for _, dir := range []struct {
		name     string
		from, to *Session
	}{
		{"initiator->responder", initiator, responder},
		{"responder->initiator", responder, initiator},
	} {
		t.Run(dir.name, func(t *testing.T) {
			seq := dir.from.nextDatagramSeq()
			pt := []byte("quantum datagram payload " + dir.name)
			header, ct := sealFrame(t, dir.from, seq, pt)
			got, err := dir.to.DatagramOpen(header[1], seq, ct, protocol.DatagramAAD(header))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
			}
		})
	}
}

func TestDatagramOpenRejectsTamperedAAD(t *testing.T) {
	initiator, responder := datagramSessionPair(t)
	seq := initiator.nextDatagramSeq()
	header, ct := sealFrame(t, initiator, seq, []byte("payload"))

	// Flip the epoch byte in the AAD: authentication must fail (not just mis-route).
	tampered := append([]byte(nil), header...)
	tampered[1] ^= 0xFF
	if _, err := responder.DatagramOpen(tampered[1], seq, ct, protocol.DatagramAAD(tampered)); err == nil {
		t.Fatal("expected authentication failure on flipped epoch, got nil")
	}
}

func TestDatagramEpochRekey(t *testing.T) {
	initiator, responder := datagramSessionPair(t)
	newSecret := bytes.Repeat([]byte{0x99}, constants.CHKEMSharedSecretSize)

	// Send one frame under epoch 0.
	seq0 := initiator.nextDatagramSeq()
	h0, ct0 := sealFrame(t, initiator, seq0, []byte("epoch-0"))

	// Advance both sides to epoch 1.
	if ep, err := initiator.AdvanceDatagramEpoch(newSecret); err != nil || ep != 1 {
		t.Fatalf("advance initiator: ep=%d err=%v", ep, err)
	}
	if ep, err := responder.AdvanceDatagramEpoch(newSecret); err != nil || ep != 1 {
		t.Fatalf("advance responder: ep=%d err=%v", ep, err)
	}

	// The epoch-0 frame still opens via the retained previous epoch.
	if _, err := responder.DatagramOpen(h0[1], seq0, ct0, protocol.DatagramAAD(h0)); err != nil {
		t.Fatalf("open retained prev-epoch frame: %v", err)
	}

	// A fresh epoch-1 frame opens via the current epoch.
	seq1 := initiator.nextDatagramSeq()
	h1, ct1 := sealFrame(t, initiator, seq1, []byte("epoch-1"))
	if h1[1] != 1 {
		t.Fatalf("expected epoch 1 in header, got %d", h1[1])
	}
	if _, err := responder.DatagramOpen(h1[1], seq1, ct1, protocol.DatagramAAD(h1)); err != nil {
		t.Fatalf("open epoch-1 frame: %v", err)
	}

	// After the previous epoch retires, an old-epoch frame is rejected.
	responder.mu.Lock()
	responder.dgramEpochs.prev.retireAfter = time.Now().Add(-time.Second)
	responder.mu.Unlock()
	if _, err := responder.DatagramOpen(h0[1], seq0, ct0, protocol.DatagramAAD(h0)); err == nil {
		t.Fatal("expected rejection of retired-epoch frame, got nil")
	}
}

func TestDatagramDoubleRekeyDropsTwoEpochsBack(t *testing.T) {
	initiator, responder := datagramSessionPair(t)
	s1 := bytes.Repeat([]byte{0x01}, constants.CHKEMSharedSecretSize)
	s2 := bytes.Repeat([]byte{0x02}, constants.CHKEMSharedSecretSize)

	seq0 := initiator.nextDatagramSeq()
	h0, ct0 := sealFrame(t, initiator, seq0, []byte("epoch-0"))

	for _, s := range [][]byte{s1, s2} {
		if _, err := initiator.AdvanceDatagramEpoch(s); err != nil {
			t.Fatalf("advance initiator: %v", err)
		}
		if _, err := responder.AdvanceDatagramEpoch(s); err != nil {
			t.Fatalf("advance responder: %v", err)
		}
	}
	// epoch 0 is now two epochs back (prev holds epoch 1): it must be rejected.
	if _, err := responder.DatagramOpen(h0[1], seq0, ct0, protocol.DatagramAAD(h0)); err == nil {
		t.Fatal("expected rejection of two-epochs-back frame, got nil")
	}
}

// TestInitializeKeysNoDatagramState guards against the stream path accidentally
// creating datagram state. The TCP/stream InitializeKeys must leave the datagram
// fields nil.
func TestInitializeKeysNoDatagramState(t *testing.T) {
	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ms := bytes.Repeat([]byte{0x7}, constants.CHKEMSharedSecretSize)
	if err := s.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatalf("init keys: %v", err)
	}
	if s.dgramEpochs != nil || s.dgramReplay != nil || s.sendNoncePrefix != nil || s.recvNoncePrefix != nil {
		t.Fatal("stream InitializeKeys must not create datagram state")
	}
}
