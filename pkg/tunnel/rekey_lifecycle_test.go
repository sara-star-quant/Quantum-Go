package tunnel

import (
	"bytes"
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// startRekey runs the stream rekey exchange at session level and stops at the point named by
// stage: "requested" (initiator asked), "prepared" (responder holds pending ciphers), or
// "done" (both sides switched). It returns the sessions and the messages exchanged so far.
type rekeyState struct {
	initiator, responder *Session
	pub, ct              []byte
	activation           uint64
}

func startRekey(t *testing.T, stage string) rekeyState {
	t.Helper()
	initiator, responder := keyedSessionPair(t)
	st := rekeyState{initiator: initiator, responder: responder}
	var err error
	if st.pub, st.activation, err = initiator.InitiateRekey(); err != nil {
		t.Fatal(err)
	}
	if stage == "requested" {
		return st
	}
	if st.ct, err = responder.PrepareRekeyResponse(st.pub, st.activation); err != nil {
		t.Fatal(err)
	}
	if stage == "prepared" {
		return st
	}
	if err := initiator.ProcessRekeyResponse(st.ct); err != nil {
		t.Fatal(err)
	}
	responder.ActivateRekeySend()
	return st
}

// Baseline for the rekey invariants: after a complete exchange both directions carry data under
// the new keys, and a record already delivered cannot be delivered again across the boundary.
func TestRekeyAtSessionLevelCarriesDataBothWaysAndRejectsBoundaryReplay(t *testing.T) {
	st := startRekey(t, "done")

	ct, seq, err := st.initiator.Encrypt([]byte("first record under the new key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.responder.Decrypt(ct, seq); err != nil || !bytes.Equal(got, []byte("first record under the new key")) {
		t.Fatalf("initiator to responder after the rekey: %q, %v", got, err)
	}
	if _, err := st.responder.Decrypt(ct, seq); !errors.Is(err, qerrors.ErrReplayDetected) {
		t.Fatalf("replay of the boundary record: err = %v, want ErrReplayDetected", err)
	}

	ct, seq, err = st.responder.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.initiator.Decrypt(ct, seq); err != nil || !bytes.Equal(got, []byte("reply")) {
		t.Fatalf("responder to initiator after the rekey: %q, %v", got, err)
	}
}

// Closed is terminal. No rekey transition may move a closed session to another state or hand it a
// cipher again, because a closed session has dropped its keys and callers read the state to know it.
func TestClosedSessionStaysClosedAcrossRekeyTransitions(t *testing.T) {
	assertStillClosed := func(t *testing.T, s *Session) {
		t.Helper()
		if got := s.State(); got != SessionStateClosed {
			t.Errorf("state = %v after Close and a rekey transition, want Closed", got)
		}
		if _, _, err := s.Encrypt([]byte("after close")); err == nil {
			t.Error("a closed session still seals records")
		}
	}

	t.Run("ActivateRekeySend after Close", func(t *testing.T) {
		st := startRekey(t, "prepared")
		st.responder.Close()
		st.responder.ActivateRekeySend()
		assertStillClosed(t, st.responder)
	})
	t.Run("ActivatePendingKeys after Close", func(t *testing.T) {
		st := startRekey(t, "prepared")
		st.responder.Close()
		st.responder.ActivatePendingKeys()
		assertStillClosed(t, st.responder)
	})
	t.Run("ProcessRekeyResponse after Close", func(t *testing.T) {
		st := startRekey(t, "prepared")
		st.initiator.Close()
		if err := st.initiator.ProcessRekeyResponse(st.ct); err == nil {
			t.Error("a closed initiator accepted a rekey response")
		}
		assertStillClosed(t, st.initiator)
	})
	t.Run("InitiateRekey after Close", func(t *testing.T) {
		initiator, _ := keyedSessionPair(t)
		initiator.Close()
		if _, _, err := initiator.InitiateRekey(); err == nil {
			t.Error("a closed session started a rekey")
		}
		assertStillClosed(t, initiator)
	})
	t.Run("PrepareRekeyResponse after Close", func(t *testing.T) {
		st := startRekey(t, "requested")
		st.responder.Close()
		if _, err := st.responder.PrepareRekeyResponse(st.pub, st.activation); err == nil {
			t.Error("a closed responder prepared a rekey response")
		}
		assertStillClosed(t, st.responder)
	})
}

// Close must also drop the key material a half-finished rekey holds. The pending ciphers, the
// pending master secret and the pending key pair are as sensitive as the live keys.
func TestCloseDropsPendingRekeyKeyMaterial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage string
		side  func(rekeyState) *Session
	}{
		{"responder with pending ciphers", "prepared", func(st rekeyState) *Session { return st.responder }},
		{"initiator with a pending key pair", "requested", func(st rekeyState) *Session { return st.initiator }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.side(startRekey(t, tc.stage))
			s.Close()
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.pendingRecvCipher != nil || s.pendingSendCipher != nil || s.pendingRekeySecret != nil || s.pendingRekeyKeyPair != nil {
				t.Fatalf("Close left pending rekey material: recv=%v send=%v secret=%v keypair=%v",
					s.pendingRecvCipher != nil, s.pendingSendCipher != nil, s.pendingRekeySecret != nil, s.pendingRekeyKeyPair != nil)
			}
		})
	}
}

// A forged record that arrives while a rekey is pending must change nothing: it must not promote
// the pending cipher, and it must not use up a sequence number the genuine new-key record needs.
func TestForgedRecordDuringRekeyChangesNothing(t *testing.T) {
	st := startRekey(t, "prepared")
	if err := st.initiator.ProcessRekeyResponse(st.ct); err != nil {
		t.Fatal(err)
	}
	st.responder.ActivateRekeySend()

	forged := bytes.Repeat([]byte{0x5A}, 32)
	if _, err := st.responder.Decrypt(forged, 7_000); !errors.Is(err, qerrors.ErrAuthenticationFailed) {
		t.Fatalf("forged record: err = %v, want ErrAuthenticationFailed", err)
	}
	st.responder.mu.RLock()
	stillPending := st.responder.pendingRecvCipher != nil
	st.responder.mu.RUnlock()
	if !stillPending {
		t.Fatal("a forged record promoted the pending receive cipher")
	}

	ct, seq, err := st.initiator.Encrypt([]byte("genuine new-key record"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.responder.Decrypt(ct, seq); err != nil || !bytes.Equal(got, []byte("genuine new-key record")) {
		t.Fatalf("genuine record after the forgery: %q, %v", got, err)
	}
}

// Only the initiator starts a stream rekey. A responder that calls it must get an error and keep
// its state, because it would otherwise wait for a response nobody sends and ignore the
// initiator's own request.
func TestOnlyTheInitiatorStartsAStreamRekey(t *testing.T) {
	_, responder := keyedSessionPair(t)
	if _, _, err := responder.InitiateRekey(); err == nil {
		t.Fatal("a responder started a rekey")
	}
	if responder.IsRekeyInProgress() || responder.State() != SessionStateEstablished {
		t.Fatalf("a refused rekey left state=%v inProgress=%v", responder.State(), responder.IsRekeyInProgress())
	}
}
