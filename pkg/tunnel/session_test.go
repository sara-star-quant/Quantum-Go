package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

func TestSessionNeedsRekeyEdgeCases(t *testing.T) {
	session, _ := NewSession(RoleInitiator)

	// Initial state (no cipher)
	if session.NeedsRekey() {
		t.Error("new session shouldn't need rekey")
	}

	// Setup established session
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	if session.NeedsRekey() {
		t.Error("freshly established session shouldn't need rekey")
	}

	// Mock high packet count
	session.PacketsSent.Store(constants.MaxPacketsBeforeRekey + 1)
	if !session.NeedsRekey() {
		t.Error("session should need rekey after high packet count")
	}
	session.PacketsSent.Store(0)

	// Mock high byte count
	session.BytesSent.Store(constants.MaxBytesBeforeRekey + 1)
	if !session.NeedsRekey() {
		t.Error("session should need rekey after high byte count")
	}
	session.BytesSent.Store(0)

	// Mock time limit
	session.EstablishedAt = time.Now().Add(-time.Duration(constants.MaxSessionDurationSeconds+1) * time.Second)
	if !session.NeedsRekey() {
		t.Error("session should need rekey after time limit")
	}
}

func TestSessionRekeyErrorPaths(t *testing.T) {
	session, _ := NewSession(RoleInitiator)

	// Rekey before established
	err := session.Rekey(make([]byte, constants.CHKEMSharedSecretSize))
	if err == nil {
		t.Error("expected error for rekey before established")
	}

	// Setup established session
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Rekey with wrong secret size
	err = session.Rekey(make([]byte, 10))
	if err == nil {
		t.Error("expected error for rekey with invalid secret size")
	}
}

func TestSessionActivatePendingKeysEdgeCases(t *testing.T) {
	session, _ := NewSession(RoleInitiator)

	// Activate before rekey initiated
	session.ActivatePendingKeys() // Should do nothing gracefully
}

func TestSessionActivateRekeySend(t *testing.T) {
	session, _ := NewSession(RoleInitiator)

	// Setup established session
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Initiate rekey
	_, _, _ = session.InitiateRekey()

	// Stage a distinct pending send cipher (as PrepareRekeyResponse does on the
	// responder). ActivateRekeySend must promote it to the live send cipher.
	newKey := make([]byte, constants.AESKeySize)
	_ = crypto.SecureRandom(newKey)
	newCipher, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, newKey)
	session.pendingSendCipher = newCipher

	session.ActivateRekeySend()
	if session.pendingSendCipher != nil {
		t.Error("pending send cipher should be cleared after ActivateRekeySend")
	}
	if session.sendCipher != newCipher {
		t.Error("send cipher should have been switched to the pending cipher")
	}

	// No pending cipher -> no-op (must not panic or clobber the live cipher).
	session.ActivateRekeySend()
	if session.sendCipher != newCipher {
		t.Error("send cipher changed unexpectedly on no-op ActivateRekeySend")
	}
}

// TestRekeyTrialDecryptionToleratesSendTiming reproduces the activation race that the
// old fixed "+16 sequence offset" could not survive at speed: the initiator keeps
// sending old-key data after InitiateRekey but before it processes the response, then
// switches. With trial decryption the receiver must accept old-key packets on its
// current cipher and new-key packets on the pending cipher, with no coordinated
// activation sequence. Deterministic (no timing).
func TestRekeyTrialDecryptionToleratesSendTiming(t *testing.T) {
	initiator, _ := NewSession(RoleInitiator)
	responder, _ := NewSession(RoleResponder)

	ms := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(ms)
	if err := initiator.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatal(err)
	}
	if err := responder.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatal(err)
	}

	// send encrypts on s and decrypts on r; AEAD integrity means err==nil implies the
	// right key/nonce/AAD were used.
	send := func(s, r *Session, payload []byte) error {
		ct, seq, err := s.Encrypt(payload)
		if err != nil {
			return err
		}
		_, err = r.Decrypt(ct, seq)
		return err
	}

	if err := send(initiator, responder, []byte("pre-rekey")); err != nil {
		t.Fatalf("pre-rekey traffic: %v", err)
	}

	// Drive the rekey handshake in the same order as transport.handleRekey.
	pub, actSeq, err := initiator.InitiateRekey()
	if err != nil {
		t.Fatal(err)
	}
	respCT, err := responder.PrepareRekeyResponse(pub, actSeq)
	if err != nil {
		t.Fatal(err)
	}

	// The race: initiator keeps sending OLD-key data after InitiateRekey but before it
	// processes the response. The responder must decrypt these on its current cipher.
	for i := 0; i < 100; i++ {
		if err := send(initiator, responder, []byte("old-key after init")); err != nil {
			t.Fatalf("old-key packet %d after rekey init: %v", i, err)
		}
	}

	// Responder switches its send cipher after its response is on the wire.
	responder.ActivateRekeySend()
	// Initiator processes the response and switches its send cipher to the new key.
	if err := initiator.ProcessRekeyResponse(respCT); err != nil {
		t.Fatal(err)
	}

	// New-key data in both directions must decrypt via trial promotion.
	for i := 0; i < 100; i++ {
		if err := send(initiator, responder, []byte("new-key after switch")); err != nil {
			t.Fatalf("new-key initiator->responder packet %d: %v", i, err)
		}
	}
	if err := send(responder, initiator, []byte("new-key responder->initiator")); err != nil {
		t.Fatalf("new-key responder->initiator: %v", err)
	}

	if initiator.IsRekeyInProgress() {
		t.Error("initiator rekey state not finalized")
	}
	if responder.IsRekeyInProgress() {
		t.Error("responder rekey state not finalized")
	}
}

// TestRekeyReplayWindowRejectsBoundaryReplay verifies the replay window is preserved
// across receive-cipher promotion during a rekey: replaying the first new-epoch packet
// (the one that triggered promotion) is rejected, not accepted a second time. Regression
// for a replay-protection bypass where promotion reset the window after the replay check.
func TestRekeyReplayWindowRejectsBoundaryReplay(t *testing.T) {
	initiator, _ := NewSession(RoleInitiator)
	responder, _ := NewSession(RoleResponder)

	ms := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(ms)
	if err := initiator.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatal(err)
	}
	if err := responder.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatal(err)
	}

	// Pre-rekey traffic so the rekey happens mid-stream (boundary sequence > 0).
	for i := 0; i < 3; i++ {
		ct, seq, err := initiator.Encrypt([]byte("pre"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := responder.Decrypt(ct, seq); err != nil {
			t.Fatalf("pre-rekey decrypt: %v", err)
		}
	}

	// Complete a rekey handshake (same ordering as transport.handleRekey).
	pub, actSeq, err := initiator.InitiateRekey()
	if err != nil {
		t.Fatal(err)
	}
	respCT, err := responder.PrepareRekeyResponse(pub, actSeq)
	if err != nil {
		t.Fatal(err)
	}
	responder.ActivateRekeySend()
	if err := initiator.ProcessRekeyResponse(respCT); err != nil {
		t.Fatal(err)
	}

	// First new-epoch packet: triggers the responder's trial-decryption promotion.
	boundaryCT, boundarySeq, err := initiator.Encrypt([]byte("first new-epoch packet"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Decrypt(boundaryCT, boundarySeq); err != nil {
		t.Fatalf("first delivery of boundary packet failed: %v", err)
	}

	// Replaying the identical boundary packet must be rejected as a replay.
	if _, err := responder.Decrypt(boundaryCT, boundarySeq); !qerrors.Is(err, qerrors.ErrReplayDetected) {
		t.Fatalf("boundary packet replay: got err=%v, want ErrReplayDetected", err)
	}
}

func TestSessionInitializeKeysInvalidSuite(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	err := session.InitializeKeys(masterSecret, constants.CipherSuite(0xFFFF))
	if err == nil {
		t.Error("expected error for invalid cipher suite")
	}
}

func TestSessionInitializeAfterClose(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	session.Close()
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	err := session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	if err == nil {
		t.Error("expected error for initialization after close")
	}
}

func TestSessionExportTicketResume(t *testing.T) {
	tmKey := make([]byte, 32)
	_ = crypto.SecureRandom(tmKey)
	tm, _ := NewTicketManager(tmKey, time.Hour)

	session, _ := NewSession(RoleInitiator)
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	ticket, err := session.ExportTicket(tm)
	if err != nil {
		t.Fatalf("ExportTicket failed: %v", err)
	}
	if len(ticket) == 0 {
		t.Fatal("exported empty ticket")
	}

	// Test Resume - returns PSK without initializing keys (keys are set after fresh KEM exchange)
	session2, _ := NewSession(RoleResponder)
	resumedSecret, err := session2.Resume(ticket, tm)
	if err != nil {
		t.Fatalf("Resume failed: %v", err)
	}

	if !bytes.Equal(masterSecret, resumedSecret) {
		t.Errorf("resumed secret mismatch:\nwant: %x\ngot:  %x", masterSecret, resumedSecret)
	}

	// Resume should NOT set state to Established - that happens after fresh KEM exchange
	if session2.State() == SessionStateEstablished {
		t.Error("Resume should not set state to Established (keys are initialized later after KEM exchange)")
	}
}
