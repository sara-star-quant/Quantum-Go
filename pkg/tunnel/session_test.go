package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/crypto"
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

func TestSessionCheckAndActivateSendCipher(t *testing.T) {
	session, _ := NewSession(RoleInitiator)

	// Setup established session
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Initiate rekey
	_, _, _ = session.InitiateRekey()

	// Mock pending keys
	session.pendingSendCipher = session.sendCipher
	session.rekeyActivationSeq = 100

	// Should not activate before activation sequence
	session.checkAndActivateSendCipher(50)
	if session.rekeyActivationSeq == 0 {
		t.Error("cipher activated prematurely")
	}

	// Should activate at or after activation sequence
	session.checkAndActivateSendCipher(100)
	if session.rekeyActivationSeq != 0 {
		t.Error("cipher should have been activated")
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

	// Test Resume
	session2, _ := NewSession(RoleResponder)
	resumedSecret, err := session2.Resume(ticket, tm)
	if err != nil {
		t.Fatalf("Resume failed: %v", err)
	}

	if !bytes.Equal(masterSecret, resumedSecret) {
		t.Errorf("resumed secret mismatch:\nwant: %x\ngot:  %x", masterSecret, resumedSecret)
	}

	if session2.State() != SessionStateEstablished {
		t.Errorf("expected Established state after Resume, got %v", session2.State())
	}
}
