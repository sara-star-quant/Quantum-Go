package tunnel

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// TestDatagramRekeyDueByAge verifies the datagram rekey also fires on epoch age, not
// only on packet count: a slow link must still renew its keys within the session
// lifetime the stream path enforces.
func TestDatagramRekeyDueByAge(t *testing.T) {
	s, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	master := make([]byte, constants.CHKEMSharedSecretSize)
	if err := s.InitializeDatagramKeys(master, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatalf("InitializeDatagramKeys: %v", err)
	}

	if s.datagramRekeyDue(1) {
		t.Fatal("fresh epoch with one packet reported due")
	}

	s.mu.Lock()
	s.dgramEpochs.cur.startedAt = time.Now().Add(-time.Duration(constants.MaxSessionDurationSeconds)*time.Second - time.Second)
	s.mu.Unlock()
	if !s.datagramRekeyDue(1) {
		t.Fatal("epoch older than the session lifetime not reported due")
	}
}
