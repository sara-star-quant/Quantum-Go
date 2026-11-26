package tunnel

import (
	"bytes"
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// A second rekey request that arrives before the first one is activated must not replace the
// pending keys. The transport guards the call, but PrepareRekeyResponse is exported, and a
// replacement would drop the first pending secret without scrubbing it and could swap the pending
// receive cipher while a record is being trial-decrypted against it.
func TestPrepareRekeyResponseRefusesASecondRequestBeforeActivation(t *testing.T) {
	st := startRekey(t, "prepared")
	r := st.responder

	r.mu.RLock()
	secret := bytes.Clone(r.pendingRekeySecret)
	recv, send := r.pendingRecvCipher, r.pendingSendCipher
	r.mu.RUnlock()
	if len(secret) == 0 || recv == nil || send == nil {
		t.Fatal("test assumption: the responder holds pending rekey state")
	}

	if _, err := r.PrepareRekeyResponse(st.pub, st.activation); !errors.Is(err, qerrors.ErrRekeyInProgress) {
		t.Fatalf("second PrepareRekeyResponse: got %v, want ErrRekeyInProgress", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if !bytes.Equal(r.pendingRekeySecret, secret) || r.pendingRecvCipher != recv || r.pendingSendCipher != send {
		t.Fatal("the refused request replaced the pending rekey state")
	}
}
