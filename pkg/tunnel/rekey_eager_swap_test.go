package tunnel

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// Session.Rekey and ActivatePendingKeys replace the receive cipher and the replay window in one
// critical section. Resetting the window is safe there only because the old cipher goes with it:
// a record sealed under the old key no longer authenticates, so a replay across the swap cannot
// be delivered. The lazy path used by the live transport keeps the window because it still opens
// old-key records with the old cipher. This pins the property for the eager methods.
func TestReplayAcrossAnEagerKeySwapIsNotDelivered(t *testing.T) {
	record := func(t *testing.T, from, to *Session) (ct []byte, seq uint64) {
		t.Helper()
		ct, seq, err := from.Encrypt([]byte("sealed under the old key"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := to.Decrypt(ct, seq); err != nil || !bytes.Equal(got, []byte("sealed under the old key")) {
			t.Fatalf("the record must be delivered once before the swap: %q %v", got, err)
		}
		return ct, seq
	}
	assertReplayRejected := func(t *testing.T, to *Session, ct []byte, seq uint64) {
		t.Helper()
		if got, err := to.Decrypt(ct, seq); err == nil {
			t.Fatalf("a replay across the key swap was delivered: %q", got)
		}
	}

	t.Run("Rekey", func(t *testing.T) {
		initiator, responder := keyedSessionPair(t)
		ct, seq := record(t, initiator, responder)
		master := bytes.Repeat([]byte{0x07}, constants.CHKEMSharedSecretSize)
		if err := initiator.Rekey(master); err != nil {
			t.Fatal(err)
		}
		if err := responder.Rekey(master); err != nil {
			t.Fatal(err)
		}
		assertReplayRejected(t, responder, ct, seq)

		fresh, fseq, err := initiator.Encrypt([]byte("under the new key"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := responder.Decrypt(fresh, fseq); err != nil {
			t.Fatalf("traffic under the new key must flow: %v", err)
		}
	})

	t.Run("ActivatePendingKeys", func(t *testing.T) {
		initiator, responder := keyedSessionPair(t)
		ct, seq := record(t, initiator, responder)
		pub, activation, err := initiator.InitiateRekey()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := responder.PrepareRekeyResponse(pub, activation)
		if err != nil {
			t.Fatal(err)
		}
		if err := initiator.ProcessRekeyResponse(resp); err != nil {
			t.Fatal(err)
		}
		responder.ActivatePendingKeys()
		assertReplayRejected(t, responder, ct, seq)
	})
}
