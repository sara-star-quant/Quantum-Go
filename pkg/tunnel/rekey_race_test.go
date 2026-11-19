package tunnel

import (
	"bytes"
	"sync"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// The exported activation methods swap the replay window and the receive path reads it, so they
// must agree on a lock. Run with -race: an unsynchronized read of the window field is reported here.
func TestReplayWindowFieldIsSynchronisedAgainstRekeyActivation(t *testing.T) {
	st := startRekey(t, "prepared")
	ct, seq, err := st.initiator.Encrypt([]byte("probe"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			_, _ = st.responder.Decrypt(ct, seq)
		}
	})
	master := bytes.Repeat([]byte{0x42}, constants.CHKEMSharedSecretSize)
	wg.Go(func() {
		for range 200 {
			_ = st.responder.Rekey(master)
		}
	})
	wg.Wait()
}
