package tunnel

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

func newPending(t *testing.T) *pendingRekeyInit {
	t.Helper()
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &pendingRekeyInit{kp: kp, epoch: 3, frames: [][]byte{{1}}}
}

func pendingNow(ds *datagramSession) *pendingRekeyInit {
	ds.rekeyPendMu.Lock()
	defer ds.rekeyPendMu.Unlock()
	return ds.rekeyPend
}

// An unanswered init keeps its key pair so a retry can resend the same init. That must not last
// as long as the session: on a dead link the secret key would stay in memory for hours.
func TestPendingRekeyInitExpires(t *testing.T) {
	ds := &datagramSession{rekeyPendTTL: 20 * time.Millisecond}
	p := newPending(t)
	ds.setPendingRekey(p)
	if ds.pendingRekeyFor(3) != p {
		t.Fatal("the pending init must be reusable inside its lifetime")
	}
	deadline := time.Now().Add(5 * time.Second)
	for pendingNow(ds) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the pending init outlived its lifetime")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ds.pendingRekeyFor(3) != nil {
		t.Fatal("an expired pending init was offered for reuse")
	}
}

// A Rekey racing with teardown can reach setPendingRekey after teardown cleared the slot. The
// key pair must not be stored on a session that is gone.
func TestPendingRekeyIsNotStoredAfterTeardown(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	_, _, ds := registerEstablished(t, e, udp("198.51.100.1", 4000))
	ds.teardown(e.registry)

	ds.setPendingRekey(newPending(t))
	if pendingNow(ds) != nil {
		t.Fatal("a pending init was stored on a torn-down session")
	}
}
