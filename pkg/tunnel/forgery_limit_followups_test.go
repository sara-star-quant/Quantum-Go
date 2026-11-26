package tunnel

import (
	"errors"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// RFC 9001 section 6.6 sets the integrity limit per AEAD: 2^36 failed packets for
// ChaCha20-Poly1305 and 2^52 for AES-GCM. One limit for both would let an attacker who can reach a
// session close an AES-GCM session with 2^36 forgeries, which buys no cryptographic margin.
func TestForgeryBudgetFollowsTheAEAD(t *testing.T) {
	failOnce := func(s *Session) { s.noteDatagramAuthFailure(qerrors.ErrAuthenticationFailed) }

	chacha, _ := datagramSessionPair(t)
	chacha.CipherSuite = constants.CipherSuiteChaCha20Poly1305
	chacha.dgramAuthFailures.Store(1<<36 - 1)
	failOnce(chacha)
	if chacha.State() != SessionStateClosed {
		t.Fatal("a ChaCha20-Poly1305 session must close at 2^36 failed authentications")
	}

	gcm, _ := datagramSessionPair(t)
	gcm.CipherSuite = constants.CipherSuiteAES256GCM
	gcm.dgramAuthFailures.Store(1 << 36)
	failOnce(gcm)
	if gcm.State() == SessionStateClosed {
		t.Fatal("an AES-GCM session closed at the ChaCha20-Poly1305 limit")
	}
	gcm.dgramAuthFailures.Store(1<<52 - 1)
	failOnce(gcm)
	if gcm.State() != SessionStateClosed {
		t.Fatal("an AES-GCM session must close at 2^52 failed authentications")
	}
}

// A forged rekey message is a decryption attempt, so reaching the limit through one closes the
// session. The close must also release the connection, as it does on the data path.
func TestForgedRekeyInitAtTheLimitTearsDownTheConnection(t *testing.T) {
	e := mustEndpoint(t, &captureConn{})
	idx, _, ds := registerEstablished(t, e, udp("198.51.100.1", 4000))
	s := ds.getSession()
	s.authFailureLimit = 1

	forged := append(make([]byte, 8), make([]byte, 48)...) // a sequence number and a tag-sized blob
	h := protocol.DatagramHandshakeHeader{
		DatagramHeader: protocol.DatagramHeader{Epoch: s.datagramSendEpoch(), RecvIndex: idx},
		MsgType:        protocol.MessageTypeDatagramRekeyInit,
	}
	e.handleRekey(h, forged)

	select {
	case <-ds.closed:
	default:
		t.Fatal("the connection was not torn down after a forged RekeyInit reached the limit")
	}
	if e.registry.lookup(idx) != nil {
		t.Fatal("the registry still holds the connection")
	}
}

// The initiator side: a forged RekeyResponse that reaches the limit must end the waiting Rekey at
// once, not leave it to time out on a session that is already closed.
func TestForgedRekeyResponseAtTheLimitEndsTheWaitingRekey(t *testing.T) {
	client, _, epA, epB := dgramPair(t, 71, 0, 0, 0)
	defer func() { _ = epA.Close(); _ = epB.Close() }()
	client.Session().authFailureLimit = 1
	memConn(epA).fault.setDropAll(protocol.MessageTypeDatagramRekeyInit) // no genuine response can arrive

	// Push the forged response only once the init is on the wire: Rekey drains its inbox before it
	// sends, so an earlier push would be discarded and the test would depend on timing.
	sent := make(chan struct{}, 1)
	memConn(epA).fault.setTap(func(data []byte) {
		if ft, err := protocol.PeekDatagramType(data); err != nil || ft != protocol.DatagramFrameHandshake {
			return
		}
		if h, _, err := protocol.ParseDatagramHandshake(data); err == nil && h.MsgType == protocol.MessageTypeDatagramRekeyInit {
			select {
			case sent <- struct{}{}:
			default:
			}
		}
	})
	done := make(chan error, 1)
	go func() { done <- client.Rekey() }()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("the RekeyInit never reached the wire")
	}
	forged := append(make([]byte, 8), make([]byte, 48)...)
	client.ds.rekeyInbox <- forged

	select {
	case err := <-done:
		if !errors.Is(err, qerrors.ErrTunnelClosed) {
			t.Fatalf("Rekey returned %v, want ErrTunnelClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Rekey kept waiting after a forged response closed the session")
	}
}
