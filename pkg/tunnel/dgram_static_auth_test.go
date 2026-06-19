package tunnel

import (
	"errors"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// dialDgramAuth runs one datagram handshake over a memPipe with the given loss
// profile and optional server static identity / client pin. It returns the
// client session (nil on failure), the server session surfaced on acceptCh (nil
// if the server never established), and the dial error.
func dialDgramAuth(t *testing.T, seed uint64, drop, dup, reorder float64, serverKP *chkem.KeyPair, clientPin *chkem.PublicKey) (client, server *Session, dialErr error) {
	return dialDgramAuthOpts(t, seed, drop, dup, reorder, serverKP, clientPin, false)
}

func dialDgramAuthOpts(t *testing.T, seed uint64, drop, dup, reorder float64, serverKP *chkem.KeyPair, clientPin *chkem.PublicKey, requireAuth bool) (client, server *Session, dialErr error) {
	t.Helper()
	connA, connB := memPipe(seed, drop, dup, reorder)
	epA := mustEndpoint(t, connA)
	epB := mustEndpoint(t, connB)
	epB.staticIdentity = serverKP
	epB.requireStaticAuth = requireAuth
	epA.pinnedServerKey = clientPin
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 2 * time.Millisecond
		ep.rtoMax = 20 * time.Millisecond
	}
	go epA.Serve()
	go epB.Serve()
	t.Cleanup(func() { _ = epA.Close(); _ = epB.Close() })

	type dialResult struct {
		conn *DatagramConn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, err := DialDatagram(epA, connB.addr)
		dialCh <- dialResult{c, err}
	}()

	select {
	case r := <-dialCh:
		if r.err != nil {
			return nil, nil, r.err
		}
		client = r.conn.Session()
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not resolve")
	}

	// On success the responder surfaced its session before the dial returned.
	select {
	case ds := <-epB.acceptCh:
		server = ds.session
	case <-time.After(time.Second):
	}
	return client, server, nil
}

func TestDgramStaticAuthSuccess(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	// Lossy channel: also proves the larger fragmented authenticated ClientHello
	// reassembles under drop/dup/reorder.
	client, server, dialErr := dialDgramAuth(t, 7, 0.2, 0.1, 0.15, serverKP, serverKP.PublicKey())
	if dialErr != nil {
		t.Fatalf("authenticated datagram handshake failed: %v", dialErr)
	}
	if client == nil || server == nil {
		t.Fatal("nil session(s) after authenticated handshake")
	}
	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
	assertDataRoundTrip(t, client, server)
	assertDataRoundTrip(t, server, client)
}

func TestDgramStaticAuthWrongPinRejected(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	otherKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}

	// Lossless so the failure is a clean retry-ceiling timeout, not loss-induced.
	_, _, dialErr := dialDgramAuth(t, 1, 0, 0, 0, serverKP, otherKP.PublicKey())
	if !errors.Is(dialErr, qerrors.ErrServerKeyMismatch) {
		t.Fatalf("wrong pin: got %v, want ErrServerKeyMismatch", dialErr)
	}
}

func TestDgramStaticAuthServerServesUnpinnedClient(t *testing.T) {
	// A server with a static identity still serves a client that does not pin it.
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	client, server, dialErr := dialDgramAuth(t, 3, 0, 0, 0, serverKP, nil)
	if dialErr != nil {
		t.Fatalf("unpinned client against static-identity server failed: %v", dialErr)
	}
	if client == nil || server == nil {
		t.Fatal("nil session(s)")
	}
	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
}

func TestDgramRequireStaticAuthAcceptsPinnedClient(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	client, server, dialErr := dialDgramAuthOpts(t, 9, 0, 0, 0, serverKP, serverKP.PublicKey(), true)
	if dialErr != nil {
		t.Fatalf("require-auth with a pinned client failed: %v", dialErr)
	}
	if client == nil || server == nil {
		t.Fatal("nil session(s)")
	}
	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
}

func TestDgramRequireStaticAuthRejectsUnpinnedClient(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	// Client does not pin: the responder drops its unauthenticated ClientHello, so
	// the dial fails closed at the retry ceiling rather than establishing.
	client, server, dialErr := dialDgramAuthOpts(t, 4, 0, 0, 0, serverKP, nil, true)
	if dialErr == nil {
		t.Fatal("require-auth responder established a session for an unpinned client")
	}
	if client != nil || server != nil {
		t.Error("require-auth responder surfaced a session for an unpinned client")
	}
}

func TestDgramRequireStaticAuthMisconfigured(t *testing.T) {
	// WithRequireStaticAuth without WithStaticIdentity must fail construction.
	connA, _ := memPipe(1, 0, 0, 0)
	_, err := NewDatagramEndpoint(connA, WithRequireStaticAuth())
	if !errors.Is(err, qerrors.ErrStaticAuthMisconfigured) {
		t.Fatalf("misconfigured require-auth: got %v, want ErrStaticAuthMisconfigured", err)
	}
}
