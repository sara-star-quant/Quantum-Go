package tunnel

import (
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// securityRecorder is an Observer that also listens for security events.
type securityRecorder struct {
	quietObserver
	mu     sync.Mutex
	events []SecurityEvent
}

func (r *securityRecorder) OnSecurityEvent(ev SecurityEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *securityRecorder) got() []SecurityEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SecurityEvent(nil), r.events...)
}

func wantEvents(t *testing.T, r *securityRecorder, want ...SecurityEvent) {
	t.Helper()
	if got := r.got(); !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
		t.Fatalf("security events = %v, want %v", got, want)
	}
}

// A session whose observer does not listen for security events must run unchanged.
func TestReportSecurityIgnoresPlainObserver(t *testing.T) {
	s, _ := inplaceSessionPair(t)
	s.reportSecurity(SecurityReplay, SecurityHigh) // no observer
	s.SetObserver(quietObserver{})
	s.reportSecurity(SecurityReplay, SecurityHigh) // observer without the extension
}

func TestSecurityEventReplayOnStream(t *testing.T) {
	tx, rx := inplaceSessionPair(t)
	rec := &securityRecorder{}
	rx.SetObserver(rec)

	ct, seq, err := tx.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Decrypt(ct, seq); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, rec) // the first delivery is healthy traffic
	if _, err := rx.Decrypt(ct, seq); err == nil {
		t.Fatal("replayed record accepted")
	}
	wantEvents(t, rec, SecurityEvent{SecurityReplay, SecurityLow})
}

func TestSecurityEventDowngradedServerHello(t *testing.T) {
	cases := []struct {
		name string
		edit func(*protocol.ServerHello)
		want []SecurityEvent
	}{
		{"suite the client did not offer", func(m *protocol.ServerHello) { m.KEMSuite = unknownSuite }, []SecurityEvent{{SecurityDowngrade, SecurityLow}}},
		// A server that speaks another protocol version is skew, not a downgrade signal.
		{"version skew", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server, ch := helloPair(t)
			rec := &securityRecorder{}
			client.session.SetObserver(rec)
			if err := server.ProcessClientHello(ch); err != nil {
				t.Fatal(err)
			}
			sh, err := server.CreateServerHello()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.ProcessServerHello(rewriteServerHello(t, client, sh, tc.edit)); err == nil {
				t.Fatal("bad ServerHello accepted")
			}
			wantEvents(t, rec, tc.want...)
		})
	}
}

func TestSecurityEventBadHelloRetryRequest(t *testing.T) {
	encode := func(h *Handshake, m *protocol.HelloRetryRequest) []byte {
		b, err := h.codec.EncodeHelloRetryRequest(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	down := SecurityEvent{SecurityDowngrade, SecurityLow}
	t.Run("suite never offered", func(t *testing.T) {
		client, _, _ := helloPair(t)
		rec := &securityRecorder{}
		client.session.SetObserver(rec)
		if err := client.ProcessHelloRetryRequest(encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: unknownSuite})); err == nil {
			t.Fatal("accepted")
		}
		wantEvents(t, rec, down)
	})
	t.Run("second retry", func(t *testing.T) {
		client := NewHandshake(newStubLedInitiator(t))
		rec := &securityRecorder{}
		client.session.SetObserver(rec)
		if _, err := client.CreateClientHello(); err != nil {
			t.Fatal(err)
		}
		hrr := encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: 1})
		if err := client.ProcessHelloRetryRequest(hrr); err != nil {
			t.Fatalf("first retry: %v", err)
		}
		wantEvents(t, rec) // one retry is normal
		if _, err := client.CreateClientHello(); err != nil {
			t.Fatal(err)
		}
		if err := client.ProcessHelloRetryRequest(hrr); err == nil {
			t.Fatal("second retry accepted")
		}
		wantEvents(t, rec, down)
	})
	t.Run("foreign version", func(t *testing.T) {
		client, _, _ := helloPair(t)
		rec := &securityRecorder{}
		client.session.SetObserver(rec)
		if err := client.ProcessHelloRetryRequest(futureVersion(encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: 1}))); err == nil {
			t.Fatal("accepted")
		}
		wantEvents(t, rec)
	})
}

// pinnedHandshake runs a stream handshake over a pipe with the client pinning pin and the
// server holding serverKey, and returns the client's recorder and error.
func pinnedHandshake(t *testing.T, serverKey *chkem.KeyPair, pin *chkem.PublicKey) (*securityRecorder, error) {
	t.Helper()
	ci, _ := NewSession(RoleInitiator)
	ri, _ := NewSession(RoleResponder)
	ci.PinnedServerKey = pin
	ri.StaticKeyPair = serverKey
	rec := &securityRecorder{}
	ci.SetObserver(rec)

	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ResponderHandshake(ri, s)
		_ = s.Close() // a failed server must not leave the client reading
	}()
	err := InitiatorHandshake(ci, c)
	_ = c.Close()
	<-done
	return rec, err
}

func TestSecurityEventPinMismatchOnStream(t *testing.T) {
	serverKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherKP, _, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec, err := pinnedHandshake(t, serverKP, serverKP.PublicKey())
	if err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	wantEvents(t, rec) // the healthy path raises nothing

	rec, err = pinnedHandshake(t, serverKP, otherKP.PublicKey())
	if err == nil {
		t.Fatal("wrong pin accepted")
	}
	wantEvents(t, rec, SecurityEvent{SecurityPinMismatch, SecurityHigh})
}
