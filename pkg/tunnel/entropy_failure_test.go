package tunnel

import (
	"errors"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/randsrc"
)

type deadEntropy struct{}

func (deadEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

// With the entropy source dead, every place the tunnel draws randomness either returns
// an error or panics; none hands back a usable secret.
func TestTunnelFailsClosedWithoutEntropy(t *testing.T) {
	// Built before the failure so the handshake randoms below are the first draws.
	initiator, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	defer randsrc.Set(deadEntropy{})()

	if cs, err := newCookieSigner(nil); err == nil || cs != nil {
		t.Fatalf("newCookieSigner = %v, %v; want nil and an error", cs, err)
	}
	if s, err := NewSession(RoleInitiator); err == nil || s != nil {
		t.Fatalf("NewSession = %v, %v; want nil and an error", s, err)
	}
	if ep, err := NewDatagramEndpoint(newDiscardConn()); err == nil || ep != nil {
		t.Fatalf("NewDatagramEndpoint = %v, %v; want nil and an error", ep, err)
	}
	if idx, err := newConnRegistry(4).add(&datagramSession{}); err == nil || idx != 0 {
		t.Fatalf("registry add = %d, %v; want 0 and an error", idx, err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("CreateClientHello drew its random without entropy and did not panic")
			}
		}()
		_, _ = NewHandshake(initiator).CreateClientHello()
	}()
}
