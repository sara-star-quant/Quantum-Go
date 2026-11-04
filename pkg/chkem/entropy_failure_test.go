package chkem

import (
	"errors"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/randsrc"
)

type deadEntropy struct{}

func (deadEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

// Static identity and X-Wing key generation draw their seed from the library's entropy
// source; with it dead they must return an error and no key.
func TestKeyGenerationFailsWithoutEntropy(t *testing.T) {
	defer randsrc.Set(deadEntropy{})()

	if kp, _, err := GenerateStaticKeyPair(); err == nil || kp != nil {
		t.Fatalf("GenerateStaticKeyPair = %v, %v; want nil and an error", kp, err)
	}
	xw, ok := GetSuite(SuiteXWing)
	if !ok {
		t.Fatal("X-Wing suite is not registered")
	}
	if kp, err := xw.GenerateKeyPair(); err == nil || kp != nil {
		t.Fatalf("X-Wing GenerateKeyPair = %v, %v; want nil and an error", kp, err)
	}
}
