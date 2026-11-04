package crypto

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// DeriveCHKEMSecret runs once per handshake on each side.
func BenchmarkDeriveCHKEMSecret(b *testing.B) {
	x := make([]byte, constants.X25519SharedSecretSize)
	m := make([]byte, constants.MLKEMSharedSecretSize)
	th := make([]byte, 32)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DeriveCHKEMSecret(x, m, th); err != nil {
			b.Fatal(err)
		}
	}
}
