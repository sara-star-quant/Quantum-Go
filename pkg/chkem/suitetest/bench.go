package suitetest

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// Bench runs the standard KEM microbenchmarks for s: key generation, encapsulation
// and decapsulation, each with allocations reported. The wire sizes are reported as
// pk-bytes and ct-bytes so suites compare on handshake cost, not only CPU.
func Bench(b *testing.B, s chkem.Suite) {
	b.Helper()
	kp, err := s.GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}
	defer kp.Zeroize()
	pub := kp.PublicKey()
	ct, _, err := s.Encapsulate(pub, chkem.RoleResponder)
	if err != nil {
		b.Fatalf("Encapsulate: %v", err)
	}

	report := func(b *testing.B) {
		b.ReportMetric(float64(s.PublicKeySize()), "pk-bytes")
		b.ReportMetric(float64(s.CiphertextSize()), "ct-bytes")
	}
	b.Run("GenerateKeyPair", func(b *testing.B) {
		b.ReportAllocs()
		report(b)
		for i := 0; i < b.N; i++ {
			k, err := s.GenerateKeyPair()
			if err != nil {
				b.Fatal(err)
			}
			k.Zeroize()
		}
	})
	b.Run("Encapsulate", func(b *testing.B) {
		b.ReportAllocs()
		report(b)
		for i := 0; i < b.N; i++ {
			if _, _, err := s.Encapsulate(pub, chkem.RoleResponder); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Decapsulate", func(b *testing.B) {
		b.ReportAllocs()
		report(b)
		for i := 0; i < b.N; i++ {
			if _, err := s.Decapsulate(ct, kp, chkem.RoleInitiator); err != nil {
				b.Fatal(err)
			}
		}
	})
}
