package crypto_test

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// The output length limit is 1 MiB. The bounds are exact: 0 and one past the limit are errors,
// 1 byte and exactly the limit succeed. A mutation run showed the comparison could change at
// both ends without failing a test.
func TestKDFOutputLengthBounds(t *testing.T) {
	const limit = 1 << 20
	derive := map[string]func(n int) ([]byte, error){
		"DeriveKey": func(n int) ([]byte, error) { return crypto.DeriveKey("test-domain", []byte("input"), n) },
		"DeriveKeyMultiple": func(n int) ([]byte, error) {
			return crypto.DeriveKeyMultiple("test-domain", [][]byte{[]byte("a"), []byte("b")}, n)
		},
	}
	for name, fn := range derive {
		for _, n := range []int{-1, 0, limit + 1} {
			if out, err := fn(n); err == nil {
				t.Errorf("%s(%d) must fail, returned %d bytes", name, n, len(out))
			}
		}
		for _, n := range []int{1, 32, limit} {
			out, err := fn(n)
			if err != nil || len(out) != n {
				t.Errorf("%s(%d) must return exactly %d bytes: got %d, %v", name, n, n, len(out), err)
			}
		}
	}
}
