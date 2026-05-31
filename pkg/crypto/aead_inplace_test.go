package crypto

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

func newTestAEAD(t *testing.T) *AEAD {
	t.Helper()
	key := make([]byte, constants.AESKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	a, err := NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	return a
}

func TestSealOpenWithNonceToRoundTrip(t *testing.T) {
	a := newTestAEAD(t)
	nonce := make([]byte, a.NonceSize())
	aad := []byte("header-aad")
	pt := []byte("the quick brown fox")

	// Seal appending after a header prefix, exactly as the datagram frame path does.
	header := append([]byte(nil), aad...)
	frame, err := a.SealWithNonceTo(header, nonce, pt, aad)
	if err != nil {
		t.Fatalf("SealWithNonceTo: %v", err)
	}
	if !bytes.Equal(frame[:len(aad)], aad) {
		t.Fatal("SealWithNonceTo overwrote the dst prefix")
	}
	ct := frame[len(aad):]

	// Cross-check against the allocating SealWithNonce.
	want, err := a.SealWithNonce(nonce, pt, aad)
	if err != nil {
		t.Fatalf("SealWithNonce: %v", err)
	}
	if !bytes.Equal(ct, want) {
		t.Fatal("SealWithNonceTo ciphertext differs from SealWithNonce")
	}

	// Open back into a reusable buffer.
	out := make([]byte, 0, len(pt))
	got, err := a.OpenWithNonceTo(out, nonce, ct, aad)
	if err != nil {
		t.Fatalf("OpenWithNonceTo: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
	}
}

func TestWithNonceToRejectsBadNonce(t *testing.T) {
	a := newTestAEAD(t)
	short := make([]byte, a.NonceSize()-1)
	if _, err := a.SealWithNonceTo(nil, short, []byte("x"), nil); err == nil {
		t.Fatal("SealWithNonceTo accepted a short nonce")
	}
	if _, err := a.OpenWithNonceTo(nil, short, []byte("x"), nil); err == nil {
		t.Fatal("OpenWithNonceTo accepted a short nonce")
	}
}

func TestWithNonceToRejectsTampered(t *testing.T) {
	a := newTestAEAD(t)
	nonce := make([]byte, a.NonceSize())
	aad := []byte("aad")
	ct, err := a.SealWithNonceTo(nil, nonce, []byte("secret"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := a.OpenWithNonceTo(nil, nonce, ct, aad); err == nil {
		t.Fatal("OpenWithNonceTo accepted a tampered tag")
	}
}

// BenchmarkSealWithNonce contrasts the allocating and zero-alloc seal paths so the
// alloc/op delta is visible (run with -benchmem).
func BenchmarkSealWithNonce(b *testing.B) {
	key := make([]byte, constants.AESKeySize)
	a, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)
	nonce := make([]byte, a.NonceSize())
	aad := make([]byte, 14)
	pt := make([]byte, 1200)

	b.Run("Alloc", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = a.SealWithNonce(nonce, pt, aad)
		}
	})

	b.Run("InPlace", func(b *testing.B) {
		b.ReportAllocs()
		buf := make([]byte, len(aad), len(aad)+len(pt)+a.Overhead())
		copy(buf, aad)
		for i := 0; i < b.N; i++ {
			_, _ = a.SealWithNonceTo(buf[:len(aad)], nonce, pt, aad)
		}
	})
}
