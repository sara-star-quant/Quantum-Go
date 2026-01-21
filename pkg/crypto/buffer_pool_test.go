package crypto

import (
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
)

func TestCryptoBufferPool(t *testing.T) {
	pool := NewCryptoBufferPool()

	t.Run("GetNonce", func(t *testing.T) {
		nonce := pool.GetNonce()
		if len(nonce) != constants.AESNonceSize {
			t.Errorf("nonce length = %d, want %d", len(nonce), constants.AESNonceSize)
		}
		pool.PutNonce(nonce)
	})

	t.Run("GetCiphertext_Small", func(t *testing.T) {
		buf := pool.GetCiphertext(100)
		if len(buf) != 100 {
			t.Errorf("buffer length = %d, want 100", len(buf))
		}
		if cap(buf) != smallCryptoBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), smallCryptoBufferSize)
		}
		pool.PutCiphertext(buf)
	})

	t.Run("GetCiphertext_Medium", func(t *testing.T) {
		buf := pool.GetCiphertext(8000)
		if len(buf) != 8000 {
			t.Errorf("buffer length = %d, want 8000", len(buf))
		}
		if cap(buf) != mediumCryptoBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), mediumCryptoBufferSize)
		}
		pool.PutCiphertext(buf)
	})

	t.Run("GetCiphertext_Large", func(t *testing.T) {
		buf := pool.GetCiphertext(32000)
		if len(buf) != 32000 {
			t.Errorf("buffer length = %d, want 32000", len(buf))
		}
		if cap(buf) != largeCryptoBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), largeCryptoBufferSize)
		}
		pool.PutCiphertext(buf)
	})

	t.Run("GetCiphertext_Oversized", func(t *testing.T) {
		// Request larger than pool max
		buf := pool.GetCiphertext(100000)
		if len(buf) != 100000 {
			t.Errorf("buffer length = %d, want 100000", len(buf))
		}
		// Oversized buffers are allocated directly, not returned to pool
		pool.PutCiphertext(buf)
	})

	t.Run("ZeroOnReturn", func(t *testing.T) {
		buf := pool.GetCiphertext(100)
		// Fill with data
		for i := range buf {
			buf[i] = 0xFF
		}
		pool.PutCiphertext(buf)

		// Get another buffer (may be the same one)
		buf2 := pool.GetCiphertext(100)
		// Check it's zeroed
		for i, b := range buf2 {
			if b != 0 {
				t.Errorf("buffer not zeroed at index %d: got %02x", i, b)
				break
			}
		}
		pool.PutCiphertext(buf2)
	})
}

func TestSealPooled(t *testing.T) {
	key := make([]byte, constants.AESKeySize)
	if err := SecureRandom(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	aead, err := NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	plaintext := []byte("Hello, pooled world!")
	aad := []byte("additional data")

	ciphertext, err := aead.SealPooled(plaintext, aad)
	if err != nil {
		t.Fatalf("SealPooled failed: %v", err)
	}
	defer PutCryptoBuffer(ciphertext)

	// Verify we can decrypt
	decrypted, err := aead.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// Benchmark comparing pooled vs non-pooled encryption.

func BenchmarkSeal_NonPooled(b *testing.B) {
	key := make([]byte, constants.AESKeySize)
	_ = SecureRandom(key)

	aead, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)

	plaintext := make([]byte, 1024)
	_ = SecureRandom(plaintext)
	aad := []byte("benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ciphertext, err := aead.Seal(plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
		_ = ciphertext
	}
}

func BenchmarkSeal_Pooled(b *testing.B) {
	key := make([]byte, constants.AESKeySize)
	_ = SecureRandom(key)

	aead, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)

	plaintext := make([]byte, 1024)
	_ = SecureRandom(plaintext)
	aad := []byte("benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ciphertext, err := aead.SealPooled(plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
		PutCryptoBuffer(ciphertext)
	}
}

func BenchmarkSeal_NonPooled_16KB(b *testing.B) {
	key := make([]byte, constants.AESKeySize)
	_ = SecureRandom(key)

	aead, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)

	plaintext := make([]byte, 16*1024)
	_ = SecureRandom(plaintext)
	aad := []byte("benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ciphertext, err := aead.Seal(plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
		_ = ciphertext
	}
}

func BenchmarkSeal_Pooled_16KB(b *testing.B) {
	key := make([]byte, constants.AESKeySize)
	_ = SecureRandom(key)

	aead, _ := NewAEAD(constants.CipherSuiteAES256GCM, key)

	plaintext := make([]byte, 16*1024)
	_ = SecureRandom(plaintext)
	aad := []byte("benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ciphertext, err := aead.SealPooled(plaintext, aad)
		if err != nil {
			b.Fatal(err)
		}
		PutCryptoBuffer(ciphertext)
	}
}

// Benchmark buffer pool get/put operations.

func BenchmarkBufferPool_GetPut_Small(b *testing.B) {
	pool := NewCryptoBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.GetCiphertext(512)
		pool.PutCiphertext(buf)
	}
}

func BenchmarkBufferPool_GetPut_Medium(b *testing.B) {
	pool := NewCryptoBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.GetCiphertext(8000)
		pool.PutCiphertext(buf)
	}
}

func BenchmarkBufferPool_GetPut_Large(b *testing.B) {
	pool := NewCryptoBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.GetCiphertext(32000)
		pool.PutCiphertext(buf)
	}
}

func BenchmarkMake_Small(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 512)
		_ = buf
	}
}

func BenchmarkMake_Medium(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 8000)
		_ = buf
	}
}

func BenchmarkMake_Large(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 32000)
		_ = buf
	}
}
