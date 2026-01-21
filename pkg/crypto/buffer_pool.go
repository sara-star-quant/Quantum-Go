// Package crypto implements cryptographic primitives for the Quantum-Go VPN.
//
// This file (buffer_pool.go) provides buffer pooling to reduce memory allocations
// during encryption/decryption, which is critical for high-throughput scenarios.
// The pool uses size classes optimized for typical AEAD operations.
package crypto

import (
	"sync"

	"github.com/pzverkov/quantum-go/internal/constants"
)

// BufferPool provides pooled byte slices for cryptographic operations.
type BufferPool struct {
	// Nonce buffers (12 bytes for AES-GCM and ChaCha20-Poly1305)
	nonce sync.Pool

	// Small ciphertext buffers (typical messages up to 1KB)
	small sync.Pool

	// Medium ciphertext buffers (up to 16KB)
	medium sync.Pool

	// Large ciphertext buffers (up to 64KB)
	large sync.Pool
}

// Buffer size class thresholds for crypto operations.
const (
	nonceBufferSize       = constants.AESNonceSize // 12 bytes
	smallCryptoBufferSize = 1024 + constants.AESNonceSize + constants.AESTagSize
	mediumCryptoBufferSize = 16*1024 + constants.AESNonceSize + constants.AESTagSize
	largeCryptoBufferSize  = 64*1024 + constants.AESNonceSize + constants.AESTagSize
)

// globalCryptoPool is the default crypto buffer pool instance.
var globalCryptoPool = NewBufferPool()

// NewBufferPool creates a new crypto buffer pool.
func NewBufferPool() *BufferPool {
	return &BufferPool{
		nonce: sync.Pool{
			New: func() any {
				buf := make([]byte, nonceBufferSize)
				return &buf
			},
		},
		small: sync.Pool{
			New: func() any {
				buf := make([]byte, smallCryptoBufferSize)
				return &buf
			},
		},
		medium: sync.Pool{
			New: func() any {
				buf := make([]byte, mediumCryptoBufferSize)
				return &buf
			},
		},
		large: sync.Pool{
			New: func() any {
				buf := make([]byte, largeCryptoBufferSize)
				return &buf
			},
		},
	}
}

// GetNonce returns a nonce buffer from the pool.
func (p *BufferPool) GetNonce() []byte {
	bufPtr := p.nonce.Get().(*[]byte)
	buf := *bufPtr
	// Zero the nonce before returning (security)
	for i := range buf {
		buf[i] = 0
	}
	return buf
}

// PutNonce returns a nonce buffer to the pool.
func (p *BufferPool) PutNonce(buf []byte) {
	if buf == nil || cap(buf) != nonceBufferSize {
		return
	}
	// Zero before returning to pool (security)
	for i := range buf[:cap(buf)] {
		buf[i] = 0
	}
	buf = buf[:cap(buf)]
	p.nonce.Put(&buf)
}

// GetCiphertext returns a ciphertext buffer of at least the requested size.
// The size should include space for nonce and tag overhead.
func (p *BufferPool) GetCiphertext(size int) []byte {
	if size <= 0 {
		return nil
	}

	var bufPtr *[]byte

	switch {
	case size <= smallCryptoBufferSize:
		bufPtr = p.small.Get().(*[]byte)
	case size <= mediumCryptoBufferSize:
		bufPtr = p.medium.Get().(*[]byte)
	case size <= largeCryptoBufferSize:
		bufPtr = p.large.Get().(*[]byte)
	default:
		// Too large for pool, allocate directly
		return make([]byte, size)
	}

	return (*bufPtr)[:size]
}

// PutCiphertext returns a ciphertext buffer to the pool.
func (p *BufferPool) PutCiphertext(buf []byte) {
	if buf == nil {
		return
	}

	bufCap := cap(buf)
	if bufCap == 0 {
		return
	}

	// Extend slice to full capacity for zeroing
	buf = buf[:bufCap]

	// Zero before returning to pool (security - clear any key material)
	for i := range buf {
		buf[i] = 0
	}

	bufPtr := &buf

	switch bufCap {
	case smallCryptoBufferSize:
		p.small.Put(bufPtr)
	case mediumCryptoBufferSize:
		p.medium.Put(bufPtr)
	case largeCryptoBufferSize:
		p.large.Put(bufPtr)
	// Non-standard sizes are not returned to pool
	}
}

// GetCryptoBuffer returns a buffer from the global crypto pool.
func GetCryptoBuffer(size int) []byte {
	return globalCryptoPool.GetCiphertext(size)
}

// PutCryptoBuffer returns a buffer to the global crypto pool.
func PutCryptoBuffer(buf []byte) {
	globalCryptoPool.PutCiphertext(buf)
}

// GetNonceBuffer returns a nonce buffer from the global pool.
func GetNonceBuffer() []byte {
	return globalCryptoPool.GetNonce()
}

// PutNonceBuffer returns a nonce buffer to the global pool.
func PutNonceBuffer(buf []byte) {
	globalCryptoPool.PutNonce(buf)
}

// SealPooled encrypts using a pooled ciphertext buffer.
// The caller must call PutCryptoBuffer on the returned ciphertext when done.
// This is more efficient for high-throughput scenarios.
func (a *AEAD) SealPooled(plaintext, additionalData []byte) ([]byte, error) {
	nonce, err := a.nextNoncePooled()
	if err != nil {
		return nil, err
	}
	defer PutNonceBuffer(nonce)

	// Get pooled buffer for ciphertext
	ciphertextSize := constants.AESNonceSize + len(plaintext) + constants.AESTagSize
	ciphertext := GetCryptoBuffer(ciphertextSize)

	// Copy nonce to beginning
	copy(ciphertext[:constants.AESNonceSize], nonce)

	// Encrypt in place after nonce
	a.cipher.Seal(ciphertext[constants.AESNonceSize:constants.AESNonceSize], nonce, plaintext, additionalData)

	return ciphertext, nil
}

// nextNoncePooled generates the next nonce using a pooled buffer.
func (a *AEAD) nextNoncePooled() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.counter >= a.maxSeq {
		return nil, errNonceExhausted
	}

	nonce := GetNonceBuffer()
	// Use big-endian counter in the last 8 bytes, first 4 bytes are zero
	nonce[0] = 0
	nonce[1] = 0
	nonce[2] = 0
	nonce[3] = 0
	nonce[4] = byte(a.counter >> 56)
	nonce[5] = byte(a.counter >> 48)
	nonce[6] = byte(a.counter >> 40)
	nonce[7] = byte(a.counter >> 32)
	nonce[8] = byte(a.counter >> 24)
	nonce[9] = byte(a.counter >> 16)
	nonce[10] = byte(a.counter >> 8)
	nonce[11] = byte(a.counter)
	a.counter++

	return nonce, nil
}

// Sentinel error for nonce exhaustion (avoid import cycle).
var errNonceExhausted = &nonceExhaustedError{}

type nonceExhaustedError struct{}

func (e *nonceExhaustedError) Error() string {
	return "aead: nonce space exhausted, rekey required"
}
