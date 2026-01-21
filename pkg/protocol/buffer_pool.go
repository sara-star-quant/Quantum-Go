// buffer_pool.go implements buffer pooling for protocol message serialization.
//
// Buffer pooling reduces memory allocations by reusing buffers across operations.
// This is especially beneficial in high-throughput scenarios where frequent
// message encoding/decoding would otherwise cause significant GC pressure.
package protocol

import (
	"sync"
)

// BufferPool provides pooled byte slices for protocol message operations.
// It uses size classes to efficiently handle different message sizes.
type BufferPool struct {
	// Size class pools
	small  sync.Pool // <= 256 bytes (headers, alerts)
	medium sync.Pool // <= 4KB (typical data messages)
	large  sync.Pool // <= 64KB (max message size)
	xlarge sync.Pool // <= 2MB (CH-KEM handshake messages)
}

// Buffer size class thresholds.
const (
	smallBufferSize  = 256
	mediumBufferSize = 4 * 1024
	largeBufferSize  = 64 * 1024
	xlargeBufferSize = 2 * 1024 * 1024
)

// globalBufferPool is the default buffer pool instance.
var globalBufferPool = NewBufferPool()

// NewBufferPool creates a new buffer pool.
func NewBufferPool() *BufferPool {
	return &BufferPool{
		small: sync.Pool{
			New: func() any {
				buf := make([]byte, smallBufferSize)
				return &buf
			},
		},
		medium: sync.Pool{
			New: func() any {
				buf := make([]byte, mediumBufferSize)
				return &buf
			},
		},
		large: sync.Pool{
			New: func() any {
				buf := make([]byte, largeBufferSize)
				return &buf
			},
		},
		xlarge: sync.Pool{
			New: func() any {
				buf := make([]byte, xlargeBufferSize)
				return &buf
			},
		},
	}
}

// Get returns a buffer of at least the requested size.
// The returned buffer may be larger than requested.
// The caller must call Put() when done with the buffer.
func (p *BufferPool) Get(size int) []byte {
	if size <= 0 {
		return nil
	}

	var bufPtr *[]byte

	switch {
	case size <= smallBufferSize:
		bufPtr = p.small.Get().(*[]byte)
	case size <= mediumBufferSize:
		bufPtr = p.medium.Get().(*[]byte)
	case size <= largeBufferSize:
		bufPtr = p.large.Get().(*[]byte)
	case size <= xlargeBufferSize:
		bufPtr = p.xlarge.Get().(*[]byte)
	default:
		// Too large for pool, allocate directly
		buf := make([]byte, size)
		return buf
	}

	// Return slice with requested length
	return (*bufPtr)[:size]
}

// Put returns a buffer to the pool.
// The buffer must have been obtained from Get() on this pool.
// After calling Put, the buffer must not be used.
func (p *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	// Get the underlying array capacity to determine which pool
	cap := cap(buf)
	if cap == 0 {
		return
	}

	// Extend to full capacity for pool storage
	buf = buf[:cap]
	bufPtr := &buf

	switch {
	case cap == smallBufferSize:
		p.small.Put(bufPtr)
	case cap == mediumBufferSize:
		p.medium.Put(bufPtr)
	case cap == largeBufferSize:
		p.large.Put(bufPtr)
	case cap == xlargeBufferSize:
		p.xlarge.Put(bufPtr)
	// Non-standard sizes are not returned to pool (they were allocated directly)
	}
}

// GetGlobal returns a buffer from the global pool.
func GetGlobal(size int) []byte {
	return globalBufferPool.Get(size)
}

// PutGlobal returns a buffer to the global pool.
func PutGlobal(buf []byte) {
	globalBufferPool.Put(buf)
}

// PooledBuffer wraps a buffer with automatic pool return.
// Use this for scoped buffer usage with defer.
type PooledBuffer struct {
	buf  []byte
	pool *BufferPool
}

// GetPooled returns a PooledBuffer that will be automatically returned to the pool.
// Usage:
//
//	pb := pool.GetPooled(1024)
//	defer pb.Release()
//	// use pb.Bytes()
func (p *BufferPool) GetPooled(size int) *PooledBuffer {
	return &PooledBuffer{
		buf:  p.Get(size),
		pool: p,
	}
}

// Bytes returns the underlying buffer.
func (pb *PooledBuffer) Bytes() []byte {
	return pb.buf
}

// Release returns the buffer to the pool.
// After calling Release, the PooledBuffer must not be used.
func (pb *PooledBuffer) Release() {
	if pb.pool != nil && pb.buf != nil {
		pb.pool.Put(pb.buf)
		pb.buf = nil
	}
}

// BufferPoolStats contains statistics about buffer pool usage.
type BufferPoolStats struct {
	SmallGets  int64
	MediumGets int64
	LargeGets  int64
	XLargeGets int64
	DirectAllocs int64
}
