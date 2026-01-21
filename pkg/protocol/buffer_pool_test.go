package protocol

import (
	"testing"
)

func TestBufferPool(t *testing.T) {
	pool := NewBufferPool()

	t.Run("GetSmall", func(t *testing.T) {
		buf := pool.Get(100)
		if len(buf) != 100 {
			t.Errorf("buffer length = %d, want 100", len(buf))
		}
		if cap(buf) != smallBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), smallBufferSize)
		}
		pool.Put(buf)
	})

	t.Run("GetMedium", func(t *testing.T) {
		buf := pool.Get(1000)
		if len(buf) != 1000 {
			t.Errorf("buffer length = %d, want 1000", len(buf))
		}
		if cap(buf) != mediumBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), mediumBufferSize)
		}
		pool.Put(buf)
	})

	t.Run("GetLarge", func(t *testing.T) {
		buf := pool.Get(10000)
		if len(buf) != 10000 {
			t.Errorf("buffer length = %d, want 10000", len(buf))
		}
		if cap(buf) != largeBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), largeBufferSize)
		}
		pool.Put(buf)
	})

	t.Run("GetXLarge", func(t *testing.T) {
		buf := pool.Get(100000)
		if len(buf) != 100000 {
			t.Errorf("buffer length = %d, want 100000", len(buf))
		}
		if cap(buf) != xlargeBufferSize {
			t.Errorf("buffer capacity = %d, want %d", cap(buf), xlargeBufferSize)
		}
		pool.Put(buf)
	})

	t.Run("GetOversized", func(t *testing.T) {
		buf := pool.Get(3 * 1024 * 1024) // 3MB
		if len(buf) != 3*1024*1024 {
			t.Errorf("buffer length = %d, want %d", len(buf), 3*1024*1024)
		}
		// Oversized buffers are not pooled
		pool.Put(buf)
	})

	t.Run("GetZero", func(t *testing.T) {
		buf := pool.Get(0)
		if buf != nil {
			t.Errorf("expected nil for size 0, got %v", buf)
		}
	})

	t.Run("GetNegative", func(t *testing.T) {
		buf := pool.Get(-1)
		if buf != nil {
			t.Errorf("expected nil for negative size, got %v", buf)
		}
	})

	t.Run("PutNil", func(t *testing.T) {
		// Should not panic
		pool.Put(nil)
	})

	t.Run("Reuse", func(t *testing.T) {
		// Get and put multiple times
		for i := 0; i < 100; i++ {
			buf := pool.Get(500)
			if len(buf) != 500 {
				t.Errorf("iteration %d: buffer length = %d, want 500", i, len(buf))
			}
			pool.Put(buf)
		}
	})
}

func TestPooledBuffer(t *testing.T) {
	pool := NewBufferPool()

	t.Run("BasicUsage", func(t *testing.T) {
		pb := pool.GetPooled(1024)
		if pb == nil {
			t.Fatal("GetPooled returned nil")
		}

		buf := pb.Bytes()
		if len(buf) != 1024 {
			t.Errorf("buffer length = %d, want 1024", len(buf))
		}

		// Write some data
		for i := range buf {
			buf[i] = byte(i)
		}

		pb.Release()

		// After release, Bytes() should return nil
		if pb.Bytes() != nil {
			t.Error("Bytes() should return nil after Release()")
		}
	})

	t.Run("DoubleRelease", func(t *testing.T) {
		pb := pool.GetPooled(100)
		pb.Release()
		// Should not panic
		pb.Release()
	})
}

func TestGlobalPool(t *testing.T) {
	buf := GetGlobal(1024)
	if len(buf) != 1024 {
		t.Errorf("buffer length = %d, want 1024", len(buf))
	}
	PutGlobal(buf)
}

// Benchmarks comparing pooled vs direct allocation.

func BenchmarkBufferPool_GetPut_256(b *testing.B) {
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(256)
		pool.Put(buf)
	}
}

func BenchmarkMake_256(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 256)
		_ = buf
	}
}

func BenchmarkBufferPool_GetPut_4KB(b *testing.B) {
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(4 * 1024)
		pool.Put(buf)
	}
}

func BenchmarkMake_4KB(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 4*1024)
		_ = buf
	}
}

func BenchmarkBufferPool_GetPut_64KB(b *testing.B) {
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(64 * 1024)
		pool.Put(buf)
	}
}

func BenchmarkMake_64KB(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 64*1024)
		_ = buf
	}
}

func BenchmarkBufferPool_GetPut_1MB(b *testing.B) {
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(1024 * 1024)
		pool.Put(buf)
	}
}

func BenchmarkMake_1MB(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 1024*1024)
		_ = buf
	}
}

// Benchmark simulating message encoding with pooled buffers.

func BenchmarkEncodeData_NonPooled(b *testing.B) {
	codec := NewCodec()
	payload := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, err := codec.EncodeData(uint64(i), payload)
		if err != nil {
			b.Fatal(err)
		}
		_ = msg
	}
}

func BenchmarkEncodeData_Pooled(b *testing.B) {
	_ = NewCodec() // Not used directly, simulating the allocation pattern
	payload := make([]byte, 1024)
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate pooled encoding
		size := HeaderSize + 8 + len(payload)
		buf := pool.Get(size)

		buf[0] = byte(MessageTypeData)
		buf[1] = byte(size >> 24)
		buf[2] = byte(size >> 16)
		buf[3] = byte(size >> 8)
		buf[4] = byte(size)
		buf[5] = byte(uint64(i) >> 56)
		buf[6] = byte(uint64(i) >> 48)
		buf[7] = byte(uint64(i) >> 40)
		buf[8] = byte(uint64(i) >> 32)
		buf[9] = byte(uint64(i) >> 24)
		buf[10] = byte(uint64(i) >> 16)
		buf[11] = byte(uint64(i) >> 8)
		buf[12] = byte(uint64(i))
		copy(buf[HeaderSize+8:], payload)

		pool.Put(buf)
	}
}

// Parallel benchmark to test pool contention.

func BenchmarkBufferPool_Parallel(b *testing.B) {
	pool := NewBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get(4 * 1024)
			pool.Put(buf)
		}
	})
}

func BenchmarkMake_Parallel(b *testing.B) {
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := make([]byte, 4*1024)
			_ = buf
		}
	})
}
