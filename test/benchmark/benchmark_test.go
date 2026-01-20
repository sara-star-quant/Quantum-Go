// Package benchmark provides performance benchmarks for the Quantum-Go VPN system.
//
// Run benchmarks with:
//
//	go test -bench=. -benchmem ./test/benchmark/
//
// For profiling:
//
//	go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof ./test/benchmark/
package benchmark

import (
	"net"
	"sync"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/chkem"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// --- Cryptographic Primitive Benchmarks ---

func BenchmarkSecureRandom32(b *testing.B) {
	buf := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.SecureRandom(buf)
	}
}

func BenchmarkSecureRandom64(b *testing.B) {
	buf := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.SecureRandom(buf)
	}
}

// --- X25519 Benchmarks ---

func BenchmarkX25519KeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.GenerateX25519KeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519SharedSecret(b *testing.B) {
	alice, _ := crypto.GenerateX25519KeyPair()
	bob, _ := crypto.GenerateX25519KeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.X25519(alice.PrivateKey, bob.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- ML-KEM-1024 Benchmarks ---

func BenchmarkMLKEMKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.GenerateMLKEMKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLKEMEncapsulation(b *testing.B) {
	kp, _ := crypto.GenerateMLKEMKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := crypto.MLKEMEncapsulate(kp.EncapsulationKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLKEMDecapsulation(b *testing.B) {
	kp, _ := crypto.GenerateMLKEMKeyPair()
	ciphertext, _, _ := crypto.MLKEMEncapsulate(kp.EncapsulationKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.MLKEMDecapsulate(kp.DecapsulationKey, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- CH-KEM Benchmarks ---

func BenchmarkCHKEMKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := chkem.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCHKEMEncapsulation(b *testing.B) {
	kp, _ := chkem.GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := chkem.Encapsulate(kp.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCHKEMDecapsulation(b *testing.B) {
	kp, _ := chkem.GenerateKeyPair()
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := chkem.Decapsulate(ct, kp)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCHKEMFullKeyExchange(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate recipient key pair
		recipientKP, _ := chkem.GenerateKeyPair()

		// Encapsulate
		ct, _, _ := chkem.Encapsulate(recipientKP.PublicKey())

		// Decapsulate
		_, _ = chkem.Decapsulate(ct, recipientKP)
	}
}

// --- KDF Benchmarks ---

func BenchmarkDeriveKey32(b *testing.B) {
	input := make([]byte, 64)
	crypto.SecureRandom(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DeriveKey("benchmark-domain", input, 32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKeyMultiple(b *testing.B) {
	inputs := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
	}
	for _, input := range inputs {
		crypto.SecureRandom(input)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DeriveKeyMultiple("benchmark-domain", inputs, 32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTranscriptHash(b *testing.B) {
	components := [][]byte{
		make([]byte, 32),
		make([]byte, 1568),
		make([]byte, 32),
		make([]byte, 1568),
	}
	for _, c := range components {
		crypto.SecureRandom(c)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.TranscriptHash(components...)
	}
}

// --- AEAD Benchmarks ---

func BenchmarkAES256GCMEncrypt(b *testing.B) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	plaintext := make([]byte, 1400) // Typical MTU payload

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, err := aead.Seal(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAES256GCMDecrypt(b *testing.B) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	plaintext := make([]byte, 1400)
	ciphertext, _ := aead.Seal(plaintext, nil)

	// Create new AEAD for decryption (reset counter)
	aead2, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, err := aead2.Open(ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Poly1305Encrypt(b *testing.B) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)
	plaintext := make([]byte, 1400)

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, err := aead.Seal(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Poly1305Decrypt(b *testing.B) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)
	plaintext := make([]byte, 1400)
	ciphertext, _ := aead.Seal(plaintext, nil)

	aead2, _ := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, err := aead2.Open(ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- Payload Size Benchmarks ---

func BenchmarkAES256GCMEncrypt64B(b *testing.B) {
	benchmarkAEADEncrypt(b, constants.CipherSuiteAES256GCM, 64)
}

func BenchmarkAES256GCMEncrypt1KB(b *testing.B) {
	benchmarkAEADEncrypt(b, constants.CipherSuiteAES256GCM, 1024)
}

func BenchmarkAES256GCMEncrypt8KB(b *testing.B) {
	benchmarkAEADEncrypt(b, constants.CipherSuiteAES256GCM, 8192)
}

func BenchmarkAES256GCMEncrypt64KB(b *testing.B) {
	benchmarkAEADEncrypt(b, constants.CipherSuiteAES256GCM, 65536)
}

func benchmarkAEADEncrypt(b *testing.B, suite constants.CipherSuite, size int) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(suite, key)
	plaintext := make([]byte, size)

	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		_, err := aead.Seal(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- Session Benchmarks ---

func BenchmarkSessionEncrypt(b *testing.B) {
	session, _ := tunnel.NewSession(tunnel.RoleInitiator)
	masterSecret := make([]byte, 32)
	crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	plaintext := make([]byte, 1400)

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, _, err := session.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSessionDecrypt(b *testing.B) {
	initiator, _ := tunnel.NewSession(tunnel.RoleInitiator)
	responder, _ := tunnel.NewSession(tunnel.RoleResponder)

	masterSecret := make([]byte, 32)
	_ = crypto.SecureRandom(masterSecret)
	_ = initiator.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	_ = responder.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	plaintext := make([]byte, 1400)
	ciphertexts := make([][]byte, 1000)
	seqs := make([]uint64, 1000)

	for i := 0; i < 1000; i++ {
		ciphertexts[i], seqs[i], _ = initiator.Encrypt(plaintext)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		idx := i % 1000
		_, err := responder.Decrypt(ciphertexts[idx], seqs[idx])
		if err != nil {
			// Replay detection may trigger after first pass
			continue
		}
	}
}

// --- Handshake Benchmarks ---

func BenchmarkHandshake(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientConn, serverConn := net.Pipe()

		initiator, _ := tunnel.NewSession(tunnel.RoleInitiator)
		responder, _ := tunnel.NewSession(tunnel.RoleResponder)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = tunnel.InitiatorHandshake(initiator, clientConn)
		}()

		go func() {
			defer wg.Done()
			_ = tunnel.ResponderHandshake(responder, serverConn)
		}()

		wg.Wait()
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
}

// --- Parallel Benchmarks ---

func BenchmarkCHKEMEncapsulationParallel(b *testing.B) {
	kp, _ := chkem.GenerateKeyPair()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = chkem.Encapsulate(kp.PublicKey())
		}
	})
}

func BenchmarkAES256GCMEncryptParallel(b *testing.B) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	plaintext := make([]byte, 1400)

	b.SetBytes(int64(len(plaintext)))
	b.RunParallel(func(pb *testing.PB) {
		aead, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
		for pb.Next() {
			_, _ = aead.Seal(plaintext, nil)
		}
	})
}

// --- Memory Allocation Benchmarks ---

func BenchmarkCHKEMKeyGenerationAllocs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = chkem.GenerateKeyPair()
	}
}

func BenchmarkCHKEMEncapsulationAllocs(b *testing.B) {
	kp, _ := chkem.GenerateKeyPair()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = chkem.Encapsulate(kp.PublicKey())
	}
}
