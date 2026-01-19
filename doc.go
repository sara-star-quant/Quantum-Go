// Package quantumgo provides quantum-resistant VPN encryption using Cascaded Hybrid KEM (CH-KEM).
//
// Quantum-Go combines ML-KEM-1024 (NIST FIPS 203) post-quantum cryptography with
// X25519 classical cryptography for defense-in-depth security against both
// classical and quantum attacks.
//
// # Quick Start
//
// For a complete VPN tunnel with handshake:
//
//	import "github.com/pzverkov/quantum-go/pkg/tunnel"
//
//	// Server
//	listener, _ := tunnel.Listen("tcp", ":8443")
//	conn, _ := listener.Accept()
//	data, _ := conn.Receive()
//
//	// Client
//	client, _ := tunnel.Dial("tcp", "localhost:8443")
//	client.Send([]byte("Hello!"))
//
// For low-level CH-KEM key encapsulation:
//
//	import "github.com/pzverkov/quantum-go/pkg/chkem"
//
//	keyPair, _ := chkem.GenerateKeyPair()
//	ciphertext, sharedSecret, _ := chkem.Encapsulate(keyPair.PublicKey())
//	recoveredSecret, _ := chkem.Decapsulate(ciphertext, keyPair)
//
// # Package Structure
//
// The library is organized into several packages:
//
//   - pkg/chkem: High-level CH-KEM key encapsulation API
//   - pkg/crypto: Low-level cryptographic primitives (ML-KEM, X25519, KDF, AEAD)
//   - pkg/tunnel: VPN tunnel with handshake protocol and encrypted transport
//   - pkg/protocol: Wire protocol message definitions and encoding
//   - internal/constants: Security parameters and protocol constants
//   - internal/errors: Custom error types for detailed error handling
//
// # Security Properties
//
// The CH-KEM construction provides:
//
//   - Post-quantum security: ML-KEM-1024 (NIST Category 5, ~256-bit security)
//   - Classical security: X25519 ECDH (128-bit security)
//   - Hybrid guarantee: Secure if EITHER algorithm is secure
//   - Forward secrecy: Ephemeral keys generated for each session
//   - Authenticated encryption: AES-256-GCM or ChaCha20-Poly1305
//   - Replay protection: Sliding window with sequence numbers
//
// # Testing
//
// The library includes comprehensive tests:
//
//	go test ./...                                    # All tests
//	go test -fuzz=FuzzParsePublicKey ./test/fuzz/  # Fuzz tests
//	go test -run TestKAT ./pkg/crypto              # Known Answer Tests
//	go test -bench=. ./test/benchmark              # Benchmarks
//
// # Performance
//
// Typical performance on modern hardware (AMD64):
//
//   - CH-KEM key generation: ~800 µs
//   - CH-KEM encapsulation: ~900 µs
//   - CH-KEM decapsulation: ~1000 µs
//   - AES-256-GCM encryption: ~2 GB/s (hardware-accelerated)
//   - ChaCha20-Poly1305: ~800 MB/s (software)
//
// # References
//
//   - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//   - RFC 7748: Elliptic Curves for Security
//   - NIST FIPS 202: SHA-3 Standard (SHAKE-256)
//
// For more information, see: https://github.com/pzverkov/quantum-go
package quantumgo
