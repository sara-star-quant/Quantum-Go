# Quantum-Go Technical Architecture

**Version:** 1.0
**Go Version:** 1.24+

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Package Structure](#2-package-structure)
3. [Core Components](#3-core-components)
4. [Protocol Design](#4-protocol-design)
5. [Key Management](#5-key-management)
6. [Security Architecture](#6-security-architecture)
7. [Performance Considerations](#7-performance-considerations)
8. [API Reference](#8-api-reference)

---

## 1. System Overview

Quantum-Go is a quantum-resistant VPN encryption library implementing the Cascaded Hybrid KEM (CH-KEM) protocol. It provides post-quantum security through ML-KEM-1024 while maintaining classical security guarantees through X25519.

### 1.1 Design Principles

1. **Defense in Depth:** Multiple cryptographic layers ensure security if one is compromised
2. **Minimal Dependencies:** Uses Go standard library where possible
3. **Constant-Time Operations:** Cryptographic operations avoid timing side-channels
4. **Clear Abstractions:** Separate concerns between crypto, protocol, and transport layers

### 1.2 Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.24+ |
| Post-Quantum KEM | ML-KEM-1024 (crypto/mlkem) |
| Classical ECDH | X25519 (crypto/ecdh) |
| KDF | SHAKE-256 (golang.org/x/crypto/sha3) |
| AEAD | AES-256-GCM, ChaCha20-Poly1305 |

---

## 2. Package Structure

```
quantum-go/
├── cmd/
│   └── quantum-vpn/           # CLI application
│       └── main.go
├── pkg/
│   ├── chkem/                 # Cascaded Hybrid KEM
│   │   ├── chkem.go           # Core implementation
│   │   └── chkem_test.go      # Unit tests
│   ├── tunnel/                # VPN tunnel
│   │   ├── session.go         # Session management
│   │   ├── handshake.go       # Key exchange protocol
│   │   ├── transport.go       # Encrypted transport
│   │   └── tunnel_test.go     # Tests
│   ├── crypto/                # Cryptographic primitives
│   │   ├── mlkem.go           # ML-KEM-1024 wrapper
│   │   ├── x25519.go          # X25519 ECDH
│   │   ├── kdf.go             # Key derivation
│   │   ├── aead.go            # Authenticated encryption
│   │   ├── random.go          # Secure random
│   │   └── crypto_test.go     # Tests
│   └── protocol/              # Wire protocol
│       ├── version.go         # Protocol versioning
│       ├── messages.go        # Message types
│       └── codec.go           # Serialization
├── internal/
│   ├── constants/             # Security parameters
│   │   └── constants.go
│   └── errors/                # Custom errors
│       └── errors.go
├── docs/                      # Documentation
├── test/                      # Integration & benchmarks
└── go.mod
```

---

## 3. Core Components

### 3.1 CH-KEM (pkg/chkem)

The Cascaded Hybrid KEM combines X25519 and ML-KEM-1024.

```go
// Generate a new key pair
kp, err := chkem.GenerateKeyPair()

// Encapsulate (sender side)
ciphertext, sharedSecret, err := chkem.Encapsulate(recipientPublicKey)

// Decapsulate (recipient side)
sharedSecret, err := chkem.Decapsulate(ciphertext, keyPair)
```

**Data Flow:**

```
Encapsulation:
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Recipient's Public Key ──┬──> X25519 DH ──> K_x           │
│                           │                                 │
│  Ephemeral X25519 Key ────┘                                │
│                                                             │
│  Recipient's ML-KEM Key ──────> ML-KEM Encaps ──> K_m      │
│                                                             │
│  Transcript = H(pk || ct)                                  │
│                                                             │
│  K_final = SHAKE-256(K_x || K_m || transcript)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Tunnel (pkg/tunnel)

The tunnel package provides secure communication channels.

**Session States:**

```
SessionStateNew ─────> SessionStateHandshaking ─────> SessionStateEstablished
        │                       │                              │
        │                       │                              ├───> SessionStateRekeying
        │                       │                              │         │
        │                       ▼                              │         │
        └─────────────> SessionStateClosed <───────────────────┴─────────┘
```

**Components:**

| Component | Responsibility |
|-----------|----------------|
| Session | State, encryption keys, statistics |
| Handshake | CH-KEM key exchange state machine |
| Transport | Encrypted message send/receive |

### 3.3 Crypto Primitives (pkg/crypto)

Low-level cryptographic operations wrapped with consistent error handling.

| Function | Description |
|----------|-------------|
| `GenerateMLKEMKeyPair()` | Generate ML-KEM-1024 key pair |
| `MLKEMEncapsulate()` | Encapsulate shared secret |
| `MLKEMDecapsulate()` | Decapsulate shared secret |
| `GenerateX25519KeyPair()` | Generate X25519 key pair |
| `X25519()` | Compute ECDH shared secret |
| `DeriveKey()` | SHAKE-256 key derivation |
| `NewAEAD()` | Create AEAD cipher |

---

## 4. Protocol Design

### 4.1 Handshake Protocol

```
Initiator                              Responder
    │                                      │
    │───────── ClientHello ───────────────>│
    │  • Protocol version                  │
    │  • Random (32B)                      │
    │  • CH-KEM public key (1600B)         │
    │  • Cipher suites                     │
    │                                      │
    │<──────── ServerHello ────────────────│
    │  • Protocol version                  │
    │  • Random (32B)                      │
    │  • Session ID (16B)                  │
    │  • CH-KEM ciphertext (1600B)         │
    │  • Selected cipher suite             │
    │                                      │
    │  [Both derive shared secret K]       │
    │                                      │
    │───────── ClientFinished ────────────>│
    │  • Encrypted(verify_data)            │
    │                                      │
    │<──────── ServerFinished ─────────────│
    │  • Encrypted(verify_data)            │
    │                                      │
    │═══════ Tunnel Established ═══════════│
```

### 4.2 Wire Format

All messages follow this structure:

```
┌──────────┬──────────────┬───────────────────┐
│ Type     │ Length       │ Payload           │
│ (1 byte) │ (4 bytes BE) │ (variable)        │
└──────────┴──────────────┴───────────────────┘
```

**Message Types:**

| Type | Value | Description |
|------|-------|-------------|
| ClientHello | 0x01 | Initiate handshake |
| ServerHello | 0x02 | Respond to handshake |
| ClientFinished | 0x03 | Client confirmation |
| ServerFinished | 0x04 | Server confirmation |
| Data | 0x10 | Encrypted payload |
| Rekey | 0x11 | Key rotation |
| Ping | 0x12 | Keepalive request |
| Pong | 0x13 | Keepalive response |
| Close | 0x14 | Graceful close |
| Alert | 0xF0 | Error condition |

### 4.3 Key Derivation

```
Master Secret (32B)
        │
        ├──> SHAKE-256("CH-KEM-VPN-Handshake") ──> Handshake Keys
        │
        ├──> SHAKE-256("CH-KEM-VPN-Traffic") ──> Traffic Keys
        │
        └──> SHAKE-256("CH-KEM-VPN-Rekey") ──> Rekey Secrets
```

---

## 5. Key Management

### 5.1 Key Hierarchy

```
CH-KEM Key Pair (Long-term)
        │
        └──> Session Master Secret (per session)
                    │
                    ├──> Initiator Write Key (32B)
                    ├──> Responder Write Key (32B)
                    ├──> Initiator Write IV (12B)
                    └──> Responder Write IV (12B)
```

### 5.2 Key Rotation

Sessions automatically rekey when:
1. Nonce counter approaches 2^28 (90% of 2^28)
2. Bytes transmitted exceed 1 GB
3. Session duration exceeds 1 hour

### 5.3 Key Zeroization

All sensitive key material is zeroized when:
- Session closes
- Keys are rotated
- Handshake completes (intermediate keys)

```go
// Example zeroization
func (s *Session) Close() {
    crypto.Zeroize(s.masterSecret)
    s.LocalKeyPair.Zeroize()
}
```

---

## 6. Security Architecture

### 6.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Quantum computer | ML-KEM-1024 post-quantum security |
| Classical cryptanalysis | X25519 hybrid approach |
| Harvest-now-decrypt-later | Immediate quantum resistance |
| Man-in-the-middle | Transcript binding, authentication |
| Replay attacks | Sequence numbers, sliding window |
| Side-channel attacks | Constant-time crypto, Go std lib |
| Nonce reuse | Counter-based nonces, rekey triggers |

### 6.2 Replay Protection

```
┌─────────────────────────────────────────────────────┐
│ Replay Window (64 packets)                         │
│                                                     │
│ HighSeq: 150                                       │
│ Window:  [87-150]                                  │
│ Bitmap:  0b11111111...1111 (packets 87-150 seen)  │
│                                                     │
│ Seq 85:  REJECT (too old)                         │
│ Seq 120: REJECT (already seen)                    │
│ Seq 151: ACCEPT (new highest)                     │
│ Seq 145: ACCEPT (in window, not seen)             │
└─────────────────────────────────────────────────────┘
```

### 6.3 Error Handling

Errors are designed to prevent information leakage:

- Decryption failures return generic `ErrAuthenticationFailed`
- Invalid ciphertexts trigger implicit rejection in ML-KEM
- Timing is constant regardless of error type

---

## 7. Performance Considerations

### 7.1 Benchmark Results (Typical)

| Operation | Time | Throughput |
|-----------|------|------------|
| CH-KEM KeyGen | ~0.1ms | 10,000 ops/s |
| CH-KEM Encapsulate | ~0.12ms | 8,000 ops/s |
| CH-KEM Decapsulate | ~0.11ms | 9,000 ops/s |
| AES-256-GCM Encrypt (1400B) | ~460ns | 3.0 GB/s |
| Full Handshake | ~0.5ms | 1,800 handshakes/s |

### 7.2 Memory Usage

| Component | Allocation |
|-----------|------------|
| CH-KEM public key | 1600 bytes |
| CH-KEM ciphertext | 1600 bytes |
| Session state | ~10 KB |
| Per-packet overhead | ~40 bytes |

### 7.3 Optimization Tips

1. **Key Reuse:** Generate CH-KEM keys once, use for multiple sessions
2. **Connection Pooling:** Reuse established sessions when possible
3. **Cipher Suite:** ChaCha20-Poly1305 may be faster without AES-NI
4. **Buffer Reuse:** Use sync.Pool for message buffers

---

## 8. API Reference

### 8.1 Quick Start

```go
package main

import (
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // Server
    listener, _ := tunnel.Listen("tcp", ":8443")
    defer listener.Close()

    go func() {
        for {
            conn, _ := listener.Accept()
            go handleClient(conn)
        }
    }()

    // Client
    client, _ := tunnel.Dial("tcp", "localhost:8443")
    defer client.Close()

    client.Send([]byte("Hello, quantum-resistant world!"))
}

func handleClient(t *tunnel.Tunnel) {
    defer t.Close()
    for {
        data, err := t.Receive()
        if err != nil {
            return
        }
        // Process data...
    }
}
```

### 8.2 Session Management

```go
// Create session
session, err := tunnel.NewSession(tunnel.RoleInitiator)

// Check state
if session.State() == tunnel.SessionStateEstablished {
    // Ready for data
}

// Get statistics
stats := session.Stats()
fmt.Printf("Sent: %d bytes, Received: %d bytes\n",
    stats.BytesSent, stats.BytesReceived)

// Close session
session.Close()
```

### 8.3 Custom Configuration

```go
config := tunnel.TransportConfig{
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
    // ObserverFactory: func(session *tunnel.Session) tunnel.Observer { ... },
    // RateLimitObserver: metrics.NewRateLimitObserver(collector, metrics.GetLogger()),
}

transport, err := tunnel.NewTransport(session, conn, config)
```

---

*Document Version: 1.1*
*Last Updated: 2026-01-21*
