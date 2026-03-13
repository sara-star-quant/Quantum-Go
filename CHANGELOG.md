# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

### Planned: v0.0.10 - Security Hardening Phase 2
- Rekey secret chaining (use existing DeriveRekeySecret)
- Handshake timeout on server Accept
- Module integrity verification (fix always-true check)
- Error message sanitization (generic alerts to remote peers)
- CI security improvements (FIPS testing, Gosec enforcement)

## [0.0.9][] - 2026-03-13

### Security
- **Session Resumption Forward Secrecy**: Resumed sessions now perform a fresh CH-KEM exchange and mix the PSK (ticket secret) with the fresh KEM shared secret via `DeriveResumptionSecret`, following the TLS 1.3 PSK+ECDHE model. Prevents nonce reuse and ensures forward secrecy for resumed sessions.
- **Verify Data Shared Secret Binding**: `ClientFinished`/`ServerFinished` verify_data now incorporates the shared secret via `DeriveKeyMultiple`, providing independent proof that both sides hold the same key material. Previously derived from transcript (public data) only.
- **Rekey Message Authentication**: Rekey payloads are now sealed with the session's AEAD cipher before transmission, providing confidentiality and MITM resistance alongside replay protection inherited from the session nonce management.
- **Key Material Zeroization**: `Zeroize()` now uses `runtime.KeepAlive` to prevent dead store elimination by the compiler. `ConstantTimeCompare` replaced with `crypto/subtle.ConstantTimeCompare`. Fixed aliased slice zeroization in `deriveHandshakeKeys`, `InitializeKeys`, and `Rekey`.
- **Iterative Message Handling**: `Receive()` replaced recursive dispatch with an iterative loop, preventing stack overflow DoS from unbounded control messages (e.g., 10,000+ consecutive Pings).
- **Rekey Forward Secrecy**: Rekey now ratchets secrets via `DeriveRekeySecret(oldMaster, freshKEM)` instead of using the raw KEM output. Compromise of a single rekey exchange no longer exposes all subsequent traffic.
- **KDF Error Handling**: `TranscriptHash` no longer panics on overflow -- returns errors instead. Prevents DoS via malformed peer data crashing the tunnel process.
- **Alert Sanitization**: Handshake alerts no longer send `err.Error()` to remote peers. All 8 alert locations now send generic "handshake failed" description. IP addresses in rate limit logs are masked (`192***100`). Crypto material removed from test log output.
- **Dependency Upgrades**: `golang.org/x/crypto` v0.47.0 -> v0.49.0 (SSH CVE fixes), `go.opentelemetry.io/otel` v1.39.0 -> v1.42.0, `golang.org/x/sys` v0.40.0 -> v0.42.0, `cloudflare/circl` v1.6.2 -> v1.6.3

### Changed
- **Go version**: Bumped minimum to Go 1.26 for `runtime/secret` secure erasure, ~18% faster ML-KEM, Green Tea GC (10-40% less GC overhead), and improved FIPS 140-3 module support
- **Wire format**: Rekey messages now use `[Type(1B)] [Len(4B)] [Seq(8B)] [AEAD-Ciphertext]` format instead of plaintext payload
- **Session resumption**: Server always performs KEM encapsulation (no more all-zeros ciphertext path)
- **`Resume()` no longer calls `InitializeKeys()`** - returns PSK only, keys are derived after fresh KEM exchange

### Fixed
- **Lint**: Use `fmt.Fprintf` instead of `WriteString(Sprintf)` in `pkg/metrics/logger.go` (staticcheck QF1012)

### Documentation
- **Legal**: Add "No Legal Advice" and "User Responsibility" sections to README
- **Roadmap**: Add v0.0.9 and v0.0.10 security hardening milestones based on internal protocol audit
- Updated ARCHITECTURE.md, SECURITY.md, and README.md to reflect v0.0.9 protocol changes and Go 1.26 performance numbers

## [0.0.8][] - 2026-01-22

### Added
- **Regulatory Documentation** (`docs/ROADMAP.md`)
  - EU Dual-Use Regulation open source exemption status documented
  - Project origin (Spain/EU) and applicable regulations clarified
  - User deployment guidance for 15+ jurisdictions
  - Clear distinction between developer obligations and user responsibilities

### Changed
- **Regulatory Section**: Reframed from developer action items to user deployment guidance
- **US/BIS Guidance**: Reframed as user deployment consideration (not developer obligation)
- **All "Action:" items**: Changed to "User Action:" to clarify responsibility lies with deployers
- **Restricted Zones**: Broadened language from region-specific to "highly regulated zones"

### Documentation
- Updated README.md with v0.0.8 status and FIPS features
- Condensed compliance section with clearer liability terms

## [0.0.7][] - 2026-01-22

### Added
- **FIPS 140-3 Compliance** (`pkg/crypto/`)
  - FIPS build mode via `//go:build fips` conditional compilation
  - Runtime FIPS mode detection with `crypto.FIPSMode()`
  - ChaCha20-Poly1305 disabled in FIPS mode (AES-256-GCM only)
  - FIPS mode indicator in session statistics and transport
  - Comprehensive FIPS deployment documentation (`docs/FIPS.md`)

- **Power-On Self-Tests (POST)** (`pkg/crypto/post.go`)
  - Known Answer Tests (KAT) for SHAKE-256, AES-256-GCM, ML-KEM-1024
  - Automatic execution on package initialization
  - Module integrity check mechanism
  - FIPS mode: failures cause panic; Standard mode: failures logged
  - `POSTRan()`, `POSTPassed()`, `RunPOST()`, `CheckModuleIntegrity()` API

- **Conditional Self-Tests (CST)** (`pkg/crypto/cst.go`)
  - Pairwise consistency tests for X25519 and ML-KEM key generation
  - DRBG/RNG continuous health check
  - Configurable via `CSTConfig` struct
  - `GenerateX25519KeyPairWithCST()`, `GenerateMLKEMKeyPairWithCST()`
  - `SecureRandomWithCST()` with continuous RNG test
  - FIPS mode: enabled by default with panic on failure
  - Standard mode: disabled by default with error return on failure

- **FIPS Cipher Suite Validation** (`pkg/protocol/`, `pkg/tunnel/`)
  - `CipherSuite.IsFIPSApproved()` method
  - `Session.IsFIPSCompliant()` for compliance verification
  - Session ticket rejection for non-FIPS cipher suites in FIPS mode
  - `ErrCipherSuiteNotFIPSApproved` error type

### Changed
- **Cipher negotiation**: In FIPS mode, only AES-256-GCM is offered/accepted
- **Session stats**: Added `FIPSMode` and `CipherSuite` fields to `Stats` struct

### Security
- FIPS 140-3 compliant self-test implementation
- Cryptographic algorithm validation at module load time
- Continuous RNG health monitoring prevents use of degraded randomness
- Pairwise consistency tests catch key generation failures before use

## [0.0.6][] - 2026-01-22

### Added
- **Connection Pooling** (`pkg/tunnel/pool*.go`)
  - Reusable `*Tunnel` connection pool reducing handshake overhead
  - Configurable pool size (MinConns, MaxConns)
  - Idle connection timeout and max lifetime
  - Background health checking with configurable interval
  - Wait timeout for exhausted pools
  - LIFO ordering for better cache locality
  - Comprehensive statistics (gauges, counters, histograms)
  - `PoolObserver` interface for metrics integration
  - Thread-safe with proper locking and atomic operations

- **Buffer Pooling** (`pkg/crypto/buffer_pool.go`, `pkg/protocol/buffer_pool.go`)
  - `sync.Pool`-based buffer reuse for message encoding/decoding
  - Size-class pooling (256B, 4KB, 64KB, 2MB for protocol; optimized for crypto)
  - Security zeroing of crypto buffers before returning to pool
  - `SealPooled()` method for zero-allocation encryption
  - 75%+ reduction in allocations for typical workloads
  - Parallel-safe with minimal contention

- **Rate Limiting & DoS Protection** (`pkg/tunnel/limiter.go`)
  - Per-IP connection rate limiting
  - Global handshake rate limiting with token bucket
  - Configurable via `TransportConfig.RateLimit`
  - Metrics for rate limit events

- **Metrics & Observability** (`pkg/metrics/`)
  - Prometheus-compatible metrics export
  - OpenTelemetry tracing support
  - Structured logging with levels
  - Health check endpoint
  - Pool metrics observer (`PoolMetricsObserver`)

### Changed
- **Performance**: Buffer pooling reduces GC pressure by 75%+ in high-throughput scenarios
- **Pool errors**: Added `ErrPoolClosed`, `ErrPoolTimeout`, `ErrPoolExhausted` to `internal/errors`

### Fixed
- **Integer overflow**: Fixed potential int64→uint64 overflow in pool statistics

### Performance
Benchmark results (Apple Silicon M1 Pro, Go 1.26):

| Operation | Non-Pooled | Pooled | Improvement |
|-----------|------------|--------|-------------|
| Seal 1KB | 384 ns, 1168 B/op | 322 ns, 48 B/op | 16% faster, 96% less alloc |
| Seal 16KB | 4505 ns, 18448 B/op | 3310 ns, 48 B/op | 26% faster, 99% less alloc |
| Encode 1KB | 192 ns, 1152 B/op | 43 ns, 24 B/op | 78% faster, 98% less alloc |
| Buffer 1MB | 43200 ns | 27 ns | 1600x faster |

## [0.0.5][] - 2026-01-21

### Added
- **Global Compliance**: Comprehensive regulatory documentation for 15+ jurisdictions (docs/ROADMAP.md) and strict liability guidelines.
- **Protocol Hardening**: Added `pkg/version` for semantic versioning and build metadata.
- **Test Coverage**: New error-path test suite (`coverage_test.go`), pushing core package coverage >90%.
- **Documentation**: Refactored `README.md` into modular usage guides (`docs/usage/`).

### Fixed
- **Security**: Fixed potential panic in benchmark tool (G602 bounds check).
- **Code Quality**: Resolved all `errcheck` lint errors in integration tests.
- **Stability**: Improved connection tear-down stability in transport layer.


## [0.0.4][] - 2026-01-20

### Added
- **Expanded test coverage** across core packages
  - pkg/crypto: 66.9% -> 86.4% (+19.5%)
  - pkg/protocol: 89.8% -> 96.0% (+6.2%)
  - pkg/tunnel: 73.2% -> 75.0% (+1.8%)
- **New crypto tests**: AEAD methods (SetCounter, NeedsRekey, Suite, Overhead, NonceSize, SealWithNonce/OpenWithNonce), ML-KEM (NewMLKEMKeyPairFromSeed, ParseMLKEMPublicKey, Zeroize), X25519 (NewX25519KeyPairFromBytes, Zeroize), random utilities (MustSecureRandom, MustSecureRandomBytes)
- **New protocol tests**: Version serialization (Bytes, Uint16, ParseVersion, String), cipher suite helpers (SupportedCipherSuites, PreferredCipherSuite), Finished message validation (ClientFinished, ServerFinished)
- **New tunnel tests**: SessionState.String(), role constants, session state edge cases (encrypt/decrypt before established, invalid cipher suite)
- **CodeQL Advanced Security Analysis** for deep semantic code analysis

### Fixed
- **Data race in Session**: Fixed concurrent access to `LastActivity` field in Encrypt/Decrypt methods by adding proper mutex synchronization
- **CI compatibility**: Fixed test runner for cross-platform execution
- **Code quality**: Resolved all static analysis warnings in test files

## [0.0.3][] - 2026-01-19

### Added
- **Command-line tool** (`quantum-vpn`) with demo, benchmark, and example modes
  - Demo mode: Interactive client/server demonstration
  - Benchmark mode: Handshake and throughput performance testing
  - Example mode: 6 interactive code examples with explanations
- **Build automation**
  - Makefile with 30+ commands for building, testing, and releasing
  - `build.sh` portable shell script as alternative to Make
  - Cross-platform compilation (Linux, macOS, Windows; amd64, arm64)
  - Docker support with multi-stage builds
  - Automated release packaging with checksums
- **CI/CD workflows**
  - GitHub Actions for continuous integration (Linux, macOS, Windows)
  - Automated releases on version tags
  - Security scanning with Gosec
  - Code coverage reporting to Codecov
  - Docker image publishing
- **Comprehensive test suite**
  - Increased coverage from 70.7% to 76.3%
  - 14 new high-level API tests (Dial/Listen/Accept)
  - 10 new transport error path tests
  - 10 new error package tests
  - 3 new constants validation tests
- **Documentation**
  - SECURITY.md: Security policy, threat model, disclosure process
  - CONTRIBUTING.md: Development setup and contribution guidelines
  - BUILD.md: Comprehensive build instructions
  - CHANGELOG.md: Version history tracking
  - Updated README with command-line tool documentation

### Changed
- **Go version requirement**: Updated to Go 1.24 for security and performance
  - Benefits from Go 1.24's native ML-KEM support
  - FIPS 140-3 module support
  - Faster crypto/rand.Read with getrandom VDSO
  - Fixed multiple crypto/x509 CVEs
- **Module path**: Corrected to `github.com/pzverkov/quantum-go`
- **All imports**: Updated across 21 files for correct module path

### Fixed
- Protocol codec panic on malformed input (missing payload length validation)
- Alert description truncation overflow (256 → 255 bytes)
- Critical handshake deadlock (missing encrypted record framing)
- Transport.Close() blocking with net.Pipe() (added timeout)
- Division by zero in benchmark with small iteration counts

### Security
- All tests pass with race detection enabled
- Fuzz tests added for security-critical parsers
- Known Answer Tests (KATs) for cryptographic correctness
- Security audit recommendations in SECURITY.md

## [0.0.2][] - 2026-01-19

### Added
- Initial public release
- ML-KEM-1024 + X25519 hybrid KEM implementation
- AES-256-GCM and ChaCha20-Poly1305 cipher suites
- 4-message handshake protocol
- Replay protection with sliding window
- Automatic session rekeying
- LICENSE (MIT)
- doc.go for pkg.go.dev

### Security
- NIST Category 5 security level
- Forward secrecy with ephemeral keys
- Hybrid guarantee (secure if either algorithm is secure)

## [0.0.1][] - 2026-01-18

### Added
- Initial development version
- Core CH-KEM implementation
- Basic tunnel API
- Unit tests for crypto primitives

[Unreleased]: https://github.com/pzverkov/quantum-go/compare/v0.0.9...HEAD
[0.0.9]: https://github.com/pzverkov/quantum-go/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/pzverkov/quantum-go/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/pzverkov/quantum-go/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/pzverkov/quantum-go/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/pzverkov/quantum-go/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/pzverkov/quantum-go/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/pzverkov/quantum-go/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/pzverkov/quantum-go/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/pzverkov/quantum-go/releases/tag/v0.0.1
