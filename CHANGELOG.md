# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

### Added
- **Static-key endpoint authentication (stream/TCP path, opt-in)**: the server can hold a long-term CH-KEM static key (`TransportConfig.StaticKeyPair`, generated and persisted via `chkem.GenerateStaticKeyPair`/`ParseKeyPair` as a 96-byte seed) and the client can pin its public key (`TransportConfig.PinnedServerKey`). The client adds a second CH-KEM leg, encapsulating to the pinned key in a new optional `ClientHello` field and folding the result into the master secret, so only the holder of the static private key derives matching handshake keys; a wrong, absent, or stripped key fails closed with `ErrServerKeyMismatch`. This stops an active relaying MitM for the pinned-server case (stronger than role binding alone) while preserving forward secrecy (the ephemeral leg stays a mandatory input). The wire alert stays generic (no pin-probe oracle). The wire field is additive and presence-flagged; the protocol version is bumped to `2.1` (major-compatible, so 2.0 and 2.1 peers still interoperate unauthenticated). Unconfigured, behavior is unchanged.
- **Static-key endpoint authentication (datagram/UDP path)**: the same authentication now works over the datagram transport via `WithStaticIdentity(kp)` (responder) and `WithPinnedServerKey(pub)` (initiator) endpoint options. The datagram handshake reuses the stream handshake builders, so the static-key fold, transcript binding, no-oracle, and forward-secrecy properties are identical; the larger authenticated ClientHello is fragmented and reassembled normally. One difference: a wrong/absent/stripped pin fails closed as a retry-ceiling timeout (the server drops the undecryptable ClientFinished as if lost), so `DialDatagram` returns `ErrServerKeyMismatch` only after the handshake times out, rather than fail-fast.
- **`quantum-tunnel keygen` CLI**: generates a long-term CH-KEM server identity for static-key endpoint authentication. It writes the secret seed to `<prefix>.key` (base64, mode 0600) and the public pin to `<prefix>.pub` (base64), refuses to clobber an existing file without `--force`, and prints an SSH-style `SHA256:` pin fingerprint for out-of-band verification. `--pub-from <keyfile>` re-derives the public pin from an existing secret seed.

### Security
- **Role and protocol-version binding in the CH-KEM transcript**: `Encapsulate`/`Decapsulate` now bind the protocol version and the encapsulating (responder) role into the transcript hash, so a reflected or role-confused handshake derives a non-matching secret and fails closed at the Finished MAC. This is composition hardening, not peer authentication, and does not stop an active relaying MitM (endpoint authentication is tracked separately). The derived secret changed, so this is wire-incompatible with prior builds; `ProtocolVersion` is bumped to `0x0002` and the wire version to `2.0` so a mismatched peer is rejected cleanly rather than failing later at the MAC. `Encapsulate` and `Decapsulate` take a new `chkem.Role` argument (breaking API, pre-1.0). Measured cost is about +1% per KEM operation (a few extra hashed bytes), no allocation change, and no data-plane impact.

### Changed
- **Threat model**: the former `docs/compliance/RISK_ASSESSMENT.md` is reframed as `docs/technical/THREAT_MODEL.md`, an honest self-authored analysis (NIST SP 800-30 methodology), with the governance scaffolding that implied a team or audit process removed.
- **CI security hardening**: gosec now fails CI on findings (dropped `-no-fail`); all current findings are triaged with justified `#nosec` annotations (bounded integer conversions, KAT nonce) and one replay cast rewritten to drop the conversion. Added a FIPS build/test job (`go test -tags fips -race ./...`) and a `go vet` step.

## [0.0.11][] - 2026-06-01

**Theme:** Connectionless UDP/datagram transport (reliable handshake, encrypted data plane, reliable rekey, anti-DoS, Linux receive scaling and offload) and datagram performance, plus two stream-path hardening fixes.

### Added
- **UDP/datagram transport (handshake)**: a connectionless transport alongside the TCP/stream one, demultiplexed by a random per-session connection index rather than source address (survives NAT rebind and roaming). It carries the full CH-KEM handshake over a lossy link: the large post-quantum Hellos are fragmented across datagrams and reassembled (`pkg/tunnel/reassembly.go`), and a transport-agnostic state machine plus reliability driver (`pkg/tunnel/dgram_handshake_{fsm,driver,wire}.go`) add retransmission with exponential backoff, a retry ceiling, duplicate/replay handling, and a responder linger that recovers a lost final flight. A bad or forged datagram drops rather than failing the handshake. The responder runs no decapsulation and sends no ServerHello until a full ClientHello arrives and a per-source half-open slot is granted, so it never sends more than it received from an unvalidated source. `DialDatagram` performs the initiator handshake and returns an established session.
- **Datagram handshake benchmark**: `quantum-tunnel bench --datagram-handshakes N` measures the datagram handshake rate over loopback UDP (~1,300/sec, ~760 us each on an M1 Pro, vs ~1,450/sec for the stream path).
- **UDP/datagram transport (encrypted data path)**: an established datagram session now carries application data. `DatagramConn` (returned by `DialDatagram` and `DatagramEndpoint.Accept`) exposes message-oriented `Send`/`Recv` and an authenticated `Close`. The AEAD nonce is derived (`prefix || seq`) and never transmitted, the per-frame epoch selects the receive cipher (the previous epoch is retained briefly so reordered packets still decrypt), and a wide, never-reset replay window tolerates datagram reordering. The receive path rejects obvious replays before decrypting and only records a sequence after authentication, so replays skip the AEAD work and a spoofed sequence cannot poison the window. A CLOSE is dropped unless its AEAD tag verifies, so an off-path party that learns the connection index cannot tear the session down; idle sessions are reaped on a timer.
- **UDP/datagram transport (rekey)**: long-lived datagram sessions rotate keys with fresh forward secrecy. Because the CH-KEM public key and ciphertext exceed the MTU, the rekey is a small fragmented two-message exchange (`RekeyInit`/`RekeyResponse`) reusing the handshake fragmenter and reassembler, authenticated under the current epoch so an off-path party cannot inject it. The initiator drives the exchange and retransmits with backoff until the response arrives; the responder answers reactively and caches its sealed response, replaying it verbatim on a retransmit rather than re-encapsulating (which would desync the epochs). The initiator starts a rekey in the background before the per-epoch key budget is exhausted; `DatagramConn.Rekey` also triggers one on demand.

### Changed
- **Rebranded to "tunnel"**, the precise term for this project. The CLI binary is now `quantum-tunnel`, the Prometheus metric namespace `quantum_vpn` is now `quantum_tunnel`, and the CH-KEM protocol and key-derivation labels move to `CH-KEM-Tunnel-*`.

### Performance
- **Datagram data plane**: zero-alloc steady-state send (in-place AEAD into a reused buffer), batched `recvmmsg`/`sendmmsg` on Linux, `SO_REUSEPORT` multi-socket receive that spreads demux and AEAD-open across cores, and a coarse activity clock that drops per-datagram `time.Now()`. Measured on an 8-core arm64 Linux container (loopback, indicative): single-flow delivered goodput ~280 MB/s (~2.2 Gb/s); a single receive goroutine tops out ~365 MB/s aggregate, which `SO_REUSEPORT` lifts ~1.6x to ~565 MB/s across 8 sockets; isolated send ~1.2 GB/s; batched receive ~1030 MB/s. Reaching the ~2.5 GB/s aggregate mark needs more cores plus GSO/GRO offload (roadmap).
- **Datagram receive offload (Linux)**: `WithDatagramOffload()` enables `UDP_GRO`, so the kernel coalesces a same-flow datagram burst into one buffer and the receive loop re-splits it, cutting receive syscalls on a busy flow. Off by default and Linux-only; a no-op on other platforms, non-UDP conns, or kernels without `UDP_GRO`. Send-side `UDP_SEGMENT` (GSO) is not yet wired.

### Security
- **Handshake timeout on the stream Accept path**: `Listener.performHandshake` set no deadline around `ResponderHandshake`, so a peer that connected and stalled mid-handshake pinned a goroutine and session indefinitely (slow-loris). `TransportConfig.HandshakeTimeout` (default 30s) now bounds it; the datagram path already had timeouts.
- **Honest module-integrity self-test**: `crypto.CheckModuleIntegrity` no longer hardcodes `Verified: true`. It pins the SHA-256 of the embedded KAT vectors and reports a real comparison, scoped in the docs as KAT-vector integrity, not binary `.text` integrity (which stays future FIPS work).

### Deferred (stream-path hardening, a later release)
- Role binding in the CH-KEM transcript (reflection-attack resistance; affects the shared crypto core).
- Resumption ticket server binding (`SHA-256(server public key)` in the ticket plaintext).
- Stream-path session-bound AEAD nonce prefix and 1024-bit replay window (the datagram path already has both).
- Real binary/`.text` module integrity (the KAT-vector check landed; full module integrity is future FIPS work).
- CI security: drop the Gosec `-no-fail`, add a FIPS build/test job.

## [0.0.10][] - 2026-05-30

**Theme:** Data-plane rekey reliability and sustained high-throughput.

### Fixed
- **Rekey self-deadlock**: `Send` no longer holds the write lock while triggering an automatic rekey. `CheckAndRekey` -> `SendRekey` re-acquired the non-reentrant `writeMu`, deadlocking the connection the first time the rekey threshold was crossed (deterministically at ~1 GiB sent). The locked write is isolated in `writeFrame`, released before the rekey check.
- **Rekey activation race**: replaced the fixed `+16` sequence-offset activation with dual-cipher trial decryption. At speed the sender outran the rekey round-trip, so the responder switched its receive key while the initiator was still sending under the old key, dropping the connection on authentication failure. Each side now switches its send cipher explicitly (initiator in `ProcessRekeyResponse`; responder in `ActivateRekeySend`, after its response is sent under the old key) and promotes its receive cipher lazily on the first packet that decrypts under the new key. No wire-format change.
- **Replay protection across rekey**: the replay window is no longer reset when the receive cipher is promoted. The reset re-armed a fresh window (whose first check accepts any sequence), letting an on-path attacker replay the rekey-boundary packet once. Sequence numbers are global and monotonic across a rekey, so the existing window stays valid.

### Changed
- **Rekey cadence**: `MaxBytesBeforeRekey` raised from 1 GiB to 64 GiB. At multi-gigabit speeds a 1 GiB limit forced a full CH-KEM rekey roughly once per second; sequential-nonce AES-GCM/ChaCha20-Poly1305 are safe well beyond this. Packet and time rekey limits are unchanged.
- **Transcript/key derivation hashing**: `pkg/crypto/kdf.go` switched from `golang.org/x/crypto/sha3` to the standard-library `crypto/sha3` (Go 1.24+). Output is identical (FIPS 202 SHA-3/SHAKE-256), verified by the existing KATs, and stdlib SHA-3 is part of the Go FIPS 140-3 module.

### Performance
- Single-tunnel throughput now sustains across automatic rekeys (previously capped/deadlocked at the 1 GiB rekey boundary). Measured ~690 MB/s end-to-end (AES-256-GCM, single TCP tunnel, Apple M1 Pro, Go 1.26.3); raw AEAD cipher rate ~2.5 GB/s AES / ~0.7 GB/s ChaCha20. Transport is TCP-only.
- `Session.Encrypt` runs ~3% faster (644 -> 626 ns/op, p=0.000, n=12, Apple M1 Pro) after removing a per-packet lock from the send path; allocations unchanged (3/op).

### Internal
- Full-duplex throughput benchmark so mid-stream rekey completes; regression tests for the deadlock, activation-race timing, and boundary-packet replay; `writeFrame` reused across control-message send paths; `binary.BigEndian.PutUint64` for the sequence AAD; `ActivatePendingKeys` delegates to `finalizeRekeyStateLocked`.

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
- **Command-line tool** (`quantum-tunnel`) with demo, benchmark, and example modes
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
- **Module path**: Corrected to `github.com/sara-star-quant/quantum-go`
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

[Unreleased]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.11...HEAD
[0.0.11]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/sara-star-quant/quantum-go/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/sara-star-quant/quantum-go/releases/tag/v0.0.1
