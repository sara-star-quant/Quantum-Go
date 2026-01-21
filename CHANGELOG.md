# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5] - 2026-01-21

### Added
- **Global Compliance**: Comprehensive regulatory documentation for 15+ jurisdictions (docs/ROADMAP.md) and strict liability guidelines.
- **Protocol Hardening**: Added `pkg/version` for semantic versioning and build metadata.
- **Test Coverage**: New error-path test suite (`coverage_test.go`), pushing core package coverage >90%.
- **Documentation**: Refactored `README.md` into modular usage guides (`docs/usage/`).

### Fixed
- **Security**: Fixed potential panic in benchmark tool (G602 bounds check).
- **Code Quality**: Resolved all `errcheck` lint errors in integration tests.
- **Stability**: Improved connection tear-down stability in transport layer.


## [0.0.4] - 2026-01-20

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

## [0.0.3] - 2026-01-19

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

## [0.0.2] - 2026-01-19

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

## [0.0.1] - 2026-01-18

### Added
- Initial development version
- Core CH-KEM implementation
- Basic tunnel API
- Unit tests for crypto primitives

[Unreleased]: https://github.com/pzverkov/quantum-go/compare/v0.0.5...HEAD
[0.0.5]: https://github.com/pzverkov/quantum-go/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/pzverkov/quantum-go/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/pzverkov/quantum-go/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/pzverkov/quantum-go/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/pzverkov/quantum-go/releases/tag/v0.0.1
