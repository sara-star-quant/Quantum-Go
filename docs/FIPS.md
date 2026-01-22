# FIPS 140-3 Compliance Guide

This document describes how to build and deploy Quantum-Go in FIPS 140-3 compliant mode.

## Overview

FIPS (Federal Information Processing Standards) 140-3 is a U.S. government security standard for cryptographic modules. When built in FIPS mode, Quantum-Go restricts cryptographic operations to FIPS-approved algorithms only.

### FIPS Mode Restrictions

| Feature | Standard Mode | FIPS Mode |
|---------|---------------|-----------|
| AES-256-GCM | Available | Available |
| ChaCha20-Poly1305 | Available | **Disabled** |
| ML-KEM-1024 | Available | Available |
| X25519 | Available | Available |
| SHAKE-256 (KDF) | Available | Available |

**Note:** ChaCha20-Poly1305 is disabled in FIPS mode as it is not FIPS 140-3 approved.

## Building in FIPS Mode

### Standard Build (Non-FIPS)

```bash
go build ./...
```

### FIPS Build

```bash
go build -tags fips ./...
```

### Running Tests

```bash
# Standard mode tests
go test ./...

# FIPS mode tests
go test -tags fips ./...
```

### Verifying FIPS Mode

You can verify FIPS mode at runtime:

```go
import "github.com/pzverkov/quantum-go/pkg/crypto"

if crypto.FIPSMode() {
    fmt.Println("Running in FIPS mode")
}
```

Session statistics also include FIPS mode status:

```go
stats := session.Stats()
fmt.Printf("FIPS Mode: %v\n", stats.FIPSMode)
fmt.Printf("Cipher Suite: %s\n", stats.CipherSuite)
```

## Deployment Requirements

### 1. Build Environment

- Use Go 1.21 or later
- Build with `-tags fips` flag
- Ensure consistent build tags across all components

### 2. Runtime Considerations

#### Cipher Suite Negotiation

In FIPS mode, only AES-256-GCM is available for negotiation. Peers offering only ChaCha20-Poly1305 will be rejected.

```go
// In FIPS mode, SupportedCipherSuites() returns only AES-256-GCM
suites := protocol.SupportedCipherSuites()
// Returns: [CipherSuiteAES256GCM]
```

#### Session Resumption

Session tickets created with non-FIPS cipher suites (ChaCha20-Poly1305) will be rejected when resuming in FIPS mode. This forces a full handshake with a FIPS-approved cipher suite.

```go
// Attempting to resume a ChaCha20-Poly1305 session in FIPS mode
// will return ErrCipherSuiteNotFIPSApproved
```

#### Error Handling

FIPS mode introduces a new error type:

```go
import qerrors "github.com/pzverkov/quantum-go/internal/errors"

// Check for FIPS-related errors
if errors.Is(err, qerrors.ErrCipherSuiteNotFIPSApproved) {
    // Handle non-FIPS cipher suite rejection
}
```

### 3. Interoperability

| Scenario | Behavior |
|----------|----------|
| FIPS client ↔ FIPS server | Works (AES-256-GCM) |
| FIPS client ↔ Standard server | Works (AES-256-GCM negotiated) |
| Standard client ↔ FIPS server | Works (AES-256-GCM negotiated) |
| ChaCha20-only client ↔ FIPS server | **Fails** (no common cipher) |

### 4. Compliance Verification

#### Session Compliance Check

```go
// Check if current session is FIPS compliant
if session.IsFIPSCompliant() {
    // Session uses FIPS mode AND FIPS-approved cipher suite
}
```

#### Runtime Mode Check

```go
// Check build-time FIPS mode
if crypto.FIPSMode() {
    // Binary was built with -tags fips
}

// Check cipher suite approval
if cipherSuite.IsFIPSApproved() {
    // Cipher suite is FIPS 140-3 approved
}
```

## API Reference

### crypto.FIPSMode()

```go
func FIPSMode() bool
```

Returns `true` if the binary was built with the `fips` build tag.

### CipherSuite.IsFIPSApproved()

```go
func (cs CipherSuite) IsFIPSApproved() bool
```

Returns `true` if the cipher suite is FIPS 140-3 approved. Currently only `CipherSuiteAES256GCM` returns `true`.

### Session.IsFIPSCompliant()

```go
func (s *Session) IsFIPSCompliant() bool
```

Returns `true` if both FIPS mode is enabled AND the session uses a FIPS-approved cipher suite.

### Stats.FIPSMode

```go
type Stats struct {
    // ... other fields ...
    CipherSuite constants.CipherSuite
    FIPSMode    bool
}
```

Session statistics include FIPS mode status and the negotiated cipher suite.

## Security Considerations

1. **Build Consistency**: Ensure all deployed binaries are built with the same FIPS mode setting to avoid interoperability issues.

2. **Ticket Rotation**: When transitioning from standard to FIPS mode, existing session tickets using ChaCha20-Poly1305 will be rejected. Plan for increased handshake load during transition.

3. **Logging**: Consider logging FIPS mode status at startup for audit purposes:
   ```go
   log.Printf("FIPS mode: %v", crypto.FIPSMode())
   ```

4. **Testing**: Always run the full test suite with `-tags fips` before deploying FIPS builds.

## Power-On Self-Tests (POST)

Quantum-Go includes FIPS 140-3 compliant Power-On Self-Tests that run automatically when the crypto package is loaded.

### What POST Verifies

| Algorithm | Test Type | Description |
|-----------|-----------|-------------|
| SHAKE-256 | KAT | Verifies key derivation produces expected output |
| AES-256-GCM | KAT | Verifies encryption/decryption with known vectors |
| ML-KEM-1024 | Consistency | Verifies encapsulation/decapsulation roundtrip |

### POST Behavior

```go
import "github.com/pzverkov/quantum-go/pkg/crypto"

// POST runs automatically on package import
// Check if POST passed:
if crypto.POSTPassed() {
    fmt.Println("All self-tests passed")
}

// Get detailed results:
result := crypto.RunPOST()
fmt.Printf("KDF: %v, AES: %v, ML-KEM: %v\n",
    result.KDFPassed, result.AESPassed, result.MLKEMPassed)
```

### Failure Handling

| Mode | Behavior on POST Failure |
|------|--------------------------|
| FIPS Mode | **Panic** - prevents use of compromised crypto |
| Standard Mode | Log error - continues operation |

### Module Integrity Check

```go
integrity := crypto.CheckModuleIntegrity()
fmt.Printf("Verified: %v\n", integrity.Verified)
```

## Conditional Self-Tests (CST)

In addition to POST, FIPS 140-3 requires Conditional Self-Tests that run during specific cryptographic operations.

### Pairwise Consistency Test

Verifies that newly generated key pairs are consistent (private and public keys correspond correctly).

```go
// Generate key pair with automatic pairwise consistency test
kp, err := crypto.GenerateX25519KeyPairWithCST()
if err != nil {
    // In FIPS mode, CST failure causes panic
    // In standard mode, returns error
}

// ML-KEM key pair with CST
mlkemKP, err := crypto.GenerateMLKEMKeyPairWithCST()
```

### DRBG Health Check

Verifies that the random number generator produces non-repeating, non-zero output.

```go
// Secure random with continuous RNG test
buf := make([]byte, 32)
err := crypto.SecureRandomWithCST(buf)
```

### CST Configuration

```go
config := crypto.CSTConfig{
    EnablePairwiseTest:     true,
    EnableRNGHealthCheck:   true,
    RNGHealthCheckInterval: 1000, // Check every 1000 RNG calls
}
crypto.InitCST(config)

// Check if CST is enabled
if crypto.CSTEnabled() {
    fmt.Println("Conditional Self-Tests are enabled")
}
```

### CST Behavior

| Mode | Pairwise Test | RNG Health Check | Failure Behavior |
|------|---------------|------------------|------------------|
| FIPS Mode | Enabled by default | Enabled by default | **Panic** |
| Standard Mode | Disabled by default | Disabled by default | Return error |

## Limitations

- **Not a Certified Module**: This implementation provides FIPS-compliant algorithm selection but is not itself a FIPS 140-3 certified cryptographic module.

- **Go Runtime**: The Go runtime's cryptographic implementations are used. For full FIPS certification, consider using a FIPS-certified cryptographic provider.

## Troubleshooting

### Error: "cipher suite not FIPS approved"

This error occurs when:
- Attempting to use ChaCha20-Poly1305 in FIPS mode
- Resuming a session ticket created with a non-FIPS cipher suite

**Solution**: Ensure all parties use AES-256-GCM or rebuild without FIPS mode if ChaCha20-Poly1305 is required.

### Peer Connection Failures

If connections fail between FIPS and non-FIPS peers:
1. Verify both peers support AES-256-GCM
2. Check that the non-FIPS peer doesn't exclusively offer ChaCha20-Poly1305
3. Review cipher suite negotiation in logs

### Performance Considerations

AES-256-GCM typically has better performance on modern CPUs with AES-NI hardware acceleration. ChaCha20-Poly1305 may be faster on systems without hardware AES support, but is unavailable in FIPS mode.
