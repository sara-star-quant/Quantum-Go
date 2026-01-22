// Package crypto implements Conditional Self-Tests (CST) for FIPS 140-3 compliance.
//
// Conditional Self-Tests differ from Power-On Self-Tests (POST) in that they run
// during specific cryptographic operations rather than at module initialization.
// They verify that each operation produces consistent, correct results.
//
// FIPS 140-3 requires two types of conditional self-tests:
//
//  1. Pairwise Consistency Test: Verifies that a newly generated key pair is
//     consistent (the private and public keys correspond correctly).
//
//  2. DRBG Health Check: Verifies that the random number generator produces
//     non-repeating, non-zero output.
//
// In FIPS mode, CST failures cause a panic to prevent use of potentially
// compromised keys or random data. In standard mode, failures return errors.
package crypto

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
)

// CSTConfig configures Conditional Self-Test behavior
type CSTConfig struct {
	// EnablePairwiseTest enables pairwise consistency tests on key generation
	EnablePairwiseTest bool

	// EnableRNGHealthCheck enables health checks on RNG output
	EnableRNGHealthCheck bool

	// RNGHealthCheckInterval is how often to run full RNG health checks
	// (number of SecureRandom calls between checks)
	RNGHealthCheckInterval uint64
}

// DefaultCSTConfig returns the default CST configuration.
// In FIPS mode, all tests are enabled; in standard mode, tests are disabled by default.
func DefaultCSTConfig() CSTConfig {
	return CSTConfig{
		EnablePairwiseTest:     FIPSMode(),
		EnableRNGHealthCheck:   FIPSMode(),
		RNGHealthCheckInterval: 1000, // Check every 1000 RNG calls
	}
}

// cstState holds global CST state
var (
	cstConfig     CSTConfig
	cstConfigOnce sync.Once
	rngCallCount  atomic.Uint64
	lastRNGOutput []byte
	lastRNGMutex  sync.Mutex
)

// InitCST initializes Conditional Self-Tests with the given configuration.
// Must be called before any cryptographic operations if custom configuration is needed.
// If not called, default configuration is used.
func InitCST(config CSTConfig) {
	cstConfigOnce.Do(func() {
		cstConfig = config
	})
}

// getConfig returns the CST configuration, initializing with defaults if needed.
func getConfig() CSTConfig {
	cstConfigOnce.Do(func() {
		cstConfig = DefaultCSTConfig()
	})
	return cstConfig
}

// CSTResult contains the results of a Conditional Self-Test
type CSTResult struct {
	Passed bool
	Error  error
}

// --- Pairwise Consistency Tests ---

// PairwiseConsistencyTestX25519 verifies that an X25519 key pair is consistent
// by performing a DH operation with a test key pair.
func PairwiseConsistencyTestX25519(kp *X25519KeyPair) *CSTResult {
	if kp == nil || kp.PrivateKey == nil || kp.PublicKey == nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("invalid key pair")}
	}

	// Generate a test key pair
	testKP, err := GenerateX25519KeyPair()
	if err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("failed to generate test key pair: %w", err)}
	}

	// Perform DH in both directions
	secret1, err := X25519(kp.PrivateKey, testKP.PublicKey)
	if err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("DH operation 1 failed: %w", err)}
	}

	secret2, err := X25519(testKP.PrivateKey, kp.PublicKey)
	if err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("DH operation 2 failed: %w", err)}
	}

	// Verify shared secrets match
	if !ConstantTimeCompare(secret1, secret2) {
		return &CSTResult{Passed: false, Error: fmt.Errorf("shared secrets do not match")}
	}

	// Verify shared secret is not all zeros
	allZeros := true
	for _, b := range secret1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return &CSTResult{Passed: false, Error: fmt.Errorf("shared secret is all zeros")}
	}

	return &CSTResult{Passed: true}
}

// PairwiseConsistencyTestMLKEM verifies that an ML-KEM key pair is consistent
// by performing encapsulation and decapsulation.
func PairwiseConsistencyTestMLKEM(kp *MLKEMKeyPair) *CSTResult {
	if kp == nil || kp.EncapsulationKey == nil || kp.DecapsulationKey == nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("invalid key pair")}
	}

	// Perform encapsulation
	ciphertext, sharedSecret1, err := MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("encapsulation failed: %w", err)}
	}

	// Perform decapsulation
	sharedSecret2, err := MLKEMDecapsulate(kp.DecapsulationKey, ciphertext)
	if err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("decapsulation failed: %w", err)}
	}

	// Verify shared secrets match
	if !ConstantTimeCompare(sharedSecret1, sharedSecret2) {
		return &CSTResult{Passed: false, Error: fmt.Errorf("shared secrets do not match")}
	}

	// Verify shared secret is not all zeros
	allZeros := true
	for _, b := range sharedSecret1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return &CSTResult{Passed: false, Error: fmt.Errorf("shared secret is all zeros")}
	}

	return &CSTResult{Passed: true}
}

// runPairwiseTestX25519 runs the pairwise consistency test if enabled,
// and handles failures according to FIPS mode.
func runPairwiseTestX25519(kp *X25519KeyPair) error {
	config := getConfig()
	if !config.EnablePairwiseTest {
		return nil
	}

	result := PairwiseConsistencyTestX25519(kp)
	if !result.Passed {
		if FIPSMode() {
			panic(fmt.Sprintf("FIPS CST failed: X25519 pairwise consistency test: %v", result.Error))
		}
		return result.Error
	}
	return nil
}

// runPairwiseTestMLKEM runs the pairwise consistency test if enabled,
// and handles failures according to FIPS mode.
func runPairwiseTestMLKEM(kp *MLKEMKeyPair) error {
	config := getConfig()
	if !config.EnablePairwiseTest {
		return nil
	}

	result := PairwiseConsistencyTestMLKEM(kp)
	if !result.Passed {
		if FIPSMode() {
			panic(fmt.Sprintf("FIPS CST failed: ML-KEM pairwise consistency test: %v", result.Error))
		}
		return result.Error
	}
	return nil
}

// --- DRBG Health Check ---

// RNGHealthCheck performs a health check on the random number generator.
// It verifies that:
// 1. The RNG produces non-zero output
// 2. The RNG produces non-repeating output
// 3. The RNG produces output with reasonable entropy distribution
func RNGHealthCheck() *CSTResult {
	// Generate test samples
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)

	if err := SecureRandom(sample1); err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG read 1 failed: %w", err)}
	}

	if err := SecureRandom(sample2); err != nil {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG read 2 failed: %w", err)}
	}

	// Check 1: Neither sample should be all zeros
	allZeros1 := true
	allZeros2 := true
	for i := 0; i < 32; i++ {
		if sample1[i] != 0 {
			allZeros1 = false
		}
		if sample2[i] != 0 {
			allZeros2 = false
		}
	}
	if allZeros1 {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG produced all-zero sample 1")}
	}
	if allZeros2 {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG produced all-zero sample 2")}
	}

	// Check 2: Samples should be different
	if bytes.Equal(sample1, sample2) {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG produced identical consecutive samples")}
	}

	// Check 3: Neither sample should be all the same byte
	allSame1 := true
	allSame2 := true
	for i := 1; i < 32; i++ {
		if sample1[i] != sample1[0] {
			allSame1 = false
		}
		if sample2[i] != sample2[0] {
			allSame2 = false
		}
	}
	if allSame1 {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG sample 1 has no variation")}
	}
	if allSame2 {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG sample 2 has no variation")}
	}

	return &CSTResult{Passed: true}
}

// ContinuousRNGTest implements the continuous RNG test required by FIPS 140-3.
// It compares each RNG output to the previous output and fails if they match.
// This function should be called after each SecureRandom call in FIPS mode.
func ContinuousRNGTest(output []byte) *CSTResult {
	lastRNGMutex.Lock()
	defer lastRNGMutex.Unlock()

	// First call - just store the output
	if lastRNGOutput == nil {
		lastRNGOutput = make([]byte, len(output))
		copy(lastRNGOutput, output)
		return &CSTResult{Passed: true}
	}

	// Compare with previous output (if same length)
	if len(output) == len(lastRNGOutput) && bytes.Equal(output, lastRNGOutput) {
		return &CSTResult{Passed: false, Error: fmt.Errorf("RNG produced repeated output")}
	}

	// Store current output for next comparison
	if len(lastRNGOutput) != len(output) {
		lastRNGOutput = make([]byte, len(output))
	}
	copy(lastRNGOutput, output)

	return &CSTResult{Passed: true}
}

// runRNGHealthCheck runs periodic RNG health checks if enabled.
func runRNGHealthCheck() error {
	config := getConfig()
	if !config.EnableRNGHealthCheck {
		return nil
	}

	count := rngCallCount.Add(1)

	// Run full health check periodically
	if count%config.RNGHealthCheckInterval == 0 {
		result := RNGHealthCheck()
		if !result.Passed {
			if FIPSMode() {
				panic(fmt.Sprintf("FIPS CST failed: RNG health check: %v", result.Error))
			}
			return result.Error
		}
	}

	return nil
}

// --- Key Generation with CST ---

// GenerateX25519KeyPairWithCST generates an X25519 key pair and runs
// the pairwise consistency test.
func GenerateX25519KeyPairWithCST() (*X25519KeyPair, error) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}

	if err := runPairwiseTestX25519(kp); err != nil {
		return nil, fmt.Errorf("pairwise consistency test failed: %w", err)
	}

	return kp, nil
}

// GenerateMLKEMKeyPairWithCST generates an ML-KEM key pair and runs
// the pairwise consistency test.
func GenerateMLKEMKeyPairWithCST() (*MLKEMKeyPair, error) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		return nil, err
	}

	if err := runPairwiseTestMLKEM(kp); err != nil {
		return nil, fmt.Errorf("pairwise consistency test failed: %w", err)
	}

	return kp, nil
}

// SecureRandomWithCST reads cryptographically secure random bytes and runs
// the continuous RNG test in FIPS mode.
func SecureRandomWithCST(b []byte) error {
	if err := SecureRandom(b); err != nil {
		return err
	}

	// Run continuous test in FIPS mode
	if FIPSMode() {
		result := ContinuousRNGTest(b)
		if !result.Passed {
			panic(fmt.Sprintf("FIPS CST failed: continuous RNG test: %v", result.Error))
		}
	}

	// Run periodic health check
	return runRNGHealthCheck()
}

// CSTEnabled returns true if Conditional Self-Tests are enabled.
func CSTEnabled() bool {
	config := getConfig()
	return config.EnablePairwiseTest || config.EnableRNGHealthCheck
}

// GetCSTConfig returns the current CST configuration.
func GetCSTConfig() CSTConfig {
	return getConfig()
}
