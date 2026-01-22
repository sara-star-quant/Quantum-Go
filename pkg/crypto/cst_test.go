package crypto_test

import (
	"testing"

	"github.com/pzverkov/quantum-go/pkg/crypto"
)

// TestCSTConfig verifies CST configuration
func TestCSTConfig(t *testing.T) {
	config := crypto.DefaultCSTConfig()

	// In non-FIPS mode, tests should be disabled by default
	if !crypto.FIPSMode() {
		if config.EnablePairwiseTest {
			t.Error("Pairwise test should be disabled in non-FIPS mode by default")
		}
		if config.EnableRNGHealthCheck {
			t.Error("RNG health check should be disabled in non-FIPS mode by default")
		}
	}

	// RNGHealthCheckInterval should have a reasonable default
	if config.RNGHealthCheckInterval == 0 {
		t.Error("RNGHealthCheckInterval should not be zero")
	}
}

// TestPairwiseConsistencyTestX25519 verifies X25519 pairwise consistency test
func TestPairwiseConsistencyTestX25519(t *testing.T) {
	// Generate a valid key pair
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate X25519 key pair: %v", err)
	}

	// Run pairwise consistency test
	result := crypto.PairwiseConsistencyTestX25519(kp)
	if !result.Passed {
		t.Errorf("Pairwise consistency test failed: %v", result.Error)
	}

	// Test with nil key pair
	result = crypto.PairwiseConsistencyTestX25519(nil)
	if result.Passed {
		t.Error("Pairwise consistency test should fail with nil key pair")
	}
}

// TestPairwiseConsistencyTestMLKEM verifies ML-KEM pairwise consistency test
func TestPairwiseConsistencyTestMLKEM(t *testing.T) {
	// Generate a valid key pair
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM key pair: %v", err)
	}

	// Run pairwise consistency test
	result := crypto.PairwiseConsistencyTestMLKEM(kp)
	if !result.Passed {
		t.Errorf("Pairwise consistency test failed: %v", result.Error)
	}

	// Test with nil key pair
	result = crypto.PairwiseConsistencyTestMLKEM(nil)
	if result.Passed {
		t.Error("Pairwise consistency test should fail with nil key pair")
	}
}

// TestRNGHealthCheck verifies RNG health check
func TestRNGHealthCheck(t *testing.T) {
	result := crypto.RNGHealthCheck()
	if !result.Passed {
		t.Errorf("RNG health check failed: %v", result.Error)
	}
}

// TestContinuousRNGTest verifies continuous RNG test
func TestContinuousRNGTest(t *testing.T) {
	// First call should pass (stores the output)
	sample1 := make([]byte, 32)
	if err := crypto.SecureRandom(sample1); err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}

	result := crypto.ContinuousRNGTest(sample1)
	if !result.Passed {
		t.Errorf("First continuous RNG test should pass: %v", result.Error)
	}

	// Second call with different data should pass
	sample2 := make([]byte, 32)
	if err := crypto.SecureRandom(sample2); err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}

	result = crypto.ContinuousRNGTest(sample2)
	if !result.Passed {
		t.Errorf("Continuous RNG test with different data should pass: %v", result.Error)
	}
}

// TestGenerateX25519KeyPairWithCST verifies X25519 key generation with CST
func TestGenerateX25519KeyPairWithCST(t *testing.T) {
	kp, err := crypto.GenerateX25519KeyPairWithCST()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPairWithCST failed: %v", err)
	}

	if kp == nil {
		t.Fatal("Key pair should not be nil")
	}

	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Error("Key pair components should not be nil")
	}
}

// TestGenerateMLKEMKeyPairWithCST verifies ML-KEM key generation with CST
func TestGenerateMLKEMKeyPairWithCST(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPairWithCST()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPairWithCST failed: %v", err)
	}

	if kp == nil {
		t.Fatal("Key pair should not be nil")
	}

	if kp.EncapsulationKey == nil || kp.DecapsulationKey == nil {
		t.Error("Key pair components should not be nil")
	}
}

// TestSecureRandomWithCST verifies SecureRandom with CST
func TestSecureRandomWithCST(t *testing.T) {
	buf := make([]byte, 32)
	if err := crypto.SecureRandomWithCST(buf); err != nil {
		t.Fatalf("SecureRandomWithCST failed: %v", err)
	}

	// Verify buffer was filled (not all zeros)
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("SecureRandomWithCST produced all zeros")
	}
}

// TestCSTEnabled verifies CSTEnabled function
func TestCSTEnabled(t *testing.T) {
	// Just verify the function works without error
	_ = crypto.CSTEnabled()
}

// TestGetCSTConfig verifies GetCSTConfig function
func TestGetCSTConfig(t *testing.T) {
	config := crypto.GetCSTConfig()

	// Verify we get a valid config
	if config.RNGHealthCheckInterval == 0 {
		t.Error("RNGHealthCheckInterval should not be zero")
	}
}

// TestCSTInFIPSMode documents CST behavior in FIPS mode
func TestCSTInFIPSMode(t *testing.T) {
	if crypto.FIPSMode() {
		t.Log("Running in FIPS mode - CST is enabled by default")
		config := crypto.GetCSTConfig()
		if !config.EnablePairwiseTest {
			t.Error("Pairwise test should be enabled in FIPS mode")
		}
		if !config.EnableRNGHealthCheck {
			t.Error("RNG health check should be enabled in FIPS mode")
		}
	} else {
		t.Log("Running in standard mode - CST is disabled by default")
	}
}

// TestMultipleRNGHealthChecks runs multiple health checks to verify consistency
func TestMultipleRNGHealthChecks(t *testing.T) {
	for i := 0; i < 10; i++ {
		result := crypto.RNGHealthCheck()
		if !result.Passed {
			t.Errorf("RNG health check %d failed: %v", i, result.Error)
		}
	}
}

// TestCSTResultStructure verifies CSTResult structure
func TestCSTResultStructure(t *testing.T) {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	result := crypto.PairwiseConsistencyTestX25519(kp)

	// Verify result structure
	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// On success, Passed should be true and Error should be nil
	if result.Passed && result.Error != nil {
		t.Error("Passed result should have nil error")
	}
}
