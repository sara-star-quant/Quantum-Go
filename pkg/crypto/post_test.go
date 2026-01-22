package crypto_test

import (
	"testing"

	"github.com/pzverkov/quantum-go/pkg/crypto"
)

// TestPOSTRan verifies that POST runs automatically on package load
func TestPOSTRan(t *testing.T) {
	if !crypto.POSTRan() {
		t.Error("POST should have run on package initialization")
	}
}

// TestPOSTPassed verifies that all POST tests passed
func TestPOSTPassed(t *testing.T) {
	if !crypto.POSTPassed() {
		t.Error("POST should have passed")
	}
}

// TestRunPOST verifies the POST result structure
func TestRunPOST(t *testing.T) {
	result := crypto.RunPOST()

	if result == nil {
		t.Fatal("RunPOST() returned nil")
	}

	if !result.Passed {
		t.Errorf("POST failed with errors: %v", result.Errors)
	}

	if !result.KDFPassed {
		t.Error("KDF KAT should have passed")
	}

	if !result.AESPassed {
		t.Error("AES-GCM KAT should have passed")
	}

	if !result.MLKEMPassed {
		t.Error("ML-KEM KAT should have passed")
	}

	if len(result.Errors) > 0 {
		t.Errorf("POST reported errors: %v", result.Errors)
	}
}

// TestRunPOSTIdempotent verifies that POST only runs once
func TestRunPOSTIdempotent(t *testing.T) {
	result1 := crypto.RunPOST()
	result2 := crypto.RunPOST()

	// Should return the same result object
	if result1 != result2 {
		t.Error("RunPOST() should return the same result on subsequent calls")
	}
}

// TestCheckModuleIntegrity verifies the integrity check mechanism
func TestCheckModuleIntegrity(t *testing.T) {
	integrity := crypto.CheckModuleIntegrity()

	if integrity == nil {
		t.Fatal("CheckModuleIntegrity() returned nil")
	}

	if integrity.ActualHash == "" {
		t.Error("ActualHash should not be empty")
	}

	if integrity.ExpectedHash == "" {
		t.Error("ExpectedHash should not be empty")
	}

	t.Logf("Module integrity - Expected: %s, Actual: %s, Verified: %v",
		integrity.ExpectedHash, integrity.ActualHash, integrity.Verified)
}

// TestCheckModuleIntegrityIdempotent verifies integrity check only runs once
func TestCheckModuleIntegrityIdempotent(t *testing.T) {
	integrity1 := crypto.CheckModuleIntegrity()
	integrity2 := crypto.CheckModuleIntegrity()

	if integrity1 != integrity2 {
		t.Error("CheckModuleIntegrity() should return the same result on subsequent calls")
	}
}

// TestPOSTInFIPSMode verifies POST behavior documentation
func TestPOSTInFIPSMode(t *testing.T) {
	// This test documents the expected behavior in FIPS mode
	// In FIPS mode, POST failures cause a panic
	// We can't easily test the panic behavior without mocking,
	// but we verify that the current implementation passes

	if crypto.FIPSMode() {
		t.Log("Running in FIPS mode - POST failures would cause panic")
	} else {
		t.Log("Running in standard mode - POST failures are logged but non-fatal")
	}

	// Verify POST passed (it must, since we're still running)
	if !crypto.POSTPassed() {
		t.Error("POST must pass for tests to continue running")
	}
}
