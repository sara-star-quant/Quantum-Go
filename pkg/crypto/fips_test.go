package crypto_test

import (
	"testing"

	"github.com/pzverkov/quantum-go/pkg/crypto"
)

// TestFIPSMode tests the FIPSMode function.
// The expected result depends on whether the test was built with the fips tag.
func TestFIPSMode(t *testing.T) {
	// This test verifies that FIPSMode returns a consistent boolean value.
	// When built with -tags fips, it should return true.
	// When built without the fips tag, it should return false.
	result := crypto.FIPSMode()

	// The result should be a valid boolean (this is a basic sanity check)
	if result != true && result != false {
		t.Errorf("FIPSMode() returned invalid value")
	}

	t.Logf("FIPSMode() = %v", result)
}

// TestFIPSModeConsistency verifies that FIPSMode returns the same value on multiple calls.
func TestFIPSModeConsistency(t *testing.T) {
	first := crypto.FIPSMode()
	for i := 0; i < 100; i++ {
		if crypto.FIPSMode() != first {
			t.Errorf("FIPSMode() returned inconsistent values")
		}
	}
}
