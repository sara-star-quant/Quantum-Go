package version

import (
	"strings"
	"testing"
)

func TestVersionStrings(t *testing.T) {
	v := String()
	if !strings.HasPrefix(v, "v") {
		t.Errorf("version string should start with v, got %s", v)
	}

	full := Full()
	if !strings.Contains(full, "Quantum-Go") {
		t.Errorf("full version should contain project name, got %s", full)
	}
	if !strings.Contains(full, v) {
		t.Errorf("full version should contain version string, got %s", full)
	}
}
