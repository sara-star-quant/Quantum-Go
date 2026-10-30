package protocol

import (
	"os"
	"strings"
	"testing"
)

// TestFormalDocsMatchCurrentVersion fails when the formal verification scripts and
// results declare a protocol version other than Current, so a wire change cannot
// ship with models that were never re-run.
func TestFormalDocsMatchCurrentVersion(t *testing.T) {
	want := "Protocol version verified: " + Current.String()
	for _, f := range []string{"../../docs/formal/verify.sh", "../../docs/formal/RESULTS.txt"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not contain %q: re-run docs/formal/verify.sh for the new protocol version", f, want)
		}
	}
}
