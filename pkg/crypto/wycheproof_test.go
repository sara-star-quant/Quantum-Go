package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// wycheproofFile is the part of a Wycheproof vector file the tests read. Every test case stays
// a generic map because the field set differs by algorithm.
type wycheproofFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		Type  string           `json:"type"`
		Tests []map[string]any `json:"tests"`
	} `json:"testGroups"`
}

// loadWycheproof reads a vendored vector file after checking its SHA-256 against the pinned value,
// so a silent edit of a vector fails the test instead of changing what it proves.
func loadWycheproof(t *testing.T, name, wantSHA256 string) wycheproofFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "wycheproof", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		t.Fatalf("%s hash = %s, want the pinned %s: update testdata/wycheproof/README.md with the new source commit", name, got, wantSHA256)
	}
	var f wycheproofFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, g := range f.TestGroups {
		total += len(g.Tests)
	}
	if total != f.NumberOfTests {
		t.Fatalf("%s holds %d tests but declares %d", name, total, f.NumberOfTests)
	}
	return f
}

// wycheproofHex decodes a hex field of a test case, failing on bad input so a malformed vector
// cannot turn into an empty slice that happens to pass.
func wycheproofHex(t *testing.T, tc map[string]any, field string) []byte {
	t.Helper()
	s, ok := tc[field].(string)
	if !ok {
		t.Fatalf("tcId %v has no %q field", tc["tcId"], field)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("tcId %v field %q: %v", tc["tcId"], field, err)
	}
	return b
}
