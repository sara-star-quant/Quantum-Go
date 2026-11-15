package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

// syncBuffer is a bytes.Buffer safe for the forwarder's goroutines and the test to share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// waitLines polls for the event, the expected number of records appearing.
func (s *syncBuffer) waitLines(t *testing.T, n int) []string {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if l := s.lines(); len(l) >= n {
			return l
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d assurance records after 15 s, want %d: %q", len(s.lines()), n, s.lines())
		}
	}
}

func TestAssuranceRecordServerSession(t *testing.T) {
	var buf syncBuffer
	lim := testLimits
	lim.assurance = newAssuranceLog(&buf, buildInventory(), false, nopLog)
	c := newCutFixture(t, lim)
	tn := c.connect(t, "alice", c.keys["alice"])
	if !roundTrip(tn) {
		t.Fatal("the session should work")
	}
	_ = tn.Close()
	raw := buf.waitLines(t, 1)[0]

	var rec assuranceRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SchemaVersion != assuranceSchema || rec.Role != "server" || rec.KEMSuite != "chkem-v1" ||
		!slices.Equal(rec.Authentication, []string{"psk"}) || rec.FIPSBuildMode != crypto.FIPSMode() || rec.Version == "" {
		t.Fatalf("unexpected record: %s", raw)
	}
	if _, err := time.Parse(time.RFC3339, rec.Time); err != nil {
		t.Fatalf("time %q is not RFC 3339: %v", rec.Time, err)
	}
	// No address and no identity unless the operator asks.
	if strings.Contains(raw, "127.0.0.1") || strings.Contains(raw, "alice") || rec.Identity != "" {
		t.Fatalf("the record leaks an address or identity: %s", raw)
	}
}

func TestAssuranceRecordIdentityOnRequest(t *testing.T) {
	var buf syncBuffer
	lim := testLimits
	lim.assurance = newAssuranceLog(&buf, buildInventory(), true, nopLog)
	c := newCutFixture(t, lim)
	tn := c.connect(t, "alice", c.keys["alice"])
	if !roundTrip(tn) {
		t.Fatal("the session should work")
	}
	_ = tn.Close()
	var rec assuranceRecord
	if err := json.Unmarshal([]byte(buf.waitLines(t, 1)[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Identity != "alice" {
		t.Fatalf("identity %q, want alice", rec.Identity)
	}
}

// A client and a server forwarder each record their side of one connection.
func TestAssuranceRecordClientAndServer(t *testing.T) {
	var buf syncBuffer
	lim := testLimits
	lim.assurance = newAssuranceLog(&buf, buildInventory(), false, nopLog)
	up, _ := startUpstream(t, echoHandler)
	conn := dial(t, sharedPSKPair(t, up, lim))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	var roles []string
	for _, l := range buf.waitLines(t, 2) {
		var rec assuranceRecord
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rec.Authentication, []string{"psk"}) {
			t.Fatalf("%s: authentication %v, want psk", rec.Role, rec.Authentication)
		}
		roles = append(roles, rec.Role)
	}
	sort.Strings(roles)
	if !slices.Equal(roles, []string{"client", "server"}) {
		t.Fatalf("roles %v, want one client and one server", roles)
	}
}

func TestAssuranceAuthMethods(t *testing.T) {
	cases := []struct {
		psk, static bool
		want        []string
	}{
		{true, false, []string{"psk"}},
		{false, true, []string{"static-key"}},
		{true, true, []string{"psk", "static-key"}},
		{false, false, []string{"none"}},
	}
	for _, c := range cases {
		if got := assuranceAuth(c.psk, c.static); !slices.Equal(got, c.want) {
			t.Errorf("assuranceAuth(%v, %v) = %v, want %v", c.psk, c.static, got, c.want)
		}
	}
}

// The record's keys are its contract with audit tooling. A rename or removal must bump
// assuranceSchema, so this test pins the set.
func TestAssuranceSchemaKeys(t *testing.T) {
	raw, err := json.Marshal(assuranceRecord{Identity: "x", Commit: "y"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range doc {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"authentication", "commit", "duration_ms", "fips_build_mode", "identity", "kem_suite", "role", "schema_version", "time", "version"}
	if !slices.Equal(got, want) || assuranceSchema != 1 {
		t.Fatalf("record keys %v (schema %d), want %v at schema 1: bump assuranceSchema if a field changed", got, assuranceSchema, want)
	}
}
