package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// The document's top-level keys are its contract with audit tooling. A rename or removal must
// bump inventorySchema, so this test pins the set.
func TestInventorySchemaKeys(t *testing.T) {
	raw, err := json.Marshal(buildInventory())
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
	// commit, commit_time, dirty_build and build_time are omitted when unknown.
	required := []string{"cipher_suites", "fips", "go_version", "kem_suites", "modules", "platform", "protocol_version", "schema_version", "tool", "version"}
	for _, want := range required {
		if _, ok := doc[want]; !ok {
			t.Errorf("missing key %q; have %v", want, got)
		}
	}
	allowed := map[string]bool{"build_time": true, "commit": true, "commit_time": true, "dirty_build": true}
	for _, k := range got {
		if !allowed[k] && !contains(required, k) {
			t.Errorf("unexpected key %q: add it to the schema test and bump inventorySchema if a meaning changed", k)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestInventoryReportsWhatTheBuildCanDo(t *testing.T) {
	inv := buildInventory()
	if inv.SchemaVersion != inventorySchema || inv.Tool != "quantum-tunnel" {
		t.Fatalf("header wrong: %+v", inv)
	}
	if want := "6.0"; inv.Protocol != want || inv.Protocol != formatProtocol(protocol.Current) {
		t.Fatalf("protocol %q, want %q", inv.Protocol, want)
	}
	if inv.Version == "" || inv.GoVersion == "" || inv.Platform == "" {
		t.Fatalf("empty identity fields: %+v", inv)
	}
	if len(inv.KEMSuites) == 0 || inv.KEMSuites[0].Name != "chkem-v1" {
		t.Fatalf("kem suites %+v, want chkem-v1 first", inv.KEMSuites)
	}
	if len(inv.CipherSuites) == 0 || inv.CipherSuites[0] != "aes-256-gcm" {
		t.Fatalf("cipher suites %v, want aes-256-gcm first", inv.CipherSuites)
	}
	if inv.FIPS.BuildMode != crypto.FIPSMode() {
		t.Fatalf("fips build mode %v does not match the library's %v", inv.FIPS.BuildMode, crypto.FIPSMode())
	}
	if !inv.FIPS.SelfTestPassed {
		t.Fatal("the self-tests did not pass")
	}
}

func formatProtocol(v protocol.Version) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}
