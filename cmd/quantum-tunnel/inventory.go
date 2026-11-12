package main

import (
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// inventorySchema is the version of the JSON document. Bump it when a field changes meaning.
const inventorySchema = 1

type inventory struct {
	SchemaVersion int             `json:"schema_version"`
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	BuildTime     string          `json:"build_time,omitempty"`
	Commit        string          `json:"commit,omitempty"`
	CommitTime    string          `json:"commit_time,omitempty"`
	DirtyBuild    bool            `json:"dirty_build,omitempty"`
	GoVersion     string          `json:"go_version"`
	Platform      string          `json:"platform"`
	Protocol      string          `json:"protocol_version"`
	KEMSuites     []inventorySuit `json:"kem_suites"`
	CipherSuites  []string        `json:"cipher_suites"`
	FIPS          inventoryFIPS   `json:"fips"`
	Modules       []inventoryMod  `json:"modules"`
}

type inventorySuit struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

type inventoryFIPS struct {
	// BuildMode is true for a binary built with the fips tag, which restricts suites and runs
	// self-tests. It is not a validation claim.
	BuildMode bool `json:"build_mode"`
	// GoModuleEnabled is true when the Go runtime runs in its FIPS 140-3 mode (GOFIPS140).
	GoModuleEnabled bool `json:"go_module_enabled"`
	SelfTestPassed  bool `json:"self_test_passed"`
}

type inventoryMod struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

func suiteName(id chkem.SuiteID) string {
	switch id {
	case chkem.SuiteCHKEMv1:
		return "chkem-v1"
	case chkem.SuiteXWing:
		return "x-wing"
	default:
		return fmt.Sprintf("custom-%#04x", uint16(id))
	}
}

func cipherName(cs constants.CipherSuite) string {
	switch cs {
	case constants.CipherSuiteAES256GCM:
		return "aes-256-gcm"
	case constants.CipherSuiteChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return fmt.Sprintf("unknown-%#04x", uint16(cs))
	}
}

// buildInventory describes this binary: what it is, what it can negotiate and how it was built.
// It holds no keys, addresses or configuration, and it describes only Quantum-Go itself, not the
// systems around it.
func buildInventory() inventory {
	inv := inventory{
		SchemaVersion: inventorySchema,
		Tool:          "quantum-tunnel",
		Version:       getVersion(),
		BuildTime:     buildTime,
		GoVersion:     runtime.Version(),
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Protocol:      fmt.Sprintf("%d.%d", protocol.Current.Major, protocol.Current.Minor),
		FIPS: inventoryFIPS{
			BuildMode:       crypto.FIPSMode(),
			GoModuleEnabled: fips140.Enabled(),
			SelfTestPassed:  crypto.RunPOST().Passed,
		},
	}
	for _, id := range chkem.SupportedSuites() {
		inv.KEMSuites = append(inv.KEMSuites, inventorySuit{ID: uint16(id), Name: suiteName(id)})
	}
	for _, cs := range protocol.SupportedCipherSuites() {
		inv.CipherSuites = append(inv.CipherSuites, cipherName(cs))
	}
	if gitCommit != "unknown" {
		inv.Commit = gitCommit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if inv.Commit == "" {
					inv.Commit = s.Value
				}
			case "vcs.time":
				inv.CommitTime = s.Value
			case "vcs.modified":
				inv.DirtyBuild = s.Value == "true"
			}
		}
		for _, m := range info.Deps {
			inv.Modules = append(inv.Modules, inventoryMod{Path: m.Path, Version: m.Version})
		}
	}
	return inv
}

func inventoryCommand() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(buildInventory()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
