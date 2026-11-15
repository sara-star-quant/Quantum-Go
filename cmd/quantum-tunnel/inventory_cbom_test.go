package main

import (
	"encoding/json"
	"slices"
	"testing"
)

// Allowed values from the CycloneDX 1.6 JSON schema (cryptoProperties and its children),
// checked against the published schema when this output was written.
var (
	cdxPrimitives = []string{"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}
	cdxEnvs       = []string{"software-plain-ram", "software-encrypted-ram", "software-tee", "hardware", "other", "unknown"}
	cdxPlatforms  = []string{"generic", "x86_32", "x86_64", "armv7-a", "armv7-m", "armv8-a", "armv8-m", "armv9-a", "armv9-m", "s390x", "ppc64", "ppc64le", "other", "unknown"}
	cdxModes      = []string{"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
	cdxFunctions  = []string{"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"}
	cdxProtocols  = []string{"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}
)

func TestCycloneDXShape(t *testing.T) {
	inv := buildInventory()
	bom := buildCycloneDX(inv)
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.Version < 1 {
		t.Fatalf("bad envelope: %q %q %d", bom.BOMFormat, bom.SpecVersion, bom.Version)
	}
	refs := map[string]bool{bom.Metadata.Component.BOMRef: true}
	var algs []cdxComponent
	var protocols []cdxComponent
	for _, c := range bom.Components {
		if refs[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		refs[c.BOMRef] = true
		if c.Type != "cryptographic-asset" || c.CryptoProperties == nil {
			t.Fatalf("%s is not a cryptographic asset", c.BOMRef)
		}
		switch c.CryptoProperties.AssetType {
		case "algorithm":
			algs = append(algs, c)
		case "protocol":
			protocols = append(protocols, c)
		default:
			t.Fatalf("%s: unexpected asset type %q", c.BOMRef, c.CryptoProperties.AssetType)
		}
	}
	for _, c := range algs {
		a := c.CryptoProperties.AlgorithmProps
		if a == nil {
			t.Fatalf("%s: algorithm without properties", c.BOMRef)
		}
		if !slices.Contains(cdxPrimitives, a.Primitive) || !slices.Contains(cdxEnvs, a.ExecutionEnvironment) ||
			!slices.Contains(cdxPlatforms, a.ImplementationPlatform) || (a.Mode != "" && !slices.Contains(cdxModes, a.Mode)) {
			t.Fatalf("%s: a value is outside the CycloneDX 1.6 enums: %+v", c.BOMRef, a)
		}
		for _, f := range a.CryptoFunctions {
			if !slices.Contains(cdxFunctions, f) {
				t.Fatalf("%s: unknown crypto function %q", c.BOMRef, f)
			}
		}
		if !slices.Equal(a.CertificationLevel, []string{"none"}) {
			t.Fatalf("%s claims certification %v; a build mode is not a validation", c.BOMRef, a.CertificationLevel)
		}
		if a.NISTQuantumSecurityLevel != nil && (*a.NISTQuantumSecurityLevel < 0 || *a.NISTQuantumSecurityLevel > 6) {
			t.Fatalf("%s: quantum security level out of range", c.BOMRef)
		}
	}
	if len(protocols) != 1 {
		t.Fatalf("%d protocol components, want 1", len(protocols))
	}
	p := protocols[0].CryptoProperties.ProtocolProperties
	if p == nil || !slices.Contains(cdxProtocols, p.Type) || p.Version != inv.Protocol {
		t.Fatalf("bad protocol properties: %+v", p)
	}
	// One cipher suite per KEM suite and AEAD, every reference resolves, no algorithm is orphaned.
	if want := len(inv.KEMSuites) * len(inv.CipherSuites); len(p.CipherSuites) != want {
		t.Fatalf("%d cipher suites, want %d", len(p.CipherSuites), want)
	}
	referenced := map[string]bool{}
	for _, cs := range p.CipherSuites {
		for _, r := range cs.Algorithms {
			if !refs[r] {
				t.Fatalf("cipher suite %q references %q, which is not a component", cs.Name, r)
			}
			referenced[r] = true
		}
	}
	for _, c := range algs {
		if !referenced[c.BOMRef] {
			t.Fatalf("%s is emitted but no cipher suite uses it", c.BOMRef)
		}
	}
}

func TestCycloneDXIsDeterministic(t *testing.T) {
	a, _ := json.Marshal(buildCycloneDX(buildInventory()))
	b, _ := json.Marshal(buildCycloneDX(buildInventory()))
	if string(a) != string(b) {
		t.Fatal("two renderings of one inventory differ")
	}
}

// A suite registered by an application appears, but with no algorithm detail: nothing here can
// say what it does.
func TestCycloneDXCustomSuiteHasNoAlgorithmClaims(t *testing.T) {
	inv := inventory{Protocol: "6.0", CipherSuites: []string{"aes-256-gcm"}, KEMSuites: []inventorySuit{{ID: 0x1234, Name: "custom-0x1234"}}}
	bom := buildCycloneDX(inv)
	if len(bom.Components) != 1 {
		t.Fatalf("%d components, want only the protocol", len(bom.Components))
	}
	cs := bom.Components[0].CryptoProperties.ProtocolProperties.CipherSuites
	if len(cs) != 1 || cs[0].Name != "custom-0x1234/aes-256-gcm" || len(cs[0].Algorithms) != 0 {
		t.Fatalf("custom suite rendered as %+v", cs)
	}
}
