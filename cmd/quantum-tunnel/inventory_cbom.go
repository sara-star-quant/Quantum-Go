package main

import (
	"fmt"
	"runtime"
)

// The cryptography bill of materials follows CycloneDX 1.6 (cryptographic-asset components). It
// describes what this build can negotiate: the algorithms behind each KEM suite and AEAD, and the
// tunnel protocol that ties them together. It states no validation or certification: every
// algorithm reports certificationLevel "none", because a build mode or a validated module
// underneath is not a validated Quantum-Go. A registered third-party suite appears as a suite
// with no algorithm detail, because nothing here can vouch for what it does.

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Component cdxComponent `json:"component"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type             string          `json:"type"`
	BOMRef           string          `json:"bom-ref"`
	Name             string          `json:"name"`
	Version          string          `json:"version,omitempty"`
	Description      string          `json:"description,omitempty"`
	CryptoProperties *cdxCryptoProps `json:"cryptoProperties,omitempty"`
	Properties       []cdxProperty   `json:"properties,omitempty"`
}

type cdxCryptoProps struct {
	AssetType          string        `json:"assetType"`
	AlgorithmProps     *cdxAlgorithm `json:"algorithmProperties,omitempty"`
	ProtocolProperties *cdxProtocol  `json:"protocolProperties,omitempty"`
}

type cdxAlgorithm struct {
	Primitive                string   `json:"primitive"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	ExecutionEnvironment     string   `json:"executionEnvironment"`
	ImplementationPlatform   string   `json:"implementationPlatform"`
	CertificationLevel       []string `json:"certificationLevel"`
	Mode                     string   `json:"mode,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

type cdxProtocol struct {
	Type         string           `json:"type"`
	Version      string           `json:"version"`
	CipherSuites []cdxCipherSuite `json:"cipherSuites"`
}

type cdxCipherSuite struct {
	Name       string   `json:"name"`
	Algorithms []string `json:"algorithms,omitempty"`
}

func ptr(n int) *int { return &n }

func platformName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "armv8-a"
	default:
		return "other"
	}
}

func algorithm(ref, name, primitive string, a cdxAlgorithm) cdxComponent {
	a.Primitive = primitive
	a.ExecutionEnvironment = "software-plain-ram"
	a.ImplementationPlatform = platformName()
	a.CertificationLevel = []string{"none"}
	return cdxComponent{
		Type: "cryptographic-asset", BOMRef: ref, Name: name,
		CryptoProperties: &cdxCryptoProps{AssetType: "algorithm", AlgorithmProps: &a},
	}
}

// Algorithm components by reference, and the references behind each built-in suite and AEAD.
var cdxAlgorithms = map[string]cdxComponent{
	"alg:ml-kem-1024": algorithm("alg:ml-kem-1024", "ML-KEM-1024", "kem", cdxAlgorithm{
		ParameterSetIdentifier: "1024", NISTQuantumSecurityLevel: ptr(5), CryptoFunctions: []string{"keygen", "encapsulate", "decapsulate"}}),
	"alg:ml-kem-768": algorithm("alg:ml-kem-768", "ML-KEM-768", "kem", cdxAlgorithm{
		ParameterSetIdentifier: "768", NISTQuantumSecurityLevel: ptr(3), CryptoFunctions: []string{"keygen", "encapsulate", "decapsulate"}}),
	"alg:x25519": algorithm("alg:x25519", "X25519", "key-agree", cdxAlgorithm{
		Curve: "curve25519", ClassicalSecurityLevel: ptr(128), CryptoFunctions: []string{"keygen", "keyderive"}}),
	"alg:shake-256": algorithm("alg:shake-256", "SHAKE-256", "xof", cdxAlgorithm{
		ParameterSetIdentifier: "256", CryptoFunctions: []string{"digest"}}),
	"alg:sha3-256": algorithm("alg:sha3-256", "SHA3-256", "hash", cdxAlgorithm{
		ParameterSetIdentifier: "256", CryptoFunctions: []string{"digest"}}),
	"alg:ch-kem-v1": algorithm("alg:ch-kem-v1", "CH-KEM-v1 combiner", "combiner", cdxAlgorithm{
		CryptoFunctions: []string{"keyderive"}}),
	"alg:x-wing": algorithm("alg:x-wing", "X-Wing combiner", "combiner", cdxAlgorithm{
		CryptoFunctions: []string{"keyderive"}}),
	"alg:aes-256-gcm": algorithm("alg:aes-256-gcm", "AES-256-GCM", "ae", cdxAlgorithm{
		ParameterSetIdentifier: "256", Mode: "gcm", ClassicalSecurityLevel: ptr(256), CryptoFunctions: []string{"encrypt", "decrypt", "tag"}}),
	"alg:chacha20-poly1305": algorithm("alg:chacha20-poly1305", "ChaCha20-Poly1305", "ae", cdxAlgorithm{
		ClassicalSecurityLevel: ptr(256), CryptoFunctions: []string{"encrypt", "decrypt", "tag"}}),
}

var cdxSuiteAlgorithms = map[string][]string{
	"chkem-v1": {"alg:ml-kem-1024", "alg:x25519", "alg:shake-256", "alg:ch-kem-v1"},
	"x-wing":   {"alg:ml-kem-768", "alg:x25519", "alg:sha3-256", "alg:x-wing"},
}

var cdxCipherAlgorithm = map[string]string{
	"aes-256-gcm":       "alg:aes-256-gcm",
	"chacha20-poly1305": "alg:chacha20-poly1305",
}

// buildCycloneDX renders an inventory as a CycloneDX 1.6 cryptography bill of materials. The
// output is deterministic: no timestamp, no serial number, stable order.
func buildCycloneDX(inv inventory) cdxBOM {
	bom := cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1}
	bom.Metadata.Component = cdxComponent{
		Type: "application", BOMRef: "app:quantum-tunnel", Name: inv.Tool, Version: inv.Version,
		Properties: []cdxProperty{
			{Name: "quantum-go:protocol-version", Value: inv.Protocol},
			{Name: "quantum-go:fips-build-mode", Value: fmt.Sprint(inv.FIPS.BuildMode)},
			{Name: "quantum-go:go-fips140-module-enabled", Value: fmt.Sprint(inv.FIPS.GoModuleEnabled)},
			{Name: "quantum-go:self-test-passed", Value: fmt.Sprint(inv.FIPS.SelfTestPassed)},
		},
	}
	used := map[string]bool{}
	var order []string
	use := func(ref string) {
		if !used[ref] {
			used[ref] = true
			order = append(order, ref)
		}
	}
	proto := &cdxProtocol{Type: "other", Version: inv.Protocol}
	for _, suite := range inv.KEMSuites {
		kemRefs, known := cdxSuiteAlgorithms[suite.Name]
		for _, c := range inv.CipherSuites {
			cs := cdxCipherSuite{Name: suite.Name + "/" + c}
			if known {
				cs.Algorithms = append(cs.Algorithms, kemRefs...)
				cs.Algorithms = append(cs.Algorithms, cdxCipherAlgorithm[c])
				for _, r := range cs.Algorithms {
					use(r)
				}
			}
			proto.CipherSuites = append(proto.CipherSuites, cs)
		}
	}
	for _, ref := range order {
		bom.Components = append(bom.Components, cdxAlgorithms[ref])
	}
	bom.Components = append(bom.Components, cdxComponent{
		Type: "cryptographic-asset", BOMRef: "protocol:quantum-go-tunnel", Name: "Quantum-Go tunnel handshake and record protocol",
		Version:          inv.Protocol,
		CryptoProperties: &cdxCryptoProps{AssetType: "protocol", ProtocolProperties: proto},
	})
	return bom
}
