//go:build !fips
// +build !fips

// Package protocol defines the wire protocol for the CH-KEM VPN tunnel.
//
// This file is compiled when the "fips" build tag is NOT specified.
// In standard mode, all supported cipher suites are available.
package protocol

import "github.com/pzverkov/quantum-go/internal/constants"

// SupportedCipherSuites returns the list of cipher suites supported in standard mode.
// Both AES-256-GCM and ChaCha20-Poly1305 are available.
func SupportedCipherSuites() []constants.CipherSuite {
	return []constants.CipherSuite{
		constants.CipherSuiteAES256GCM,
		constants.CipherSuiteChaCha20Poly1305,
	}
}

// PreferredCipherSuite returns the preferred cipher suite for new connections.
// AES-256-GCM is preferred due to hardware acceleration on modern CPUs.
func PreferredCipherSuite() constants.CipherSuite {
	return constants.CipherSuiteAES256GCM
}
