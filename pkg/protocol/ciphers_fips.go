//go:build fips
// +build fips

// Package protocol defines the wire protocol for the CH-KEM VPN tunnel.
//
// This file is compiled when the "fips" build tag is specified.
// In FIPS mode, only FIPS 140-3 approved cipher suites are available.
package protocol

import "github.com/pzverkov/quantum-go/internal/constants"

// SupportedCipherSuites returns the list of cipher suites supported in FIPS mode.
// In FIPS mode, only AES-256-GCM is available as it is FIPS 140-3 approved.
func SupportedCipherSuites() []constants.CipherSuite {
	return []constants.CipherSuite{constants.CipherSuiteAES256GCM}
}

// PreferredCipherSuite returns the preferred cipher suite for new connections.
// In FIPS mode, AES-256-GCM is the only option.
func PreferredCipherSuite() constants.CipherSuite {
	return constants.CipherSuiteAES256GCM
}
