//go:build fips
// +build fips

// Package crypto implements cryptographic primitives for the Quantum-Go VPN.
//
// This file is compiled when the "fips" build tag is specified.
// In FIPS mode, only FIPS 140-3 approved algorithms are available.
package crypto

// FIPSMode reports whether the binary was built in FIPS mode.
// When true, only FIPS 140-3 approved algorithms (AES-256-GCM) are available.
func FIPSMode() bool { return true }
