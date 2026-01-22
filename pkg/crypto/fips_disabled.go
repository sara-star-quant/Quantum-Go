//go:build !fips
// +build !fips

// Package crypto implements cryptographic primitives for the Quantum-Go VPN.
//
// This file is compiled when the "fips" build tag is NOT specified.
// In standard mode, all supported algorithms are available.
package crypto

// FIPSMode reports whether the binary was built in FIPS mode.
// When false, all supported algorithms (AES-256-GCM and ChaCha20-Poly1305) are available.
func FIPSMode() bool { return false }
