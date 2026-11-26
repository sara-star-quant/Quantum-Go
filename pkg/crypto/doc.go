// Package crypto provides the cryptographic primitives behind Quantum-Go: ML-KEM-1024
// and X25519 key agreement, the X-Wing KEM, SHAKE-256 key derivation with domain
// separation, and AES-256-GCM and ChaCha20-Poly1305 authenticated encryption.
//
// Most programs use package tunnel or package chkem instead of calling these
// directly. A build with the fips tag restricts the package to FIPS-approved
// algorithms. Power-on self-tests run in every build; conditional self-tests run only
// through the *WithCST functions.
package crypto
