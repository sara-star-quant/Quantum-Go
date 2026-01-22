// Package constants defines security parameters and protocol constants for the
// Quantum-Go VPN encryption system.
//
// Security Level: NIST Category 5 (equivalent to AES-256 against quantum adversaries)
// This targets maximum security suitable for high-security enterprise/government use.
package constants

// Protocol version and identification
const (
	// ProtocolVersion is the current version of the CH-KEM VPN protocol
	ProtocolVersion uint16 = 0x0001

	// ProtocolName is used for domain separation in key derivation
	ProtocolName = "CH-KEM-VPN-v1"
)

// ML-KEM-1024 Parameters (NIST FIPS 203)
// These parameters provide NIST Category 5 security (~256-bit post-quantum security)
const (
	// MLKEMPublicKeySize is the size of ML-KEM-1024 encapsulation key in bytes
	MLKEMPublicKeySize = 1568

	// MLKEMPrivateKeySize is the size of ML-KEM-1024 decapsulation key in bytes
	MLKEMPrivateKeySize = 3168

	// MLKEMCiphertextSize is the size of ML-KEM-1024 ciphertext in bytes
	MLKEMCiphertextSize = 1568

	// MLKEMSharedSecretSize is the size of the shared secret from ML-KEM in bytes
	MLKEMSharedSecretSize = 32

	// MLKEM polynomial ring parameters
	// n = 256 (polynomial degree)
	// k = 4 (module rank for ML-KEM-1024)
	// q = 3329 (modulus)
	MLKEMPolynomialDegree = 256
	MLKEMModuleRank       = 4
	MLKEMModulus          = 3329
)

// X25519 Parameters (RFC 7748)
const (
	// X25519PublicKeySize is the size of X25519 public key in bytes
	X25519PublicKeySize = 32

	// X25519PrivateKeySize is the size of X25519 private key in bytes
	X25519PrivateKeySize = 32

	// X25519SharedSecretSize is the size of the X25519 shared secret in bytes
	X25519SharedSecretSize = 32
)

// Symmetric Encryption Parameters (AES-256-GCM)
const (
	// AESKeySize is the size of AES-256 keys in bytes
	AESKeySize = 32

	// AESNonceSize is the size of AES-GCM nonce in bytes (96 bits)
	AESNonceSize = 12

	// AESTagSize is the size of AES-GCM authentication tag in bytes
	AESTagSize = 16

	// ChaCha20KeySize is the size of ChaCha20-Poly1305 keys in bytes
	ChaCha20KeySize = 32

	// ChaCha20NonceSize is the size of ChaCha20-Poly1305 nonce in bytes
	ChaCha20NonceSize = 12
)

// Key Derivation Parameters (SHAKE-256)
const (
	// KDFOutputSize is the default output size for key derivation in bytes
	KDFOutputSize = 32

	// TranscriptHashSize is the size of the handshake transcript hash in bytes
	TranscriptHashSize = 32

	// DomainSeparatorCHKEM is used in CH-KEM key derivation
	DomainSeparatorCHKEM = "CH-KEM-v1-SharedSecret"

	// DomainSeparatorHandshake is used in handshake key derivation
	DomainSeparatorHandshake = "CH-KEM-VPN-Handshake"

	// DomainSeparatorTraffic is used in traffic key derivation
	DomainSeparatorTraffic = "CH-KEM-VPN-Traffic"

	// DomainSeparatorRekey is used in rekey derivation
	DomainSeparatorRekey = "CH-KEM-VPN-Rekey"
)

// Session Parameters
const (
	// MaxSessionDuration is the maximum duration of a session before forced rekey
	// Recommended: 1 hour for high-security environments
	MaxSessionDurationSeconds = 3600

	// MaxBytesBeforeRekey is the maximum bytes transmitted before triggering rekey
	// Recommended: 1 GB to limit exposure from any single key
	MaxBytesBeforeRekey = 1 << 30

	// MaxPacketsBeforeRekey is the maximum packets before triggering rekey
	// This prevents nonce exhaustion in AES-GCM (2^32 limit with 96-bit nonce)
	MaxPacketsBeforeRekey = 1 << 28

	// SessionIDSize is the size of session identifiers in bytes
	SessionIDSize = 16
)

// Message Size Limits
const (
	// MaxMessageSize is the maximum size of a single protocol message
	MaxMessageSize = 65536

	// MaxPayloadSize is the maximum size of encrypted payload per packet
	MaxPayloadSize = 65507 // UDP max payload - headers

	// MinPacketSize is the minimum size of a valid encrypted packet
	MinPacketSize = AESNonceSize + AESTagSize + 1
)

// CH-KEM Ciphertext Sizes (combined)
const (
	// CHKEMPublicKeySize is the combined size of X25519 + ML-KEM-1024 public keys
	CHKEMPublicKeySize = X25519PublicKeySize + MLKEMPublicKeySize

	// CHKEMCiphertextSize is the combined size of X25519 public + ML-KEM ciphertext
	CHKEMCiphertextSize = X25519PublicKeySize + MLKEMCiphertextSize

	// CHKEMSharedSecretSize is the size of the final derived shared secret
	CHKEMSharedSecretSize = 32
)

// CipherSuite identifiers
type CipherSuite uint16

const (
	// CipherSuiteAES256GCM uses AES-256-GCM for symmetric encryption
	CipherSuiteAES256GCM CipherSuite = 0x0001

	// CipherSuiteChaCha20Poly1305 uses ChaCha20-Poly1305 for symmetric encryption
	CipherSuiteChaCha20Poly1305 CipherSuite = 0x0002
)

// String returns a human-readable name for the cipher suite
func (cs CipherSuite) String() string {
	switch cs {
	case CipherSuiteAES256GCM:
		return "AES-256-GCM"
	case CipherSuiteChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	default:
		return "Unknown"
	}
}

// IsSupported returns true if the cipher suite is supported
func (cs CipherSuite) IsSupported() bool {
	return cs == CipherSuiteAES256GCM || cs == CipherSuiteChaCha20Poly1305
}

// IsFIPSApproved returns true if the cipher suite is FIPS 140-3 approved.
// Currently only AES-256-GCM is FIPS approved; ChaCha20-Poly1305 is not.
func (cs CipherSuite) IsFIPSApproved() bool {
	return cs == CipherSuiteAES256GCM
}
