package constants

import "testing"

// TestCipherSuiteString tests String method for CipherSuite.
func TestCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  string
	}{
		{CipherSuiteAES256GCM, "AES-256-GCM"},
		{CipherSuiteChaCha20Poly1305, "ChaCha20-Poly1305"},
		{CipherSuite(0x9999), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.suite.String()
		if got != tt.want {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", tt.suite, got, tt.want)
		}
	}
}

// TestCipherSuiteIsSupported tests IsSupported method for CipherSuite.
func TestCipherSuiteIsSupported(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  bool
	}{
		{CipherSuiteAES256GCM, true},
		{CipherSuiteChaCha20Poly1305, true},
		{CipherSuite(0x0000), false},
		{CipherSuite(0xFFFF), false},
		{CipherSuite(0x0003), false},
	}

	for _, tt := range tests {
		got := tt.suite.IsSupported()
		if got != tt.want {
			t.Errorf("CipherSuite(%d).IsSupported() = %v, want %v", tt.suite, got, tt.want)
		}
	}
}

// TestConstants verifies constant values using table-driven tests.
func TestConstants(t *testing.T) {
	t.Run("KeySizes", testKeySizes)
	t.Run("CHKEMSizes", testCHKEMSizes)
	t.Run("AEADParameters", testAEADParameters)
	t.Run("SessionParameters", testSessionParameters)
	t.Run("RekeyThresholds", testRekeyThresholds)
	t.Run("MessageLimits", testMessageLimits)
	t.Run("DomainSeparators", testDomainSeparators)
}

func testKeySizes(t *testing.T) {
	tests := []struct {
		name  string
		got   int
		want  int
	}{
		{"X25519PublicKeySize", X25519PublicKeySize, 32},
		{"MLKEMPublicKeySize", MLKEMPublicKeySize, 1568},
		{"MLKEMCiphertextSize", MLKEMCiphertextSize, 1568},
		{"MLKEMSharedSecretSize", MLKEMSharedSecretSize, 32},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func testCHKEMSizes(t *testing.T) {
	tests := []struct {
		name  string
		got   int
		want  int
	}{
		{"CHKEMPublicKeySize", CHKEMPublicKeySize, X25519PublicKeySize + MLKEMPublicKeySize},
		{"CHKEMCiphertextSize", CHKEMCiphertextSize, X25519PublicKeySize + MLKEMCiphertextSize},
		{"CHKEMSharedSecretSize", CHKEMSharedSecretSize, 32},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func testAEADParameters(t *testing.T) {
	tests := []struct {
		name  string
		got   int
		want  int
	}{
		{"AESNonceSize", AESNonceSize, 12},
		{"AESTagSize", AESTagSize, 16},
		{"ChaCha20NonceSize", ChaCha20NonceSize, 12},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func testSessionParameters(t *testing.T) {
	if SessionIDSize != 16 {
		t.Errorf("SessionIDSize = %d, want 16", SessionIDSize)
	}
}

func testRekeyThresholds(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
	}{
		{"MaxBytesBeforeRekey", MaxBytesBeforeRekey},
		{"MaxSessionDurationSeconds", MaxSessionDurationSeconds},
		{"MaxPacketsBeforeRekey", MaxPacketsBeforeRekey},
	}
	for _, tt := range tests {
		if tt.value == 0 {
			t.Errorf("%s should be non-zero", tt.name)
		}
	}
}

func testMessageLimits(t *testing.T) {
	tests := []struct {
		name  string
		value int
	}{
		{"MaxMessageSize", MaxMessageSize},
		{"MaxPayloadSize", MaxPayloadSize},
	}
	for _, tt := range tests {
		if tt.value == 0 {
			t.Errorf("%s should be non-zero", tt.name)
		}
	}
}

func testDomainSeparators(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"DomainSeparatorCHKEM", DomainSeparatorCHKEM},
		{"DomainSeparatorHandshake", DomainSeparatorHandshake},
		{"DomainSeparatorTraffic", DomainSeparatorTraffic},
		{"DomainSeparatorRekey", DomainSeparatorRekey},
	}
	for _, tt := range tests {
		if len(tt.value) == 0 {
			t.Errorf("%s is empty", tt.name)
		}
	}
}

// TestCipherSuiteUniqueness ensures cipher suite IDs are unique.
func TestCipherSuiteUniqueness(t *testing.T) {
	if CipherSuiteAES256GCM == CipherSuiteChaCha20Poly1305 {
		t.Error("Cipher suite IDs must be unique")
	}
}

// TestCipherSuiteIsFIPSApproved tests IsFIPSApproved method for CipherSuite.
func TestCipherSuiteIsFIPSApproved(t *testing.T) {
	tests := []struct {
		suite CipherSuite
		want  bool
	}{
		{CipherSuiteAES256GCM, true},          // AES-256-GCM is FIPS approved
		{CipherSuiteChaCha20Poly1305, false},  // ChaCha20-Poly1305 is NOT FIPS approved
		{CipherSuite(0x0000), false},          // Unknown suites are not approved
		{CipherSuite(0xFFFF), false},          // Unknown suites are not approved
		{CipherSuite(0x0003), false},          // Unknown suites are not approved
	}

	for _, tt := range tests {
		got := tt.suite.IsFIPSApproved()
		if got != tt.want {
			t.Errorf("CipherSuite(%d).IsFIPSApproved() = %v, want %v", tt.suite, got, tt.want)
		}
	}
}

// TestFIPSApprovedImpliesSupported verifies that all FIPS approved suites are also supported.
func TestFIPSApprovedImpliesSupported(t *testing.T) {
	suites := []CipherSuite{CipherSuiteAES256GCM, CipherSuiteChaCha20Poly1305}
	for _, s := range suites {
		if s.IsFIPSApproved() && !s.IsSupported() {
			t.Errorf("CipherSuite %v is FIPS approved but not supported", s)
		}
	}
}
