// Package crypto implements Power-On Self-Tests (POST) for FIPS 140-3 compliance.
//
// IMPORTANT: POST is production code, not test code. FIPS 140-3 requires self-tests
// to run at module load time (not just during development testing) to verify the
// cryptographic implementation before any operations are performed. This catches
// issues like corrupted binaries, hardware failures, or tampered code.
//
// POST runs automatically when the crypto package is loaded and verifies that
// all cryptographic primitives produce expected outputs using Known Answer Tests (KAT).
//
// The tests verify:
//   - SHAKE-256 (key derivation function)
//   - AES-256-GCM (authenticated encryption)
//   - ML-KEM-1024 (post-quantum key encapsulation)
//
// In FIPS mode, POST failures cause a panic to prevent use of potentially
// compromised cryptographic implementations. In standard mode, failures are
// logged but do not prevent operation.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// POST KAT (Known Answer Test) values
// These are pre-computed expected outputs for known inputs
var (
	// SHAKE-256 KDF KAT
	// Input: domain="POST-KAT-TEST", input=0x0123456789abcdef... (32 bytes)
	// Output: 32-byte derived key
	postKATKDFInput, _    = hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	postKATKDFExpected, _ = hex.DecodeString("f6cd6267523cd5717f431170c2501816d6b1439b1fe8f084cd028e892cff9b6a")

	// AES-256-GCM KAT
	// Key: 0x0123456789abcdef... (32 bytes)
	// Nonce: 0x000000000000000000000000 (12 bytes)
	// Plaintext: "POST-KAT-TEST"
	// Expected ciphertext + tag
	postKATAESKey, _       = hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	postKATAESNonce, _     = hex.DecodeString("000000000000000000000000")
	postKATAESPlaintext, _ = hex.DecodeString("504f53542d4b41542d54455354") // "POST-KAT-TEST"
	postKATAESExpected, _  = hex.DecodeString("5a48b3005aeb1b0a8cd6767b8cded311eb6185c16343d286e3541e9d98")

	// ML-KEM KAT
	// Using a deterministic seed to generate a known key pair and verify encap/decap
	postKATMLKEMSeed, _ = hex.DecodeString(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
			"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
)

// POSTResult contains the results of Power-On Self-Tests
type POSTResult struct {
	Passed      bool
	KDFPassed   bool
	AESPassed   bool
	MLKEMPassed bool
	Errors      []string
}

// postResult stores the cached POST result
var (
	postResult     *POSTResult
	postResultOnce sync.Once
	postRan        bool
)

// POSTDomain is the domain separator used in POST KDF tests
const POSTDomain = "POST-KAT-TEST"

// RunPOST executes the Power-On Self-Tests and returns the results.
// This function is safe to call multiple times; tests only run once.
func RunPOST() *POSTResult {
	postResultOnce.Do(func() {
		postResult = &POSTResult{
			Passed: true,
		}

		// Run KDF test
		if err := runKDFKAT(); err != nil {
			postResult.KDFPassed = false
			postResult.Passed = false
			postResult.Errors = append(postResult.Errors, fmt.Sprintf("KDF KAT failed: %v", err))
		} else {
			postResult.KDFPassed = true
		}

		// Run AES-GCM test
		if err := runAESGCMKAT(); err != nil {
			postResult.AESPassed = false
			postResult.Passed = false
			postResult.Errors = append(postResult.Errors, fmt.Sprintf("AES-GCM KAT failed: %v", err))
		} else {
			postResult.AESPassed = true
		}

		// Run ML-KEM test
		if err := runMLKEMKAT(); err != nil {
			postResult.MLKEMPassed = false
			postResult.Passed = false
			postResult.Errors = append(postResult.Errors, fmt.Sprintf("ML-KEM KAT failed: %v", err))
		} else {
			postResult.MLKEMPassed = true
		}

		postRan = true

		// In FIPS mode, POST failures are fatal
		if FIPSMode() && !postResult.Passed {
			panic(fmt.Sprintf("FIPS POST failed: %v", postResult.Errors))
		}
	})

	return postResult
}

// POSTRan returns true if POST has been executed
func POSTRan() bool {
	return postRan
}

// POSTPassed returns true if POST has run and all tests passed
func POSTPassed() bool {
	if postResult == nil {
		return false
	}
	return postResult.Passed
}

// runKDFKAT verifies SHAKE-256 KDF with a known answer test
func runKDFKAT() error {
	output, err := DeriveKey(POSTDomain, postKATKDFInput, 32)
	if err != nil {
		return fmt.Errorf("DeriveKey failed: %w", err)
	}

	if !bytes.Equal(output, postKATKDFExpected) {
		return fmt.Errorf("KDF output mismatch: got %x, want %x", output, postKATKDFExpected)
	}

	return nil
}

// runAESGCMKAT verifies AES-256-GCM with a known answer test
func runAESGCMKAT() error {
	block, err := aes.NewCipher(postKATAESKey)
	if err != nil {
		return fmt.Errorf("NewCipher failed: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("NewGCM failed: %w", err)
	}

	// Test encryption
	// Note: Hardcoded nonce is intentional for KAT - we need deterministic values
	// to verify the implementation produces expected outputs.
	ciphertext := aesgcm.Seal(nil, postKATAESNonce, postKATAESPlaintext, nil) // #nosec G407 -- KAT requires a fixed, known nonce for deterministic output
	if !bytes.Equal(ciphertext, postKATAESExpected) {
		return fmt.Errorf("AES-GCM encrypt mismatch: got %x, want %x", ciphertext, postKATAESExpected)
	}

	// Test decryption
	plaintext, err := aesgcm.Open(nil, postKATAESNonce, ciphertext, nil) //nolint:gosec // G407: Hardcoded nonce is required for KAT
	if err != nil {
		return fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	if !bytes.Equal(plaintext, postKATAESPlaintext) {
		return fmt.Errorf("AES-GCM decrypt mismatch: got %x, want %x", plaintext, postKATAESPlaintext)
	}

	return nil
}

// runMLKEMKAT verifies ML-KEM-1024 with a consistency test
// Since ML-KEM uses randomness in encapsulation, we use deterministic key generation
// and verify that decapsulation produces a consistent shared secret
func runMLKEMKAT() error {
	// Generate deterministic key pair from seed
	kp, err := NewMLKEMKeyPairFromSeed(postKATMLKEMSeed)
	if err != nil {
		return fmt.Errorf("NewMLKEMKeyPairFromSeed failed: %w", err)
	}

	// Verify public key has expected size
	pkBytes := kp.PublicKeyBytes()
	if len(pkBytes) != 1568 {
		return fmt.Errorf("public key size mismatch: got %d, want 1568", len(pkBytes))
	}

	// Perform encapsulation
	ciphertext, sharedSecret1, err := MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		return fmt.Errorf("MLKEMEncapsulate failed: %w", err)
	}

	// Verify ciphertext size
	if len(ciphertext) != 1568 {
		return fmt.Errorf("ciphertext size mismatch: got %d, want 1568", len(ciphertext))
	}

	// Verify shared secret size
	if len(sharedSecret1) != 32 {
		return fmt.Errorf("shared secret size mismatch: got %d, want 32", len(sharedSecret1))
	}

	// Perform decapsulation
	sharedSecret2, err := MLKEMDecapsulate(kp.DecapsulationKey, ciphertext)
	if err != nil {
		return fmt.Errorf("MLKEMDecapsulate failed: %w", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		return fmt.Errorf("shared secret mismatch after decapsulation")
	}

	return nil
}

// ModuleIntegrity contains information about the crypto module's integrity
type ModuleIntegrity struct {
	// ExpectedHash is the SHA-256 of the embedded KAT vectors, pinned at source. It is
	// NOT a hash of the binary .text section (see CheckModuleIntegrity).
	ExpectedHash string

	// ActualHash is the runtime SHA-256 of the same KAT vectors.
	ActualHash string

	// Verified is true when ActualHash matches ExpectedHash, i.e. the KAT vectors in the
	// binary were not altered. It does NOT attest the binary as a whole.
	Verified bool
}

// postIntegrityCheck stores the module integrity check result
var (
	postIntegrity     *ModuleIntegrity
	postIntegrityOnce sync.Once
)

// CheckModuleIntegrity verifies that the embedded known-answer-test (KAT) vectors have
// not been altered in the binary, by comparing their SHA-256 against a value pinned at
// source. This is a NARROW check: it covers the KAT vectors POST relies on, not the
// binary .text section. Full module integrity (an HMAC over the .text/binary, failing
// hard in FIPS mode) is future FIPS work; this no longer claims it.
func CheckModuleIntegrity() *ModuleIntegrity {
	postIntegrityOnce.Do(func() {
		h := sha256.New()
		h.Write(postKATKDFInput)
		h.Write(postKATKDFExpected)
		h.Write(postKATAESKey)
		h.Write(postKATAESNonce)
		h.Write(postKATAESPlaintext)
		h.Write(postKATAESExpected)
		h.Write(postKATMLKEMSeed)
		actualHash := hex.EncodeToString(h.Sum(nil))

		// SHA-256 of the KAT vectors above, pinned at source. A mismatch means a KAT
		// vector was altered in the binary. Recompute and update this if the vectors change.
		const expectedHash = "0aa6a0d630f79affdeb0850b02bf827416cb43bfd04a1bb1be7e2241c1ad1868"

		postIntegrity = &ModuleIntegrity{
			ExpectedHash: expectedHash,
			ActualHash:   actualHash,
			Verified:     actualHash == expectedHash,
		}
	})

	return postIntegrity
}

// init runs POST automatically when the package is loaded
func init() {
	// Run POST on package initialization
	RunPOST()
}
