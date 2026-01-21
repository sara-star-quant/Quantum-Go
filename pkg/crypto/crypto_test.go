package crypto_test

import (
	"bytes"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/crypto"
)

// --- Random Tests ---

func TestSecureRandom(t *testing.T) {
	buf := make([]byte, 32)
	if err := crypto.SecureRandom(buf); err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}

	// Check that it's not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("SecureRandom returned all zeros")
	}
}

func TestSecureRandomBytes(t *testing.T) {
	sizes := []int{16, 32, 64, 128}
	for _, size := range sizes {
		buf, err := crypto.SecureRandomBytes(size)
		if err != nil {
			t.Fatalf("SecureRandomBytes(%d) failed: %v", size, err)
		}
		if len(buf) != size {
			t.Errorf("SecureRandomBytes(%d) returned %d bytes", size, len(buf))
		}
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("hello world")
	b := []byte("hello world")
	c := []byte("hello worle")
	d := []byte("hello")

	if !crypto.ConstantTimeCompare(a, b) {
		t.Error("Equal slices should compare equal")
	}
	if crypto.ConstantTimeCompare(a, c) {
		t.Error("Different slices should not compare equal")
	}
	if crypto.ConstantTimeCompare(a, d) {
		t.Error("Different length slices should not compare equal")
	}
}

func TestZeroize(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	crypto.Zeroize(buf)

	for i, b := range buf {
		if b != 0 {
			t.Errorf("Zeroize failed at index %d: got %d, want 0", i, b)
		}
	}
}

// --- X25519 Tests ---

func TestX25519KeyGeneration(t *testing.T) {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	if len(kp.PublicKeyBytes()) != constants.X25519PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(kp.PublicKeyBytes()), constants.X25519PublicKeySize)
	}

	if len(kp.PrivateKeyBytes()) != constants.X25519PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(kp.PrivateKeyBytes()), constants.X25519PrivateKeySize)
	}
}

func TestX25519KeyExchange(t *testing.T) {
	// Generate two key pairs
	alice, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed for Alice: %v", err)
	}

	bob, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed for Bob: %v", err)
	}

	// Compute shared secrets
	secretAlice, err := crypto.X25519(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("X25519 failed for Alice: %v", err)
	}

	secretBob, err := crypto.X25519(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("X25519 failed for Bob: %v", err)
	}

	// Verify secrets match
	if !bytes.Equal(secretAlice, secretBob) {
		t.Error("X25519 shared secrets do not match")
	}

	if len(secretAlice) != constants.X25519SharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(secretAlice), constants.X25519SharedSecretSize)
	}
}

func TestX25519ParsePublicKey(t *testing.T) {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Parse the public key
	parsed, err := crypto.ParseX25519PublicKey(kp.PublicKeyBytes())
	if err != nil {
		t.Fatalf("ParseX25519PublicKey failed: %v", err)
	}

	if !bytes.Equal(parsed.Bytes(), kp.PublicKeyBytes()) {
		t.Error("Parsed public key does not match original")
	}
}

// --- ML-KEM Tests ---

func TestMLKEMKeyGeneration(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	if len(kp.PublicKeyBytes()) != constants.MLKEMPublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(kp.PublicKeyBytes()), constants.MLKEMPublicKeySize)
	}
}

func TestMLKEMEncapsulationDecapsulation(t *testing.T) {
	// Generate key pair
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	// Encapsulate
	ciphertext, sharedSecretEnc, err := crypto.MLKEMEncapsulate(kp.EncapsulationKey)
	if err != nil {
		t.Fatalf("MLKEMEncapsulate failed: %v", err)
	}

	if len(ciphertext) != constants.MLKEMCiphertextSize {
		t.Errorf("Ciphertext size: got %d, want %d", len(ciphertext), constants.MLKEMCiphertextSize)
	}

	if len(sharedSecretEnc) != constants.MLKEMSharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(sharedSecretEnc), constants.MLKEMSharedSecretSize)
	}

	// Decapsulate
	sharedSecretDec, err := crypto.MLKEMDecapsulate(kp.DecapsulationKey, ciphertext)
	if err != nil {
		t.Fatalf("MLKEMDecapsulate failed: %v", err)
	}

	// Verify secrets match
	if !bytes.Equal(sharedSecretEnc, sharedSecretDec) {
		t.Error("ML-KEM shared secrets do not match")
	}
}

func TestMLKEMInvalidCiphertext(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	// Try to decapsulate invalid ciphertext (wrong size)
	_, err = crypto.MLKEMDecapsulate(kp.DecapsulationKey, []byte("short"))
	if err == nil {
		t.Error("Expected error for invalid ciphertext size")
	}
}

// --- KDF Tests ---

func TestDeriveKey(t *testing.T) {
	domain := "test-domain"
	input := []byte("test input data")

	key1, err := crypto.DeriveKey(domain, input, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Derived key size: got %d, want 32", len(key1))
	}

	// Same inputs should produce same output
	key2, err := crypto.DeriveKey(domain, input, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey not deterministic")
	}

	// Different domain should produce different output
	key3, err := crypto.DeriveKey("different-domain", input, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("Different domains should produce different keys")
	}
}

func TestDeriveKeyMultiple(t *testing.T) {
	domain := "test-domain"
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
	}

	key, err := crypto.DeriveKeyMultiple(domain, inputs, 32)
	if err != nil {
		t.Fatalf("DeriveKeyMultiple failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Derived key size: got %d, want 32", len(key))
	}
}

func TestDeriveCHKEMSecret(t *testing.T) {
	x25519Secret := make([]byte, 32)
	mlkemSecret := make([]byte, 32)
	transcriptHash := make([]byte, 32)

	// Fill with some data
	for i := range x25519Secret {
		x25519Secret[i] = byte(i)
		mlkemSecret[i] = byte(i + 32)
		transcriptHash[i] = byte(i + 64)
	}

	secret, err := crypto.DeriveCHKEMSecret(x25519Secret, mlkemSecret, transcriptHash)
	if err != nil {
		t.Fatalf("DeriveCHKEMSecret failed: %v", err)
	}

	if len(secret) != constants.CHKEMSharedSecretSize {
		t.Errorf("Derived secret size: got %d, want %d", len(secret), constants.CHKEMSharedSecretSize)
	}
}

func TestTranscriptHash(t *testing.T) {
	components := [][]byte{
		[]byte("component1"),
		[]byte("component2"),
		[]byte("component3"),
	}

	hash := crypto.TranscriptHash(components...)

	if len(hash) != 32 {
		t.Errorf("Transcript hash size: got %d, want 32", len(hash))
	}

	// Same components should produce same hash
	hash2 := crypto.TranscriptHash(components...)
	if !bytes.Equal(hash, hash2) {
		t.Error("TranscriptHash not deterministic")
	}
}

// --- AEAD Tests ---

func TestAEADAES256GCM(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	plaintext := []byte("Hello, quantum-resistant world!")
	additionalData := []byte("additional data")

	// Encrypt
	ciphertext, err := aead.Seal(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Decrypt
	decrypted, err := aead.Open(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted plaintext does not match original")
	}
}

func TestAEADChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	plaintext := []byte("Hello, quantum-resistant world!")
	additionalData := []byte("additional data")

	// Encrypt
	ciphertext, err := aead.Seal(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Decrypt
	decrypted, err := aead.Open(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted plaintext does not match original")
	}
}

func TestAEADTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	plaintext := []byte("Hello, quantum-resistant world!")
	additionalData := []byte("additional data")

	ciphertext, err := aead.Seal(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	// Decryption should fail
	_, err = aead.Open(ciphertext, additionalData)
	if err == nil {
		t.Error("Expected error for tampered ciphertext")
	}
}

func TestAEADWrongAAD(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	plaintext := []byte("Hello, quantum-resistant world!")
	additionalData := []byte("additional data")
	wrongAAD := []byte("wrong data")

	ciphertext, err := aead.Seal(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Decryption with wrong AAD should fail
	_, err = aead.Open(ciphertext, wrongAAD)
	if err == nil {
		t.Error("Expected error for wrong AAD")
	}
}

func TestAEADNonceCounter(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	// Counter should start at 0
	if aead.Counter() != 0 {
		t.Errorf("Initial counter: got %d, want 0", aead.Counter())
	}

	// Encrypt multiple messages
	for i := 0; i < 10; i++ {
		_, err := aead.Seal([]byte("test"), nil)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
	}

	// Counter should be 10
	if aead.Counter() != 10 {
		t.Errorf("Counter after 10 encryptions: got %d, want 10", aead.Counter())
	}
}

func TestAEADInvalidKeySize(t *testing.T) {
	invalidKey := make([]byte, 16) // Should be 32

	_, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestAEADSetCounter(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	// Set counter to a valid value
	err = aead.SetCounter(100)
	if err != nil {
		t.Errorf("SetCounter failed: %v", err)
	}

	if aead.Counter() != 100 {
		t.Errorf("Counter: got %d, want 100", aead.Counter())
	}

	// Set counter to max value should fail
	err = aead.SetCounter(constants.MaxPacketsBeforeRekey)
	if err == nil {
		t.Error("Expected error for counter at max")
	}
}

func TestAEADNeedsRekey(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	// Initially should not need rekey
	if aead.NeedsRekey() {
		t.Error("Fresh AEAD should not need rekey")
	}

	// Set counter to 90% of capacity
	var threshold uint64 = constants.MaxPacketsBeforeRekey * 9 / 10
	_ = aead.SetCounter(threshold)

	// Now should need rekey
	if !aead.NeedsRekey() {
		t.Error("AEAD at 90% capacity should need rekey")
	}
}

func TestAEADSuite(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	if aead.Suite() != constants.CipherSuiteAES256GCM {
		t.Errorf("Suite: got %d, want %d", aead.Suite(), constants.CipherSuiteAES256GCM)
	}

	aead2, err := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	if aead2.Suite() != constants.CipherSuiteChaCha20Poly1305 {
		t.Errorf("Suite: got %d, want %d", aead2.Suite(), constants.CipherSuiteChaCha20Poly1305)
	}
}

func TestAEADOverhead(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	overhead := aead.Overhead()
	// Overhead should be nonce size (12) + tag size (16) = 28
	if overhead != constants.AESNonceSize+constants.AESTagSize {
		t.Errorf("Overhead: got %d, want %d", overhead, constants.AESNonceSize+constants.AESTagSize)
	}
}

func TestAEADNonceSize(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	nonceSize := aead.NonceSize()
	if nonceSize != constants.AESNonceSize {
		t.Errorf("NonceSize: got %d, want %d", nonceSize, constants.AESNonceSize)
	}
}

func TestAEADUnsupportedCipherSuite(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	_, err := crypto.NewAEAD(constants.CipherSuite(0xFF), key)
	if err == nil {
		t.Error("Expected error for unsupported cipher suite")
	}
}

func TestAEADSealWithNonce(t *testing.T) {
	key := make([]byte, 32)
	_ = crypto.SecureRandom(key)

	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD failed: %v", err)
	}

	nonce := make([]byte, constants.AESNonceSize)
	_ = crypto.SecureRandom(nonce)

	plaintext := []byte("test message")
	additionalData := []byte("aad")

	ciphertext, err := aead.SealWithNonce(nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("SealWithNonce failed: %v", err)
	}

	// Decrypt with OpenWithNonce
	decrypted, err := aead.OpenWithNonce(nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("OpenWithNonce failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted plaintext does not match original")
	}

	// Test invalid nonce size
	_, err = aead.SealWithNonce([]byte("short"), plaintext, additionalData)
	if err == nil {
		t.Error("Expected error for invalid nonce size")
	}

	// Test invalid nonce size for OpenWithNonce
	_, err = aead.OpenWithNonce([]byte("short"), ciphertext, additionalData)
	if err == nil {
		t.Error("Expected error for invalid nonce size in OpenWithNonce")
	}

	// Test short ciphertext in OpenWithNonce
	_, err = aead.OpenWithNonce(nonce, []byte("short"), additionalData)
	if err == nil {
		t.Error("Expected error for short ciphertext in OpenWithNonce")
	}
}

// --- More ML-KEM Tests ---

func TestMLKEMKeyPairFromSeed(t *testing.T) {
	seed := make([]byte, 64)
	_ = crypto.SecureRandom(seed)

	kp1, err := crypto.NewMLKEMKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("NewMLKEMKeyPairFromSeed failed: %v", err)
	}

	// Same seed should produce same key pair
	kp2, err := crypto.NewMLKEMKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("NewMLKEMKeyPairFromSeed failed: %v", err)
	}

	if !bytes.Equal(kp1.PublicKeyBytes(), kp2.PublicKeyBytes()) {
		t.Error("Same seed should produce same public key")
	}

	// Invalid seed size should fail
	_, err = crypto.NewMLKEMKeyPairFromSeed([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid seed size")
	}
}

func TestMLKEMParsePublicKey(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	// Parse the public key
	parsed, err := crypto.ParseMLKEMPublicKey(kp.PublicKeyBytes())
	if err != nil {
		t.Fatalf("ParseMLKEMPublicKey failed: %v", err)
	}

	if !bytes.Equal(parsed.Bytes(), kp.PublicKeyBytes()) {
		t.Error("Parsed public key does not match original")
	}

	// Invalid public key size should fail
	_, err = crypto.ParseMLKEMPublicKey([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid public key size")
	}
}

func TestMLKEMZeroize(t *testing.T) {
	kp, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	kp.Zeroize()

	if kp.EncapsulationKey != nil {
		t.Error("EncapsulationKey should be nil after Zeroize")
	}
	if kp.DecapsulationKey != nil {
		t.Error("DecapsulationKey should be nil after Zeroize")
	}
}

// --- More X25519 Tests ---

func TestX25519KeyPairFromBytes(t *testing.T) {
	// Generate a key pair first
	original, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	// Create from bytes
	kp, err := crypto.NewX25519KeyPairFromBytes(original.PrivateKeyBytes())
	if err != nil {
		t.Fatalf("NewX25519KeyPairFromBytes failed: %v", err)
	}

	// Should produce same public key
	if !bytes.Equal(kp.PublicKeyBytes(), original.PublicKeyBytes()) {
		t.Error("Key pair from bytes should have same public key")
	}

	// Invalid key size should fail
	_, err = crypto.NewX25519KeyPairFromBytes([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid private key size")
	}
}

func TestX25519Zeroize(t *testing.T) {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	kp.Zeroize()

	if kp.PublicKey != nil {
		t.Error("PublicKey should be nil after Zeroize")
	}
	if kp.PrivateKey != nil {
		t.Error("PrivateKey should be nil after Zeroize")
	}
}

func TestX25519NilKeys(t *testing.T) {
	// Test X25519 with nil private key
	_, err := crypto.X25519(nil, nil)
	if err == nil {
		t.Error("Expected error for nil private key")
	}

	// Test X25519 with nil public key
	kp, _ := crypto.GenerateX25519KeyPair()
	_, err = crypto.X25519(kp.PrivateKey, nil)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

// --- More Random Tests ---

func TestMustSecureRandom(t *testing.T) {
	buf := make([]byte, 32)
	// Should not panic
	crypto.MustSecureRandom(buf)

	// Check that it's not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("MustSecureRandom returned all zeros")
	}
}

func TestMustSecureRandomBytes(t *testing.T) {
	buf := crypto.MustSecureRandomBytes(32)

	if len(buf) != 32 {
		t.Errorf("MustSecureRandomBytes returned %d bytes, want 32", len(buf))
	}

	// Check that it's not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("MustSecureRandomBytes returned all zeros")
	}
}
