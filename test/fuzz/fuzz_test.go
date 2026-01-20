// Package fuzz provides fuzz tests for security-critical parsing functions.
//
// Run fuzz tests with:
//
//	go test -fuzz=FuzzParsePublicKey -fuzztime=30s ./test/fuzz/
//	go test -fuzz=FuzzParseCiphertext -fuzztime=30s ./test/fuzz/
//	go test -fuzz=FuzzDecodeClientHello -fuzztime=30s ./test/fuzz/
//	go test -fuzz=FuzzDecodeServerHello -fuzztime=30s ./test/fuzz/
//	go test -fuzz=FuzzAEADOpen -fuzztime=30s ./test/fuzz/
//
// Run all fuzz tests sequentially:
//
//	go test -fuzz=Fuzz -fuzztime=10s ./test/fuzz/
package fuzz

import (
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/chkem"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

// FuzzParsePublicKey fuzzes the CH-KEM public key parser.
// This is security-critical as it processes untrusted input from the network.
func FuzzParsePublicKey(f *testing.F) {
	// Add seed corpus
	// Valid public key
	kp, _ := chkem.GenerateKeyPair()
	f.Add(kp.PublicKey().Bytes())

	// Edge cases
	f.Add([]byte{})
	f.Add(make([]byte, constants.CHKEMPublicKeySize-1))
	f.Add(make([]byte, constants.CHKEMPublicKeySize+1))
	f.Add(make([]byte, constants.CHKEMPublicKeySize))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		pk, err := chkem.ParsePublicKey(data)
		if err != nil {
			return
		}

		// If parsing succeeded, re-serialization should match
		if pk != nil {
			reserialized := pk.Bytes()
			if len(reserialized) != constants.CHKEMPublicKeySize {
				t.Errorf("reserialized public key has wrong size: %d", len(reserialized))
			}
		}
	})
}

// FuzzParseCiphertext fuzzes the CH-KEM ciphertext parser.
func FuzzParseCiphertext(f *testing.F) {
	// Add seed corpus
	kp, _ := chkem.GenerateKeyPair()
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())
	f.Add(ct.Bytes())

	// Edge cases
	f.Add([]byte{})
	f.Add(make([]byte, constants.CHKEMCiphertextSize-1))
	f.Add(make([]byte, constants.CHKEMCiphertextSize+1))
	f.Add(make([]byte, constants.CHKEMCiphertextSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		ct, err := chkem.ParseCiphertext(data)
		if err != nil {
			return
		}

		// If parsing succeeded, re-serialization should match
		if ct != nil {
			reserialized := ct.Bytes()
			if len(reserialized) != constants.CHKEMCiphertextSize {
				t.Errorf("reserialized ciphertext has wrong size: %d", len(reserialized))
			}
		}
	})
}

// FuzzDecodeClientHello fuzzes the ClientHello decoder.
func FuzzDecodeClientHello(f *testing.F) {
	codec := protocol.NewCodec()

	// Add valid ClientHello as seed
	kp, _ := chkem.GenerateKeyPair()
	validHello := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         make([]byte, 32),
		SessionID:      nil,
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}
	_ = crypto.SecureRandom(validHello.Random)
	encoded, _ := codec.EncodeClientHello(validHello)
	f.Add(encoded)

	// Edge cases
	f.Add([]byte{})
	f.Add([]byte{0x01})                    // Just message type
	f.Add([]byte{0x01, 0, 0, 0, 0})        // Header only
	f.Add([]byte{0x01, 0xff, 0xff, 0xff, 0xff}) // Huge length

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		msg, err := codec.DecodeClientHello(data)
		if err != nil {
			return
		}

		// If decoding succeeded, validate the message
		if msg != nil {
			if err := msg.Validate(); err != nil {
				// Decoding should have caught validation errors
				t.Logf("decoded invalid message: %v", err)
			}
		}
	})
}

// FuzzDecodeServerHello fuzzes the ServerHello decoder.
func FuzzDecodeServerHello(f *testing.F) {
	codec := protocol.NewCodec()

	// Add valid ServerHello as seed
	kp, _ := chkem.GenerateKeyPair()
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())
	sessionID := make([]byte, constants.SessionIDSize)
	_ = crypto.SecureRandom(sessionID)

	validHello := &protocol.ServerHello{
		Version:         protocol.Current,
		Random:          make([]byte, 32),
		SessionID:       sessionID,
		CHKEMCiphertext: ct.Bytes(),
		CipherSuite:     constants.CipherSuiteAES256GCM,
	}
	_ = crypto.SecureRandom(validHello.Random)
	encoded, _ := codec.EncodeServerHello(validHello)
	f.Add(encoded)

	// Edge cases
	f.Add([]byte{})
	f.Add([]byte{0x02})
	f.Add([]byte{0x02, 0, 0, 0, 0})
	f.Add([]byte{0x02, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		msg, err := codec.DecodeServerHello(data)
		if err != nil {
			return
		}

		if msg != nil {
			if err := msg.Validate(); err != nil {
				t.Logf("decoded invalid message: %v", err)
			}
		}
	})
}

// FuzzDecodeData fuzzes the Data message decoder.
func FuzzDecodeData(f *testing.F) {
	codec := protocol.NewCodec()

	// Add valid Data message as seed
	validData, _ := codec.EncodeData(12345, []byte("test payload"))
	f.Add(validData)

	// Edge cases
	f.Add([]byte{})
	f.Add([]byte{0x10})
	f.Add([]byte{0x10, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1}) // Minimal valid

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		seq, payload, err := codec.DecodeData(data)
		if err != nil {
			return
		}

		// If successful, sequence should be recoverable
		_ = seq
		_ = payload
	})
}

// FuzzDecodeAlert fuzzes the Alert message decoder.
func FuzzDecodeAlert(f *testing.F) {
	codec := protocol.NewCodec()

	// Add valid Alert as seed
	validAlert := codec.EncodeAlert(protocol.AlertCodeHandshakeFailure, "test error")
	f.Add(validAlert)

	// Edge cases
	f.Add([]byte{})
	f.Add([]byte{0xF0})
	f.Add([]byte{0xF0, 0, 0, 0, 2, 0x03, 0}) // Minimal valid

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		code, desc, err := codec.DecodeAlert(data)
		if err != nil {
			return
		}
		_ = code
		_ = desc
	})
}

// FuzzAEADOpen fuzzes the AEAD decryption path.
// This is critical as it processes potentially malicious ciphertext.
func FuzzAEADOpen(f *testing.F) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)

	// Add valid ciphertext as seed
	plaintext := []byte("test plaintext data")
	validCiphertext, _ := aead.Seal(plaintext, nil)
	f.Add(validCiphertext)

	// Edge cases
	f.Add([]byte{})
	f.Add(make([]byte, constants.AESNonceSize+constants.AESTagSize-1)) // Too short
	f.Add(make([]byte, constants.AESNonceSize+constants.AESTagSize))   // Minimum size
	f.Add(make([]byte, constants.AESNonceSize+constants.AESTagSize+100))

	// Create fresh AEAD for fuzzing (to avoid nonce counter issues)
	f.Fuzz(func(t *testing.T, data []byte) {
		testAEAD, _ := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
		// Should not panic regardless of input
		_, err := testAEAD.Open(data, nil)
		if err != nil {
			// Expected for invalid ciphertext
			return
		}
	})
}

// FuzzAEADOpenChaCha20 fuzzes ChaCha20-Poly1305 decryption.
func FuzzAEADOpenChaCha20(f *testing.F) {
	key := make([]byte, 32)
	crypto.SecureRandom(key)
	aead, _ := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)

	// Add valid ciphertext as seed
	plaintext := []byte("test plaintext data")
	validCiphertext, _ := aead.Seal(plaintext, nil)
	f.Add(validCiphertext)

	f.Add([]byte{})
	f.Add(make([]byte, 28)) // Minimum size for ChaCha20-Poly1305

	f.Fuzz(func(t *testing.T, data []byte) {
		testAEAD, _ := crypto.NewAEAD(constants.CipherSuiteChaCha20Poly1305, key)
		_, _ = testAEAD.Open(data, nil)
	})
}

// FuzzDecapsulate fuzzes CH-KEM decapsulation with arbitrary ciphertext.
// ML-KEM uses implicit rejection, so this tests that behavior.
func FuzzDecapsulate(f *testing.F) {
	// Generate a key pair for decapsulation
	kp, _ := chkem.GenerateKeyPair()

	// Add valid ciphertext as seed
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())
	f.Add(ct.Bytes())

	// Edge cases
	f.Add([]byte{})
	f.Add(make([]byte, constants.CHKEMCiphertextSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		ct, err := chkem.ParseCiphertext(data)
		if err != nil {
			return
		}

		// Decapsulation should not panic even with invalid ciphertext
		// ML-KEM uses implicit rejection (returns random-looking secret)
		_, _ = chkem.Decapsulate(ct, kp)
	})
}

// FuzzMLKEMDecapsulate directly fuzzes ML-KEM decapsulation.
func FuzzMLKEMDecapsulate(f *testing.F) {
	kp, _ := crypto.GenerateMLKEMKeyPair()
	validCt, _, _ := crypto.MLKEMEncapsulate(kp.EncapsulationKey)
	f.Add(validCt)

	f.Add([]byte{})
	f.Add(make([]byte, constants.MLKEMCiphertextSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic - ML-KEM has implicit rejection
		_, _ = crypto.MLKEMDecapsulate(kp.DecapsulationKey, data)
	})
}

// FuzzX25519ParsePublicKey fuzzes X25519 public key parsing.
func FuzzX25519ParsePublicKey(f *testing.F) {
	kp, _ := crypto.GenerateX25519KeyPair()
	f.Add(kp.PublicKeyBytes())

	f.Add([]byte{})
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 33))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = crypto.ParseX25519PublicKey(data)
	})
}

// FuzzDeriveKey fuzzes the KDF with arbitrary inputs.
func FuzzDeriveKey(f *testing.F) {
	f.Add("domain", []byte("input"))
	f.Add("", []byte{})
	f.Add("test-domain-separator", make([]byte, 1000))

	f.Fuzz(func(t *testing.T, domain string, input []byte) {
		// Should not panic for any input
		key, err := crypto.DeriveKey(domain, input, 32)
		if err != nil {
			return
		}
		if len(key) != 32 {
			t.Errorf("unexpected key length: %d", len(key))
		}
	})
}
