package tunnel

import (
	"bytes"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
)

func TestTicketManager(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	tm, err := NewTicketManager(key, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create ticket manager: %v", err)
	}

	masterSecret := bytes.Repeat([]byte{0x42}, 32)
	ticket := &SessionTicket{
		Version:      1,
		CipherSuite:  constants.CipherSuiteAES256GCM,
		MasterSecret: masterSecret,
		CreatedAt:    time.Now(),
	}

	// Encrypt
	encrypted, err := tm.EncryptTicket(ticket)
	if err != nil {
		t.Fatalf("Failed to encrypt ticket: %v", err)
	}

	// Decrypt
	decrypted, err := tm.DecryptTicket(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt ticket: %v", err)
	}

	if decrypted.Version != ticket.Version {
		t.Errorf("Version mismatch: got %v, want %v", decrypted.Version, ticket.Version)
	}
	if decrypted.CipherSuite != ticket.CipherSuite {
		t.Errorf("CipherSuite mismatch: got %v, want %v", decrypted.CipherSuite, ticket.CipherSuite)
	}
	if !bytes.Equal(decrypted.MasterSecret, ticket.MasterSecret) {
		t.Errorf("MasterSecret mismatch")
	}
}

func TestTicketManagerKeyRotation(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x01}, 32)
	tm, _ := NewTicketManager(key1, time.Hour)

	masterSecret := bytes.Repeat([]byte{0x42}, 32)
	ticket := &SessionTicket{
		Version:      1,
		CipherSuite:  constants.CipherSuiteAES256GCM,
		MasterSecret: masterSecret,
		CreatedAt:    time.Now(),
	}

	encrypted1, _ := tm.EncryptTicket(ticket)

	// Rotate key
	key2 := bytes.Repeat([]byte{0x02}, 32)
	tm.RotateKey(key2)

	// Should still be able to decrypt with previous key
	decrypted, err := tm.DecryptTicket(encrypted1)
	if err != nil {
		t.Errorf("Failed to decrypt with previous key: %v", err)
	}
	if !bytes.Equal(decrypted.MasterSecret, masterSecret) {
		t.Errorf("MasterSecret mismatch after rotation")
	}

	// New tickets use new key
	encrypted2, _ := tm.EncryptTicket(ticket)
	decrypted2, err := tm.DecryptTicket(encrypted2)
	if err != nil {
		t.Errorf("Failed to decrypt with current key: %v", err)
	}
	if !bytes.Equal(decrypted2.MasterSecret, masterSecret) {
		t.Errorf("MasterSecret mismatch with current key")
	}
}

func TestTicketExpiration(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	tm, _ := NewTicketManager(key, 100*time.Millisecond)

	ticket := &SessionTicket{
		Version:      1,
		CipherSuite:  constants.CipherSuiteAES256GCM,
		MasterSecret: bytes.Repeat([]byte{0x42}, 32),
		CreatedAt:    time.Now().Add(-1 * time.Second),
	}

	encrypted, _ := tm.EncryptTicket(ticket)

	_, err := tm.DecryptTicket(encrypted)
	if err == nil {
		t.Errorf("Expected error for expired ticket, got nil")
	}
}
