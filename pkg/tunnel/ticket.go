// Package tunnel implements session resumption tickets for the CH-KEM VPN.
//
// This file (ticket.go) provides encrypted session tickets that allow
// clients to resume previous sessions without a full handshake.
package tunnel

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/crypto"
)

// SessionTicket holds the encrypted state for session resumption.
type SessionTicket struct {
	Version      uint8
	CipherSuite  constants.CipherSuite
	MasterSecret []byte
	CreatedAt    time.Time
}

// TicketManager handles encryption and decryption of session tickets.
type TicketManager struct {
	mu          sync.RWMutex
	currentKey  []byte
	previousKey []byte
	lifetime    time.Duration
}

// NewTicketManager creates a new ticket manager with the given key.
func NewTicketManager(key []byte, lifetime time.Duration) (*TicketManager, error) {
	if len(key) != 32 {
		return nil, qerrors.ErrInvalidKeySize
	}
	if lifetime == 0 {
		lifetime = 24 * time.Hour // Default 24 hours
	}
	return &TicketManager{
		currentKey: key,
		lifetime:   lifetime,
	}, nil
}

// RotateKey updates the encryption key and demotes the current key to previous.
func (tm *TicketManager) RotateKey(newKey []byte) error {
	if len(newKey) != 32 {
		return qerrors.ErrInvalidKeySize
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.previousKey = tm.currentKey
	tm.currentKey = newKey
	return nil
}

// EncryptTicket serializes and encrypts a session ticket.
func (tm *TicketManager) EncryptTicket(ticket *SessionTicket) ([]byte, error) {
	tm.mu.RLock()
	key := tm.currentKey
	tm.mu.RUnlock()

	// Serialize ticket
	// Version (1) + CipherSuite (2) + MasterSecret (32) + CreatedAt (8) = 43 bytes
	plaintext := make([]byte, 43)
	plaintext[0] = ticket.Version
	binary.BigEndian.PutUint16(plaintext[1:3], uint16(ticket.CipherSuite))
	copy(plaintext[3:35], ticket.MasterSecret)

	unixTime := ticket.CreatedAt.Unix()
	if unixTime < 0 {
		return nil, qerrors.ErrInvalidMessage
	}
	binary.BigEndian.PutUint64(plaintext[35:43], uint64(unixTime))

	// Encrypt
	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		return nil, err
	}

	return aead.Seal(plaintext, nil)
}

// DecryptTicket decrypts and deserializes a session ticket.
func (tm *TicketManager) DecryptTicket(data []byte) (*SessionTicket, error) {
	tm.mu.RLock()
	currentKey := tm.currentKey
	previousKey := tm.previousKey
	lifetime := tm.lifetime
	tm.mu.RUnlock()

	// Try current key
	plaintext, err := tm.decryptWithKey(data, currentKey)
	if err != nil && previousKey != nil {
		// Try previous key
		plaintext, err = tm.decryptWithKey(data, previousKey)
	}

	if err != nil {
		return nil, qerrors.ErrInvalidTicket
	}

	if len(plaintext) != 43 {
		return nil, qerrors.ErrInvalidTicket
	}

	unixTime := binary.BigEndian.Uint64(plaintext[35:43])
	if unixTime > 0x7FFFFFFFFFFFFFFF {
		return nil, qerrors.ErrInvalidTicket
	}

	ticket := &SessionTicket{
		Version:      plaintext[0],
		CipherSuite:  constants.CipherSuite(binary.BigEndian.Uint16(plaintext[1:3])),
		MasterSecret: make([]byte, 32),
		CreatedAt:    time.Unix(int64(unixTime), 0),
	}
	copy(ticket.MasterSecret, plaintext[3:35])

	// Check expiration
	if time.Since(ticket.CreatedAt) > lifetime {
		return nil, qerrors.ErrExpiredTicket
	}

	// In FIPS mode, reject tickets with non-FIPS approved cipher suites
	if crypto.FIPSMode() && !ticket.CipherSuite.IsFIPSApproved() {
		return nil, qerrors.ErrCipherSuiteNotFIPSApproved
	}

	return ticket, nil
}

func (tm *TicketManager) decryptWithKey(data, key []byte) ([]byte, error) {
	aead, err := crypto.NewAEAD(constants.CipherSuiteAES256GCM, key)
	if err != nil {
		return nil, err
	}
	return aead.Open(data, nil)
}
