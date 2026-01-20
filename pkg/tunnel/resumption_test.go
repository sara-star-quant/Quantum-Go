package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSessionResumption(t *testing.T) {
	// 1. Initial full handshake
	clientSession, _ := NewSession(RoleInitiator)
	serverSession, _ := NewSession(RoleResponder)

	c1, s1 := net.Pipe()

	errChan := make(chan error, 2)

	go func() {
		errChan <- ResponderHandshake(serverSession, s1)
	}()

	err := InitiatorHandshake(clientSession, c1)
	if err != nil {
		t.Fatalf("Initial initiator handshake failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("Initial responder handshake failed: %v", err)
	}

	// 2. Export ticket on responder
	tmKey := bytes.Repeat([]byte{0x99}, 32)
	tm, _ := NewTicketManager(tmKey, time.Hour)
	ticket, err := serverSession.ExportTicket(tm)
	if err != nil {
		t.Fatalf("Failed to export ticket: %v", err)
	}

	// Initiator stores the ticket and its master secret (plaintext)
	clientSession.mu.RLock()
	ticketSecret := make([]byte, len(clientSession.masterSecret))
	copy(ticketSecret, clientSession.masterSecret)
	clientSession.mu.RUnlock()

	// 3. Resumption handshake
	clientSession2, _ := NewSession(RoleInitiator)
	serverSession2, _ := NewSession(RoleResponder)

	c2, s2 := net.Pipe()

	go func() {
		errChan <- ResponderResumptionHandshake(serverSession2, s2, tm)
	}()

	err = InitiatorResumptionHandshake(clientSession2, c2, ticket, ticketSecret)
	if err != nil {
		t.Fatalf("Resumption initiator handshake failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("Resumption responder handshake failed: %v", err)
	}

	// 4. Verify data exchange
	plaintext := []byte("hello resumption")
	ciphertext, seq, err := clientSession2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Resumed encryption failed: %v", err)
	}

	decrypted, err := serverSession2.Decrypt(ciphertext, seq)
	if err != nil {
		t.Fatalf("Resumed decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data mismatch")
	}
}

func TestSessionResumptionFallbackInvalidTicket(t *testing.T) {
	// 1. Initial full handshake to get a ticket (tampered in this case)
	clientSession, _ := NewSession(RoleInitiator)
	serverSession, _ := NewSession(RoleResponder)
	c1, s1 := net.Pipe()
	errChan := make(chan error, 2)
	go func() { errChan <- ResponderHandshake(serverSession, s1) }()
	if err := InitiatorHandshake(clientSession, c1); err != nil {
		t.Fatalf("Initial handshake failed: %v", err)
	}
	<-errChan

	tmKey := bytes.Repeat([]byte{0x99}, 32)
	tm, _ := NewTicketManager(tmKey, time.Hour)
	ticket, _ := serverSession.ExportTicket(tm)

	clientSession.mu.RLock()
	ticketSecret := make([]byte, len(clientSession.masterSecret))
	copy(ticketSecret, clientSession.masterSecret)
	clientSession.mu.RUnlock()

	// Tamper with the ticket
	ticket[len(ticket)-1] ^= 0xFF

	// 2. Resumption attempt with tampered ticket
	clientSession2, _ := NewSession(RoleInitiator)
	serverSession2, _ := NewSession(RoleResponder)
	c2, s2 := net.Pipe()

	go func() {
		errChan <- ResponderResumptionHandshake(serverSession2, s2, tm)
	}()

	// Initiator should see that server didn't echo the ticket (because it was invalid)
	// and fall back to full handshake.
	err := InitiatorResumptionHandshake(clientSession2, c2, ticket, ticketSecret)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Verify it was a full handshake (ID should be new, not the ticket)
	if bytes.Equal(clientSession2.ID, ticket) {
		t.Error("Expected full handshake fallback, but session ID equals ticket")
	}
}

func TestSessionResumptionExpiredTicket(t *testing.T) {
	clientSession, _ := NewSession(RoleInitiator)
	serverSession, _ := NewSession(RoleResponder)
	c1, s1 := net.Pipe()
	errChan := make(chan error, 2)
	go func() { errChan <- ResponderHandshake(serverSession, s1) }()
	if err := InitiatorHandshake(clientSession, c1); err != nil {
		t.Fatalf("Initial handshake failed: %v", err)
	}
	<-errChan

	tmKey := bytes.Repeat([]byte{0x99}, 32)
	// Very short lifetime
	tm, _ := NewTicketManager(tmKey, 1*time.Millisecond)
	ticket, _ := serverSession.ExportTicket(tm)

	clientSession.mu.RLock()
	ticketSecret := make([]byte, len(clientSession.masterSecret))
	copy(ticketSecret, clientSession.masterSecret)
	clientSession.mu.RUnlock()

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	clientSession2, _ := NewSession(RoleInitiator)
	serverSession2, _ := NewSession(RoleResponder)
	c2, s2 := net.Pipe()

	go func() {
		errChan <- ResponderResumptionHandshake(serverSession2, s2, tm)
	}()

	err := InitiatorResumptionHandshake(clientSession2, c2, ticket, ticketSecret)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Verify fallback
	if bytes.Equal(clientSession2.ID, ticket) {
		t.Error("Expected full handshake fallback for expired ticket")
	}
}

func TestSessionResumptionFallbackNoTicketManager(t *testing.T) {
	clientSession, _ := NewSession(RoleInitiator)
	serverSession, _ := NewSession(RoleResponder)
	c1, s1 := net.Pipe()
	errChan := make(chan error, 2)
	go func() { errChan <- ResponderHandshake(serverSession, s1) }()
	if err := InitiatorHandshake(clientSession, c1); err != nil {
		t.Fatalf("Initial handshake failed: %v", err)
	}
	<-errChan

	tmKey := bytes.Repeat([]byte{0x99}, 32)
	tm, _ := NewTicketManager(tmKey, time.Hour)
	ticket, _ := serverSession.ExportTicket(tm)

	clientSession.mu.RLock()
	ticketSecret := make([]byte, len(clientSession.masterSecret))
	copy(ticketSecret, clientSession.masterSecret)
	clientSession.mu.RUnlock()

	clientSession2, _ := NewSession(RoleInitiator)
	serverSession2, _ := NewSession(RoleResponder)
	c2, s2 := net.Pipe()

	go func() {
		// Server intentionally NOT setting ticket manager
		errChan <- ResponderResumptionHandshake(serverSession2, s2, nil)
	}()

	err := InitiatorResumptionHandshake(clientSession2, c2, ticket, ticketSecret)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Verify fallback
	if bytes.Equal(clientSession2.ID, ticket) {
		t.Error("Expected full handshake fallback when no ticket manager on server")
	}
}
