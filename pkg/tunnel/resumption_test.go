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

	// 4. Verify bidirectional data exchange
	// Client -> Server
	plaintext := []byte("hello resumption")
	ciphertext, seq, err := clientSession2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Resumed encryption (client->server) failed: %v", err)
	}

	decrypted, err := serverSession2.Decrypt(ciphertext, seq)
	if err != nil {
		t.Fatalf("Resumed decryption (client->server) failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data mismatch (client->server)")
	}

	// Server -> Client
	plaintext2 := []byte("hello back from server")
	ciphertext2, seq2, err := serverSession2.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("Resumed encryption (server->client) failed: %v", err)
	}

	decrypted2, err := clientSession2.Decrypt(ciphertext2, seq2)
	if err != nil {
		t.Fatalf("Resumed decryption (server->client) failed: %v", err)
	}

	if !bytes.Equal(decrypted2, plaintext2) {
		t.Errorf("Decrypted data mismatch (server->client)")
	}

	// 5. Verify resumed session uses different keys than original
	clientSession.mu.RLock()
	origSecret := make([]byte, len(clientSession.masterSecret))
	copy(origSecret, clientSession.masterSecret)
	clientSession.mu.RUnlock()

	clientSession2.mu.RLock()
	resumedSecret := make([]byte, len(clientSession2.masterSecret))
	copy(resumedSecret, clientSession2.masterSecret)
	clientSession2.mu.RUnlock()

	if bytes.Equal(origSecret, resumedSecret) {
		t.Error("resumed session should use different master secret than original (fresh KEM exchange)")
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

func TestResumptionForwardSecrecy(t *testing.T) {
	// Verify that compromise of ticket key alone is insufficient
	// The resumed session's secret should depend on both PSK and fresh KEM

	// 1. Full handshake
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

	// 2. Two separate resumptions with the same ticket
	var secrets [2][]byte
	for i := 0; i < 2; i++ {
		cs, _ := NewSession(RoleInitiator)
		ss, _ := NewSession(RoleResponder)
		c, s := net.Pipe()

		go func() { errChan <- ResponderResumptionHandshake(ss, s, tm) }()
		if err := InitiatorResumptionHandshake(cs, c, ticket, ticketSecret); err != nil {
			t.Fatalf("Resumption %d failed: %v", i, err)
		}
		if err := <-errChan; err != nil {
			t.Fatalf("Resumption %d (responder) failed: %v", i, err)
		}

		cs.mu.RLock()
		secrets[i] = make([]byte, len(cs.masterSecret))
		copy(secrets[i], cs.masterSecret)
		cs.mu.RUnlock()
	}

	// Each resumption should produce a unique master secret
	// (because each uses a fresh KEM exchange)
	if bytes.Equal(secrets[0], secrets[1]) {
		t.Error("two resumptions with the same ticket should produce different secrets (fresh KEM)")
	}
}
