package tunnel_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// TestHandshakeStateMachine verifies the handshake state transitions.
func TestHandshakeStateMachine(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession (client) failed: %v", err)
	}

	serverSession, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("NewSession (server) failed: %v", err)
	}

	// Verify initial state
	if clientSession.State() != tunnel.SessionStateNew {
		t.Errorf("Client initial state: got %v, want New", clientSession.State())
	}
	if serverSession.State() != tunnel.SessionStateNew {
		t.Errorf("Server initial state: got %v, want New", serverSession.State())
	}

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		clientErr = tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		serverErr = tunnel.ResponderHandshake(serverSession, serverConn)
	}()

	wg.Wait()

	if clientErr != nil {
		t.Fatalf("Client handshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("Server handshake failed: %v", serverErr)
	}

	// Verify final state
	if clientSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Client final state: got %v, want Established", clientSession.State())
	}
	if serverSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Server final state: got %v, want Established", serverSession.State())
	}

	// Verify session IDs match
	if !bytes.Equal(clientSession.ID, serverSession.ID) {
		t.Error("Session IDs should match after handshake")
	}

	// Verify cipher suites match
	if clientSession.CipherSuite != serverSession.CipherSuite {
		t.Errorf("Cipher suite mismatch: client=%v, server=%v",
			clientSession.CipherSuite, serverSession.CipherSuite)
	}
}

// TestHandshakeTimeout verifies that handshake respects timeouts.
func TestHandshakeTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)

	// Set a very short deadline
	_ = clientConn.SetDeadline(time.Now().Add(10 * time.Millisecond))

	// Handshake should fail because no responder
	err := tunnel.InitiatorHandshake(clientSession, clientConn)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

// TestHandshakeWithData verifies data can be sent immediately after handshake.
func TestHandshakeWithData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		tunnel.ResponderHandshake(serverSession, serverConn)
	}()

	wg.Wait()

	// Create transports
	clientTransport, err := tunnel.NewTransport(clientSession, clientConn, tunnel.DefaultTransportConfig())
	if err != nil {
		t.Fatalf("NewTransport (client) failed: %v", err)
	}
	defer clientTransport.Close()

	serverTransport, err := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())
	if err != nil {
		t.Fatalf("NewTransport (server) failed: %v", err)
	}
	defer serverTransport.Close()

	// Send data immediately after handshake
	testData := []byte("First message after handshake!")

	wg.Add(2)

	var received []byte
	var receiveErr error

	go func() {
		defer wg.Done()
		clientTransport.Send(testData)
	}()

	go func() {
		defer wg.Done()
		received, receiveErr = serverTransport.Receive()
	}()

	wg.Wait()

	if receiveErr != nil {
		t.Fatalf("Receive failed: %v", receiveErr)
	}

	if !bytes.Equal(testData, received) {
		t.Errorf("Data mismatch: got %q, want %q", received, testData)
	}
}

// TestMultipleHandshakes verifies multiple concurrent handshakes work correctly.
func TestMultipleHandshakes(t *testing.T) {
	const numPairs = 5

	var wg sync.WaitGroup
	errors := make(chan error, numPairs*2)

	for i := 0; i < numPairs; i++ {
		clientConn, serverConn := net.Pipe()

		wg.Add(2)

		go func() {
			defer wg.Done()
			defer clientConn.Close()

			clientSession, err := tunnel.NewSession(tunnel.RoleInitiator)
			if err != nil {
				errors <- err
				return
			}

			if err := tunnel.InitiatorHandshake(clientSession, clientConn); err != nil {
				errors <- err
				return
			}

			if clientSession.State() != tunnel.SessionStateEstablished {
				errors <- io.ErrUnexpectedEOF // Use as sentinel
			}
		}()

		go func() {
			defer wg.Done()
			defer serverConn.Close()

			serverSession, err := tunnel.NewSession(tunnel.RoleResponder)
			if err != nil {
				errors <- err
				return
			}

			if err := tunnel.ResponderHandshake(serverSession, serverConn); err != nil {
				errors <- err
				return
			}

			if serverSession.State() != tunnel.SessionStateEstablished {
				errors <- io.ErrUnexpectedEOF
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Handshake error: %v", err)
	}
}

// TestHandshakeEncryptedRecordFraming verifies the encrypted record framing.
func TestHandshakeEncryptedRecordFraming(t *testing.T) {
	// This test verifies that ClientFinished and ServerFinished messages
	// are properly framed with length prefixes for encrypted data.

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		clientErr = tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		serverErr = tunnel.ResponderHandshake(serverSession, serverConn)
	}()

	wg.Wait()

	// Both sides should succeed with proper framing
	if clientErr != nil {
		t.Errorf("Client handshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("Server handshake failed: %v", serverErr)
	}

	// Sessions should be established
	if clientSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Client not established: %v", clientSession.State())
	}
	if serverSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Server not established: %v", serverSession.State())
	}
}

// TestSessionKeyAgreement verifies both sides derive the same keys.
func TestSessionKeyAgreement(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		tunnel.ResponderHandshake(serverSession, serverConn)
	}()

	wg.Wait()

	// Test that data encrypted by one side can be decrypted by the other
	testData := []byte("Key agreement test data")

	// Client encrypts
	ciphertext, seq, err := clientSession.Encrypt(testData)
	if err != nil {
		t.Fatalf("Client encrypt failed: %v", err)
	}

	// Server decrypts
	plaintext, err := serverSession.Decrypt(ciphertext, seq)
	if err != nil {
		t.Fatalf("Server decrypt failed: %v", err)
	}

	if !bytes.Equal(testData, plaintext) {
		t.Error("Decrypted data doesn't match original")
	}

	// Server encrypts
	ciphertext2, seq2, err := serverSession.Encrypt(testData)
	if err != nil {
		t.Fatalf("Server encrypt failed: %v", err)
	}

	// Client decrypts
	plaintext2, err := clientSession.Decrypt(ciphertext2, seq2)
	if err != nil {
		t.Fatalf("Client decrypt failed: %v", err)
	}

	if !bytes.Equal(testData, plaintext2) {
		t.Error("Decrypted data doesn't match original (server->client)")
	}
}

// TestTransportCloseNonBlocking verifies Close() doesn't block indefinitely.
func TestTransportCloseNonBlocking(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		tunnel.ResponderHandshake(serverSession, serverConn)
	}()

	wg.Wait()

	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, tunnel.DefaultTransportConfig())
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())

	// Close both transports - this should not block
	done := make(chan struct{})

	go func() {
		clientTransport.Close()
		serverTransport.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success - Close() returned promptly
	case <-time.After(1 * time.Second):
		t.Fatal("Transport.Close() blocked for too long")
	}
}
