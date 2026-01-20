package tunnel_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

func TestSessionCreation(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if session == nil {
		t.Fatal("NewSession returned nil")
	}

	if len(session.ID) != constants.SessionIDSize {
		t.Errorf("Session ID size: got %d, want %d", len(session.ID), constants.SessionIDSize)
	}

	if session.Role != tunnel.RoleInitiator {
		t.Errorf("Session role: got %d, want %d", session.Role, tunnel.RoleInitiator)
	}

	if session.State() != tunnel.SessionStateNew {
		t.Errorf("Session state: got %v, want New", session.State())
	}

	if session.LocalKeyPair == nil {
		t.Error("Session local key pair is nil")
	}
}

func TestSessionKeyInitialization(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Generate a test master secret
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)

	// Initialize keys
	err = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	if err != nil {
		t.Fatalf("InitializeKeys failed: %v", err)
	}

	if session.State() != tunnel.SessionStateEstablished {
		t.Errorf("Session state after init: got %v, want Established", session.State())
	}
}

func TestSessionEncryptDecrypt(t *testing.T) {
	// Create two sessions (initiator and responder) with same master secret
	initiator, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession (initiator) failed: %v", err)
	}

	responder, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("NewSession (responder) failed: %v", err)
	}

	// Same master secret for both
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)

	err = initiator.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	if err != nil {
		t.Fatalf("InitializeKeys (initiator) failed: %v", err)
	}

	err = responder.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	if err != nil {
		t.Fatalf("InitializeKeys (responder) failed: %v", err)
	}

	// Initiator sends to responder
	plaintext := []byte("Hello from initiator!")
	ciphertext, seq, err := initiator.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := responder.Decrypt(ciphertext, seq)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original")
	}

	// Responder sends to initiator
	plaintext2 := []byte("Hello from responder!")
	ciphertext2, seq2, err := responder.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("Encrypt (responder) failed: %v", err)
	}

	decrypted2, err := initiator.Decrypt(ciphertext2, seq2)
	if err != nil {
		t.Fatalf("Decrypt (initiator) failed: %v", err)
	}

	if !bytes.Equal(plaintext2, decrypted2) {
		t.Error("Decrypted text does not match original (responder->initiator)")
	}
}

func TestReplayProtection(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)
	session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Create a second session to decrypt (simulating receiver)
	receiver, _ := tunnel.NewSession(tunnel.RoleResponder)
	receiver.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	plaintext := []byte("test message")
	ciphertext, seq, err := session.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// First decryption should succeed
	_, err = receiver.Decrypt(ciphertext, seq)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	// Replay (same sequence number) should fail
	_, err = receiver.Decrypt(ciphertext, seq)
	if err == nil {
		t.Error("Expected replay detection error")
	}
}

func TestReplayWindow(t *testing.T) {
	rw := tunnel.NewReplayWindow()

	// Test normal sequence
	for i := uint64(0); i < 100; i++ {
		if !rw.Check(i) {
			t.Errorf("Sequence %d should be valid", i)
		}
	}

	// Test replay (already seen)
	for i := uint64(36); i < 100; i++ {
		if rw.Check(i) {
			t.Errorf("Sequence %d should be rejected as replay", i)
		}
	}

	// Test old sequence (before window)
	if rw.Check(0) {
		t.Error("Very old sequence should be rejected")
	}

	// Test future sequence (jumps ahead)
	if !rw.Check(200) {
		t.Error("Future sequence should be valid")
	}
}

func TestSessionClose(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)
	session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	session.Close()

	if session.State() != tunnel.SessionStateClosed {
		t.Errorf("Session state after close: got %v, want Closed", session.State())
	}
}

func TestSessionStats(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)
	session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Encrypt some data
	for i := 0; i < 10; i++ {
		_, _, err := session.Encrypt([]byte("test"))
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
	}

	stats := session.Stats()

	if stats.PacketsSent != 10 {
		t.Errorf("PacketsSent: got %d, want 10", stats.PacketsSent)
	}

	if stats.BytesSent != 40 { // 10 * 4 bytes
		t.Errorf("BytesSent: got %d, want 40", stats.BytesSent)
	}
}

// --- Integration Tests ---

// mockConn implements net.Conn for testing
//
//nolint:unused // Reserved for future use
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	mu       sync.Mutex
}

//nolint:unused // Reserved for future use
func newMockConnPair() (*mockConn, *mockConn) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}

	conn1 := &mockConn{
		readBuf:  buf1,
		writeBuf: buf2,
	}
	conn2 := &mockConn{
		readBuf:  buf2,
		writeBuf: buf1,
	}

	return conn1, conn2
}

//nolint:unused // Reserved for future use
func (c *mockConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return c.readBuf.Read(b)
}

//nolint:unused // Reserved for future use
func (c *mockConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return c.writeBuf.Write(b)
}

//nolint:unused // Reserved for future use
func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

//nolint:unused // Reserved for future use
func (c *mockConn) LocalAddr() net.Addr { return nil }

//nolint:unused // Reserved for future use
func (c *mockConn) RemoteAddr() net.Addr { return nil }

//nolint:unused // Reserved for future use
func (c *mockConn) SetDeadline(t time.Time) error { return nil }

//nolint:unused // Reserved for future use
func (c *mockConn) SetReadDeadline(t time.Time) error { return nil }

//nolint:unused // Reserved for future use
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHandshake(t *testing.T) {
	// Create sessions
	initiator, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession (initiator) failed: %v", err)
	}

	responder, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("NewSession (responder) failed: %v", err)
	}

	// Create pipe for communication
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Run handshakes concurrently
	var wg sync.WaitGroup
	var initiatorErr, responderErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		initiatorErr = tunnel.InitiatorHandshake(initiator, clientConn)
	}()

	go func() {
		defer wg.Done()
		responderErr = tunnel.ResponderHandshake(responder, serverConn)
	}()

	wg.Wait()

	if initiatorErr != nil {
		t.Fatalf("Initiator handshake failed: %v", initiatorErr)
	}

	if responderErr != nil {
		t.Fatalf("Responder handshake failed: %v", responderErr)
	}

	// Both sessions should be established
	if initiator.State() != tunnel.SessionStateEstablished {
		t.Errorf("Initiator state: got %v, want Established", initiator.State())
	}

	if responder.State() != tunnel.SessionStateEstablished {
		t.Errorf("Responder state: got %v, want Established", responder.State())
	}
}

func TestFullTunnel(t *testing.T) {
	// Create connected pair
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create sessions
	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	// Run handshakes
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

	serverTransport, err := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())
	if err != nil {
		t.Fatalf("NewTransport (server) failed: %v", err)
	}

	// Test bidirectional communication
	testData := []byte("Hello, quantum-resistant tunnel!")

	// Client sends
	var receiveErr error
	var received []byte

	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := clientTransport.Send(testData); err != nil {
			t.Errorf("Client send failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		received, receiveErr = serverTransport.Receive()
	}()

	wg.Wait()

	if receiveErr != nil {
		t.Fatalf("Server receive failed: %v", receiveErr)
	}

	if !bytes.Equal(testData, received) {
		t.Errorf("Received data mismatch: got %q, want %q", received, testData)
	}

	// Clean up
	clientTransport.Close()
	serverTransport.Close()
}

func TestSessionRekey(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initialize with first secret
	masterSecret1 := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret1)
	session.InitializeKeys(masterSecret1, constants.CipherSuiteAES256GCM)

	// Encrypt some data
	plaintext := []byte("before rekey")
	_, seq1, _ := session.Encrypt(plaintext)

	// Rekey with new secret
	masterSecret2 := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret2)
	err = session.Rekey(masterSecret2)
	if err != nil {
		t.Fatalf("Rekey failed: %v", err)
	}

	// Encrypt more data
	_, seq2, _ := session.Encrypt(plaintext)

	// Sequence should reset (or at least be valid)
	if seq2 < seq1 {
		t.Log("Sequence reset after rekey (expected behavior)")
	}
}

func TestNeedsRekey(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	crypto.SecureRandom(masterSecret)
	session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Initially should not need rekey
	if session.NeedsRekey() {
		t.Error("Fresh session should not need rekey")
	}
}
