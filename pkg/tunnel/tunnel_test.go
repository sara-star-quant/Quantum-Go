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
	_ = crypto.SecureRandom(masterSecret)

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
	_ = crypto.SecureRandom(masterSecret)

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
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Create a second session to decrypt (simulating receiver)
	receiver, _ := tunnel.NewSession(tunnel.RoleResponder)
	_ = receiver.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

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
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

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
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

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
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

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
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Create sessions
	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

	// Run handshakes
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = tunnel.InitiatorHandshake(clientSession, clientConn)
	}()

	go func() {
		defer wg.Done()
		_ = tunnel.ResponderHandshake(serverSession, serverConn)
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
	_ = clientTransport.Close()
	_ = serverTransport.Close()
}

func TestSessionRekey(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initialize with first secret
	masterSecret1 := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret1)
	_ = session.InitializeKeys(masterSecret1, constants.CipherSuiteAES256GCM)

	// Encrypt some data
	plaintext := []byte("before rekey")
	_, seq1, _ := session.Encrypt(plaintext)

	// Rekey with new secret
	masterSecret2 := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret2)
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
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Initially should not need rekey
	if session.NeedsRekey() {
		t.Error("Fresh session should not need rekey")
	}
}

// --- SessionState Tests ---

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state    tunnel.SessionState
		expected string
	}{
		{tunnel.SessionStateNew, "New"},
		{tunnel.SessionStateHandshaking, "Handshaking"},
		{tunnel.SessionStateEstablished, "Established"},
		{tunnel.SessionStateRekeying, "Rekeying"},
		{tunnel.SessionStateClosed, "Closed"},
		{tunnel.SessionState(99), "Unknown"},
	}

	for _, tc := range tests {
		if tc.state.String() != tc.expected {
			t.Errorf("SessionState(%d).String() = %q, want %q", tc.state, tc.state.String(), tc.expected)
		}
	}
}

// --- Role Tests ---

func TestRoleConstants(t *testing.T) {
	// Verify roles are distinct
	if tunnel.RoleInitiator == tunnel.RoleResponder {
		t.Error("RoleInitiator and RoleResponder should be distinct")
	}

	// Test creating sessions with both roles
	initiator, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession (initiator) failed: %v", err)
	}
	if initiator.Role != tunnel.RoleInitiator {
		t.Errorf("Initiator role: got %d, want %d", initiator.Role, tunnel.RoleInitiator)
	}

	responder, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("NewSession (responder) failed: %v", err)
	}
	if responder.Role != tunnel.RoleResponder {
		t.Errorf("Responder role: got %d, want %d", responder.Role, tunnel.RoleResponder)
	}
}

// --- Session Edge Cases ---

func TestSessionEncryptBeforeEstablished(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Try to encrypt before session is established
	_, _, err = session.Encrypt([]byte("test"))
	if err == nil {
		t.Error("Expected error when encrypting before session is established")
	}
}

func TestSessionDecryptBeforeEstablished(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Try to decrypt before session is established
	_, err = session.Decrypt([]byte("test"), 0)
	if err == nil {
		t.Error("Expected error when decrypting before session is established")
	}
}

func TestSessionInitializeKeysInvalidCipherSuite(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	// Try with invalid cipher suite
	err = session.InitializeKeys(masterSecret, constants.CipherSuite(0xFF))
	if err == nil {
		t.Error("Expected error for invalid cipher suite")
	}
}

// --- Rekey Protocol Tests ---

func TestSessionInitiateRekey(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initialize keys first
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Initiate rekey
	newPublicKey, activationSeq, err := session.InitiateRekey()
	if err != nil {
		t.Fatalf("InitiateRekey failed: %v", err)
	}

	if len(newPublicKey) != constants.CHKEMPublicKeySize {
		t.Errorf("new public key size: got %d, want %d", len(newPublicKey), constants.CHKEMPublicKeySize)
	}

	if activationSeq == 0 {
		t.Error("activation sequence should not be 0")
	}

	if !session.IsRekeyInProgress() {
		t.Error("session should be in rekeying state")
	}

	if session.State() != tunnel.SessionStateRekeying {
		t.Errorf("session state: got %v, want Rekeying", session.State())
	}

	// Trying to initiate again should fail
	_, _, err = session.InitiateRekey()
	if err == nil {
		t.Error("expected error when initiating rekey while already in progress")
	}
}

func TestSessionInitiateRekeyBeforeEstablished(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Don't initialize keys - session not established
	_, _, err = session.InitiateRekey()
	if err == nil {
		t.Error("expected error when initiating rekey before session established")
	}
}

func TestSessionRekeyFullFlow(t *testing.T) {
	// Create initiator and responder sessions
	initiator, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession (initiator) failed: %v", err)
	}

	responder, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("NewSession (responder) failed: %v", err)
	}

	// Initialize with same master secret
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = initiator.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	_ = responder.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	// Step 1: Initiator starts rekey
	newPublicKey, activationSeq, err := initiator.InitiateRekey()
	if err != nil {
		t.Fatalf("InitiateRekey failed: %v", err)
	}

	// Step 2: Responder processes rekey request and generates response
	ciphertext, err := responder.PrepareRekeyResponse(newPublicKey, activationSeq)
	if err != nil {
		t.Fatalf("PrepareRekeyResponse failed: %v", err)
	}

	if len(ciphertext) != constants.CHKEMCiphertextSize {
		t.Errorf("ciphertext size: got %d, want %d", len(ciphertext), constants.CHKEMCiphertextSize)
	}

	// Step 3: Initiator processes response
	err = initiator.ProcessRekeyResponse(ciphertext)
	if err != nil {
		t.Fatalf("ProcessRekeyResponse failed: %v", err)
	}

	// Step 4: Both activate pending keys
	initiator.ActivatePendingKeys()
	responder.ActivatePendingKeys()

	// Verify both are back to established state
	if initiator.State() != tunnel.SessionStateEstablished {
		t.Errorf("initiator state: got %v, want Established", initiator.State())
	}
	if responder.State() != tunnel.SessionStateEstablished {
		t.Errorf("responder state: got %v, want Established", responder.State())
	}

	// Verify rekey is no longer in progress
	if initiator.IsRekeyInProgress() {
		t.Error("initiator should not be in rekey progress")
	}
	if responder.IsRekeyInProgress() {
		t.Error("responder should not be in rekey progress")
	}

	// Test that encryption/decryption still works after rekey
	plaintext := []byte("Test message after rekey")
	ciphertextMsg, seq, err := initiator.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt after rekey failed: %v", err)
	}

	decrypted, err := responder.Decrypt(ciphertextMsg, seq)
	if err != nil {
		t.Fatalf("Decrypt after rekey failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted message doesn't match after rekey")
	}
}

func TestIsRekeyInProgress(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initially not in progress
	if session.IsRekeyInProgress() {
		t.Error("new session should not be in rekey progress")
	}

	// Initialize and start rekey
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	_, _, _ = session.InitiateRekey()

	if !session.IsRekeyInProgress() {
		t.Error("session should be in rekey progress after InitiateRekey")
	}
}

func TestGetRekeyActivationSeq(t *testing.T) {
	session, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initially 0
	if session.GetRekeyActivationSeq() != 0 {
		t.Error("new session should have 0 activation seq")
	}

	// Initialize and start rekey
	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)
	_ = session.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	_, activationSeq, _ := session.InitiateRekey()

	if session.GetRekeyActivationSeq() != activationSeq {
		t.Errorf("activation seq: got %d, want %d", session.GetRekeyActivationSeq(), activationSeq)
	}
}
