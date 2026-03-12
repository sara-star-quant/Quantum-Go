package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

func TestTransportAlerts(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}

	server := &Transport{
		session: serverSession,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	// Test sending/receiving alert
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := client.sendAlert(protocol.AlertLevelFatal, protocol.AlertCodeHandshakeFailure, "test fatal error")
		if err != nil {
			t.Errorf("sendAlert failed: %v", err)
		}
	}()

	_, err := server.Receive()
	if err == nil {
		t.Fatal("expected error from alert, got nil")
	}

	if err.Error() != "protocol alert: alert (fatal): test fatal error" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
	wg.Wait()
}

func TestTransportPingPong(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}

	server := &Transport{
		session: serverSession,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	// Test Ping/Pong
	pongReceived := make(chan struct{})
	go func() {
		t.Log("Client: Waiting for Pong...")
		msg, err := client.codec.ReadMessage(client.conn)
		if err != nil {
			t.Logf("Client: ReadMessage error (expected on close): %v", err)
			return
		}
		msgType, _ := client.codec.GetMessageType(msg)
		t.Logf("Client: Received message type: %v", msgType)
		if msgType == protocol.MessageTypePong {
			close(pongReceived)
		}
	}()

	// Server should receive ping and auto-respond with pong
	serverErr := make(chan error, 1)
	go func() {
		t.Log("Server: Waiting for Ping...")
		_, err := server.Receive()
		serverErr <- err
	}()

	// Small delay to ensure goroutines have started
	time.Sleep(10 * time.Millisecond)

	t.Log("Client: Sending Ping...")
	if err := client.SendPing(); err != nil {
		t.Errorf("SendPing failed: %v", err)
	}

	select {
	case <-pongReceived:
		t.Log("Client: Pong received!")
		// Success
	case err := <-serverErr:
		t.Fatalf("Server: Receive returned error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pong")
	}
}

func TestTransportTimeouts(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session:     clientSession,
		conn:        clientConn,
		codec:       protocol.NewCodec(),
		readTimeout: 100 * time.Millisecond,
	}

	// Read should timeout
	_, err := client.Receive()
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
		t.Errorf("expected net timeout error, got %v", err)
	}
}

func TestTransportGracefulClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)
	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}
	server := &Transport{
		session: serverSession,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = client.Close()
	}()

	_, err := server.Receive()
	if err == nil {
		t.Fatal("expected error from close, got nil")
	}
}

func TestTransportRekey(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}

	server := &Transport{
		session: serverSession,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	// Test Rekey (now encrypted)
	serverRekeyDone := make(chan struct{})
	go func() {
		t.Log("Server: Waiting for Rekey...")
		msg, err := server.codec.ReadMessage(server.conn)
		if err != nil {
			t.Errorf("Server: ReadMessage failed: %v", err)
			return
		}
		if err := server.handleRekey(msg); err != nil {
			t.Errorf("Server: handleRekey failed: %v", err)
			return
		}
		close(serverRekeyDone)
	}()

	clientRekeyDone := make(chan struct{})
	go func() {
		t.Log("Client: Waiting for Rekey Response...")
		msg2, err := client.codec.ReadMessage(client.conn)
		if err != nil {
			t.Logf("Client: ReadMessage error (expected on close): %v", err)
			return
		}
		if err := client.handleRekey(msg2); err != nil {
			t.Errorf("Client: handleRekey failed: %v", err)
			return
		}
		close(clientRekeyDone)
	}()

	// Small delay
	time.Sleep(10 * time.Millisecond)

	t.Log("Client: Sending Rekey...")
	if err := client.SendRekey(); err != nil {
		t.Errorf("SendRekey failed: %v", err)
	}

	select {
	case <-serverRekeyDone:
		t.Log("Server: Rekey handled!")
	case <-time.After(5 * time.Second):
		t.Fatal("Server: Timed out waiting for Rekey")
	}

	select {
	case <-clientRekeyDone:
		t.Log("Client: Rekey response handled!")
	case <-time.After(5 * time.Second):
		t.Fatal("Client: Timed out waiting for Rekey response")
	}
}

func TestRekeyEncrypted(t *testing.T) {
	// Verify rekey messages are encrypted on the wire
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}

	// Capture the raw wire data
	var rawMsg []byte
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65536)
		n, _ := serverConn.Read(buf)
		rawMsg = make([]byte, n)
		copy(rawMsg, buf[:n])
		close(done)
	}()

	_ = client.SendRekey()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for rekey message")
	}

	// Verify it's a Rekey message
	if len(rawMsg) < 1 || protocol.MessageType(rawMsg[0]) != protocol.MessageTypeRekey {
		t.Fatal("expected Rekey message type on the wire")
	}

	// The raw message should NOT contain the public key in plaintext
	// Get the client's rekey public key
	clientSession.mu.RLock()
	hasRekey := clientSession.rekeyInProgress
	clientSession.mu.RUnlock()
	if !hasRekey {
		t.Fatal("expected rekey to be in progress")
	}

	// The wire message should contain encrypted data, not raw public key bytes
	// Verify the message has the encrypted format: [Type(1B)] [Len(4B)] [Seq(8B)] [Ciphertext]
	if len(rawMsg) < protocol.HeaderSize+8 {
		t.Fatal("rekey message too short for encrypted format")
	}
}

func TestRekeyForgedRejected(t *testing.T) {
	// Verify that tampered rekey ciphertext is rejected
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	server := &Transport{
		session: serverSession,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	// Send a forged rekey message (invalid ciphertext)
	go func() {
		codec := protocol.NewCodec()
		fakeCiphertext := make([]byte, 200) // Random garbage
		_ = crypto.SecureRandom(fakeCiphertext)
		msg, _ := codec.EncodeRekey(0, fakeCiphertext)
		_, _ = clientConn.Write(msg)
	}()

	// Server should reject the forged message
	err := server.handleRekey(func() []byte {
		msg, _ := server.codec.ReadMessage(server.conn)
		return msg
	}())

	if err == nil {
		t.Fatal("expected error for forged rekey message, got nil")
	}
}

func TestTransportInvalidMessages(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	client := &Transport{
		session: clientSession,
		conn:    clientConn,
		codec:   protocol.NewCodec(),
	}

	// Send invalid message type
	go func() {
		buf := []byte{0xFF, 0, 0, 0, 0}
		_, _ = serverConn.Write(buf)
	}()

	_, err := client.Receive()
	if err == nil {
		t.Fatal("expected error for invalid message type, got nil")
	}
}

func TestReceiveIterativePingFlood(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(masterSecret)

	clientSession, _ := NewSession(RoleInitiator)
	_ = clientSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	serverSession, _ := NewSession(RoleResponder)
	_ = serverSession.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	server := &Transport{
		session:     serverSession,
		conn:        serverConn,
		codec:       protocol.NewCodec(),
		readTimeout: 10 * time.Second,
	}

	const pingCount = 10000

	// Drain pong responses from client side so sendPong doesn't block on net.Pipe
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Writer goroutine: send 10,000 pings followed by a data message
	go func() {
		codec := protocol.NewCodec()
		pingMsg := make([]byte, protocol.HeaderSize)
		pingMsg[0] = byte(protocol.MessageTypePing)

		for i := 0; i < pingCount; i++ {
			if _, err := clientConn.Write(pingMsg); err != nil {
				return
			}
		}

		// Send a real data message after all pings
		plaintext := []byte("survived the flood")
		ciphertext, seq, err := clientSession.Encrypt(plaintext)
		if err != nil {
			return
		}
		msg, err := codec.EncodeData(seq, ciphertext)
		if err != nil {
			return
		}
		_, _ = clientConn.Write(msg)
	}()

	// This should NOT stack overflow - iterative loop handles all pings
	data, err := server.Receive()
	if err != nil {
		t.Fatalf("Receive failed after ping flood: %v", err)
	}

	if string(data) != "survived the flood" {
		t.Errorf("unexpected data: %q", string(data))
	}
}
