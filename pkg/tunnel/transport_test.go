package tunnel

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
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

func TestRekeyEncrypted(t *testing.T) {
	// Verify rekey messages are encrypted on the wire and the public key
	// is NOT visible in plaintext
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

	// Get the public key that will be used for rekey BEFORE sending,
	// so we can verify it doesn't appear in plaintext on the wire
	rekeyPubKey, _, err := clientSession.InitiateRekey()
	if err != nil {
		t.Fatalf("InitiateRekey failed: %v", err)
	}

	// Reset state so SendRekey can initiate again
	clientSession.mu.Lock()
	clientSession.rekeyInProgress = false
	clientSession.pendingRekeyKeyPair = nil
	clientSession.SetState(SessionStateEstablished)
	clientSession.mu.Unlock()

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

	// Verify it's a Rekey message with encrypted format
	if len(rawMsg) < 1 || protocol.MessageType(rawMsg[0]) != protocol.MessageTypeRekey {
		t.Fatal("expected Rekey message type on the wire")
	}
	if len(rawMsg) < protocol.HeaderSize+8 {
		t.Fatal("rekey message too short for encrypted format")
	}

	// The raw wire message must NOT contain the public key in plaintext.
	// Take a significant chunk of the public key (first 64 bytes) and
	// verify it doesn't appear anywhere in the wire message payload.
	pubKeyPrefix := rekeyPubKey[:64]
	wirePayload := rawMsg[protocol.HeaderSize:]
	if bytes.Contains(wirePayload, pubKeyPrefix) {
		t.Fatal("public key is visible in plaintext on the wire - rekey message is NOT encrypted")
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

func TestRekeyThenDataExchange(t *testing.T) {
	// End-to-end: perform encrypted rekey, then verify data exchange works after
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
		session:      clientSession,
		conn:         clientConn,
		codec:        protocol.NewCodec(),
		writeTimeout: 5 * time.Second,
	}

	server := &Transport{
		session:      serverSession,
		conn:         serverConn,
		codec:        protocol.NewCodec(),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}

	// Step 1: Send data before rekey
	preRekeyData := []byte("before rekey")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := server.Receive()
		if err != nil {
			t.Errorf("pre-rekey Receive failed: %v", err)
			return
		}
		if !bytes.Equal(data, preRekeyData) {
			t.Errorf("pre-rekey data mismatch: got %q", data)
		}
	}()

	if err := client.Send(preRekeyData); err != nil {
		t.Fatalf("pre-rekey Send failed: %v", err)
	}
	wg.Wait()

	// Step 2: Perform rekey
	serverRekeyDone := make(chan error, 1)
	go func() {
		msg, err := server.codec.ReadMessage(server.conn)
		if err != nil {
			serverRekeyDone <- err
			return
		}
		serverRekeyDone <- server.handleRekey(msg)
	}()

	clientRekeyDone := make(chan error, 1)
	go func() {
		msg, err := client.codec.ReadMessage(client.conn)
		if err != nil {
			clientRekeyDone <- err
			return
		}
		clientRekeyDone <- client.handleRekey(msg)
	}()

	if err := client.SendRekey(); err != nil {
		t.Fatalf("SendRekey failed: %v", err)
	}

	if err := <-serverRekeyDone; err != nil {
		t.Fatalf("server handleRekey failed: %v", err)
	}
	if err := <-clientRekeyDone; err != nil {
		t.Fatalf("client handleRekey failed: %v", err)
	}

	// Force key activation
	clientSession.ActivatePendingKeys()
	serverSession.ActivatePendingKeys()

	// Step 3: Send data after rekey (client -> server) - should work with new keys
	postRekeyData := []byte("after rekey")
	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := server.Receive()
		if err != nil {
			t.Errorf("post-rekey Receive failed: %v", err)
			return
		}
		if !bytes.Equal(data, postRekeyData) {
			t.Errorf("post-rekey data mismatch: got %q", data)
		}
	}()

	if err := client.Send(postRekeyData); err != nil {
		t.Fatalf("post-rekey Send failed: %v", err)
	}
	wg.Wait()

	// Step 4: Send data after rekey (server -> client) - bidirectional verification
	reverseData := []byte("server to client after rekey")
	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := client.Receive()
		if err != nil {
			t.Errorf("reverse post-rekey Receive failed: %v", err)
			return
		}
		if !bytes.Equal(data, reverseData) {
			t.Errorf("reverse post-rekey data mismatch: got %q", data)
		}
	}()

	if err := server.Send(reverseData); err != nil {
		t.Fatalf("reverse post-rekey Send failed: %v", err)
	}
	wg.Wait()
}
