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

	// Test Rekey
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

func TestTransportInvalidMessages(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

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
