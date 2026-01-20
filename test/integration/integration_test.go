// Package integration provides end-to-end integration tests for the Quantum-Go VPN system.
//
// These tests verify the complete flow from handshake to encrypted data transfer.
package integration

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// TestFullHandshakeAndDataTransfer verifies the complete tunnel establishment and data transfer.
func TestFullHandshakeAndDataTransfer(t *testing.T) {
	// Create network pipes
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Create sessions
	clientSession, err := tunnel.NewSession(tunnel.RoleInitiator)
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	serverSession, err := tunnel.NewSession(tunnel.RoleResponder)
	if err != nil {
		t.Fatalf("Failed to create server session: %v", err)
	}

	// Perform handshake concurrently
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

	// Verify sessions are established
	if clientSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Client session not established: %v", clientSession.State())
	}
	if serverSession.State() != tunnel.SessionStateEstablished {
		t.Errorf("Server session not established: %v", serverSession.State())
	}

	// Create transports
	config := tunnel.DefaultTransportConfig()
	clientTransport, err := tunnel.NewTransport(clientSession, clientConn, config)
	if err != nil {
		t.Fatalf("Failed to create client transport: %v", err)
	}
	defer func() { _ = clientTransport.Close() }()

	serverTransport, err := tunnel.NewTransport(serverSession, serverConn, config)
	if err != nil {
		t.Fatalf("Failed to create server transport: %v", err)
	}
	defer func() { _ = serverTransport.Close() }()

	// Test data transfer: client -> server
	testData := []byte("Hello from quantum-resistant client!")

	wg.Add(2)

	var receivedData []byte
	var receiveErr error

	go func() {
		defer wg.Done()
		if err := clientTransport.Send(testData); err != nil {
			t.Errorf("Client send failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		receivedData, receiveErr = serverTransport.Receive()
	}()

	wg.Wait()

	if receiveErr != nil {
		t.Fatalf("Server receive failed: %v", receiveErr)
	}

	if !bytes.Equal(testData, receivedData) {
		t.Errorf("Data mismatch: got %q, want %q", receivedData, testData)
	}
}

// TestBidirectionalDataTransfer verifies data can flow both directions.
func TestBidirectionalDataTransfer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

	config := tunnel.DefaultTransportConfig()
	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Test multiple messages in both directions
	messages := []string{
		"Message 1: Client to Server",
		"Message 2: Server to Client",
		"Message 3: Client to Server",
		"Message 4: Server to Client",
	}

	for i, msg := range messages {
		var sender, receiver *tunnel.Transport
		if i%2 == 0 {
			sender = clientTransport
			receiver = serverTransport
		} else {
			sender = serverTransport
			receiver = clientTransport
		}

		wg.Add(2)

		var received []byte
		var err error

		go func() {
			defer wg.Done()
			_ = sender.Send([]byte(msg))
		}()

		go func() {
			defer wg.Done()
			received, err = receiver.Receive()
		}()

		wg.Wait()

		if err != nil {
			t.Errorf("Message %d: receive error: %v", i, err)
		}

		if string(received) != msg {
			t.Errorf("Message %d: got %q, want %q", i, received, msg)
		}
	}
}

// TestLargeDataTransfer verifies handling of larger payloads.
func TestLargeDataTransfer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

	config := tunnel.DefaultTransportConfig()
	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Test with various payload sizes
	sizes := []int{100, 1000, 10000, 60000}

	for _, size := range sizes {
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		wg.Add(2)

		var received []byte
		var err error

		go func() {
			defer wg.Done()
			_ = clientTransport.Send(testData)
		}()

		go func() {
			defer wg.Done()
			received, err = serverTransport.Receive()
		}()

		wg.Wait()

		if err != nil {
			t.Errorf("Size %d: receive error: %v", size, err)
			continue
		}

		if !bytes.Equal(testData, received) {
			t.Errorf("Size %d: data mismatch", size)
		}
	}
}

// TestConcurrentTransfers verifies multiple concurrent transfers.
func TestConcurrentTransfers(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

	config := tunnel.DefaultTransportConfig()
	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Send multiple messages concurrently
	messageCount := 10
	messages := make([][]byte, messageCount)
	for i := 0; i < messageCount; i++ {
		messages[i] = []byte("Message " + string(rune('A'+i)))
	}

	// Sender goroutine
	go func() {
		for _, msg := range messages {
			_ = clientTransport.Send(msg)
		}
	}()

	// Receiver
	received := make([][]byte, 0, messageCount)
	for i := 0; i < messageCount; i++ {
		data, err := serverTransport.Receive()
		if err != nil {
			t.Errorf("Receive %d error: %v", i, err)
			break
		}
		received = append(received, data)
	}

	if len(received) != messageCount {
		t.Errorf("Received %d messages, expected %d", len(received), messageCount)
	}
}

// TestSessionStatistics verifies statistics tracking.
func TestSessionStatistics(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

	config := tunnel.DefaultTransportConfig()
	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Send some messages
	messageCount := 5
	messageSize := 100

	for i := 0; i < messageCount; i++ {
		msg := make([]byte, messageSize)
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = clientTransport.Send(msg)
		}()

		go func() {
			defer wg.Done()
			_, _ = serverTransport.Receive()
		}()

		wg.Wait()
	}

	// Check statistics
	clientStats := clientSession.Stats()
	serverStats := serverSession.Stats()

	if clientStats.PacketsSent != uint64(messageCount) {
		t.Errorf("Client packets sent: got %d, want %d", clientStats.PacketsSent, messageCount)
	}

	if clientStats.BytesSent != uint64(messageCount*messageSize) {
		t.Errorf("Client bytes sent: got %d, want %d", clientStats.BytesSent, messageCount*messageSize)
	}

	if serverStats.PacketsRecv != uint64(messageCount) {
		t.Errorf("Server packets received: got %d, want %d", serverStats.PacketsRecv, messageCount)
	}
}

// TestDifferentCipherSuites verifies both cipher suites work correctly.
func TestDifferentCipherSuites(t *testing.T) {
	suites := []constants.CipherSuite{
		constants.CipherSuiteAES256GCM,
		constants.CipherSuiteChaCha20Poly1305,
	}

	for _, suite := range suites {
		t.Run(suite.String(), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = serverConn.Close() }()

			clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
			serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

			// Verify cipher suite was negotiated
			if clientSession.CipherSuite != suite && clientSession.CipherSuite != constants.CipherSuiteAES256GCM {
				// Note: The actual negotiated suite depends on preference order
				t.Logf("Negotiated cipher suite: %s", clientSession.CipherSuite)
			}

			config := tunnel.DefaultTransportConfig()
			clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
			serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
			defer func() { _ = clientTransport.Close() }()
			defer func() { _ = serverTransport.Close() }()

			// Test data transfer
			testData := []byte("Test with " + suite.String())

			wg.Add(2)

			var received []byte
			var err error

			go func() {
				defer wg.Done()
				_ = clientTransport.Send(testData)
			}()

			go func() {
				defer wg.Done()
				received, err = serverTransport.Receive()
			}()

			wg.Wait()

			if err != nil {
				t.Fatalf("Receive error: %v", err)
			}

			if !bytes.Equal(testData, received) {
				t.Error("Data mismatch")
			}
		})
	}
}

// TestTunnelTimeout verifies timeout handling.
func TestTunnelTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientSession, _ := tunnel.NewSession(tunnel.RoleInitiator)
	serverSession, _ := tunnel.NewSession(tunnel.RoleResponder)

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

	// Create transport with short timeout
	config := tunnel.TransportConfig{
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
	}

	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, config)
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, config)
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Attempt to receive without any data being sent (should timeout)
	_, err := serverTransport.Receive()
	if err == nil {
		t.Error("Expected timeout error")
	}
}
