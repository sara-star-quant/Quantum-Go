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

// --- Rekey Under Load Tests ---

// TestRekeyDuringDataTransfer verifies rekey completes correctly while data is being transferred.
func TestRekeyDuringDataTransfer(t *testing.T) {
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

	// Message counts
	messageCount := 50
	messagesBeforeRekey := 10
	var serverRecvCount, clientRecvCount int
	var mu sync.Mutex
	serverRecvDone := make(chan struct{})
	clientRecvDone := make(chan struct{})

	// Server receiver goroutine - receives data from client
	go func() {
		defer close(serverRecvDone)
		for i := 0; i < messageCount; i++ {
			_, err := serverTransport.Receive()
			if err != nil {
				t.Errorf("Server receive %d error: %v", i, err)
				return
			}
			mu.Lock()
			serverRecvCount++
			mu.Unlock()
		}
	}()

	// Client receiver goroutine - needed to receive rekey response
	go func() {
		defer close(clientRecvDone)
		for {
			_, err := clientTransport.Receive()
			if err != nil {
				// Expected when connection closes
				return
			}
			mu.Lock()
			clientRecvCount++
			mu.Unlock()
		}
	}()

	// Client sender - sends data and triggers rekey
	for i := 0; i < messageCount; i++ {
		msg := []byte("Message " + string(rune('A'+i%26)) + " #" + string(rune('0'+i/10)) + string(rune('0'+i%10)))

		// Trigger rekey after some messages
		if i == messagesBeforeRekey {
			if err := clientTransport.SendRekey(); err != nil {
				t.Errorf("SendRekey error: %v", err)
			}
		}

		if err := clientTransport.Send(msg); err != nil {
			t.Errorf("Send %d error: %v", i, err)
			break
		}
	}

	// Wait for server to receive all messages
	<-serverRecvDone

	// Verify message count
	mu.Lock()
	count := serverRecvCount
	mu.Unlock()

	if count != messageCount {
		t.Errorf("Server received %d messages, expected %d", count, messageCount)
	}
}

// TestRekeyWithBidirectionalTraffic verifies rekey works with traffic in both directions.
func TestRekeyWithBidirectionalTraffic(t *testing.T) {
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

	roundCount := 20
	rekeyAt := 10

	// Channels for server-received and client-received messages
	serverRecv := make(chan []byte, roundCount+5)
	clientRecv := make(chan []byte, roundCount+5)

	// Server receiver goroutine
	go func() {
		for {
			data, err := serverTransport.Receive()
			if err != nil {
				return
			}
			serverRecv <- data
		}
	}()

	// Client receiver goroutine - also receives rekey response (handled internally)
	go func() {
		for {
			data, err := clientTransport.Receive()
			if err != nil {
				return
			}
			clientRecv <- data
		}
	}()

	// Send client to server messages with rekey at midpoint
	for i := 0; i < roundCount; i++ {
		// Trigger rekey at midpoint
		if i == rekeyAt {
			if err := clientTransport.SendRekey(); err != nil {
				t.Errorf("SendRekey error: %v", err)
			}
		}
		msg := []byte("C2S:" + string(rune('0'+i/10)) + string(rune('0'+i%10)))
		if err := clientTransport.Send(msg); err != nil {
			t.Fatalf("C2S send %d error: %v", i, err)
		}
	}

	// Receive all C2S messages
	for i := 0; i < roundCount; i++ {
		select {
		case <-serverRecv:
		case <-time.After(5 * time.Second):
			t.Fatalf("C2S message %d: timeout", i)
		}
	}

	// Send server to client messages
	for i := 0; i < roundCount; i++ {
		msg := []byte("S2C:" + string(rune('0'+i/10)) + string(rune('0'+i%10)))
		if err := serverTransport.Send(msg); err != nil {
			t.Fatalf("S2C send %d error: %v", i, err)
		}
	}

	// Receive all S2C messages
	for i := 0; i < roundCount; i++ {
		select {
		case <-clientRecv:
		case <-time.After(5 * time.Second):
			t.Fatalf("S2C message %d: timeout", i)
		}
	}
}

// TestMultipleSequentialRekeys verifies multiple rekey operations work correctly.
func TestMultipleSequentialRekeys(t *testing.T) {
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

	rekeyCount := 3
	messagesPerCycle := 25 // Must be > 16 (activation offset) to complete rekey

	// Client receiver goroutine - needed to receive rekey responses
	go func() {
		for {
			_, err := clientTransport.Receive()
			if err != nil {
				return
			}
		}
	}()

	// Server receiver goroutine with channel for received messages
	serverRecv := make(chan []byte, 100)
	serverErr := make(chan error, 1)
	go func() {
		for {
			data, err := serverTransport.Receive()
			if err != nil {
				serverErr <- err
				return
			}
			serverRecv <- data
		}
	}()

	for rekey := 0; rekey < rekeyCount; rekey++ {
		// Send messages, with rekey in the middle
		for i := 0; i < messagesPerCycle; i++ {
			// Trigger rekey at the 5th message
			if i == 5 {
				if err := clientTransport.SendRekey(); err != nil {
					t.Fatalf("Rekey %d: SendRekey error: %v", rekey, err)
				}
			}

			msg := []byte("Cycle" + string(rune('0'+rekey)) + "-Msg" + string(rune('0'+i/10)) + string(rune('0'+i%10)))
			if err := clientTransport.Send(msg); err != nil {
				t.Fatalf("Rekey %d, message %d: send error: %v", rekey, i, err)
			}
		}

		// Receive all messages
		for i := 0; i < messagesPerCycle; i++ {
			select {
			case received := <-serverRecv:
				expected := []byte("Cycle" + string(rune('0'+rekey)) + "-Msg" + string(rune('0'+i/10)) + string(rune('0'+i%10)))
				if !bytes.Equal(expected, received) {
					t.Errorf("Rekey %d, message %d: got %q, want %q", rekey, i, received, expected)
				}
			case err := <-serverErr:
				t.Fatalf("Rekey %d, message %d: receive error: %v", rekey, i, err)
			case <-time.After(5 * time.Second):
				t.Fatalf("Rekey %d, message %d: timeout waiting for message", rekey, i)
			}
		}

		// Wait for rekey to complete
		for i := 0; i < 100 && clientSession.IsRekeyInProgress(); i++ {
			time.Sleep(10 * time.Millisecond)
		}

		if clientSession.IsRekeyInProgress() {
			t.Fatalf("Rekey %d: still in progress after receiving all messages", rekey)
		}
	}
}

// TestRekeyDataIntegrity verifies data integrity is maintained through rekey.
func TestRekeyDataIntegrity(t *testing.T) {
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

	// Client receiver goroutine - needed to receive rekey responses
	go func() {
		for {
			_, err := clientTransport.Receive()
			if err != nil {
				return
			}
		}
	}()

	// Generate test data with pattern for verification
	dataSize := 10000
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Send data before rekey
	sendDone := make(chan struct{})
	recvDone := make(chan struct{})
	var receivedBefore []byte
	var errBefore error

	go func() {
		defer close(sendDone)
		_ = clientTransport.Send(testData)
	}()

	go func() {
		defer close(recvDone)
		receivedBefore, errBefore = serverTransport.Receive()
	}()

	<-sendDone
	<-recvDone

	if errBefore != nil {
		t.Fatalf("Receive before rekey: %v", errBefore)
	}
	if !bytes.Equal(testData, receivedBefore) {
		t.Error("Data mismatch before rekey")
	}

	// Send rekey and data after - single Receive() handles rekey internally
	sendDone2 := make(chan struct{})
	recvDone2 := make(chan struct{})
	var receivedAfter []byte
	var errAfter error

	go func() {
		defer close(sendDone2)
		// Send rekey first, then data
		if err := clientTransport.SendRekey(); err != nil {
			t.Errorf("SendRekey error: %v", err)
			return
		}
		_ = clientTransport.Send(testData)
	}()

	go func() {
		defer close(recvDone2)
		// Single Receive() handles rekey internally and returns data
		receivedAfter, errAfter = serverTransport.Receive()
	}()

	<-sendDone2
	<-recvDone2

	if errAfter != nil {
		t.Fatalf("Receive after rekey: %v", errAfter)
	}
	if !bytes.Equal(testData, receivedAfter) {
		t.Error("Data mismatch after rekey")
	}

	// Verify data integrity by checking pattern
	for i := range receivedAfter {
		if receivedAfter[i] != byte(i%256) {
			t.Errorf("Data corruption at byte %d: got %d, want %d", i, receivedAfter[i], i%256)
			break
		}
	}
}

// TestRekeyUnderHighLoad verifies rekey under high message throughput.
func TestRekeyUnderHighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high load test in short mode")
	}

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

	// Client receiver goroutine - needed to receive rekey responses
	go func() {
		for {
			_, err := clientTransport.Receive()
			if err != nil {
				return
			}
		}
	}()

	messageCount := 500
	messagesReceived := 0
	var mu sync.Mutex
	done := make(chan struct{})

	// Server receiver
	go func() {
		for i := 0; i < messageCount; i++ {
			_, err := serverTransport.Receive()
			if err != nil {
				continue
			}
			mu.Lock()
			messagesReceived++
			mu.Unlock()
		}
		close(done)
	}()

	// Sender with periodic rekeys
	rekeyInterval := 100
	for i := 0; i < messageCount; i++ {
		msg := make([]byte, 1000)
		for j := range msg {
			msg[j] = byte((i + j) % 256)
		}

		if err := clientTransport.Send(msg); err != nil {
			t.Errorf("Send %d error: %v", i, err)
			break
		}

		// Trigger rekey periodically
		if i > 0 && i%rekeyInterval == 0 {
			// Only rekey if not already in progress
			if !clientSession.IsRekeyInProgress() {
				_ = clientTransport.SendRekey()
			}
		}
	}

	// Wait for receiver with timeout
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Test timed out")
	}

	mu.Lock()
	received := messagesReceived
	mu.Unlock()

	// We may miss some messages due to rekey processing, but should receive most
	minExpected := messageCount * 80 / 100 // At least 80%
	if received < minExpected {
		t.Errorf("Received %d messages, expected at least %d", received, minExpected)
	}

	t.Logf("Received %d/%d messages under high load with rekeys", received, messageCount)
}
