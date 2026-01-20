package tunnel_test

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// TestTransportSendPing tests SendPing functionality.
func TestTransportSendPing(t *testing.T) {
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

	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, tunnel.DefaultTransportConfig())
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())
	defer func() { _ = clientTransport.Close() }()
	defer func() { _ = serverTransport.Close() }()

	// Send ping from client
	wg.Add(1)
	var pingErr error

	go func() {
		defer wg.Done()
		pingErr = clientTransport.SendPing()
	}()

	// Server should receive the ping and respond with pong
	// For now, this will test that SendPing doesn't panic
	time.Sleep(100 * time.Millisecond)

	wg.Wait()

	if pingErr != nil {
		t.Logf("SendPing error (expected in basic test): %v", pingErr)
	}
}

// TestTransportReceiveWithTimeout tests Receive with timeout.
func TestTransportReceiveWithTimeout(t *testing.T) {
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

	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())
	defer func() { _ = serverTransport.Close() }()

	// Set a short read timeout
	serverTransport.SetReadTimeout(100 * time.Millisecond)

	// Receive should timeout since no data is being sent
	_, err := serverTransport.Receive()
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

// TestTransportSendLargeMessage tests sending a large message (within protocol limits).
func TestTransportSendLargeMessage(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	// Create a large message (32KB - within 65KB protocol limit)
	largeData := make([]byte, 32*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	var serverErr, clientErr error
	var receivedData []byte

	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer func() { _ = conn.Close() }()

		data, err := conn.Receive()
		if err != nil {
			serverErr = err
			return
		}
		receivedData = data
	}()

	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			clientErr = err
			return
		}
		defer func() { _ = client.Close() }()

		if err := client.Send(largeData); err != nil {
			clientErr = err
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Errorf("Server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Errorf("Client error: %v", clientErr)
	}

	if !bytes.Equal(largeData, receivedData) {
		t.Errorf("Large data mismatch: got %d bytes, want %d bytes", len(receivedData), len(largeData))
	}
}

// TestTransportMultipleMessages tests sending multiple messages in sequence.
func TestTransportMultipleMessages(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()
	numMessages := 10

	var wg sync.WaitGroup
	var serverErr, clientErr error
	receivedMessages := make([][]byte, 0, numMessages)

	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer func() { _ = conn.Close() }()

		for i := 0; i < numMessages; i++ {
			data, err := conn.Receive()
			if err != nil {
				serverErr = err
				return
			}
			receivedMessages = append(receivedMessages, data)
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			clientErr = err
			return
		}
		defer func() { _ = client.Close() }()

		for i := 0; i < numMessages; i++ {
			msg := []byte{byte(i), byte(i + 1), byte(i + 2)}
			if err := client.Send(msg); err != nil {
				clientErr = err
				return
			}
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("Server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("Client error: %v", clientErr)
	}

	if len(receivedMessages) != numMessages {
		t.Fatalf("Received %d messages, want %d", len(receivedMessages), numMessages)
	}

	for i := 0; i < numMessages; i++ {
		expected := []byte{byte(i), byte(i + 1), byte(i + 2)}
		if !bytes.Equal(receivedMessages[i], expected) {
			t.Errorf("Message %d: got %v, want %v", i, receivedMessages[i], expected)
		}
	}
}

// TestTransportCloseBehavior tests transport close behavior.
func TestTransportCloseBehavior(t *testing.T) {
	clientConn, serverConn := net.Pipe()

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

	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, tunnel.DefaultTransportConfig())
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())

	// Test Close
	err := clientTransport.Close()
	if err != nil {
		t.Logf("Close returned error: %v", err)
	}

	_ = serverTransport.Close()
	_ = serverConn.Close()
	_ = clientConn.Close()
}

// TestTransportClosedConnection tests behavior when connection is closed.
func TestTransportClosedConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()

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

	clientTransport, _ := tunnel.NewTransport(clientSession, clientConn, tunnel.DefaultTransportConfig())
	serverTransport, _ := tunnel.NewTransport(serverSession, serverConn, tunnel.DefaultTransportConfig())

	// Close client connection
	_ = clientTransport.Close()
	_ = clientConn.Close()

	// Server should get error when trying to receive
	_, err := serverTransport.Receive()
	if err == nil {
		t.Error("Expected error when receiving from closed connection, got nil")
	}

	_ = serverTransport.Close()
	_ = serverConn.Close()
}

// TestTransportConcurrentSendReceive tests concurrent Send and Receive operations.
func TestTransportConcurrentSendReceive(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	errors := make(chan error, 20)
	numMessages := 10

	// Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer func() { _ = conn.Close() }()

		// Concurrent receives and sends
		var serverWg sync.WaitGroup

		// Receive messages
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			for i := 0; i < numMessages; i++ {
				_, err := conn.Receive()
				if err != nil {
					errors <- err
					return
				}
			}
		}()

		// Send messages
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			for i := 0; i < numMessages; i++ {
				msg := []byte{byte(i)}
				if err := conn.Send(msg); err != nil {
					errors <- err
					return
				}
			}
		}()

		serverWg.Wait()
	}()

	// Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			errors <- err
			return
		}
		defer func() { _ = client.Close() }()

		var clientWg sync.WaitGroup

		// Send messages
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			for i := 0; i < numMessages; i++ {
				msg := []byte{byte(i)}
				if err := client.Send(msg); err != nil {
					errors <- err
					return
				}
			}
		}()

		// Receive messages
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			for i := 0; i < numMessages; i++ {
				_, err := client.Receive()
				if err != nil {
					errors <- err
					return
				}
			}
		}()

		clientWg.Wait()
	}()

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Error during concurrent operations: %v", err)
	}
}

// TestDefaultTransportConfig tests DefaultTransportConfig.
func TestDefaultTransportConfig(t *testing.T) {
	config := tunnel.DefaultTransportConfig()

	if config.ReadTimeout == 0 {
		t.Error("DefaultTransportConfig.ReadTimeout is 0")
	}

	if config.WriteTimeout == 0 {
		t.Error("DefaultTransportConfig.WriteTimeout is 0")
	}
}
