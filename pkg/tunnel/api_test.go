package tunnel_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pzverkov/quantum-go/pkg/tunnel"
)

// TestDialAndListen tests the basic Dial/Listen/Accept flow.
func TestDialAndListen(t *testing.T) {
	// Start listener
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	var serverErr, clientErr error
	testData := []byte("Hello from client!")
	var receivedData []byte

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("Accept failed: %w", err)
			return
		}
		defer conn.Close()

		data, err := conn.Receive()
		if err != nil {
			serverErr = fmt.Errorf("Receive failed: %w", err)
			return
		}
		receivedData = data
	}()

	// Client goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give server time to start accepting
		time.Sleep(50 * time.Millisecond)

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			clientErr = fmt.Errorf("Dial failed: %w", err)
			return
		}
		defer client.Close()

		if err := client.Send(testData); err != nil {
			clientErr = fmt.Errorf("Send failed: %w", err)
			return
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Errorf("Server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Errorf("Client error: %v", clientErr)
	}

	if !bytes.Equal(testData, receivedData) {
		t.Errorf("Data mismatch: got %q, want %q", receivedData, testData)
	}
}

// TestDialWithConfig tests Dial with custom configuration.
func TestDialWithConfig(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)

		config := tunnel.DefaultTransportConfig()
		config.ReadTimeout = 10 * time.Second

		client, err := tunnel.DialWithConfig("tcp", addr, config)
		if err != nil {
			t.Errorf("DialWithConfig failed: %v", err)
			return
		}
		client.Close()
	}()

	wg.Wait()
}

// TestDialInvalidAddress tests Dial with invalid address.
func TestDialInvalidAddress(t *testing.T) {
	_, err := tunnel.Dial("tcp", "127.0.0.1:99999")
	if err == nil {
		t.Error("Expected error for invalid port, got nil")
	}
}

// TestDialConnectionRefused tests Dial when server is not running.
func TestDialConnectionRefused(t *testing.T) {
	// Use a port that's likely not in use
	_, err := tunnel.Dial("tcp", "127.0.0.1:54321")
	if err == nil {
		t.Error("Expected connection refused error, got nil")
	}
}

// TestListenerSetConfig tests SetConfig on listener.
func TestListenerSetConfig(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	config := tunnel.DefaultTransportConfig()
	config.WriteTimeout = 5 * time.Second
	listener.SetConfig(config)

	// Verify listener still works after SetConfig
	if listener.Addr() == nil {
		t.Error("Listener address is nil after SetConfig")
	}
}

// TestListenerAddr tests Addr method.
func TestListenerAddr(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr()
	if addr == nil {
		t.Error("Listener.Addr() returned nil")
	}

	if addr.Network() != "tcp" {
		t.Errorf("Expected network 'tcp', got %q", addr.Network())
	}
}

// TestListenerClose tests closing listener.
func TestListenerClose(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Accept should fail after close
	_, err = listener.Accept()
	if err == nil {
		t.Error("Accept should fail after Close")
	}
}

// TestMultipleClients tests multiple concurrent clients.
func TestMultipleClients(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	numClients := 5

	var wg sync.WaitGroup
	errors := make(chan error, numClients*2)
	receivedMessages := make(map[string]bool)
	var mu sync.Mutex

	// Server: accept numClients connections
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numClients; i++ {
			conn, err := listener.Accept()
			if err != nil {
				errors <- fmt.Errorf("Accept %d failed: %w", i, err)
				continue
			}

			go func(c *tunnel.Tunnel) {
				defer c.Close()
				data, err := c.Receive()
				if err != nil {
					errors <- fmt.Errorf("Receive failed: %w", err)
					return
				}
				// Track received messages (order doesn't matter)
				mu.Lock()
				receivedMessages[string(data)] = true
				mu.Unlock()
			}(conn)
		}
	}()

	// Clients
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)

			client, err := tunnel.Dial("tcp", addr)
			if err != nil {
				errors <- fmt.Errorf("Client %d dial failed: %w", clientID, err)
				return
			}
			defer client.Close()

			msg := []byte(fmt.Sprintf("Message from client %d", clientID))
			if err := client.Send(msg); err != nil {
				errors <- fmt.Errorf("Client %d send failed: %w", clientID, err)
			}
		}(i)
	}

	wg.Wait()

	// Give a bit of time for all server goroutines to process
	time.Sleep(200 * time.Millisecond)

	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Verify all messages were received
	mu.Lock()
	numReceived := len(receivedMessages)
	mu.Unlock()

	if numReceived != numClients {
		t.Errorf("Received %d messages, want %d", numReceived, numClients)
	}
	for i := 0; i < numClients; i++ {
		expected := fmt.Sprintf("Message from client %d", i)
		mu.Lock()
		received := receivedMessages[expected]
		mu.Unlock()
		if !received {
			t.Errorf("Did not receive message: %q", expected)
		}
	}
}

// TestBidirectionalCommunication tests data flowing both directions.
func TestBidirectionalCommunication(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	var serverErr, clientErr error
	clientMsg := []byte("Hello from client")
	serverMsg := []byte("Hello from server")

	// Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("Accept failed: %w", err)
			return
		}
		defer conn.Close()

		// Receive from client
		data, err := conn.Receive()
		if err != nil {
			serverErr = fmt.Errorf("Server receive failed: %w", err)
			return
		}
		if !bytes.Equal(data, clientMsg) {
			serverErr = fmt.Errorf("Server got %q, want %q", data, clientMsg)
			return
		}

		// Send to client
		if err := conn.Send(serverMsg); err != nil {
			serverErr = fmt.Errorf("Server send failed: %w", err)
		}
	}()

	// Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)

		client, err := tunnel.Dial("tcp", addr)
		if err != nil {
			clientErr = fmt.Errorf("Dial failed: %w", err)
			return
		}
		defer client.Close()

		// Send to server
		if err := client.Send(clientMsg); err != nil {
			clientErr = fmt.Errorf("Client send failed: %w", err)
			return
		}

		// Receive from server
		data, err := client.Receive()
		if err != nil {
			clientErr = fmt.Errorf("Client receive failed: %w", err)
			return
		}
		if !bytes.Equal(data, serverMsg) {
			clientErr = fmt.Errorf("Client got %q, want %q", data, serverMsg)
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Errorf("Server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Errorf("Client error: %v", clientErr)
	}
}

// TestTunnelGetters tests Transport getter methods.
func TestTunnelGetters(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	var serverTunnel, clientTunnel *tunnel.Tunnel

	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err == nil {
			serverTunnel = conn
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		client, err := tunnel.Dial("tcp", addr)
		if err == nil {
			clientTunnel = client
		}
	}()

	wg.Wait()

	if serverTunnel == nil || clientTunnel == nil {
		t.Fatal("Failed to establish tunnels")
	}
	defer serverTunnel.Close()
	defer clientTunnel.Close()

	// Test Session getter
	if serverTunnel.Session() == nil {
		t.Error("Server Session() returned nil")
	}
	if clientTunnel.Session() == nil {
		t.Error("Client Session() returned nil")
	}

	// Test LocalAddr
	if serverTunnel.LocalAddr() == nil {
		t.Error("Server LocalAddr() returned nil")
	}
	if clientTunnel.LocalAddr() == nil {
		t.Error("Client LocalAddr() returned nil")
	}

	// Test RemoteAddr
	if serverTunnel.RemoteAddr() == nil {
		t.Error("Server RemoteAddr() returned nil")
	}
	if clientTunnel.RemoteAddr() == nil {
		t.Error("Client RemoteAddr() returned nil")
	}

	// Test SetReadTimeout
	clientTunnel.SetReadTimeout(5 * time.Second)
	serverTunnel.SetReadTimeout(5 * time.Second)

	// Test SetWriteTimeout
	clientTunnel.SetWriteTimeout(5 * time.Second)
	serverTunnel.SetWriteTimeout(5 * time.Second)
}

// TestListenInvalidNetwork tests Listen with invalid network type.
func TestListenInvalidNetwork(t *testing.T) {
	_, err := tunnel.Listen("invalid", "127.0.0.1:0")
	if err == nil {
		t.Error("Expected error for invalid network type, got nil")
	}
}
