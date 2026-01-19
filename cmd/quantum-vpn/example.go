package main

import (
	"fmt"
	"strings"
)

func showExamples() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║      Quantum-Go: Interactive Examples                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	examples := []struct {
		title       string
		description string
		code        string
	}{
		{
			title:       "Example 1: Basic Server/Client",
			description: "Simple echo server and client using the high-level tunnel API",
			code: `package main

import (
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // SERVER
    listener, _ := tunnel.Listen("tcp", ":8443")
    defer listener.Close()

    go func() {
        for {
            conn, _ := listener.Accept()
            go func(t *tunnel.Tunnel) {
                defer t.Close()
                data, _ := t.Receive()
                fmt.Printf("Received: %s\n", data)
                t.Send([]byte("Echo: " + string(data)))
            }(conn)
        }
    }()

    // CLIENT
    client, _ := tunnel.Dial("tcp", "localhost:8443")
    defer client.Close()

    client.Send([]byte("Hello, quantum world!"))
    response, _ := client.Receive()
    fmt.Printf("Server replied: %s\n", response)
}`,
		},
		{
			title:       "Example 2: Low-Level CH-KEM API",
			description: "Direct use of the Cascaded Hybrid KEM for key encapsulation",
			code: `package main

import (
    "bytes"
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/chkem"
)

func main() {
    // RECIPIENT: Generate key pair
    keyPair, _ := chkem.GenerateKeyPair()
    publicKey := keyPair.PublicKey()

    // SENDER: Encapsulate to create shared secret
    ciphertext, sharedSecretSender, _ := chkem.Encapsulate(publicKey)

    // RECIPIENT: Decapsulate to recover shared secret
    sharedSecretRecipient, _ := chkem.Decapsulate(ciphertext, keyPair)

    // Both now have the same 32-byte secret
    fmt.Printf("Secrets match: %v\n",
        bytes.Equal(sharedSecretSender, sharedSecretRecipient))

    // Key sizes
    fmt.Printf("Public key: %d bytes\n", len(publicKey.Bytes()))
    fmt.Printf("Ciphertext: %d bytes\n", len(ciphertext.Bytes()))
    fmt.Printf("Shared secret: %d bytes\n", len(sharedSecretSender))
}`,
		},
		{
			title:       "Example 3: Custom Configuration",
			description: "Using custom transport configuration with timeouts",
			code: `package main

import (
    "time"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // Custom configuration
    config := tunnel.TransportConfig{
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    }

    // Dial with custom config
    client, _ := tunnel.DialWithConfig("tcp", "server:8443", config)
    defer client.Close()

    // Set per-operation timeouts
    client.SetReadTimeout(5 * time.Second)
    client.SetWriteTimeout(5 * time.Second)

    client.Send([]byte("Request"))
    response, _ := client.Receive()
}`,
		},
		{
			title:       "Example 4: Session Management",
			description: "Monitoring session state and statistics",
			code: `package main

import (
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    client, _ := tunnel.Dial("tcp", "server:8443")
    defer client.Close()

    // Access session information
    session := client.Session()
    fmt.Printf("Session ID: %x\n", session.ID)
    fmt.Printf("Cipher Suite: %v\n", session.CipherSuite)
    fmt.Printf("State: %v\n", session.State())

    // Send some data
    client.Send([]byte("Test data"))
    client.Receive()

    // Get session statistics
    stats := session.Stats()
    fmt.Printf("Bytes sent: %d\n", stats.BytesSent)
    fmt.Printf("Bytes received: %d\n", stats.BytesReceived)
    fmt.Printf("Packets sent: %d\n", stats.PacketsSent)
    fmt.Printf("Packets received: %d\n", stats.PacketsReceived)
}`,
		},
		{
			title:       "Example 5: Error Handling",
			description: "Proper error handling and resource cleanup",
			code: `package main

import (
    "fmt"
    "log"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
    qerrors "github.com/pzverkov/quantum-go/internal/errors"
)

func main() {
    client, err := tunnel.Dial("tcp", "server:8443")
    if err != nil {
        log.Fatalf("Connection failed: %v", err)
    }
    defer client.Close()

    // Send with error checking
    if err := client.Send([]byte("Important data")); err != nil {
        // Check for specific error types
        if qerrors.Is(err, qerrors.ErrTunnelClosed) {
            fmt.Println("Tunnel was closed")
        } else if qerrors.Is(err, qerrors.ErrTimeout) {
            fmt.Println("Send timed out")
        } else {
            log.Printf("Send error: %v", err)
        }
        return
    }

    // Receive with timeout handling
    data, err := client.Receive()
    if err != nil {
        log.Printf("Receive error: %v", err)
        return
    }

    fmt.Printf("Received: %s\n", data)
}`,
		},
		{
			title:       "Example 6: Security Best Practices",
			description: "Important security considerations",
			code: `package main

import (
    "crypto/tls"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // BEST PRACTICE 1: Add authentication layer
    // Quantum-Go provides encryption, but you must add authentication.
    // Use TLS certificates, pre-shared keys, or other auth mechanisms.

    // Example: Wrap with TLS for authentication
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }

    // BEST PRACTICE 2: Set reasonable timeouts
    config := tunnel.DefaultTransportConfig()
    config.ReadTimeout = 30 * time.Second
    config.WriteTimeout = 30 * time.Second

    // BEST PRACTICE 3: Monitor for rekey
    client, _ := tunnel.DialWithConfig("tcp", "server:8443", config)
    defer client.Close()

    session := client.Session()
    if session.NeedsRekey() {
        // Automatic rekeying happens, but you can monitor
        log.Println("Session is rekeying")
    }

    // BEST PRACTICE 4: Handle errors and close connections
    // Always defer Close() and check all errors

    // BEST PRACTICE 5: Use HSM for long-term keys in production
    // This library uses ephemeral keys per session (good!)
    // For server identity keys, use hardware security modules
}`,
		},
	}

	for i, ex := range examples {
		fmt.Printf("┌%s┐\n", strings.Repeat("─", 58))
		fmt.Printf("│ %s%s │\n", ex.title, strings.Repeat(" ", 58-len(ex.title)-2))
		fmt.Printf("└%s┘\n", strings.Repeat("─", 58))
		fmt.Println()
		fmt.Println(ex.description)
		fmt.Println()
		fmt.Println(ex.code)
		fmt.Println()

		if i < len(examples)-1 {
			fmt.Println()
		}
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                    Next Steps                             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Try the demo:")
	fmt.Println("  1. Terminal 1: quantum-vpn demo --mode server --addr :8443")
	fmt.Println("  2. Terminal 2: quantum-vpn demo --mode client --addr localhost:8443")
	fmt.Println()
	fmt.Println("Run benchmarks:")
	fmt.Println("  quantum-vpn bench --handshakes 100 --throughput")
	fmt.Println()
	fmt.Println("Documentation:")
	fmt.Println("  https://github.com/pzverkov/quantum-go")
	fmt.Println("  https://pkg.go.dev/github.com/pzverkov/quantum-go")
	fmt.Println()
	fmt.Println("Security:")
	fmt.Println("  See SECURITY.md for security policy and best practices")
	fmt.Println("  Report vulnerabilities: pzverkov@protonmail.com")
	fmt.Println()
}
