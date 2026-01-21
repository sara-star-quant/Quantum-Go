# Quick Start Guide

## Installation

```bash
go get github.com/pzverkov/quantum-go
```

**Requirements:** Go 1.24 or later

## Basic Usage

### Server Transport

```go
package main

import (
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    // Server
    listener, _ := tunnel.Listen("tcp", ":8443")
    defer listener.Close()

    go func() {
        for {
            conn, _ := listener.Accept()
            go func(t *tunnel.Tunnel) {
                defer t.Close()
                data, _ := t.Receive()
                fmt.Printf("Received: %s\n", data)
            }(conn)
        }
    }()
}
```

### Client Transport

```go
package main

import (
    "github.com/pzverkov/quantum-go/pkg/tunnel"
)

func main() {
    client, _ := tunnel.Dial("tcp", "localhost:8443")
    defer client.Close()

    client.Send([]byte("Hello, quantum-resistant world!"))
}
```

## Low-Level CH-KEM API

For direct access to the hybrid encapsulation mechanism:

```go
package main

import (
    "bytes"
    "fmt"
    "github.com/pzverkov/quantum-go/pkg/chkem"
)

func main() {
    // Generate key pair (recipient)
    keyPair, _ := chkem.GenerateKeyPair()

    // Encapsulate (sender)
    ciphertext, sharedSecretSender, _ := chkem.Encapsulate(keyPair.PublicKey())

    // Decapsulate (recipient)
    sharedSecretRecipient, _ := chkem.Decapsulate(ciphertext, keyPair)

    // Both now have the same 32-byte shared secret
    fmt.Printf("Secrets match: %v\n",
        bytes.Equal(sharedSecretSender, sharedSecretRecipient))
}
```
