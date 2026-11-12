# Quick Start Guide

## Installation

```bash
go get github.com/sara-star-quant/quantum-go
```

**Requirements:** Go 1.26 or later

## Basic Usage

### Server Transport

```go
package main

import (
    "fmt"
    "github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func main() {
    // Server
    cfg := tunnel.DefaultTransportConfig()
    cfg.PSK, cfg.PSKIdentity = psk, []byte("client-1") // 32+ random bytes shared out of band

    listener, _ := tunnel.Listen("tcp", ":8443")
    listener.SetConfig(cfg)
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
    "github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func main() {
    cfg := tunnel.DefaultTransportConfig()
    cfg.PSK, cfg.PSKIdentity = psk, []byte("client-1") // the same PSK as the server

    client, _ := tunnel.DialWithConfig("tcp", "localhost:8443", cfg)
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
    "github.com/sara-star-quant/quantum-go/pkg/chkem"
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
