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
    "encoding/hex"
    "fmt"
    "log"
    "os"

    "github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func main() {
    psk, err := hex.DecodeString(os.Getenv("QT_PSK")) // openssl rand -hex 32, shared out of band
    if err != nil {
        log.Fatal(err)
    }
    cfg := tunnel.DefaultTransportConfig()
    cfg.PSK, cfg.PSKIdentity = psk, []byte("client-1")

    listener, err := tunnel.Listen("tcp", ":8443")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()
    listener.SetConfig(cfg)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Print(err)
            continue
        }
        go func(t *tunnel.Tunnel) {
            defer t.Close()
            data, err := t.Receive()
            if err != nil {
                log.Print(err)
                return
            }
            fmt.Printf("Received: %s\n", data)
        }(conn)
    }
}
```

### Client Transport

```go
package main

import (
    "encoding/hex"
    "log"
    "os"

    "github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func main() {
    psk, err := hex.DecodeString(os.Getenv("QT_PSK")) // the same PSK as the server
    if err != nil {
        log.Fatal(err)
    }
    cfg := tunnel.DefaultTransportConfig()
    cfg.PSK, cfg.PSKIdentity = psk, []byte("client-1")

    client, err := tunnel.DialWithConfig("tcp", "localhost:8443", cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    if err := client.Send([]byte("Hello, quantum-resistant world!")); err != nil {
        log.Fatal(err)
    }
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
    ciphertext, sharedSecretSender, _ := chkem.Encapsulate(keyPair.PublicKey(), chkem.RoleResponder)

    // Decapsulate (recipient)
    sharedSecretRecipient, _ := chkem.Decapsulate(ciphertext, keyPair, chkem.RoleInitiator)

    // Both now have the same 32-byte shared secret
    fmt.Printf("Secrets match: %v\n",
        bytes.Equal(sharedSecretSender, sharedSecretRecipient))
}
```
