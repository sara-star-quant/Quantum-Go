package tunnel_test

import (
	"fmt"
	"net"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// A stream tunnel: the server accepts a connection and receives what the client sends.
func Example() {
	ln, _ := tunnel.ListenInsecure("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()

	received := make(chan string)
	go func() {
		conn, _ := ln.Accept()
		msg, _ := conn.Receive()
		received <- string(msg)
	}()

	client, _ := tunnel.DialInsecure("tcp", ln.Addr().String())
	_ = client.Send([]byte("hello"))

	fmt.Println(<-received)
	// Output: hello
}

// Send several datagrams at once. With WithDatagramOffload on Linux, runs of
// equal-size datagrams leave in a single system call.
func ExampleDatagramConn_SendBatch() {
	serverSock, _ := net.ListenPacket("udp", "127.0.0.1:0")
	server, _ := tunnel.NewDatagramEndpoint(serverSock, tunnel.WithAllowUnauthenticated(), tunnel.WithDatagramOffload())
	go server.Serve()
	defer func() { _ = server.Close() }()

	clientSock, _ := net.ListenPacket("udp", "127.0.0.1:0")
	client, _ := tunnel.NewDatagramEndpoint(clientSock, tunnel.WithAllowUnauthenticated(), tunnel.WithDatagramOffload())
	go client.Serve()
	defer func() { _ = client.Close() }()

	got := make(chan int)
	go func() {
		conn, _ := server.Accept()
		n := 0
		for n < 3 {
			if _, err := conn.Recv(); err != nil {
				break
			}
			n++
		}
		got <- n
	}()

	conn, _ := tunnel.DialDatagram(client, serverSock.LocalAddr())
	_ = conn.SendBatch([][]byte{[]byte("one"), []byte("two"), []byte("six")})

	fmt.Println(<-got, "datagrams received")
	// Output: 3 datagrams received
}
