// Package tunnel is a post-quantum encrypted tunnel for Go over TCP and UDP.
//
// A hybrid ML-KEM-1024 and X25519 handshake (the Cascaded Hybrid KEM) keys the client
// after one round trip, so the first byte of application data can follow the
// handshake without a second wait. An attacker has to break both algorithms, so
// traffic recorded today stays protected against a future quantum computer.
//
// # Stream transport
//
// Dial and Listen give a length-prefixed, encrypted stream. Each accepted
// connection handshakes in its own goroutine, so one slow peer does not block the
// others.
//
//	ln, _ := tunnel.Listen("tcp", ":8443")
//	conn, _ := ln.Accept()
//	msg, _ := conn.Receive()
//
//	c, _ := tunnel.Dial("tcp", "server:8443")
//	_ = c.Send([]byte("hello"))
//
// # Datagram transport
//
// ListenDatagram and DialDatagram run a connectionless UDP transport with a
// fragmented handshake, retransmission, reliable rekey, anti-DoS cookies and
// authenticated roaming across address changes. DatagramConn.SendBatch sends
// several datagrams at once; with WithDatagramOffload on Linux, runs of equal-size
// datagrams go out in a single system call.
//
//	ep, _ := tunnel.ListenDatagram("udp", ":51820", tunnel.WithDatagramOffload())
//	go ep.Serve()
//	conn, _ := ep.Accept()
//	pkt, _ := conn.Recv()
//
// # Authentication
//
// Endpoint authentication is opt in: pin a server's static key
// (TransportConfig.PinnedServerKey, WithPinnedServerKey), require it on the server
// (RequireStaticAuth), or give each client its own pre-shared key (PSKLookup,
// RequirePSK). The cryptography is fixed at NIST Category 5; a build with the fips
// tag restricts it to AES-GCM and runs power-on self-tests.
//
// # Scope
//
// This package encrypts and authenticates bytes. It does not create a TUN device,
// route traffic, handle DNS or provide a kill-switch; see docs/SCOPE.md in the
// repository. It is pre-1.0 and has not had a third-party audit.
package tunnel
