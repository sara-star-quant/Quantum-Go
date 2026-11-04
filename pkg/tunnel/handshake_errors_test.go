package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

const unknownSuite uint16 = 0x7777

// helloPair returns a client and server Handshake plus the client's honest ClientHello.
func helloPair(t *testing.T) (client, server *Handshake, ch []byte) {
	t.Helper()
	ci, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	client, server = NewHandshake(ci), NewHandshake(mustResponder(t))
	ch, err = client.CreateClientHello()
	if err != nil {
		t.Fatalf("CreateClientHello: %v", err)
	}
	return client, server, ch
}

// futureVersion rewrites the version major of a framed hello: 5 bytes of frame header,
// then the version. The codec refuses to encode an unknown version, so flip the byte.
func futureVersion(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[5] = 99
	return out
}

func rewriteClientHello(t *testing.T, h *Handshake, ch []byte, edit func(*protocol.ClientHello)) []byte {
	t.Helper()
	if edit == nil {
		return futureVersion(ch)
	}
	m, err := h.codec.DecodeClientHello(ch)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := h.codec.EncodeClientHello(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rewriteServerHello(t *testing.T, h *Handshake, sh []byte, edit func(*protocol.ServerHello)) []byte {
	t.Helper()
	if edit == nil {
		return futureVersion(sh)
	}
	m, err := h.codec.DecodeServerHello(sh)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := h.codec.EncodeServerHello(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var badClientHellos = []struct {
	name string
	edit func(*protocol.ClientHello)
	want error
}{
	{"version from the future", nil, qerrors.ErrUnsupportedVersion},
	{"suite nobody supports", func(m *protocol.ClientHello) { m.KEMSuite, m.KEMSuites = unknownSuite, []uint16{unknownSuite} }, qerrors.ErrUnsupportedKEMSuite},
}

// Each bad ClientHello fails closed on the stream path with the documented error and
// is dropped without effect on the datagram path, where a bad datagram never aborts a
// handshake and the genuine retransmit still completes it.
func TestHandshakeRejectsUnsupportedClientHello(t *testing.T) {
	for _, tc := range badClientHellos {
		t.Run("stream/"+tc.name, func(t *testing.T) {
			client, server, ch := helloPair(t)
			if err := server.ProcessClientHello(rewriteClientHello(t, client, ch, tc.edit)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if server.IsComplete() || server.sendHRR {
				t.Fatal("server kept going after an unusable ClientHello")
			}
		})
		t.Run("datagram/"+tc.name, func(t *testing.T) {
			initiator, responder := newFSMPair(t)
			chs, err := initiator.start()
			if err != nil {
				t.Fatal(err)
			}
			bad := rewriteClientHello(t, initiator.hs, chs[0].body, tc.edit)
			if out, done := responder.onMessage(protocol.MessageTypeClientHello, bad); out != nil || done {
				t.Fatalf("bad ClientHello produced output=%v done=%v", out, done)
			}
			if out, _ := responder.onMessage(protocol.MessageTypeClientHello, chs[0].body); len(out) != 2 {
				t.Fatal("honest ClientHello no longer works after a bad one")
			}
		})
	}
}

// A server that answers with a different version or KEM suite than the client used is
// a downgrade attempt and must not complete.
func TestHandshakeRejectsDowngradedServerHello(t *testing.T) {
	edits := []struct {
		name string
		edit func(*protocol.ServerHello)
		want error
	}{
		{"version", nil, qerrors.ErrUnsupportedVersion},
		{"suite", func(m *protocol.ServerHello) { m.KEMSuite = unknownSuite }, qerrors.ErrUnsupportedKEMSuite},
	}
	for _, tc := range edits {
		t.Run("stream/"+tc.name, func(t *testing.T) {
			client, server, ch := helloPair(t)
			if err := server.ProcessClientHello(ch); err != nil {
				t.Fatal(err)
			}
			sh, err := server.CreateServerHello()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.ProcessServerHello(rewriteServerHello(t, client, sh, tc.edit)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
		t.Run("datagram/"+tc.name, func(t *testing.T) {
			initiator, responder := newFSMPair(t)
			chs, _ := initiator.start()
			flight, _ := responder.onMessage(protocol.MessageTypeClientHello, chs[0].body)
			sh, sf := serverFlight(t, flight)
			bad := rewriteServerHello(t, initiator.hs, sh.body, tc.edit)
			initiator.onMessage(protocol.MessageTypeServerHello, bad)
			if _, done := initiator.onMessage(protocol.MessageTypeServerFinished, sf.body); done {
				t.Fatal("initiator completed after a downgraded ServerHello")
			}
		})
	}
}

// A HelloRetryRequest cannot steer the client to a suite it never offered, carry a
// foreign version, or repeat.
func TestHandshakeRejectsBadHelloRetryRequest(t *testing.T) {
	encode := func(h *Handshake, m *protocol.HelloRetryRequest) []byte {
		b, err := h.codec.EncodeHelloRetryRequest(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("suite never offered", func(t *testing.T) {
		client, _, _ := helloPair(t)
		err := client.ProcessHelloRetryRequest(encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: unknownSuite}))
		if !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("foreign version", func(t *testing.T) {
		client, _, _ := helloPair(t)
		err := client.ProcessHelloRetryRequest(futureVersion(encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: 1})))
		if !errors.Is(err, qerrors.ErrUnsupportedVersion) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("loop is bounded", func(t *testing.T) {
		client := NewHandshake(newStubLedInitiator(t))
		if _, err := client.CreateClientHello(); err != nil {
			t.Fatal(err)
		}
		hrr := encode(client, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: 1})
		if err := client.ProcessHelloRetryRequest(hrr); err != nil {
			t.Fatalf("first HelloRetryRequest: %v", err)
		}
		if _, err := client.CreateClientHello(); err != nil {
			t.Fatal(err)
		}
		if err := client.ProcessHelloRetryRequest(hrr); err == nil {
			t.Fatal("a second HelloRetryRequest was accepted")
		}
	})
	t.Run("datagram repeat replays the retried hello", func(t *testing.T) {
		initiator := newDgramHandshake(newStubLedInitiator(t))
		if _, err := initiator.start(); err != nil {
			t.Fatal(err)
		}
		hrr := encode(initiator.hs, &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: 1})
		first, _ := initiator.onMessage(protocol.MessageTypeHelloRetryRequest, hrr)
		again, _ := initiator.onMessage(protocol.MessageTypeHelloRetryRequest, hrr)
		if len(first) != 1 || len(again) != 1 || string(first[0].body) != string(again[0].body) {
			t.Fatal("a repeated HelloRetryRequest produced a fresh ClientHello instead of replaying the retried one")
		}
	})
}

// A client-only PSK and a wrong PSK must look identical to the client, so a probe
// cannot learn whether the server holds a key for the identity.
func TestHandshakePSKFailuresLookAlike(t *testing.T) {
	key := func(b byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b
		}
		return k
	}
	for _, rn := range []hsRunner{{"stream", runStreamMatrix}, {"datagram", runDgramMatrix}} {
		t.Run(rn.name, func(t *testing.T) {
			cli := hsSide{psk: key(8), pskID: []byte("edge")}
			wrong := rn.run(t, hsSide{psk: key(7), pskID: []byte("edge")}, cli, false)
			absent := rn.run(t, hsSide{}, cli, false)
			if wrong.clientErr == nil || absent.clientErr == nil {
				t.Fatalf("a failing PSK handshake succeeded: wrong=%v absent=%v", wrong.clientErr, absent.clientErr)
			}
			if wrong.clientErr.Error() != absent.clientErr.Error() {
				t.Fatalf("wrong PSK reports %q but a missing PSK reports %q", wrong.clientErr, absent.clientErr)
			}
		})
	}
}

// relay copies one direction of a TCP connection and flips a bit at one stream offset.
func relay(dst, src net.Conn, flipAt int, flipped *bool, mu *sync.Mutex) {
	buf := make([]byte, 4096)
	off := 0
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if flipAt >= off && flipAt < off+n {
				buf[flipAt-off] ^= 0x01
				mu.Lock()
				*flipped = true
				mu.Unlock()
			}
			off += n
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

// Flip one bit of the stream handshake as it crosses a real socket, in each direction at
// offsets through the hellos and finished messages. Whatever happens, both sides must
// never end up with an established session that carries data.
func TestStreamHandshakeThroughTamperingProxy(t *testing.T) {
	for _, toServer := range []bool{true, false} {
		for _, off := range []int{0, 2, 4, 5, 9, 40, 300, 1700, 3200} {
			name := "server-to-client"
			if toServer {
				name = "client-to-server"
			}
			t.Run(name+"/"+time.Duration(off).String(), func(t *testing.T) {
				ln, err := Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				cfg := DefaultTransportConfig()
				cfg.HandshakeTimeout = 3 * time.Second
				ln.SetConfig(cfg)
				defer func() { _ = ln.Close() }()
				srvAcc := make(chan *Tunnel, 1)
				go func() { c, _ := ln.Accept(); srvAcc <- c }()

				front, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = front.Close() }()
				var flipped bool
				var mu sync.Mutex
				go func() {
					c, err := front.Accept()
					if err != nil {
						return
					}
					up, err := net.Dial("tcp", ln.Addr().String())
					if err != nil {
						_ = c.Close()
						return
					}
					deadline := time.Now().Add(3 * time.Second)
					_ = c.SetDeadline(deadline)
					_ = up.SetDeadline(deadline)
					cOff, sOff := -1, -1
					if toServer {
						cOff = off
					} else {
						sOff = off
					}
					go relay(up, c, cOff, &flipped, &mu)
					relay(c, up, sOff, &flipped, &mu)
				}()

				client, cerr := Dial("tcp", front.Addr().String())
				var server *Tunnel
				select {
				case server = <-srvAcc:
				case <-time.After(30 * time.Second):
					t.Fatal("responder never resolved")
				}
				mu.Lock()
				hit := flipped
				mu.Unlock()
				if cerr == nil && server != nil {
					defer func() { _ = client.Close(); _ = server.Close() }()
					if hit && exchange(t, client.Send, server.Receive) {
						t.Fatalf("a flipped bit at offset %d (%s) still produced a working session", off, name)
					}
				}
			})
		}
	}
}

// Corrupt one datagram of a handshake on a real UDP path. A flipped bit may be dropped
// like loss (the retransmit completes the handshake) or may change a hello into
// something that parses but cannot finish (the handshake then fails closed). Either way
// the dial must resolve, and any data that arrives must be intact.
func TestDatagramHandshakeThroughTamperingProxy(t *testing.T) {
	for _, toServer := range []bool{true, false} {
		for idx := 0; idx < 3; idx++ {
			for _, pos := range []int{0, 60} {
				name := "server-to-client"
				if toServer {
					name = "client-to-server"
				}
				t.Run(fmt.Sprintf("%s/datagram%d/byte%d", name, idx, pos), func(t *testing.T) {
					srvSock, _ := net.ListenPacket("udp", "127.0.0.1:0")
					srvEP, err := NewDatagramEndpoint(srvSock)
					if err != nil {
						t.Fatal(err)
					}
					cliSock, _ := net.ListenPacket("udp", "127.0.0.1:0")
					cliEP, err := NewDatagramEndpoint(cliSock)
					if err != nil {
						t.Fatal(err)
					}
					for _, ep := range []*DatagramEndpoint{srvEP, cliEP} {
						ep.rtoInitial, ep.rtoMax, ep.maxRetries = 5*time.Millisecond, 30*time.Millisecond, 30
						go ep.Serve()
						t.Cleanup(func() { _ = ep.Close() })
					}

					front, _ := net.ListenPacket("udp", "127.0.0.1:0")
					back, _ := net.ListenPacket("udp", "127.0.0.1:0")
					t.Cleanup(func() { _ = front.Close(); _ = back.Close() })
					var mu sync.Mutex
					var clientAddr net.Addr
					seen := [2]int{} // datagrams seen per direction
					pass := func(dir int, p []byte) []byte {
						mu.Lock()
						defer mu.Unlock()
						n := seen[dir]
						seen[dir]++
						if (dir == 0) == toServer && n == idx && pos < len(p) {
							p[pos] ^= 0x01
						}
						return p
					}
					go func() { // client -> server
						buf := make([]byte, 65535)
						for {
							n, from, err := front.ReadFrom(buf)
							if err != nil {
								return
							}
							mu.Lock()
							clientAddr = from
							mu.Unlock()
							_, _ = back.WriteTo(pass(0, append([]byte(nil), buf[:n]...)), srvSock.LocalAddr())
						}
					}()
					go func() { // server -> client
						buf := make([]byte, 65535)
						for {
							n, _, err := back.ReadFrom(buf)
							if err != nil {
								return
							}
							mu.Lock()
							to := clientAddr
							mu.Unlock()
							if to != nil {
								_, _ = front.WriteTo(pass(1, append([]byte(nil), buf[:n]...)), to)
							}
						}
					}()

					acc := make(chan *DatagramConn, 1)
					go func() { c, _ := srvEP.Accept(); acc <- c }()
					type dialRes struct {
						c   *DatagramConn
						err error
					}
					client := within(t, "dial", func() dialRes {
						c, err := DialDatagram(cliEP, front.LocalAddr())
						return dialRes{c, err}
					})
					if client.err != nil {
						return // failed closed
					}
					server := within(t, "responder session", func() *DatagramConn { return <-acc })
					if server == nil {
						t.Fatal("client established but the responder did not")
					}
					got := make(chan []byte, 8)
					go func() {
						for {
							p, err := server.Recv()
							if err != nil {
								return
							}
							got <- p
						}
					}()
					for range 3 {
						_ = client.c.Send([]byte("matrix"))
					}
					deadline := time.After(500 * time.Millisecond)
					for {
						select {
						case p := <-got:
							if string(p) != "matrix" {
								t.Fatalf("corrupted payload delivered: %q", p)
							}
						case <-deadline:
							return
						}
					}
				})
			}
		}
	}
}
