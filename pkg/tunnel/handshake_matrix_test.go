package tunnel

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// hsSide is one peer's authentication settings, expressed once and applied to either
// transport through its public configuration.
type hsSide struct {
	kp          *chkem.KeyPair   // server static identity
	pin         *chkem.PublicKey // client pin on the server key
	requireAuth bool
	psk, pskID  []byte
	lookup      func([]byte) []byte
	requirePSK  bool
}

// hsResult is what a run observed.
type hsResult struct {
	setupErr  error // endpoint or listener refused the configuration
	clientErr error // the dial failed
	surfaced  bool  // the responder produced a session
	dataOK    bool  // a payload crossed in both directions
}

type hsRunner struct {
	name string
	run  func(t *testing.T, srv, cli hsSide, wantOK bool) hsResult
}

func within[T any](t *testing.T, what string, f func() T) T {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- f() }()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out: %s", what)
		panic("unreachable")
	}
}

func streamConfig(s hsSide) TransportConfig {
	c := DefaultTransportConfig()
	c.AllowUnauthenticated = true // the matrix includes the no-authentication combination
	c.StaticKeyPair = s.kp
	c.PinnedServerKey = s.pin
	c.RequireStaticAuth = s.requireAuth
	c.PSK, c.PSKIdentity = s.psk, s.pskID
	c.PSKLookup = s.lookup
	c.RequirePSK = s.requirePSK
	return c
}

func runStreamMatrix(t *testing.T, srv, cli hsSide, _ bool) hsResult {
	t.Helper()
	ln, err := ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ln.SetConfig(streamConfig(srv))
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		tun *Tunnel
		err error
	}
	acc := make(chan accepted, 1)
	go func() {
		tun, err := ln.Accept()
		acc <- accepted{tun, err}
	}()

	var res hsResult
	client, err := DialWithConfig("tcp", ln.Addr().String(), streamConfig(cli))
	res.clientErr = err
	a := within(t, "stream Accept", func() accepted { return <-acc })
	if a.err != nil {
		if errors.Is(a.err, qerrors.ErrStaticAuthMisconfigured) || errors.Is(a.err, qerrors.ErrPSKMisconfigured) {
			res.setupErr = a.err
		}
		return res
	}
	res.surfaced = a.tun != nil
	if err != nil || a.tun == nil {
		return res
	}
	defer func() { _ = client.Close(); _ = a.tun.Close() }()
	res.dataOK = exchange(t, client.Send, a.tun.Receive) && exchange(t, a.tun.Send, client.Receive)
	return res
}

func exchange(t *testing.T, send func([]byte) error, recv func() ([]byte, error)) bool {
	t.Helper()
	if err := send([]byte("matrix")); err != nil {
		return false
	}
	got := within(t, "receive", func() string { p, _ := recv(); return string(p) })
	return got == "matrix"
}

func runDgramMatrix(t *testing.T, srv, cli hsSide, wantOK bool) hsResult {
	t.Helper()
	build := func(s hsSide) (*DatagramEndpoint, net.PacketConn, error) {
		sock, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		var opts []DatagramEndpointOption
		if s.kp != nil {
			opts = append(opts, WithStaticIdentity(s.kp))
		}
		if s.pin != nil {
			opts = append(opts, WithPinnedServerKey(s.pin))
		}
		if s.requireAuth {
			opts = append(opts, WithRequireStaticAuth())
		}
		if s.psk != nil {
			opts = append(opts, WithPSK(s.pskID, s.psk))
		}
		if s.lookup != nil {
			opts = append(opts, WithPSKLookup(s.lookup))
		}
		if s.requirePSK {
			opts = append(opts, WithRequirePSK())
		}
		ep, err := NewDatagramEndpoint(sock, append([]DatagramEndpointOption{WithAllowUnauthenticated()}, opts...)...)
		if err != nil {
			_ = sock.Close()
			return nil, nil, err
		}
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 30 * time.Millisecond
		if wantOK {
			ep.maxRetries = 100 // headroom for a loaded runner
		} else {
			ep.maxRetries = 12 // a rejected dial gives up quickly
		}
		go ep.Serve()
		t.Cleanup(func() { _ = ep.Close() })
		return ep, sock, nil
	}

	var res hsResult
	srvEP, srvSock, err := build(srv)
	if err != nil {
		res.setupErr = err
		return res
	}
	cliEP, _, err := build(cli)
	if err != nil {
		res.setupErr = err
		return res
	}
	acc := make(chan *DatagramConn, 1)
	go func() {
		c, _ := srvEP.Accept()
		acc <- c
	}()

	client, err := DialDatagram(cliEP, srvSock.LocalAddr())
	res.clientErr = err
	wait := 30 * time.Second
	if err != nil {
		wait = time.Second // absence check: a rejected peer must not surface; generous because the scenarios run in parallel
	}
	select {
	case server := <-acc:
		res.surfaced = server != nil
		if err == nil && server != nil {
			res.dataOK = exchange(t, client.Send, server.Recv) && exchange(t, server.Send, client.Recv)
		}
	case <-time.After(wait):
	}
	return res
}

func TestHandshakeMatrix(t *testing.T) {
	psk := func(b byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b
		}
		return k
	}
	table := func(id string, key []byte) func([]byte) []byte {
		return func(got []byte) []byte {
			if string(got) == id {
				return key
			}
			return nil
		}
	}

	type scenario struct {
		name     string
		srv, cli func(kp, other *chkem.KeyPair) hsSide
		ok       bool
		wantErr  error // the dial error, or the setup error for a misconfiguration
		reject   bool  // fails closed with any error
	}
	scenarios := []scenario{
		{name: "unauthenticated", ok: true,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "pinned server key", ok: true,
			srv: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{kp: kp} },
			cli: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{pin: kp.PublicKey()} }},
		{name: "pinned with require-auth", ok: true,
			srv: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{kp: kp, requireAuth: true} },
			cli: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{pin: kp.PublicKey()} }},
		{name: "unpinned client, server has identity", ok: true,
			srv: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{kp: kp} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "shared PSK", ok: true,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(7), pskID: []byte("edge")} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(7), pskID: []byte("edge")} }},
		{name: "per-client PSK with require-psk", ok: true,
			srv: func(_, _ *chkem.KeyPair) hsSide {
				return hsSide{lookup: table("edge", psk(7)), requirePSK: true}
			},
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(7), pskID: []byte("edge")} }},
		{name: "pinned key and PSK together", ok: true,
			srv: func(kp, _ *chkem.KeyPair) hsSide {
				return hsSide{kp: kp, requireAuth: true, lookup: table("edge", psk(7)), requirePSK: true}
			},
			cli: func(kp, _ *chkem.KeyPair) hsSide {
				return hsSide{pin: kp.PublicKey(), psk: psk(7), pskID: []byte("edge")}
			}},

		{name: "wrong pin", wantErr: qerrors.ErrServerKeyMismatch,
			srv: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{kp: kp} },
			cli: func(_, other *chkem.KeyPair) hsSide { return hsSide{pin: other.PublicKey()} }},
		{name: "pin against a server without identity", wantErr: qerrors.ErrServerKeyMismatch,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} },
			cli: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{pin: kp.PublicKey()} }},
		{name: "require-auth without identity", wantErr: qerrors.ErrStaticAuthMisconfigured,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{requireAuth: true} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "require-auth rejects an unpinned client", reject: true,
			srv: func(kp, _ *chkem.KeyPair) hsSide { return hsSide{kp: kp, requireAuth: true} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "require-psk without any key", wantErr: qerrors.ErrPSKMisconfigured,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{requirePSK: true} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "require-psk rejects a client without a PSK", reject: true,
			srv: func(_, _ *chkem.KeyPair) hsSide {
				return hsSide{lookup: table("edge", psk(7)), requirePSK: true}
			},
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{} }},
		{name: "require-psk rejects an unknown identity", reject: true,
			srv: func(_, _ *chkem.KeyPair) hsSide {
				return hsSide{lookup: table("edge", psk(7)), requirePSK: true}
			},
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(7), pskID: []byte("intruder")} }},
		{name: "wrong PSK", reject: true,
			srv: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(7), pskID: []byte("edge")} },
			cli: func(_, _ *chkem.KeyPair) hsSide { return hsSide{psk: psk(8), pskID: []byte("edge")} }},
	}

	runners := []hsRunner{{"stream", runStreamMatrix}, {"datagram", runDgramMatrix}}
	// Every built-in suite the registry offers runs the whole matrix, so a new built-in
	// is covered the moment it is registered. External ids (>= CustomSuiteMin) are
	// skipped: other tests register permanent stand-ins that are not full suites.
	type matrixSuite struct {
		name string
		gen  func(testing.TB) *chkem.KeyPair
	}
	var suites []matrixSuite
	for _, id := range chkem.SupportedSuites() {
		if id >= chkem.CustomSuiteMin {
			continue
		}
		s, ok := chkem.GetSuite(id)
		if !ok {
			t.Fatalf("suite %#x is offered but not registered", id)
		}
		name := map[chkem.SuiteID]string{chkem.SuiteCHKEMv1: "ch-kem-v1", chkem.SuiteXWing: "x-wing"}[id]
		if name == "" {
			name = fmt.Sprintf("suite-%04x", uint16(id))
		}
		suites = append(suites, matrixSuite{name: name, gen: func(tb testing.TB) *chkem.KeyPair {
			tb.Helper()
			kp, _, err := s.GenerateStaticKeyPair()
			if err != nil {
				tb.Fatal(err)
			}
			return kp
		}})
	}
	if len(suites) < 2 {
		t.Fatalf("matrix covers %d built-in suites, want at least CH-KEM-v1 and X-Wing", len(suites))
	}

	for _, rn := range runners {
		for _, su := range suites {
			for _, sc := range scenarios {
				t.Run(rn.name+"/"+su.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel() // each scenario owns its endpoints, keys and sockets
					kp, other := su.gen(t), su.gen(t)
					res := rn.run(t, sc.srv(kp, other), sc.cli(kp, other), sc.ok)
					switch {
					case sc.ok:
						if res.setupErr != nil || res.clientErr != nil || !res.surfaced || !res.dataOK {
							t.Fatalf("valid combination failed: %+v", res)
						}
					case sc.wantErr != nil && (errors.Is(sc.wantErr, qerrors.ErrStaticAuthMisconfigured) || errors.Is(sc.wantErr, qerrors.ErrPSKMisconfigured)):
						if !errors.Is(res.setupErr, sc.wantErr) {
							t.Fatalf("setup error = %v, want %v (%+v)", res.setupErr, sc.wantErr, res)
						}
					case sc.wantErr != nil:
						if !errors.Is(res.clientErr, sc.wantErr) {
							t.Fatalf("dial error = %v, want %v", res.clientErr, sc.wantErr)
						}
					default:
						if res.clientErr == nil || res.surfaced || res.dataOK {
							t.Fatalf("rejected combination was admitted: %+v", res)
						}
					}
				})
			}
		}
	}
}
