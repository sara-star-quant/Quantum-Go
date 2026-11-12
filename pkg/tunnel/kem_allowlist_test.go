package tunnel

import (
	"errors"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

const (
	v1 = chkem.SuiteCHKEMv1
	xw = chkem.SuiteXWing
)

// dialAllow connects a client to a stream listener with the given allowlists and first offer
// and returns both ends' negotiated suite.
func dialAllow(t *testing.T, serverAllow, clientAllow []chkem.SuiteID, first chkem.SuiteID) (server, client chkem.SuiteID, err error) {
	t.Helper()
	serverCfg := DefaultTransportConfig()
	serverCfg.AllowedKEMSuites = serverAllow
	serverCfg.HandshakeTimeout = 5 * time.Second
	ln, accepted := acceptOne(t, serverCfg)
	cfg := DefaultTransportConfig()
	cfg.AllowedKEMSuites = clientAllow
	cfg.KEMSuite = first
	cfg.HandshakeTimeout = 5 * time.Second
	c, err := DialWithConfig("tcp", ln.Addr().String(), cfg)
	if err != nil {
		return 0, 0, err
	}
	t.Cleanup(func() { _ = c.Close() })
	s := <-accepted
	t.Cleanup(func() { _ = s.Close() })
	return s.Peer().Suite, c.Peer().Suite, nil
}

func TestAllowedKEMSuitesStream(t *testing.T) {
	cases := []struct {
		name          string
		serverAllow   []chkem.SuiteID
		clientAllow   []chkem.SuiteID
		first         chkem.SuiteID
		want          chkem.SuiteID
		wantHandshake bool
	}{
		{"server allows only level 5, client leads with the smaller suite", []chkem.SuiteID{v1}, nil, xw, v1, true},
		{"server allows only the smaller suite, client leads with the default", []chkem.SuiteID{xw}, nil, 0, xw, true},
		{"client allows only the smaller suite", nil, []chkem.SuiteID{xw}, 0, xw, true},
		{"no overlap between the two lists", []chkem.SuiteID{xw}, []chkem.SuiteID{v1}, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli, err := dialAllow(t, tc.serverAllow, tc.clientAllow, tc.first)
			if !tc.wantHandshake {
				if err == nil {
					t.Fatal("a handshake with no overlapping suite completed")
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake failed: %v", err)
			}
			if srv != tc.want || cli != tc.want {
				t.Fatalf("negotiated server=%v client=%v, want %v on both", srv, cli, tc.want)
			}
		})
	}
}

func TestAllowedKEMSuitesDatagram(t *testing.T) {
	cases := []struct {
		name        string
		serverAllow []chkem.SuiteID
		clientOpts  []DatagramEndpointOption
		want        chkem.SuiteID
	}{
		{"server allows only level 5, client leads with the smaller suite", []chkem.SuiteID{v1}, []DatagramEndpointOption{WithKEMSuite(xw)}, v1},
		{"server allows only the smaller suite", []chkem.SuiteID{xw}, nil, xw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server, _, err := pubDgramPair(t,
				[]DatagramEndpointOption{WithAllowedKEMSuites(tc.serverAllow...)}, tc.clientOpts)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if got := server.Peer().Suite; got != tc.want {
				t.Fatalf("server negotiated %v, want %v", got, tc.want)
			}
			if got := client.Peer().Suite; got != tc.want {
				t.Fatalf("client negotiated %v, want %v", got, tc.want)
			}
		})
	}
}

// An allowlist that permits no supported suite is a configuration error caught before any
// packet is sent, on both transports.
func TestAllowedKEMSuitesRejectsEmptyIntersection(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.AllowedKEMSuites = []chkem.SuiteID{0x7FFF}
	if _, err := DialWithConfig("tcp", "127.0.0.1:1", cfg); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("Dial: got %v, want ErrUnsupportedKEMSuite", err)
	}
	if _, err := NewDatagramEndpoint(nil, WithAllowUnauthenticated(), WithAllowedKEMSuites(0x7FFF)); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("NewDatagramEndpoint: got %v, want ErrUnsupportedKEMSuite", err)
	}
	if err := cfg.Validate(); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("Validate: got %v, want ErrUnsupportedKEMSuite", err)
	}
	// A listener reports it on its first Accept, so a server cannot run with a list that allows nothing.
	ln, err := ListenInsecure("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ln.SetConfig(cfg)
	if _, err := ln.Accept(); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("Accept: got %v, want ErrUnsupportedKEMSuite", err)
	}
	// The starting suite must be one the list allows.
	conflict := DefaultTransportConfig()
	conflict.AllowedKEMSuites = []chkem.SuiteID{v1}
	conflict.KEMSuite = xw
	if err := conflict.Validate(); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("a starting suite outside the list: got %v", err)
	}
}

// A pinned server key keeps its own suite: the allowlist governs the ephemeral exchange only,
// so an operator can require level 5 for the session and still pin an X-Wing identity.
func TestAllowedKEMSuitesDoNotRestrictTheStaticKeySuite(t *testing.T) {
	suite, ok := chkem.GetSuite(xw)
	if !ok {
		t.Skip("X-Wing is not registered in this build")
	}
	kp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := DefaultTransportConfig()
	serverCfg.StaticKeyPair = kp
	serverCfg.AllowedKEMSuites = []chkem.SuiteID{v1}
	serverCfg.HandshakeTimeout = 5 * time.Second
	ln, accepted := acceptOne(t, serverCfg)
	cfg := DefaultTransportConfig()
	cfg.PinnedServerKey = kp.PublicKey()
	cfg.AllowedKEMSuites = []chkem.SuiteID{v1}
	cfg.HandshakeTimeout = 5 * time.Second
	c, err := DialWithConfig("tcp", ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("a pin in a suite outside the allowlist failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := <-accepted
	t.Cleanup(func() { _ = s.Close() })
	if got := s.Peer().Suite; got != v1 {
		t.Fatalf("session suite %v, want %v", got, v1)
	}
}

// A server config copied from a client config can carry a KEMSuite the allowlist excludes. The
// listener has no use for that field, so it must keep accepting.
func TestListenerIgnoresTheClientOnlyKEMSuite(t *testing.T) {
	serverCfg := DefaultTransportConfig()
	serverCfg.AllowedKEMSuites = []chkem.SuiteID{v1}
	serverCfg.KEMSuite = xw // meaningful only to a dialer
	serverCfg.HandshakeTimeout = 5 * time.Second
	ln, accepted := acceptOne(t, serverCfg)
	c, err := DialWithConfig("tcp", ln.Addr().String(), DefaultTransportConfig())
	if err != nil {
		t.Fatalf("a listener with a stray KEMSuite refused a client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := <-accepted
	t.Cleanup(func() { _ = s.Close() })
}
