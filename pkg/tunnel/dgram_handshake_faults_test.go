package tunnel

import (
	"fmt"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// handshakeOverFaults runs one datagram handshake over a link that drops, duplicates and
// reorders, with the endpoints built from the given options, and returns both sessions.
func handshakeOverFaults(t *testing.T, seed uint64, serverOpts []DatagramEndpointOption, tune func(client, server *DatagramEndpoint)) (client, server *Session) {
	t.Helper()
	connA, connB := memPipe(seed, 0.15, 0.1, 0.2)
	epA, err := NewDatagramEndpoint(connA, WithAllowUnauthenticated())
	if err != nil {
		t.Fatal(err)
	}
	epB, err := NewDatagramEndpoint(connB, append([]DatagramEndpointOption{WithAllowUnauthenticated()}, serverOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range []*DatagramEndpoint{epA, epB} {
		ep.rtoInitial = 5 * time.Millisecond
		ep.rtoMax = 50 * time.Millisecond
		ep.maxRetries = 40 // ~2s of headroom for slow CI runners
	}
	if tune != nil {
		tune(epA, epB)
	}
	go epA.Serve()
	go epB.Serve()
	t.Cleanup(func() { _ = epA.Close(); _ = epB.Close() })

	type dialResult struct {
		conn *DatagramConn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, err := DialDatagram(epA, connB.addr)
		dialCh <- dialResult{c, err}
	}()
	select {
	case ds := <-epB.acceptCh:
		server = ds.getSession()
	case <-time.After(10 * time.Second):
		t.Fatal("responder did not surface a session")
	}
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("dial: %v", r.err)
		}
		client = r.conn.Session()
	case <-time.After(10 * time.Second):
		t.Fatal("dial did not complete")
	}
	if client.State() != SessionStateEstablished || server.State() != SessionStateEstablished {
		t.Fatalf("not established: client=%v server=%v", client.State(), server.State())
	}
	return client, server
}

// The two handshake branches that add a round trip, the cookie gate and the HelloRetryRequest,
// complete over a link that drops, duplicates and reorders, across seeds. Both ends then agree
// on keys, and the retry lands both on the suite the server insists on.
func TestDatagramHandshakeBranchesUnderFaults(t *testing.T) {
	const seeds = 16
	for seed := uint64(1); seed <= seeds; seed++ {
		t.Run(fmt.Sprintf("cookie/seed-%d", seed), func(t *testing.T) {
			client, server := handshakeOverFaults(t, seed, nil, func(_, server *DatagramEndpoint) {
				server.cookiePressureHighWater = 0 // the responder always demands a cookie
			})
			assertDataRoundTrip(t, client, server)
			assertDataRoundTrip(t, server, client)
		})
		t.Run(fmt.Sprintf("retry-request/seed-%d", seed), func(t *testing.T) {
			// The client leads with the default suite, which the server refuses.
			client, server := handshakeOverFaults(t, seed, []DatagramEndpointOption{WithAllowedKEMSuites(chkem.SuiteXWing)}, nil)
			if c, s := client.kemSuite.ID(), server.kemSuite.ID(); c != chkem.SuiteXWing || s != chkem.SuiteXWing {
				t.Fatalf("suites after the retry: client=%#x server=%#x, want X-Wing on both", c, s)
			}
			assertDataRoundTrip(t, client, server)
			assertDataRoundTrip(t, server, client)
		})
	}
}
