package tunnel

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

var errInjected = errors.New("injected I/O fault")

// ioFaultConn fails the k-th Read or Write it sees (counting from 1) and closes the connection at
// that point, the way a dropped link would. k of zero never fails. The test is single-goroutine per
// side, so the counters need no lock.
type ioFaultConn struct {
	net.Conn
	k, ops int
	fired  bool
}

func (c *ioFaultConn) tick() error {
	c.ops++
	if c.k > 0 && c.ops == c.k {
		c.fired = true
		_ = c.Close()
		return errInjected
	}
	return nil
}

func (c *ioFaultConn) Read(p []byte) (int, error) {
	if err := c.tick(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *ioFaultConn) Write(p []byte) (int, error) {
	if err := c.tick(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type pairResult struct {
	initErr, respErr error
	initiator        *Session
	responder        *Session
	faulted          *ioFaultConn
}

// runFaultedHandshake runs a stream handshake over a pipe and fails the k-th I/O operation of one
// side. Both sides must come back inside the deadline: a fault must never leave either one hanging.
func runFaultedHandshake(t *testing.T, retry, faultInitiator bool, k int) pairResult {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	ca, cb := &ioFaultConn{Conn: a}, &ioFaultConn{Conn: b}
	res := pairResult{faulted: cb}
	if faultInitiator {
		ca.k, res.faulted = k, ca
	} else {
		cb.k = k
	}

	initiator, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	responder := mustResponder(t)
	if retry {
		responder.AllowedKEMSuites = []chkem.SuiteID{chkem.SuiteXWing} // refuses the default suite, so the server sends a HelloRetryRequest
	}
	res.initiator, res.responder = initiator, responder

	initDone, respDone := make(chan error, 1), make(chan error, 1)
	go func() { initDone <- InitiatorHandshake(initiator, ca) }()
	go func() { respDone <- ResponderHandshake(responder, cb) }()
	for _, side := range []struct {
		name string
		ch   chan error
		dst  *error
	}{{"initiator", initDone, &res.initErr}, {"responder", respDone, &res.respErr}} {
		select {
		case *side.dst = <-side.ch:
		case <-time.After(8 * time.Second):
			t.Fatalf("k=%d: the %s hung after the fault", k, side.name)
		}
	}
	return res
}

// A handshake that loses its link at any single I/O step must fail on the side that lost it, with
// the error the link gave and no other, and must leave neither side hanging. The test fails the 1st,
// 2nd, ... last I/O operation of each side in turn, for the plain handshake and for the one with a
// HelloRetryRequest, so every error return along the way runs. It also pins that a swallowed error
// cannot pass: the first failure must reach the caller unchanged.
func TestStreamHandshakeSurvivesAnIOFaultAtEveryStep(t *testing.T) {
	for _, tc := range []struct {
		name           string
		retry          bool
		faultInitiator bool
		minOps         int
	}{
		{"plain/initiator", false, true, 4},
		{"plain/responder", false, false, 4},
		{"retry/initiator", true, true, 6},
		{"retry/responder", true, false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := runFaultedHandshake(t, tc.retry, tc.faultInitiator, 0)
			if control.initErr != nil || control.respErr != nil {
				t.Fatalf("control run without a fault failed: initiator=%v responder=%v", control.initErr, control.respErr)
			}
			ops := control.faulted.ops
			if ops < tc.minOps {
				t.Fatalf("the faulted side made %d I/O operations, want at least %d: the test stopped covering the handshake", ops, tc.minOps)
			}
			for k := 1; k <= ops; k++ {
				res := runFaultedHandshake(t, tc.retry, tc.faultInitiator, k)
				if !res.faulted.fired {
					t.Fatalf("k=%d: the fault never fired", k)
				}
				got := res.respErr
				if tc.faultInitiator {
					got = res.initErr
				}
				if !errors.Is(got, errInjected) {
					t.Errorf("k=%d: the side that lost its link returned %v, want the injected error", k, got)
				}
				// An error must never sit beside a usable session: the side that failed ends closed,
				// including the initiator whose last write failed after it had derived its keys.
				if res.initErr != nil && res.initiator.State() != SessionStateClosed {
					t.Errorf("k=%d: the initiator returned %v but its session is %v, want Closed", k, res.initErr, res.initiator.State())
				}
				if res.respErr != nil && res.responder.State() != SessionStateClosed {
					t.Errorf("k=%d: the responder returned %v but its session is %v, want Closed", k, res.respErr, res.responder.State())
				}
			}
		})
	}
}
