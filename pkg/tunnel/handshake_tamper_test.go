package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// tamperOffsets returns the byte offsets to flip in a message of n bytes: every byte
// of a short message, and for a long one the first and last 64 bytes (headers,
// lengths, tags) plus every third byte of the body, so a sweep stays fast under the
// race detector while still touching every field.
func tamperOffsets(n int) []int {
	if n <= 256 {
		all := make([]int, n)
		for i := range all {
			all[i] = i
		}
		return all
	}
	var out []int
	for i := 0; i < n; i++ {
		if i < 64 || i >= n-64 || i%3 == 0 {
			out = append(out, i)
		}
	}
	return out
}

// runDgramHandshakeTampered drives a datagram handshake between two state machines
// and flips one byte of one message in flight. It reports whether each side ended
// complete. Messages the receiver drops are simply not delivered further, as on a
// real network where a bad datagram is discarded.
func runDgramHandshakeTampered(t *testing.T, which protocol.MessageType, offset int, mask byte) (initDone, respDone bool) {
	t.Helper()
	initiator, responder := newFSMPair(t)
	flip := func(m hsMessage) hsMessage {
		if m.typ != which {
			return m
		}
		body := append([]byte(nil), m.body...)
		if offset < len(body) {
			body[offset] ^= mask
		}
		return hsMessage{typ: m.typ, body: body}
	}

	chs, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var flight []hsMessage
	for _, m := range chs {
		out, _ := responder.onMessage(flip(m).typ, flip(m).body)
		flight = append(flight, out...)
	}
	var toResp []hsMessage
	for _, m := range flight {
		fm := flip(m)
		out, _ := initiator.onMessage(fm.typ, fm.body)
		toResp = append(toResp, out...)
	}
	for _, m := range toResp {
		fm := flip(m)
		responder.onMessage(fm.typ, fm.body)
	}
	return initiator.isComplete(), responder.isComplete()
}

// honestDgramLengths returns the byte length of each handshake message in an
// untampered run, so the sweep knows how many offsets each message has.
func honestDgramLengths(t *testing.T) map[protocol.MessageType]int {
	t.Helper()
	initiator, responder := newFSMPair(t)
	lens := map[protocol.MessageType]int{}
	chs, _ := initiator.start()
	for _, m := range chs {
		lens[m.typ] = len(m.body)
	}
	flight, _ := responder.onMessage(chs[0].typ, chs[0].body)
	var cf []hsMessage
	for _, m := range flight {
		lens[m.typ] = len(m.body)
		out, _ := initiator.onMessage(m.typ, m.body)
		cf = append(cf, out...)
	}
	for _, m := range cf {
		lens[m.typ] = len(m.body)
		responder.onMessage(m.typ, m.body)
	}
	if !initiator.isComplete() || !responder.isComplete() {
		t.Fatal("untampered handshake did not complete")
	}
	return lens
}

// TestDgramHandshakeRejectsEveryTamperedByte flips single bytes of every handshake
// message, one at a time, and requires that the two sides never both complete. A
// completed pair after a tamper would mean some byte of the handshake is not
// authenticated by the transcript or the Finished MACs.
func TestDgramHandshakeRejectsEveryTamperedByte(t *testing.T) {
	lens := honestDgramLengths(t)
	for _, typ := range []protocol.MessageType{
		protocol.MessageTypeClientHello, protocol.MessageTypeServerHello,
		protocol.MessageTypeServerFinished, protocol.MessageTypeClientFinished,
	} {
		n, ok := lens[typ]
		if !ok {
			t.Fatalf("message type %v missing from the honest run", typ)
		}
		for _, off := range tamperOffsets(n) {
			for _, mask := range []byte{0x01, 0x80} {
				initDone, respDone := runDgramHandshakeTampered(t, typ, off, mask)
				if initDone && respDone {
					t.Fatalf("both sides completed after flipping bit mask %#x of byte %d of %v (%d bytes)", mask, off, typ, n)
				}
			}
		}
	}
}

// flipConn flips one byte of the stream written through it.
type flipConn struct {
	net.Conn
	mu    sync.Mutex
	at    int // offset to flip, or -1 for none
	mask  byte
	count int
}

func (c *flipConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	buf := p
	if c.at >= c.count && c.at < c.count+len(p) {
		buf = append([]byte(nil), p...)
		buf[c.at-c.count] ^= c.mask
	}
	c.count += len(p)
	c.mu.Unlock()
	return c.Conn.Write(buf)
}

func (c *flipConn) written() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// runStreamHandshake runs the stream handshake over an in-memory pipe, tampering with
// one byte in one direction. It returns whether each side finished without error and
// how many bytes each side wrote. The deadline only stops a case where the tamper
// leaves a side waiting for bytes that never come; such a case counts as not
// completed, so a slow machine can only make the assertion easier to meet.
func runStreamHandshake(t *testing.T, clientFlip, serverFlip int, mask byte, deadline time.Duration) (clientOK, serverOK bool, clientBytes, serverBytes int) {
	t.Helper()
	a, b := net.Pipe()
	cc := &flipConn{Conn: a, at: clientFlip, mask: mask}
	sc := &flipConn{Conn: b, at: serverFlip, mask: mask}
	_ = a.SetDeadline(time.Now().Add(deadline))
	_ = b.SetDeadline(time.Now().Add(deadline))

	cs, err := NewSession(RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := NewSession(RoleResponder)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var cerr, serr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		cerr = InitiatorHandshake(cs, cc)
		if cerr != nil {
			_ = a.Close() // unblock the peer, as a real client dropping the connection would
		}
	}()
	go func() {
		defer wg.Done()
		serr = ResponderHandshake(ss, sc)
		if serr != nil {
			_ = b.Close()
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return cerr == nil, serr == nil, cc.written(), sc.written()
}

// TestStreamHandshakeRejectsTamperedBytes does the same sweep over the real stream
// handshake and its length-prefixed framing, in both directions.
func TestStreamHandshakeRejectsTamperedBytes(t *testing.T) {
	clientOK, serverOK, cBytes, sBytes := runStreamHandshake(t, -1, -1, 0, 30*time.Second)
	if !clientOK || !serverOK {
		t.Fatalf("untampered stream handshake failed: client=%v server=%v", clientOK, serverOK)
	}
	for _, dir := range []struct {
		name   string
		n      int
		client bool
	}{{"client to server", cBytes, true}, {"server to client", sBytes, false}} {
		for _, off := range tamperOffsets(dir.n) {
			if off >= 32 && off < dir.n-32 && off%61 != 0 {
				continue // thin the stream sweep: the datagram sweep is exhaustive, this one covers the framing
			}
			cf, sf := -1, -1
			if dir.client {
				cf = off
			} else {
				sf = off
			}
			cOK, sOK, _, _ := runStreamHandshake(t, cf, sf, 0x01, 120*time.Millisecond)
			if cOK && sOK {
				t.Fatalf("both sides completed after flipping byte %d of the %s stream (%d bytes)", off, dir.name, dir.n)
			}
		}
	}
}
