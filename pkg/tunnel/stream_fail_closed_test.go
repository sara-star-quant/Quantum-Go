package tunnel

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// A stream delivers records in order, so a record that fails a check means tampering or a broken
// peer. The first one ends the tunnel: Receive reports the cause once, then the tunnel is closed.
func TestStreamBadRecordClosesTheTunnel(t *testing.T) {
	seal := func(t *testing.T, s *Session) []byte {
		t.Helper()
		frame, _, err := s.encryptFrameTo(nil, []byte("record"), nil)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	header := func(typ protocol.MessageType, n uint32) []byte {
		return []byte{byte(typ), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	cases := map[string]func(t *testing.T, ci *Session) []byte{
		"forged record": func(t *testing.T, ci *Session) []byte {
			f := seal(t, ci)
			f[len(f)-1] ^= 1
			return f
		},
		"replayed record": func(t *testing.T, ci *Session) []byte {
			f := seal(t, ci)
			return append(append([]byte{}, f...), f...)
		},
		"truncated data record":  func(*testing.T, *Session) []byte { return header(protocol.MessageTypeData, 0) },
		"truncated rekey record": func(*testing.T, *Session) []byte { return header(protocol.MessageTypeRekey, 0) },
		"unknown type":           func(*testing.T, *Session) []byte { return header(0x7f, 0) },
		"oversize length":        func(*testing.T, *Session) []byte { return header(protocol.MessageTypeData, protocol.MaxMessageSize+1) },
		"fatal alert": func(*testing.T, *Session) []byte {
			return protocol.NewCodec().EncodeAlert(protocol.AlertLevelFatal, protocol.AlertCodeHandshakeFailure, "x")
		},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			ct, rt, cfc, _, ci, ri := rekeyPair(t)
			if _, err := cfc.Write(bad(t, ci)); err != nil {
				t.Fatal(err)
			}
			if name == "replayed record" {
				if _, err := receiveResult(t, rt); err != nil {
					t.Fatalf("the first copy is genuine: %v", err)
				}
			}
			_, err := receiveResult(t, rt)
			if err == nil || errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Fatalf("Receive must report the cause once, got %v", err)
			}
			// A genuine record sent afterwards must not be delivered.
			_ = ct.Send([]byte("after"))
			if data, err := receiveResult(t, rt); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Fatalf("Receive after a bad record = %q, %v; want ErrTunnelClosed", data, err)
			}
			if err := rt.Send([]byte("x")); !errors.Is(err, qerrors.ErrTunnelClosed) {
				t.Fatalf("Send after a bad record = %v; want ErrTunnelClosed", err)
			}
			if ri.State() != SessionStateClosed {
				t.Fatalf("session state = %v, want Closed", ri.State())
			}
			// No close notice: the peer must not read tampering as a graceful end.
			if err := ct.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := ct.conn.Read(b[:]); n != 0 || err == nil {
				t.Fatalf("peer read %d bytes (%v); want the connection closed with nothing sent", n, err)
			}
		})
	}
}

// A read timeout is not a bad record. The tunnel stays usable.
func TestStreamReadTimeoutLeavesTheTunnelOpen(t *testing.T) {
	ct, rt, _, _, _, _ := rekeyPair(t)
	rt.SetReadTimeout(20 * time.Millisecond)
	_, err := receiveResult(t, rt)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("want a timeout, got %v", err)
	}
	rt.SetReadTimeout(0)
	_ = rt.conn.SetReadDeadline(time.Time{})
	if err := ct.Send([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if data, err := receiveResult(t, rt); err != nil || string(data) != "after" {
		t.Fatalf("Receive after a timeout = %q, %v", data, err)
	}
}

// A control record takes its sequence number under the write lock, like a data record. Otherwise a
// large batch can overtake it, push it out of the peer's replay window and end a healthy tunnel.
func TestControlRecordsTakeTheirSequenceUnderTheWriteLock(t *testing.T) {
	cases := map[string]func(ct *Transport) error{
		"rekey request":  func(ct *Transport) error { return ct.SendRekey() },
		"rekey response": func(ct *Transport) error { return ct.sendRekeyResponse([]byte("ciphertext"), 0) },
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			ct, _, _, _, ci, _ := rekeyPair(t)
			before := ci.sendSeq.Load()
			ct.writeMu.Lock()
			done := make(chan error, 1)
			go func() { done <- send(ct) }()
			// Nothing signals "blocked on a mutex", so watch for the wrong behavior for a while.
			// A scheduler stall can only hide a failure, never cause one.
			deadline := time.Now().Add(200 * time.Millisecond)
			for time.Now().Before(deadline) && ci.sendSeq.Load() == before {
				time.Sleep(time.Millisecond)
			}
			taken := ci.sendSeq.Load() - before
			ct.writeMu.Unlock()
			if err := within(t, name, func() error { return <-done }); err != nil {
				t.Fatal(err)
			}
			if taken != 0 {
				t.Fatalf("%s took %d sequence numbers while another writer held the lock", name, taken)
			}
		})
	}
}

// The abort runs on the reader's goroutine while the application may still be sending. Every call
// must return. Run under -race.
func TestStreamBadRecordAbortRacesSenders(t *testing.T) {
	for range 20 {
		ct, rt, cfc, _, _, _ := rekeyPair(t)
		go func() { // keep the peer's socket drained so the senders make progress
			buf := make([]byte, 4096)
			for {
				if _, err := ct.conn.Read(buf); err != nil {
					return
				}
			}
		}()
		var wg sync.WaitGroup
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for rt.Send([]byte("x")) == nil {
				}
			}()
		}
		if _, err := cfc.Write([]byte{0x7f, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if _, err := receiveResult(t, rt); err == nil {
			t.Fatal("Receive must refuse the record")
		}
		within(t, "senders", func() struct{} { wg.Wait(); return struct{}{} })
		_ = ct.Close()
	}
}
