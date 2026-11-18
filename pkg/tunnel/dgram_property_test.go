package tunnel

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// dataPlaneViolations drains what the server delivered and reports every breach of the
// data-plane property: a payload that was never sent (altered or invented) or one delivered
// more than once (a replay the window let through). Loss is allowed. When complete is true,
// every message must also have arrived.
func dataPlaneViolations(delivered map[string]int, sent []string, complete bool) []string {
	known := make(map[string]bool, len(sent))
	for _, m := range sent {
		known[m] = true
	}
	var bad []string
	for payload, n := range delivered {
		switch {
		case !known[payload] && !strings.HasPrefix(payload, "flush-"):
			bad = append(bad, fmt.Sprintf("delivered %q, which was never sent", payload))
		case n > 1:
			bad = append(bad, fmt.Sprintf("delivered %q %d times", payload, n))
		}
	}
	if complete {
		for _, m := range sent {
			if delivered[m] == 0 {
				bad = append(bad, fmt.Sprintf("never delivered %q", m))
			}
		}
	}
	return bad
}

func TestDataPlanePropertyChecker(t *testing.T) {
	sent := []string{"msg-0", "msg-1"}
	if bad := dataPlaneViolations(map[string]int{"msg-0": 1, "msg-1": 1, "flush-0": 1}, sent, true); len(bad) != 0 {
		t.Fatalf("clean run flagged: %v", bad)
	}
	for name, delivered := range map[string]map[string]int{
		"duplicate": {"msg-0": 2, "msg-1": 1},
		"altered":   {"msg-0": 1, "msg-1": 1, "msg-X": 1},
		"missing":   {"msg-0": 1},
	} {
		if bad := dataPlaneViolations(delivered, sent, true); len(bad) == 0 {
			t.Errorf("%s: checker missed the violation", name)
		}
	}
}

// Across a range of seeds, a datagram session over a link that duplicates, reorders and
// drops never delivers an altered payload and never delivers one twice. The seed is in the
// subtest name, so a failure replays with: go test -run 'TestDatagramDataPlaneProperty/.../seed-N'.
func TestDatagramDataPlaneProperty(t *testing.T) {
	profiles := []struct {
		name               string
		drop, dup, reorder float64
		complete           bool // loss-free links must deliver everything
	}{
		{"dup-reorder", 0, 0.3, 0.3, true},
		{"lossy", 0.15, 0.1, 0.2, false},
	}
	const (
		seeds    = 24
		messages = 40
	)
	for _, p := range profiles {
		for seed := uint64(1); seed <= seeds; seed++ {
			t.Run(fmt.Sprintf("%s/seed-%d", p.name, seed), func(t *testing.T) {
				client, server, epA, epB := dgramPair(t, seed, p.drop, p.dup, p.reorder)
				defer func() { _ = epA.Close() }()
				defer func() { _ = epB.Close() }()

				sent := make([]string, messages)
				for i := range sent {
					sent[i] = fmt.Sprintf("msg-%03d", i)
					if err := client.Send([]byte(sent[i])); err != nil {
						t.Fatalf("send %d: %v", i, err)
					}
				}

				// The fault model holds a packet until the next one overtakes it and data
				// frames are not retransmitted, so a throwaway flush packet releases a held
				// tail. Stop once nothing new has arrived for long enough. Before the first
				// message lands the wait is long, because a loaded runner can starve the
				// receiver for a second or more and silence then says nothing about the link.
				delivered := make(map[string]int)
				flushes := 0
				lastProgress := time.Now()
				for {
					got := 0
					for k := range delivered {
						if strings.HasPrefix(k, "msg-") {
							got++
						}
					}
					if p.complete {
						// A loss-free link must deliver everything, so wait for it, not for quiet.
						if got == messages || time.Since(lastProgress) > 10*time.Second {
							break
						}
					} else {
						quietFor := 300 * time.Millisecond
						if got == 0 {
							quietFor = 5 * time.Second
						}
						if time.Since(lastProgress) > quietFor {
							break
						}
					}
					select {
					case b := <-server.ds.recvCh:
						delivered[string(b)]++
						if strings.HasPrefix(string(b), "msg-") {
							lastProgress = time.Now() // a flush that arrives does not count as traffic
						}
					case <-time.After(20 * time.Millisecond):
						_ = client.Send(fmt.Appendf(nil, "flush-%d", flushes))
						flushes++
					}
				}
				if !p.complete {
					// A lossy link may lose messages, but a run that delivered none proves nothing.
					got := 0
					for k := range delivered {
						if strings.HasPrefix(k, "msg-") {
							got++
						}
					}
					if got == 0 {
						t.Fatalf("seed %d: nothing was delivered, so the property was not exercised", seed)
					}
				}
				if bad := dataPlaneViolations(delivered, sent, p.complete); len(bad) != 0 {
					t.Fatalf("seed %d: %s", seed, strings.Join(bad, "; "))
				}
			})
		}
	}
}
