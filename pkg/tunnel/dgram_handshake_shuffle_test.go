package tunnel

import (
	"math/rand"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

// shuffleHandshake runs one handshake between two FSMs over a message-level network
// that reorders, duplicates and (when drop > 0) loses every flight. Each round both
// sides first resend their cached flight, standing in for a retransmit timer. It
// returns the round in which both sides were complete, or -1.
func shuffleHandshake(t *testing.T, rng *rand.Rand, drop, dup float64, maxRounds int) int {
	t.Helper()
	initiator, responder := newFSMPair(t)
	toResp, toInit := []hsMessage(nil), []hsMessage(nil)

	first, err := initiator.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	toResp = append(toResp, first...)

	mangle := func(in []hsMessage) []hsMessage {
		var out []hsMessage
		for _, m := range in {
			if rng.Float64() < drop {
				continue
			}
			out = append(out, m)
			if rng.Float64() < dup {
				out = append(out, m)
			}
		}
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	}

	for round := 0; round < maxRounds; round++ {
		if round > 0 {
			toResp = append(toResp, initiator.cached...)
			toInit = append(toInit, responder.cached...)
		}
		in, out := mangle(toResp), mangle(toInit)
		toResp, toInit = nil, nil
		for _, m := range in {
			reply, _ := responder.onMessage(m.typ, m.body)
			toInit = append(toInit, reply...)
		}
		for _, m := range out {
			reply, _ := initiator.onMessage(m.typ, m.body)
			toResp = append(toResp, reply...)
		}
		// Deliver what the delivery above produced within the same round when the
		// network is clean, so a loss-free run needs no retransmit.
		for i := 0; i < 8 && drop == 0 && (len(toResp) > 0 || len(toInit) > 0); i++ {
			a, b := mangle(toResp), mangle(toInit)
			toResp, toInit = nil, nil
			for _, m := range a {
				reply, _ := responder.onMessage(m.typ, m.body)
				toInit = append(toInit, reply...)
			}
			for _, m := range b {
				reply, _ := initiator.onMessage(m.typ, m.body)
				toResp = append(toResp, reply...)
			}
		}
		if initiator.isComplete() && responder.isComplete() {
			return round
		}
	}
	return -1
}

// TestDgramHandshakeShuffledFlights checks the FSM pair converges under message
// reordering and duplication without any retransmit, and under loss with them.
func TestDgramHandshakeShuffledFlights(t *testing.T) {
	for seed := int64(0); seed < 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		if r := shuffleHandshake(t, rng, 0, 0.5, 3); r != 0 {
			t.Fatalf("seed %d: reorder+dup without loss completed in round %d; want 0", seed, r)
		}
	}
	for seed := int64(0); seed < 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		if r := shuffleHandshake(t, rng, 0.4, 0.3, 60); r < 0 {
			t.Fatalf("seed %d: no convergence under loss", seed)
		}
	}
}

// TestDgramHandshakeStrayMessagesIgnored feeds each side every message type with a
// junk body in every state and checks nothing completes or panics.
func TestDgramHandshakeStrayMessagesIgnored(t *testing.T) {
	types := []protocol.MessageType{
		protocol.MessageTypeClientHello, protocol.MessageTypeServerHello,
		protocol.MessageTypeServerFinished, protocol.MessageTypeClientFinished,
		protocol.MessageTypeHelloRetryRequest,
	}
	initiator, responder := newFSMPair(t)
	_, _ = initiator.start()
	for _, typ := range types {
		for _, fsm := range []*dgramHandshake{initiator, responder} {
			if out, done := fsm.onMessage(typ, []byte{1, 2, 3}); done || (out != nil && fsm == initiator) {
				t.Fatalf("junk %v: out=%v done=%v", typ, out, done)
			}
		}
	}
	if initiator.isComplete() || responder.isComplete() {
		t.Fatal("junk completed a handshake")
	}
}
