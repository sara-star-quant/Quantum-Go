package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

func TestDeriveStreamNoncePrefixes(t *testing.T) {
	ms := mkSecret(0x5a)

	initiator, responder, err := crypto.DeriveStreamNoncePrefixes(ms)
	if err != nil {
		t.Fatalf("DeriveStreamNoncePrefixes: %v", err)
	}
	if len(initiator) != constants.DatagramNoncePrefixSize || len(responder) != constants.DatagramNoncePrefixSize {
		t.Fatalf("prefix sizes: got %d/%d, want %d", len(initiator), len(responder), constants.DatagramNoncePrefixSize)
	}

	// Deterministic.
	i2, r2, _ := crypto.DeriveStreamNoncePrefixes(ms)
	if !bytes.Equal(initiator, i2) || !bytes.Equal(responder, r2) {
		t.Error("not deterministic for the same master secret")
	}

	// The two directions differ, so send/recv never share a nonce prefix.
	if bytes.Equal(initiator, responder) {
		t.Error("initiator and responder prefixes are identical")
	}

	// Domain separation from the datagram derivation: same secret, different output.
	di, dr, _ := crypto.DeriveDatagramNoncePrefixes(ms)
	if bytes.Equal(initiator, di) || bytes.Equal(responder, dr) {
		t.Error("stream prefixes collide with datagram prefixes for the same secret")
	}

	// A different master secret yields different prefixes (per-session binding).
	oi, _, _ := crypto.DeriveStreamNoncePrefixes(mkSecret(0x5b))
	if bytes.Equal(initiator, oi) {
		t.Error("different master secret produced the same prefix")
	}
}

func TestDeriveStreamNoncePrefixesRejectsWrongLength(t *testing.T) {
	if _, _, err := crypto.DeriveStreamNoncePrefixes(make([]byte, 16)); err == nil {
		t.Error("expected error for a short master secret")
	}
}
