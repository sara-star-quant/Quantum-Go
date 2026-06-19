package tunnel

import (
	"bytes"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

func initStreamSession(t *testing.T, role Role, secretByte byte) *Session {
	t.Helper()
	s, err := NewSession(role)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ms := bytes.Repeat([]byte{secretByte}, constants.CHKEMSharedSecretSize)
	if err := s.InitializeKeys(ms, constants.CipherSuiteAES256GCM); err != nil {
		t.Fatalf("InitializeKeys: %v", err)
	}
	return s
}

// TestStreamRecordOmitsNonce verifies the stream no longer transmits the 12-byte
// AEAD nonce: a sealed record is exactly plaintext + tag.
func TestStreamRecordOmitsNonce(t *testing.T) {
	s := initStreamSession(t, RoleInitiator, 0x11)
	plaintext := []byte("hello quantum tunnel")

	ct, _, err := s.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want := len(plaintext) + constants.AESTagSize
	if len(ct) != want {
		t.Fatalf("record size: got %d, want %d (plaintext+tag, no transmitted nonce)", len(ct), want)
	}
}

// TestStreamNoncePrefixPerSession closes the "identical nonce sequences" limitation:
// two sessions derive different nonce prefixes, and the derivation is deterministic.
func TestStreamNoncePrefixPerSession(t *testing.T) {
	a := initStreamSession(t, RoleInitiator, 0x22)
	b := initStreamSession(t, RoleInitiator, 0x23) // different master secret

	if bytes.Equal(a.sendNoncePrefix, b.sendNoncePrefix) {
		t.Error("two sessions derived the same send nonce prefix")
	}

	// Same role and same secret derive the same prefix (deterministic, so both peers agree).
	c := initStreamSession(t, RoleInitiator, 0x22)
	if !bytes.Equal(a.sendNoncePrefix, c.sendNoncePrefix) {
		t.Error("identical inputs derived different prefixes")
	}
}

// TestStreamNoncePeersAgree verifies the initiator's send prefix matches the
// responder's recv prefix (and vice versa) for the same master secret, so derived
// nonces line up across the wire.
func TestStreamNoncePeersAgree(t *testing.T) {
	initiator := initStreamSession(t, RoleInitiator, 0x33)
	responder := initStreamSession(t, RoleResponder, 0x33)

	if !bytes.Equal(initiator.sendNoncePrefix, responder.recvNoncePrefix) {
		t.Error("initiator send prefix != responder recv prefix")
	}
	if !bytes.Equal(responder.sendNoncePrefix, initiator.recvNoncePrefix) {
		t.Error("responder send prefix != initiator recv prefix")
	}
}

// TestStreamKeyWearTrigger verifies the per-epoch key-wear logic now driven by
// seq - sendEpochStartSeq (the AEAD counter no longer tracks it under SealWithNonce).
func TestStreamKeyWearTrigger(t *testing.T) {
	s := initStreamSession(t, RoleInitiator, 0x44)

	// Below the high-water mark: no rekey needed.
	s.sendEpochStartSeq.Store(0)
	s.sendSeq.Store(datagramRekeyHighWater - 1)
	if s.NeedsRekey() {
		t.Error("NeedsRekey fired below the high-water mark")
	}

	// At the high-water mark: a background rekey should start.
	s.sendSeq.Store(datagramRekeyHighWater)
	if !s.NeedsRekey() {
		t.Error("NeedsRekey did not fire at the high-water mark")
	}

	// At the hard cap, Encrypt must fail closed rather than overrun the key.
	s.sendEpochStartSeq.Store(0)
	s.sendSeq.Store(constants.MaxPacketsBeforeRekey)
	if _, _, err := s.Encrypt([]byte("x")); !qerrors.Is(err, qerrors.ErrNonceExhausted) {
		t.Fatalf("hard cap: got %v, want ErrNonceExhausted", err)
	}
}

// TestStreamKeyWearBoundaryNoUnderflow guards the rekey-boundary race where a record's
// seq is assigned just before sendEpochStartSeq advances (seq < startSeq). The hard cap
// must not underflow uint64 and spuriously report nonce exhaustion.
func TestStreamKeyWearBoundaryNoUnderflow(t *testing.T) {
	s := initStreamSession(t, RoleInitiator, 0x55)

	// sendSeq is 0, so Encrypt assigns seq 0; set the epoch start ahead of it.
	s.sendSeq.Store(0)
	s.sendEpochStartSeq.Store(8)
	if _, _, err := s.Encrypt([]byte("boundary")); err != nil {
		t.Fatalf("seq < startSeq must not trip the key-wear guard: %v", err)
	}
}
