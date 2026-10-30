package chkem

import (
	"bytes"
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// TestSuiteRoundTripAndMalformedInputs runs every registered suite through a round
// trip, then checks truncated, extended and bit-flipped inputs are rejected or yield
// a different secret, never a panic or a match.
func TestSuiteRoundTripAndMalformedInputs(t *testing.T) {
	for _, id := range []SuiteID{SuiteCHKEMv1, SuiteXWing} {
		suite, ok := GetSuite(id)
		if !ok {
			t.Fatalf("suite %v not registered", id)
		}
		kp, err := suite.GenerateKeyPair()
		if err != nil {
			t.Fatalf("suite %v keygen: %v", id, err)
		}
		if kp.Suite() != id || kp.PublicKey().Suite() != id {
			t.Fatalf("suite %v: key reports suite %v/%v", id, kp.Suite(), kp.PublicKey().Suite())
		}
		ct, secret, err := suite.Encapsulate(kp.PublicKey(), RoleResponder)
		if err != nil {
			t.Fatalf("suite %v encapsulate: %v", id, err)
		}
		got, err := suite.Decapsulate(ct, kp, RoleInitiator)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("suite %v round trip: err=%v equal=%v", id, err, bytes.Equal(got, secret))
		}

		raw := ct.Bytes()
		for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
			if _, err := suite.ParseCiphertext(bad); err == nil {
				t.Fatalf("suite %v accepted a ciphertext of length %d", id, len(bad))
			}
		}
		pub := kp.PublicKey().Bytes()
		for _, bad := range [][]byte{nil, pub[:len(pub)-1], append(append([]byte(nil), pub...), 0)} {
			if _, err := suite.ParsePublicKey(bad); err == nil {
				t.Fatalf("suite %v accepted a public key of length %d", id, len(bad))
			}
		}

		flipped := append([]byte(nil), raw...)
		flipped[len(flipped)/2] ^= 0x01
		if bad, err := suite.ParseCiphertext(flipped); err == nil {
			if s, derr := suite.Decapsulate(bad, kp, RoleInitiator); derr == nil && bytes.Equal(s, secret) {
				t.Fatalf("suite %v: tampered ciphertext produced the original secret", id)
			}
		}
	}
}

// TestSuiteTaggedIdentity covers the suite-tagged seed and pin formats.
func TestSuiteTaggedIdentity(t *testing.T) {
	for _, id := range []SuiteID{SuiteCHKEMv1, SuiteXWing} {
		suite, _ := GetSuite(id)
		kp, seed, err := suite.GenerateStaticKeyPair()
		if err != nil {
			t.Fatalf("suite %v: %v", id, err)
		}
		back, err := ParseTaggedKeyPair(TagSuite(id, seed))
		if err != nil || back.Suite() != id || !bytes.Equal(back.PublicKey().Bytes(), kp.PublicKey().Bytes()) {
			t.Fatalf("suite %v tagged key pair round trip: %v", id, err)
		}
		pin, err := ParseTaggedPublicKey(TagSuite(id, kp.PublicKey().Bytes()))
		if err != nil || pin.Suite() != id {
			t.Fatalf("suite %v tagged public key: %v", id, err)
		}
	}
	if _, err := ParseTaggedKeyPair([]byte{0x01}); !errors.Is(err, qerrors.ErrInvalidKeySize) {
		t.Fatalf("one-byte tagged seed: got %v, want ErrInvalidKeySize", err)
	}
	if _, err := ParseTaggedPublicKey([]byte{0xFF, 0xFF, 1, 2, 3}); !errors.Is(err, qerrors.ErrUnsupportedKEMSuite) {
		t.Fatalf("unknown suite tag: got %v, want ErrUnsupportedKEMSuite", err)
	}
	if _, err := ParseTaggedKeyPair(TagSuite(SuiteCHKEMv1, []byte("short"))); err == nil {
		t.Fatal("short seed accepted")
	}
}
