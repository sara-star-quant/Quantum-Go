package crypto

import (
	"errors"
	"io"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/randsrc"
)

var errEntropy = errors.New("entropy source failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errEntropy }

// shortReader supplies n bytes and then fails, like an entropy source dying mid-read.
type shortReader struct{ left int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errEntropy
	}
	n := min(len(p), r.left)
	r.left -= n
	return n, nil
}

// stuckReader returns the same bytes forever, the failure the continuous RNG test exists for.
type stuckReader struct{}

func (stuckReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

func withEntropy(t *testing.T, r io.Reader) {
	t.Helper()
	t.Cleanup(randsrc.Set(r))
}

func TestRandomnessFailureFailsClosed(t *testing.T) {
	for name, r := range map[string]io.Reader{"dead": failingReader{}, "dies mid-read": &shortReader{left: 3}} {
		t.Run(name, func(t *testing.T) {
			withEntropy(t, r)

			if err := SecureRandom(make([]byte, 32)); err == nil {
				t.Fatal("SecureRandom returned no error")
			}
			if b, err := SecureRandomBytes(32); err == nil || b != nil {
				t.Fatalf("SecureRandomBytes = %v, %v; want nil and an error", b, err)
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("MustSecureRandomBytes did not panic")
					}
				}()
				MustSecureRandomBytes(32)
			}()

			// Key generation for ML-KEM and X25519 is delegated to the Go standard library,
			// which draws its own entropy and ignores an injected reader, so only the
			// seed-based X-Wing generator is covered here.
			if kp, err := GenerateXWingKeyPair(); err == nil || kp != nil {
				t.Fatalf("GenerateXWingKeyPair = %v, %v; want nil and an error", kp, err)
			}
		})
	}
}

func TestEncapsulationFailsWithoutEntropy(t *testing.T) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xw, err := GenerateXWingKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	withEntropy(t, failingReader{})
	if ct, ss, err := MLKEMEncapsulate(kp.EncapsulationKey); err == nil || ct != nil || ss != nil {
		t.Fatalf("MLKEMEncapsulate produced output without entropy: %v %v %v", ct, ss, err)
	}
	if ct, ss, err := XWingEncapsulate(xw.publicKey); err == nil || ct != nil || ss != nil {
		t.Fatalf("XWingEncapsulate produced output without entropy: %v %v %v", ct, ss, err)
	}
}

// A failing known-answer test fails the module's power-on result and, in FIPS mode,
// stops the process; outside FIPS mode it is reported without panicking.
func TestPOSTFailureBlocksFIPSMode(t *testing.T) {
	pass := func() error { return nil }
	fail := func() error { return errors.New("wrong answer") }

	if r := evaluatePOST(pass, pass, pass); !r.Passed || !r.KDFPassed || !r.AESPassed || !r.MLKEMPassed {
		t.Fatalf("healthy KATs reported %+v", r)
	}
	for name, tc := range map[string][3]func() error{
		"kdf":    {fail, pass, pass},
		"aes":    {pass, fail, pass},
		"ml-kem": {pass, pass, fail},
	} {
		t.Run(name, func(t *testing.T) {
			r := evaluatePOST(tc[0], tc[1], tc[2])
			if r.Passed || len(r.Errors) != 1 {
				t.Fatalf("failing KAT reported %+v", r)
			}
			panicked := func() (p bool) {
				defer func() { p = recover() != nil }()
				enforcePOST(r)
				return false
			}()
			if panicked != FIPSMode() {
				t.Fatalf("enforcePOST panicked=%v, want %v (FIPS mode %v)", panicked, FIPSMode(), FIPSMode())
			}
		})
	}
	if !POSTPassed() {
		t.Fatal("the real power-on self-tests did not pass")
	}
}

func withPairwiseTests(t *testing.T) {
	t.Helper()
	getConfig()
	prev := cstConfig
	cstConfig.EnablePairwiseTest = true
	t.Cleanup(func() { cstConfig = prev })
}

// A key pair whose halves do not belong together must fail the pairwise test: an error
// outside FIPS mode, a panic inside it. The caller never receives the pair.
func TestPairwiseConsistencyRejectsMismatchedKeys(t *testing.T) {
	withPairwiseTests(t)
	expect := func(t *testing.T, run func() error) {
		t.Helper()
		var err error
		panicked := func() (p bool) {
			defer func() { p = recover() != nil }()
			err = run()
			return false
		}()
		switch {
		case FIPSMode() && !panicked:
			t.Fatal("FIPS mode accepted an inconsistent key pair")
		case !FIPSMode() && (panicked || err == nil):
			t.Fatalf("want an error, got panic=%v err=%v", panicked, err)
		}
	}

	t.Run("x25519", func(t *testing.T) {
		a, _ := GenerateX25519KeyPair()
		b, _ := GenerateX25519KeyPair()
		bad := &X25519KeyPair{PublicKey: b.PublicKey, PrivateKey: a.PrivateKey}
		if PairwiseConsistencyTestX25519(bad).Passed {
			t.Fatal("pairwise test passed for a mismatched X25519 pair")
		}
		expect(t, func() error { return runPairwiseTestX25519(bad) })
	})
	t.Run("ml-kem", func(t *testing.T) {
		a, _ := GenerateMLKEMKeyPair()
		b, _ := GenerateMLKEMKeyPair()
		bad := &MLKEMKeyPair{EncapsulationKey: a.EncapsulationKey, DecapsulationKey: b.DecapsulationKey}
		if PairwiseConsistencyTestMLKEM(bad).Passed {
			t.Fatal("pairwise test passed for a mismatched ML-KEM pair")
		}
		expect(t, func() error { return runPairwiseTestMLKEM(bad) })
	})
}

// A stuck entropy source repeats its output; the continuous test catches the second
// block, and in FIPS mode SecureRandomWithCST refuses to return it.
func TestContinuousRNGTestCatchesStuckSource(t *testing.T) {
	lastRNGMutex.Lock()
	prev := lastRNGOutput
	lastRNGOutput = nil
	lastRNGMutex.Unlock()
	t.Cleanup(func() { lastRNGMutex.Lock(); lastRNGOutput = prev; lastRNGMutex.Unlock() })

	withEntropy(t, stuckReader{})
	buf := make([]byte, 47)
	if err := SecureRandomWithCST(buf); err != nil {
		t.Fatalf("first block: %v", err)
	}
	if !FIPSMode() {
		// Outside FIPS mode SecureRandomWithCST skips the continuous test, so feed it
		// the block directly.
		_ = ContinuousRNGTest(buf)
		if ContinuousRNGTest(buf).Passed {
			t.Fatal("continuous test passed for a repeated block")
		}
		return
	}
	defer func() {
		if recover() == nil {
			t.Fatal("FIPS mode returned a repeated RNG block")
		}
	}()
	_ = SecureRandomWithCST(buf)
}
