package crypto

import (
	"bytes"
	"sync"
	"testing"
)

// chunkReader serves fixed chunks, one per Read, then repeats the last.
type chunkReader struct {
	chunks [][]byte
	n      int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	c := r.chunks[min(r.n, len(r.chunks)-1)]
	r.n++
	return copy(p, c), nil
}

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// withCST installs a self-test configuration for one test and restores the old one.
func withCST(t *testing.T, cfg CSTConfig) {
	t.Helper()
	prev := getConfig() // initialize the defaults first so the restore puts them back
	cstConfig = cfg
	t.Cleanup(func() { cstConfig = prev })
}

// failsClosed runs fn and requires a failure: a panic in FIPS mode, an error otherwise.
func failsClosed(t *testing.T, what string, fn func() error) {
	t.Helper()
	defer func() {
		r := recover()
		if FIPSMode() && r == nil {
			t.Errorf("%s: FIPS mode did not panic", what)
		}
		if !FIPSMode() && r != nil {
			t.Errorf("%s: panicked outside FIPS mode: %v", what, r)
		}
	}()
	if err := fn(); err == nil && !FIPSMode() {
		t.Errorf("%s: no error", what)
	}
}

// Each way the entropy source can go bad must fail the health check, not pass it.
func TestRNGHealthCheckRejectsBadSources(t *testing.T) {
	varied := make([]byte, 32)
	for i := range varied {
		varied[i] = byte(i + 1)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(200 - i)
	}
	cases := map[string]*chunkReader{
		"dead":               nil,
		"all zero":           {chunks: [][]byte{fill(0)}},
		"first sample zero":  {chunks: [][]byte{fill(0), varied}},
		"second sample zero": {chunks: [][]byte{varied, fill(0)}},
		"repeats":            {chunks: [][]byte{varied}},
		"first constant":     {chunks: [][]byte{fill(7), other}},
		"second constant":    {chunks: [][]byte{varied, fill(9)}},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if src == nil {
				withEntropy(t, failingReader{})
			} else {
				withEntropy(t, src)
			}
			if RNGHealthCheck().Passed {
				t.Fatal("health check passed a bad source")
			}
		})
	}
	withEntropy(t, &chunkReader{chunks: [][]byte{varied, other}})
	if r := RNGHealthCheck(); !r.Passed {
		t.Fatalf("health check failed a varied source: %v", r.Error)
	}
}

// The periodic check fires on its interval, and a bad source then fails closed.
func TestPeriodicRNGHealthCheckFailsClosed(t *testing.T) {
	withCST(t, CSTConfig{EnableRNGHealthCheck: true, RNGHealthCheckInterval: 1})
	withEntropy(t, &chunkReader{chunks: [][]byte{fill(0)}})
	failsClosed(t, "runRNGHealthCheck", runRNGHealthCheck)

	withCST(t, CSTConfig{EnableRNGHealthCheck: false, RNGHealthCheckInterval: 1})
	if err := runRNGHealthCheck(); err != nil {
		t.Fatalf("disabled check returned %v", err)
	}
}

func TestInitCSTKeepsTheFirstConfiguration(t *testing.T) {
	prev := GetCSTConfig()
	t.Cleanup(func() {
		cstConfigOnce = sync.Once{}
		cstConfigOnce.Do(func() {})
		cstConfig = prev
	})
	cstConfigOnce = sync.Once{}

	first := CSTConfig{EnablePairwiseTest: true, RNGHealthCheckInterval: 7}
	InitCST(first)
	InitCST(CSTConfig{RNGHealthCheckInterval: 99})
	if got := GetCSTConfig(); got != first {
		t.Fatalf("config = %+v, want the first %+v", got, first)
	}
	if !CSTEnabled() {
		t.Fatal("CSTEnabled false with pairwise tests on")
	}
}

// A wrong known answer must fail the power-on test.
func TestKATMismatchFails(t *testing.T) {
	flip := func(b []byte) { b[0] ^= 1; t.Cleanup(func() { b[0] ^= 1 }) }

	flip(postKATKDFExpected)
	if err := runKDFKAT(); err == nil {
		t.Error("KDF KAT passed with a wrong expected value")
	}
	flip(postKATAESExpected)
	if err := runAESGCMKAT(); err == nil {
		t.Error("AES-GCM KAT passed with a wrong expected value")
	}
}
