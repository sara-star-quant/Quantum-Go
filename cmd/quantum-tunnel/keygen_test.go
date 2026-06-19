package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// readPin decodes a base64 key/pin file written by runKeygen.
func readPin(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return raw
}

func TestKeygenRoundTrip(t *testing.T) {
	out := filepath.Join(t.TempDir(), "server")
	var buf bytes.Buffer
	if err := runKeygen(out, false, "", "chkem-v1", &buf); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}

	// Secret seed reconstructs a key pair whose public pin matches the .pub file.
	seed := readPin(t, out+".key")
	kp, err := chkem.ParseTaggedKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseTaggedKeyPair: %v", err)
	}
	defer kp.Zeroize()

	pin := readPin(t, out+".pub")
	if _, err := chkem.ParseTaggedPublicKey(pin); err != nil {
		t.Fatalf("ParseTaggedPublicKey: %v", err)
	}
	if !bytes.Equal(pin, chkem.TagSuite(kp.Suite(), kp.PublicKey().Bytes())) {
		t.Fatal("public pin does not match the secret key's public key")
	}

	if !strings.Contains(buf.String(), "SHA256:") {
		t.Errorf("expected a fingerprint in output, got: %q", buf.String())
	}
}

func TestKeygenSecretPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission bits are not meaningful on Windows")
	}
	out := filepath.Join(t.TempDir(), "server")
	if err := runKeygen(out, false, "", "chkem-v1", &bytes.Buffer{}); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}
	info, err := os.Stat(out + ".key")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("secret key mode = %o, want 600", perm)
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "server")
	if err := runKeygen(out, false, "", "chkem-v1", &bytes.Buffer{}); err != nil {
		t.Fatalf("first runKeygen: %v", err)
	}
	err := runKeygen(out, false, "", "chkem-v1", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected refusal to overwrite existing files")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}

	// --force overwrites.
	if err := runKeygen(out, true, "", "chkem-v1", &bytes.Buffer{}); err != nil {
		t.Errorf("force overwrite failed: %v", err)
	}
}

func TestKeygenPubFrom(t *testing.T) {
	out := filepath.Join(t.TempDir(), "server")
	if err := runKeygen(out, false, "", "chkem-v1", &bytes.Buffer{}); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}
	want := readPin(t, out+".pub")

	// Remove the pub file and re-derive it from the secret seed.
	if err := os.Remove(out + ".pub"); err != nil {
		t.Fatalf("remove pub: %v", err)
	}
	if err := runKeygen(out, false, out+".key", "chkem-v1", &bytes.Buffer{}); err != nil {
		t.Fatalf("pub-from: %v", err)
	}
	got := readPin(t, out+".pub")
	if !bytes.Equal(got, want) {
		t.Fatal("re-derived pin does not match original")
	}
}

func TestKeygenXWingSuite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "edge")
	if err := runKeygen(out, false, "", "x-wing", &bytes.Buffer{}); err != nil {
		t.Fatalf("runKeygen x-wing: %v", err)
	}

	seed := readPin(t, out+".key")
	kp, err := chkem.ParseTaggedKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseTaggedKeyPair: %v", err)
	}
	defer kp.Zeroize()
	if kp.Suite() != chkem.SuiteXWing {
		t.Errorf("key suite = %#x, want X-Wing", kp.Suite())
	}

	pin := readPin(t, out+".pub")
	pub, err := chkem.ParseTaggedPublicKey(pin)
	if err != nil {
		t.Fatalf("ParseTaggedPublicKey: %v", err)
	}
	if pub.Suite() != chkem.SuiteXWing {
		t.Errorf("pin suite = %#x, want X-Wing", pub.Suite())
	}
}

func TestKeygenUnknownSuiteRejected(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x")
	if err := runKeygen(out, false, "", "bogus", &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for an unknown suite")
	}
}
