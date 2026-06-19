package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
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
	if err := runKeygen(out, false, "", &buf); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}

	// Secret seed reconstructs a key pair whose public pin matches the .pub file.
	seed := readPin(t, out+".key")
	kp, err := chkem.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	defer kp.Zeroize()

	pin := readPin(t, out+".pub")
	if _, err := chkem.ParsePublicKey(pin); err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !bytes.Equal(pin, kp.PublicKey().Bytes()) {
		t.Fatal("public pin does not match the secret key's public key")
	}

	if !strings.Contains(buf.String(), "SHA256:") {
		t.Errorf("expected a fingerprint in output, got: %q", buf.String())
	}
}

func TestKeygenSecretPerms(t *testing.T) {
	out := filepath.Join(t.TempDir(), "server")
	if err := runKeygen(out, false, "", &bytes.Buffer{}); err != nil {
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
	if err := runKeygen(out, false, "", &bytes.Buffer{}); err != nil {
		t.Fatalf("first runKeygen: %v", err)
	}
	err := runKeygen(out, false, "", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected refusal to overwrite existing files")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}

	// --force overwrites.
	if err := runKeygen(out, true, "", &bytes.Buffer{}); err != nil {
		t.Errorf("force overwrite failed: %v", err)
	}
}

func TestKeygenPubFrom(t *testing.T) {
	out := filepath.Join(t.TempDir(), "server")
	if err := runKeygen(out, false, "", &bytes.Buffer{}); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}
	want := readPin(t, out+".pub")

	// Remove the pub file and re-derive it from the secret seed.
	if err := os.Remove(out + ".pub"); err != nil {
		t.Fatalf("remove pub: %v", err)
	}
	if err := runKeygen(out, false, out+".key", &bytes.Buffer{}); err != nil {
		t.Fatalf("pub-from: %v", err)
	}
	got := readPin(t, out+".pub")
	if !bytes.Equal(got, want) {
		t.Fatal("re-derived pin does not match original")
	}
}
