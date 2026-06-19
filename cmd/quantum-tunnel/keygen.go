package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// keygenCommand generates a long-term CH-KEM identity for static-key endpoint
// authentication: a secret seed the server persists and a public pin the clients
// require. See pkg/tunnel.TransportConfig.StaticKeyPair / PinnedServerKey.
func keygenCommand() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "server", "Output file prefix; writes <prefix>.key (secret) and <prefix>.pub (pin)")
	force := fs.Bool("force", false, "Overwrite output files if they already exist")
	pubFrom := fs.String("pub-from", "", "Re-derive the public pin from an existing secret key file (no new key)")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-tunnel keygen [options]

Generate a long-term CH-KEM server identity for static-key endpoint authentication.

The server holds the secret seed (<prefix>.key) and proves possession of it during
the handshake. Clients pin the matching public key (<prefix>.pub) and reject any
server that cannot prove possession, stopping an active relaying MitM.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
FILES:
    <prefix>.key   Secret seed, base64. Keep private (written mode 0600).
    <prefix>.pub   Public pin, base64. Distribute to clients.

USING THE KEYS:
    // Server (Listen): load the secret seed and prove possession.
    seed, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyFileBytes)))
    kp, _ := chkem.ParseKeyPair(seed)
    cfg := tunnel.TransportConfig{StaticKeyPair: kp}

    // Client (Dial): pin the public key and require proof.
    pin, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubFileBytes)))
    pub, _ := chkem.ParsePublicKey(pin)
    cfg := tunnel.TransportConfig{PinnedServerKey: pub}

EXAMPLES:
    # Generate server.key and server.pub
    quantum-tunnel keygen

    # Write to a custom prefix
    quantum-tunnel keygen --out prod-edge

    # Recover the public pin from an existing secret key
    quantum-tunnel keygen --pub-from server.key --out server`)
	}

	_ = fs.Parse(os.Args[2:])

	if err := runKeygen(*out, *force, *pubFrom, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
}

// runKeygen holds the keygen logic independent of os.Args so it can be tested.
// When pubFrom is set it only re-derives the public pin from an existing secret
// seed; otherwise it generates a fresh identity and writes both files.
func runKeygen(out string, force bool, pubFrom string, w io.Writer) error {
	keyPath := out + ".key"
	pubPath := out + ".pub"

	if pubFrom != "" {
		kp, err := loadSecretKey(pubFrom)
		if err != nil {
			return err
		}
		defer kp.Zeroize()
		pin := kp.PublicKey().Bytes()
		if err := writeFile(pubPath, encodeLine(pin), 0o644, force); err != nil {
			return err
		}
		fmt.Fprintf(w, "Re-derived public pin from %s.\n", pubFrom)
		fmt.Fprintf(w, "  Public pin:   %s  (distribute to clients)\n", pubPath)
		fmt.Fprintf(w, "  Fingerprint:  %s\n", fingerprint(pin))
		return nil
	}

	kp, seed, err := chkem.GenerateStaticKeyPair()
	if err != nil {
		return err
	}
	defer kp.Zeroize()
	defer zeroize(seed)

	pin := kp.PublicKey().Bytes()
	if err := writeFile(keyPath, encodeLine(seed), 0o600, force); err != nil {
		return err
	}
	if err := writeFile(pubPath, encodeLine(pin), 0o644, force); err != nil {
		return err
	}

	fmt.Fprintln(w, "Generated static CH-KEM server identity.")
	fmt.Fprintf(w, "  Secret seed:  %s  (keep private, mode 0600)\n", keyPath)
	fmt.Fprintf(w, "  Public pin:   %s  (distribute to clients)\n", pubPath)
	fmt.Fprintf(w, "  Fingerprint:  %s  (verify out-of-band)\n", fingerprint(pin))
	return nil
}

// loadSecretKey reads a base64 secret seed file and reconstructs the key pair.
func loadSecretKey(path string) (*chkem.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	defer zeroize(seed)
	kp, err := chkem.ParseKeyPair(seed)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return kp, nil
}

// writeFile creates path with the given mode and refuses to clobber an existing
// file unless force is set, so a stray run never overwrites a live secret.
func writeFile(path string, data []byte, perm os.FileMode, force bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !force {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// encodeLine base64-encodes data as a single line with a trailing newline.
func encodeLine(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data) + "\n")
}

// fingerprint returns an SSH-style SHA256 fingerprint of the public pin so an
// operator can confirm out-of-band that a client pinned the right key.
func fingerprint(pin []byte) string {
	sum := sha256.Sum256(pin)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// zeroize clears a secret byte slice in place.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
