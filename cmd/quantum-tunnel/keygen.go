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
	suite := fs.String("suite", "chkem-v1", "KEM suite for a new identity: chkem-v1 or x-wing")

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
    // Server (Listen): load the secret seed and prove possession. The seed is
    // suite-tagged, so ParseTaggedKeyPair selects the right KEM suite.
    seed, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyFileBytes)))
    kp, _ := chkem.ParseTaggedKeyPair(seed)
    cfg := tunnel.TransportConfig{StaticKeyPair: kp}

    // Client (Dial): pin the public key and require proof.
    pin, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubFileBytes)))
    pub, _ := chkem.ParseTaggedPublicKey(pin)
    cfg := tunnel.TransportConfig{PinnedServerKey: pub}

EXAMPLES:
    # Generate server.key and server.pub (CH-KEM-v1)
    quantum-tunnel keygen

    # Generate an X-Wing identity
    quantum-tunnel keygen --suite x-wing --out edge

    # Recover the public pin from an existing secret key
    quantum-tunnel keygen --pub-from server.key --out server`)
	}

	_ = fs.Parse(os.Args[2:])

	if err := runKeygen(*out, *force, *pubFrom, *suite, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
}

// suiteByName maps the --suite flag value to a KEM suite.
func suiteByName(name string) (chkem.Suite, error) {
	switch name {
	case "chkem-v1":
		return chkem.DefaultSuite(), nil
	case "x-wing":
		s, ok := chkem.GetSuite(chkem.SuiteXWing)
		if !ok {
			return nil, fmt.Errorf("x-wing suite is not registered")
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unknown suite %q (want chkem-v1 or x-wing)", name)
	}
}

// runKeygen holds the keygen logic independent of os.Args so it can be tested.
// When pubFrom is set it only re-derives the public pin from an existing secret
// seed; otherwise it generates a fresh identity and writes both files.
func runKeygen(out string, force bool, pubFrom, suiteName string, w io.Writer) error {
	keyPath := out + ".key"
	pubPath := out + ".pub"
	// A write to the output sink is not recoverable in a CLI, so ignore it here
	// rather than thread the error through every status line.
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

	if pubFrom != "" {
		kp, err := loadSecretKey(pubFrom)
		if err != nil {
			return err
		}
		defer kp.Zeroize()
		// The pin is tagged with the identity's own suite, taken from the key pair.
		pin := chkem.TagSuite(kp.Suite(), kp.PublicKey().Bytes())
		if err := writeFile(pubPath, encodeLine(pin), 0o644, force); err != nil {
			return err
		}
		p("Re-derived public pin from %s.\n", pubFrom)
		p("  Public pin:   %s  (distribute to clients)\n", pubPath)
		p("  Fingerprint:  %s\n", fingerprint(pin))
		return nil
	}

	suite, err := suiteByName(suiteName)
	if err != nil {
		return err
	}
	kp, seed, err := suite.GenerateStaticKeyPair()
	if err != nil {
		return err
	}
	defer kp.Zeroize()
	defer zeroize(seed)

	// Tag the seed and pin with the suite id so a loader self-selects the suite.
	taggedSeed := chkem.TagSuite(suite.ID(), seed)
	pin := chkem.TagSuite(suite.ID(), kp.PublicKey().Bytes())
	defer zeroize(taggedSeed)
	if err := writeFile(keyPath, encodeLine(taggedSeed), 0o600, force); err != nil {
		return err
	}
	if err := writeFile(pubPath, encodeLine(pin), 0o644, force); err != nil {
		return err
	}

	p("Generated static %s server identity.\n", suiteName)
	p("  Secret seed:  %s  (keep private, mode 0600)\n", keyPath)
	p("  Public pin:   %s  (distribute to clients)\n", pubPath)
	p("  Fingerprint:  %s  (verify out-of-band)\n", fingerprint(pin))
	return nil
}

// loadSecretKey reads a base64 suite-tagged secret seed file and reconstructs the
// key pair, selecting the KEM suite from the seed's tag.
func loadSecretKey(path string) (*chkem.KeyPair, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI key file argument; reading the named secret is the command's purpose
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	defer zeroize(seed)
	kp, err := chkem.ParseTaggedKeyPair(seed)
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
	f, err := os.OpenFile(path, flags, perm) // #nosec G304 -- path is an operator-supplied CLI output file argument; writing the named key file is the command's purpose
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
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
