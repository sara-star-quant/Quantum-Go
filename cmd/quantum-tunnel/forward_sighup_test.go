package main

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// SIGHUP must make a running server read its key file again. The unit tests call reloadKeys
// directly; this one runs the built binary, so the signal registration and the select loop that
// delivers it are covered too.
func TestForwardServerReloadsKeysOnSIGHUP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGHUP")
	}
	bin := t.TempDir() + "/quantum-tunnel"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	up, _ := startUpstream(t, echoHandler)
	pskPath := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	oldAuth := forwardAuth{pskFile: writeSecret(t, "old.hex", mustRead(t, pskPath), 0o600)}

	cmd := exec.Command(bin, "forward", "--serve", "127.0.0.1:0", "--upstream", up, "--psk-file", pskPath)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	// The server prints its bound address once it listens; that line is the readiness event.
	addrRE := regexp.MustCompile(`forwarding tunnels on (\S+) to`)
	addrCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if m := addrRE.FindStringSubmatch(sc.Text()); m != nil {
				addrCh <- m[1]
				break
			}
		}
		_, _ = io.Copy(io.Discard, stderr) // keep draining so the child never blocks on a full pipe
	}()
	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not report its address")
	}

	works := func(a forwardAuth) bool {
		cfg, err := buildForwardConfig(false, a)
		if err != nil {
			t.Fatal(err)
		}
		tn, err := tunnel.DialWithConfig("tcp", addr, cfg)
		if err != nil {
			return false
		}
		defer func() { _ = tn.Close() }()
		if err := tn.Send([]byte{frameData, 'x'}); err != nil {
			return false
		}
		data, err := tn.Receive()
		return err == nil && len(data) == 2 && data[1] == 'x'
	}
	if !works(oldAuth) {
		t.Fatal("the original key should work before the reload")
	}

	if err := os.WriteFile(pskPath, []byte(randomPSK(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newAuth := forwardAuth{pskFile: pskPath}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	// The reload is asynchronous: poll for the event, the new key being accepted.
	for deadline := time.Now().Add(20 * time.Second); !works(newAuth); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the server never accepted the new key after SIGHUP")
		}
	}
	if works(oldAuth) {
		t.Fatal("the old key still works after the reload")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
