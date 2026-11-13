package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/metrics"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// Each tunnel record carries a one-byte frame type, so a TCP half-close travels through the
// tunnel (which has no half-close of its own) without any change to the wire protocol.
const (
	frameData byte = 0x00
	frameEOF  byte = 0x01

	// forwardChunk is the largest record we send, frame byte included. It stays under the
	// tunnel's 65,507 byte limit and matches the record size the benchmarks use.
	forwardChunk = 60 << 10

	pskHexLen = 64 // a 32-byte pre-shared key as hex
)

// forwardLimits bounds what one forwarder will hold open.
type forwardLimits struct {
	maxConns    int
	idleTimeout time.Duration
	dialTimeout time.Duration
	// socketMode is the permission of a Unix socket on the plain side; 0 means 0600.
	socketMode os.FileMode
	// maxPerIP caps concurrent connections from one source address, and handshakeRate caps
	// handshakes per second across all sources. Each handshake costs the server an ML-KEM
	// operation before it knows who the peer is, so these bound what a stranger can spend.
	// 0 disables the limit.
	maxPerIP      int
	handshakeRate float64
}

// isAcceptFailure reports whether err comes from the listening socket's accept call.
func isAcceptFailure(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "accept"
}

// refusalLog logs refused handshakes at most once a second and counts the rest, so a flood
// the rate limits are absorbing does not become a flood of log lines.
type refusalLog struct {
	last       time.Time
	suppressed int
}

func (r *refusalLog) note(logf func(string, ...any), err error) {
	if time.Since(r.last) < time.Second {
		r.suppressed++
		return
	}
	if r.suppressed > 0 {
		logf("handshake refused (a wrong PSK or key, a rate limit, or a peer that is not a tunnel client): %v (and %d more in the last second)", err, r.suppressed)
	} else {
		logf("handshake refused (a wrong PSK or key, a rate limit, or a peer that is not a tunnel client): %v", err)
	}
	r.last, r.suppressed = time.Now(), 0
}

// forwarder is a running client or server side of a forwarding pair.
type forwarder struct {
	addr    net.Addr
	closeFn func() error
	closed  atomic.Bool
	wg      sync.WaitGroup
	// done closes when the accept loop ends, so the command can exit when a listener dies
	// instead of idling with nothing to serve.
	done chan struct{}
	// cfg is the live transport config. A reload swaps it: new connections use the new keys,
	// open ones keep the keys they started with.
	cfg atomic.Pointer[tunnel.TransportConfig]
	// ops holds the counts, readiness and drain state the metrics endpoint reports.
	ops *forwardOps
}

func (f *forwarder) Addr() net.Addr { return f.addr }

// Reload makes next the config for connections that start from now on. A client takes the
// whole config (PSK and pinned key). A server takes only the PSK table, because its listener
// keeps the static key it started with; changing --server-key needs a restart.
func (f *forwarder) Reload(next tunnel.TransportConfig) { f.cfg.Store(&next) }

// Drain stops accepting, reports not ready, and waits up to timeout for open connections to
// finish. It returns true when they all did. The caller cuts whatever is left by exiting.
func (f *forwarder) Drain(timeout time.Duration) bool {
	_ = f.Close()
	return f.ops.drain(timeout)
}

// Close stops accepting and waits for the accept loop to finish. Connections already
// piping are cut when the process exits; Drain waits for them first.
func (f *forwarder) Close() error {
	f.closed.Store(true)
	err := f.closeFn()
	f.wg.Wait()
	return err
}

// startForwardServer accepts tunnels on addr and hands each one to the single fixed
// upstream. The peer never chooses a destination, so this cannot act as an open relay.
func startForwardServer(addr, upstream string, cfg tunnel.TransportConfig, lim forwardLimits, logf func(string, ...any)) (*forwarder, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if path, isUnix := unixPath(upstream); isUnix {
		if runtime.GOOS == "windows" {
			return nil, errNoUnixSockets
		}
		// Not fatal: the service may start after the forwarder. Say so, or every connection fails quietly.
		if _, err := os.Stat(path); err != nil {
			logf("upstream socket %s does not exist yet; connections fail until it does", path)
		}
	}
	ln, err := tunnel.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	f := &forwarder{addr: ln.Addr(), closeFn: ln.Close, done: make(chan struct{}), ops: newForwardOps()}
	stored := cfg // the listener gets a copy whose lookup reads the live config
	f.cfg.Store(&stored)
	cfg.PSKLookup = func(identity []byte) []byte {
		if lookup := f.cfg.Load().PSKLookup; lookup != nil {
			return lookup(identity)
		}
		return nil
	}
	cfg.RateLimit = tunnel.RateLimitConfig{
		MaxConnectionsPerIP: lim.maxPerIP,
		HandshakeRateLimit:  lim.handshakeRate,
		HandshakeBurst:      max(1, int(2*lim.handshakeRate)), // a burst of 0 would refuse every handshake
	}
	// The observer counts handshake load and rate-limit hits for the metrics endpoint. Its own
	// log lines go nowhere: the refusal log below already reports them, throttled.
	cfg.RateLimitObserver = metrics.NewRateLimitObserver(f.ops.collector, metrics.NewLogger(metrics.WithOutput(io.Discard)))
	ln.SetConfig(cfg)
	sem := make(chan struct{}, lim.maxConns)
	f.ops.ready.Store(true)
	f.wg.Go(func() {
		defer close(f.done)
		acceptFails := 0
		var refusals refusalLog
		for {
			t, err := ln.Accept()
			if err != nil {
				if f.closed.Load() {
					return
				}
				// A failure of the socket itself (out of descriptors, closed underneath us) is an
				// accept error from the net package. A failed handshake is not, even when two in
				// a row carry the same error, so a stranger that hangs up cannot stop the loop.
				if isAcceptFailure(err) {
					acceptFails++
					if acceptFails >= 20 || errors.Is(err, net.ErrClosed) {
						logf("listener failed: %v", err)
						return
					}
					logf("accept: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				// A wrong PSK, a wrong pinned key, a rate-limited peer or a client that is not a
				// tunnel peer all surface here; keep serving.
				f.ops.refused.Add(1)
				refusals.note(logf, err)
				continue
			}
			acceptFails = 0
			select {
			case sem <- struct{}{}:
			default:
				logf("rejecting %v: %d connections already open", t.RemoteAddr(), lim.maxConns)
				_ = t.Close()
				continue
			}
			done := f.ops.serving()
			go func() {
				defer done()
				defer func() { <-sem }()
				serveOne(t, upstream, lim, logf, f.ops)
			}()
		}
	})
	return f, nil
}

func serveOne(t *tunnel.Tunnel, upstream string, lim forwardLimits, logf func(string, ...any), ops *forwardOps) {
	defer func() { _ = t.Close() }()
	start := time.Now()
	conn, err := dialUpstream(upstream, lim.dialTimeout)
	if err != nil {
		ops.dialFailed.Add(1)
		logf("upstream %s: %v", upstream, err)
		return
	}
	defer func() { _ = conn.Close() }()
	sent, recv := pipe(conn, t, lim.idleTimeout)
	ops.bytes(recv, sent)
	logf("closed %v after %s: %d bytes to upstream, %d back", t.RemoteAddr(), time.Since(start).Round(time.Millisecond), recv, sent)
}

// startForwardClient accepts plain TCP on listen and carries each connection to connect
// through its own tunnel.
func startForwardClient(listen, connect string, cfg tunnel.TransportConfig, lim forwardLimits, logf func(string, ...any)) (*forwarder, error) {
	ln, err := listenPlain(listen, lim.socketMode)
	if err != nil {
		return nil, err
	}
	f := &forwarder{addr: ln.Addr(), closeFn: ln.Close, done: make(chan struct{}), ops: newForwardOps()}
	f.cfg.Store(&cfg)
	sem := make(chan struct{}, lim.maxConns)
	f.ops.ready.Store(true)
	f.wg.Go(func() {
		defer close(f.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				if f.closed.Load() || errors.Is(err, net.ErrClosed) {
					return
				}
				logf("accept: %v", err)
				time.Sleep(100 * time.Millisecond) // out of descriptors and the like: do not spin
				continue
			}
			select {
			case sem <- struct{}{}:
			default:
				logf("rejecting %s: %d connections already open", connLabel(conn), lim.maxConns)
				_ = conn.Close()
				continue
			}
			done := f.ops.serving()
			go func() {
				defer done()
				defer func() { <-sem }()
				defer func() { _ = conn.Close() }()
				start := time.Now()
				t, err := tunnel.DialWithConfig("tcp", connect, *f.cfg.Load())
				if err != nil {
					f.ops.dialFailed.Add(1)
					logf("tunnel to %s: %v", connect, err)
					return
				}
				defer func() { _ = t.Close() }()
				sent, recv := pipe(conn, t, lim.idleTimeout)
				f.ops.bytes(sent, recv)
				logf("closed %s after %s: %d bytes sent, %d received", connLabel(conn), time.Since(start).Round(time.Millisecond), sent, recv)
			}()
		}
	})
	return f, nil
}

// pipe copies both directions between a TCP connection and a tunnel until each side has
// finished, or until either fails, and returns the byte counts (TCP to tunnel, tunnel to TCP).
// A connection is idle only when neither direction moved data for the idle timeout, so a long
// upload with a silent upstream, or a long download with a silent client, stays open.
func pipe(conn net.Conn, t *tunnel.Tunnel, idle time.Duration) (sent, recv int64) {
	var once sync.Once
	abort := func() {
		once.Do(func() {
			_ = conn.Close()
			_ = t.Close()
		})
	}
	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	finished := make(chan struct{})
	defer close(finished)
	if idle > 0 {
		go func() {
			tick := time.NewTicker(max(idle/4, time.Millisecond))
			defer tick.Stop()
			for {
				select {
				case <-finished:
					return
				case <-tick.C:
					if time.Since(time.Unix(0, last.Load())) > idle {
						abort()
						return
					}
				}
			}
		}()
	}

	// Both directions end with an EOF frame. The tunnel keeps being read after the peer's EOF
	// so rekeys and the close alert still get processed; the pair ends when both EOFs are done.
	var halves atomic.Int32
	halfDone := func() {
		if halves.Add(1) == 2 {
			abort()
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // TCP to tunnel
		defer wg.Done()
		buf := make([]byte, forwardChunk)
		for {
			n, err := conn.Read(buf[1:])
			if n > 0 {
				buf[0] = frameData
				if serr := t.Send(buf[:n+1]); serr != nil {
					abort()
					return
				}
				touch()
				atomic.AddInt64(&sent, int64(n))
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					if serr := t.Send([]byte{frameEOF}); serr != nil {
						abort()
						return
					}
					halfDone()
					return
				}
				abort()
				return
			}
		}
	}()

	go func() { // tunnel to TCP
		defer wg.Done()
		buf := make([]byte, 0, forwardChunk)
		for {
			data, err := t.ReceiveInto(buf[:0])
			if err != nil || len(data) == 0 {
				abort()
				return
			}
			touch()
			switch data[0] {
			case frameData:
				if len(data) > 1 {
					if idle > 0 {
						_ = conn.SetWriteDeadline(time.Now().Add(idle))
					}
					if _, werr := conn.Write(data[1:]); werr != nil {
						abort()
						return
					}
					atomic.AddInt64(&recv, int64(len(data)-1))
				}
			case frameEOF:
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				halfDone()
			default:
				abort()
				return
			}
		}
	}()

	wg.Wait()
	abort()
	return atomic.LoadInt64(&sent), atomic.LoadInt64(&recv)
}

// forwardAuth holds the authentication choices from the command line.
type forwardAuth struct {
	pskFile     string
	clientsFile string
	identity    string
	serverKey   string
	pin         string
	insecure    bool
	// suite is the KEM suite a client offers first: "chkem-v1" (the default) or "x-wing".
	// A server steers a client to a suite it supports, so it needs no setting.
	suite string
	// allowSuites restricts the KEM suites this side offers and accepts, as a comma-separated
	// list of suite names. Empty allows every supported suite.
	allowSuites string
}

// buildForwardConfig turns the flags into a transport config. Authentication is mandatory:
// the server needs a PSK source (otherwise anyone could reach the upstream) and the client
// needs a PSK, unless --insecure-no-auth is given for tests and development.
func buildForwardConfig(server bool, a forwardAuth) (tunnel.TransportConfig, error) {
	cfg := tunnel.DefaultTransportConfig()
	cfg.ReadTimeout = 0 // the idle timeout in pipe covers both directions; a per-read timeout would not
	if a.suite != "" {
		if server {
			return cfg, errors.New("--suite is a client option: the server follows whatever suite the client offers")
		}
		suite, err := suiteByName(a.suite)
		if err != nil {
			return cfg, fmt.Errorf("--suite: %w", err)
		}
		cfg.KEMSuite = suite.ID()
	}
	if a.allowSuites != "" {
		for _, name := range strings.Split(a.allowSuites, ",") {
			suite, err := suiteByName(strings.TrimSpace(name))
			if err != nil {
				return cfg, fmt.Errorf("--allow-suite: %w", err)
			}
			cfg.AllowedKEMSuites = append(cfg.AllowedKEMSuites, suite.ID())
		}
		if cfg.KEMSuite != 0 && !slices.Contains(cfg.AllowedKEMSuites, cfg.KEMSuite) {
			return cfg, errors.New("--suite names a suite that --allow-suite excludes")
		}
	}
	if a.identity == "" {
		a.identity = "default"
	}
	if err := checkIdentity(a.identity); err != nil {
		return cfg, fmt.Errorf("--identity: %w", err)
	}

	switch {
	case a.insecure && (a.pskFile != "" || a.clientsFile != "" || a.serverKey != "" || a.pin != ""):
		return cfg, errors.New("--insecure-no-auth cannot be combined with --psk-file, --clients-file, --server-key or --pin: it would ignore them")
	case a.insecure:
		cfg.AllowUnauthenticated = true
		return cfg, nil
	case server && a.pskFile == "" && a.clientsFile == "":
		return cfg, errors.New("the server needs --psk-file or --clients-file so only authorized clients can reach the upstream (or --insecure-no-auth for development)")
	case !server && a.pskFile == "":
		return cfg, errors.New("the client needs --psk-file (or --insecure-no-auth for development)")
	}

	// A server holds every PSK in one lookup table, so a reload can swap it whole and the
	// --psk-file identity and the --clients-file identities work together.
	table := make(map[string][]byte)
	if a.pskFile != "" {
		key, err := readPSKFile(a.pskFile)
		if err != nil {
			return cfg, err
		}
		if server {
			table[a.identity] = key
		} else {
			cfg.PSK = key
			cfg.PSKIdentity = []byte(a.identity)
		}
	}
	if server && a.clientsFile != "" {
		clients, err := readClientsFile(a.clientsFile)
		if err != nil {
			return cfg, err
		}
		for id, key := range clients {
			if _, dup := table[id]; dup {
				return cfg, fmt.Errorf("identity %q is in both --psk-file (its identity is --identity, default \"default\") and --clients-file; rename one", id)
			}
			table[id] = key
		}
	}
	// The identity a server reports is proven only by holding that identity's key, so two
	// identities that share a key could not be told apart.
	owner := make(map[string]string, len(table))
	for _, id := range slices.Sorted(maps.Keys(table)) {
		if other, dup := owner[string(table[id])]; dup {
			return cfg, fmt.Errorf("identities %q and %q share one key; give each its own", other, id)
		}
		owner[string(table[id])] = id
	}
	if server {
		cfg.PSKLookup = func(identity []byte) []byte { return table[string(identity)] }
		cfg.RequirePSK = true
	}

	if server && a.serverKey != "" {
		if err := checkSecretFile(a.serverKey); err != nil {
			return cfg, fmt.Errorf("--server-key: %w", err)
		}
		kp, err := loadSecretKey(a.serverKey)
		if err != nil {
			return cfg, fmt.Errorf("--server-key: %w", err)
		}
		cfg.StaticKeyPair = kp
		cfg.RequireStaticAuth = true
	}
	if !server && a.pin != "" {
		pub, err := loadPinKey(a.pin)
		if err != nil {
			return cfg, fmt.Errorf("--pin: %w", err)
		}
		cfg.PinnedServerKey = pub
	}
	return cfg, nil
}

// checkSecretFile refuses a key file that its group can write or that others can touch. Group
// read stays allowed because mounted container secrets arrive group-owned with mode 0440;
// on a shared host, use 0600. Windows reports permission bits that mean nothing, so the
// check is skipped there.
func checkSecretFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o027 != 0 {
		return fmt.Errorf("%s is writable by its group or accessible by others (mode %#o); run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	return nil
}

// checkIdentity applies the tunnel's own bound to a PSK identity, so a bad one fails at
// startup and on reload instead of as a client dial error later.
func checkIdentity(id string) error {
	if id == "" || len(id) > constants.MaxPSKIdentitySize {
		return fmt.Errorf("an identity is 1 to %d bytes, got %d", constants.MaxPSKIdentitySize, len(id))
	}
	return nil
}

// reloadKeys re-reads the key files and swaps them into f. A server reloads PSKs only, so a
// broken or changed --server-key cannot block a PSK rotation and is never silently ignored.
// On any error the current keys stay in place.
func reloadKeys(f *forwarder, server bool, a forwardAuth, logf func(string, ...any)) error {
	if server {
		a.serverKey = ""
	}
	next, err := buildForwardConfig(server, a)
	if err != nil {
		f.ops.reloadFailed.Add(1)
		f.ops.lastReloadOK.Store(0)
		logf("reload failed, keeping the current keys: %v", err)
		return err
	}
	f.Reload(next)
	f.ops.reloads.Add(1)
	f.ops.lastReloadOK.Store(1)
	logf("reloaded keys; open connections keep the keys they started with")
	return nil
}

func decodePSK(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != pskHexLen {
		return nil, fmt.Errorf("a PSK is %d hex characters (32 bytes), got %d; generate one with: openssl rand -hex 32", pskHexLen, len(s))
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("a PSK must be hex: %w", err)
	}
	if bytes.Count(key, key[:1]) == len(key) {
		return nil, errors.New("a PSK of one repeated byte looks like a placeholder; generate one with: openssl rand -hex 32")
	}
	return key, nil
}

func readPSKFile(path string) ([]byte, error) {
	if err := checkSecretFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI PSK file argument, permission-checked by checkSecretFile
	if err != nil {
		return nil, err
	}
	key, err := decodePSK(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// readClientsFile reads "identity hexkey" lines, one client per line; '#' starts a comment.
func readClientsFile(path string) (map[string][]byte, error) {
	if err := checkSecretFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied CLI clients file argument, permission-checked by checkSecretFile
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	table := make(map[string][]byte)
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s line %d: want \"identity hexkey\"", path, n)
		}
		if err := checkIdentity(fields[0]); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		key, err := decodePSK(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		if _, dup := table[fields[0]]; dup {
			return nil, fmt.Errorf("%s line %d: identity %q appears twice", path, n, fields[0])
		}
		table[fields[0]] = key
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("%s has no clients", path)
	}
	return table, nil
}

// loopbackHost makes a bare ":port" bind to 127.0.0.1, so the plain side of a client never
// listens on every interface by accident.
func loopbackHost(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func forwardCommand() {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	listen := fs.String("listen", "", "Client side: accept plain TCP on this address (a bare :port binds 127.0.0.1), or on a Unix socket as unix:/path")
	connect := fs.String("connect", "", "Client side: carry each connection to this --serve address through a tunnel")
	serve := fs.String("serve", "", "Server side: accept tunnels on this address")
	upstream := fs.String("upstream", "", "Server side: hand each tunnel to this single fixed TCP address, or Unix socket as unix:/path")
	pskFile := fs.String("psk-file", "", "File holding a 32-byte PSK as 64 hex characters (mode 0600); required on both sides")
	clientsFile := fs.String("clients-file", "", "Server side: file of \"identity hexkey\" lines, one PSK per client (mode 0600)")
	suite := fs.String("suite", "", "Client side: KEM suite to offer first, chkem-v1 (default, ML-KEM-1024, or the first allowed suite when --allow-suite excludes it) or x-wing (ML-KEM-768, smaller handshake)")
	socketMode := fs.String("socket-mode", "0600", "Client side: permission of a unix: socket, octal (0600 owner only, 0660 owner and group)")
	allowSuites := fs.String("allow-suite", "", "Either side: only these KEM suites, comma-separated (chkem-v1, x-wing). Use chkem-v1 to refuse the smaller suite")
	identity := fs.String("identity", "default", "PSK identity the client announces, and the server matches against --psk-file")
	serverKey := fs.String("server-key", "", "Server side: static key file from keygen; clients must then pin it with --pin")
	pin := fs.String("pin", "", "Client side: the server's public key file from keygen")
	maxConns := fs.Int("max-conns", 1024, "Most connections held open at once")
	maxPerIP := fs.Int("max-conns-per-ip", 256, "Server side: most concurrent connections from one source address; raise it above the largest --max-conns of any one client forwarder (0 disables)")
	handshakeRate := fs.Float64("handshake-rate", 1000, "Server side: most handshakes per second across all sources (0 disables)")
	idle := fs.Duration("idle-timeout", 5*time.Minute, "Close a connection after this long with no data in either direction (0 disables)")
	insecure := fs.Bool("insecure-no-auth", false, "Skip authentication. For tests and development only: anyone who can reach the server can reach the upstream")
	verbose := fs.Bool("verbose", false, "Log every connection")
	metricsAddr := fs.String("metrics-addr", "", "Serve /metrics, /healthz and /readyz on this address (off by default; a bare :port binds 127.0.0.1, a wildcard address is refused)")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "On SIGTERM or Ctrl-C, stop accepting and let open connections finish for this long before cutting them (0 cuts at once); a second signal cuts at once")

	fs.Usage = func() {
		fmt.Println(`USAGE: quantum-tunnel forward [options]

Protect any TCP service with the post-quantum tunnel, without changing the service.
Run the server side next to the service and the client side next to its users:

    quantum-tunnel forward --serve :9000 --upstream 127.0.0.1:8080 --psk-file psk.hex
    quantum-tunnel forward --listen 127.0.0.1:8080 --connect host:9000 --psk-file psk.hex

Each accepted TCP connection gets its own tunnel (one handshake, one round trip). The
server forwards only to its one upstream address. Half-close is preserved. UDP is not.

OPTIONS:`)
		fs.PrintDefaults()
		fmt.Println(`
EXAMPLES:
    # A shared PSK (generate with: openssl rand -hex 32 > psk.hex && chmod 600 psk.hex)
    quantum-tunnel forward --serve :9000 --upstream 127.0.0.1:5432 --psk-file psk.hex
    quantum-tunnel forward --listen 127.0.0.1:5432 --connect db.example.com:9000 --psk-file psk.hex

    # One PSK per client, and the server pinned by key (see: quantum-tunnel keygen --help)
    quantum-tunnel forward --serve :9000 --upstream 127.0.0.1:8080 --clients-file clients.txt --server-key server.key
    quantum-tunnel forward --listen 127.0.0.1:8080 --connect host:9000 --psk-file psk.hex --identity alice --pin server.pub`)
	}
	_ = fs.Parse(os.Args[2:])

	isClient := *listen != "" || *connect != ""
	isServer := *serve != "" || *upstream != ""
	switch {
	case isClient == isServer:
		fmt.Fprintln(os.Stderr, "Choose one side: --listen with --connect, or --serve with --upstream")
		os.Exit(2)
	case isClient && (*listen == "" || *connect == ""):
		fmt.Fprintln(os.Stderr, "The client side needs both --listen and --connect")
		os.Exit(2)
	case isServer && (*serve == "" || *upstream == ""):
		fmt.Fprintln(os.Stderr, "The server side needs both --serve and --upstream")
		os.Exit(2)
	case *maxConns < 1:
		fmt.Fprintln(os.Stderr, "--max-conns must be at least 1")
		os.Exit(2)
	}

	auth := forwardAuth{
		pskFile: *pskFile, clientsFile: *clientsFile, identity: *identity,
		serverKey: *serverKey, pin: *pin, insecure: *insecure, suite: *suite, allowSuites: *allowSuites,
	}
	cfg, err := buildForwardConfig(isServer, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	if *insecure {
		log.Println("WARNING: --insecure-no-auth is on: the tunnel is encrypted but nobody is authenticated")
	}

	logf := func(format string, args ...any) {
		if *verbose || !strings.HasPrefix(format, "closed ") {
			log.Printf(format, args...)
		}
	}
	socketModeSet := false
	fs.Visit(func(f *flag.Flag) { socketModeSet = socketModeSet || f.Name == "socket-mode" })
	mode, merr := resolveSocketMode(*socketMode, socketModeSet, *listen)
	if merr != nil {
		fmt.Fprintln(os.Stderr, merr)
		os.Exit(2)
	}
	lim := forwardLimits{socketMode: mode, maxConns: *maxConns, idleTimeout: *idle, dialTimeout: 10 * time.Second, maxPerIP: *maxPerIP, handshakeRate: *handshakeRate}

	// Register before the listeners start, so a signal in the startup gap is not lost.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	var f *forwarder
	if isServer {
		f, err = startForwardServer(*serve, *upstream, cfg, lim, logf)
		if err == nil {
			log.Printf("forwarding tunnels on %v to %s (limits: %d connections, %d per source address, %.0f handshakes per second; 0 means off)", f.Addr(), *upstream, *maxConns, *maxPerIP, *handshakeRate)
		}
	} else {
		bind := *listen
		if _, isUnix := unixPath(bind); !isUnix {
			bind, err = loopbackHost(bind)
		}
		if err == nil {
			f, err = startForwardClient(bind, *connect, cfg, lim, logf)
		}
		if err == nil {
			log.Printf("forwarding the plain side on %v through tunnels to %s", f.Addr(), *connect)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *metricsAddr != "" {
		ms, merr := startMetricsServer(*metricsAddr, getVersion(), f.ops)
		if merr != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "Error: %v\n", merr)
			os.Exit(2)
		}
		defer func() { _ = ms.Close() }()
		log.Printf("serving /metrics, /healthz and /readyz on %v", ms.addr)
	}

	for waiting := true; waiting; {
		select {
		case <-stop:
			waiting = false
		case <-f.done:
			fmt.Fprintln(os.Stderr, "Error: the listener stopped")
			os.Exit(1)
		case <-hup:
			_ = reloadKeys(f, isServer, auth, logf)
		}
	}
	log.Printf("shutting down: waiting up to %s for %d open connections (a second signal cuts them)", *drainTimeout, f.ops.active.Load())
	drained := make(chan bool, 1)
	go func() { drained <- f.Drain(*drainTimeout) }()
	select {
	case ok := <-drained:
		if !ok {
			log.Printf("drain timed out with %d connections still open; cutting them", f.ops.active.Load())
		}
	case <-stop:
		log.Printf("second signal: cutting %d open connections", f.ops.active.Load())
	}
}
