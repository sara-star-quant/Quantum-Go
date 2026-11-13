package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMetricsBindRefusal(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9100", "[::]:9100", "0.0.0.0:0"} {
		if _, err := metricsBind(addr); err == nil {
			t.Errorf("%s was accepted: it listens on every interface", addr)
		}
	}
	for _, addr := range []string{"0:0", "00:0", "[::]:0"} {
		if ms, err := startMetricsServer(addr, "test", newForwardOps()); err == nil {
			_ = ms.Close()
			t.Errorf("%s bound every interface", addr)
		}
	}
	got, err := metricsBind(":9100")
	if err != nil || got != "127.0.0.1:9100" {
		t.Errorf("bare port = %q, %v; want 127.0.0.1:9100", got, err)
	}
	for _, addr := range []string{"127.0.0.1:9100", "[::1]:9100", "192.0.2.1:9100", "localhost:9100"} {
		if got, err := metricsBind(addr); err != nil || got != addr {
			t.Errorf("%s = %q, %v; a named address is the operator's choice", addr, got, err)
		}
	}
}

func scrape(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// metric returns the value of one forward metric from a scrape, or -1 when it is absent.
func metric(body, name string) int64 {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, "quantum_tunnel_forward_"+name+" "); ok {
			var v int64
			for _, c := range rest {
				v = v*10 + int64(c-'0')
			}
			return v
		}
	}
	return -1
}

func waitMetric(t *testing.T, addr, name string, want int64) string {
	t.Helper()
	var body string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, body = scrape(t, addr, "/metrics")
		if metric(body, name) == want {
			return body
		}
	}
	t.Fatalf("metric %s never reached %d:\n%s", name, want, body)
	return ""
}

// One forwarder pair with a metrics endpoint on the server side.
func opsPair(t *testing.T, srvPSK, cliPSK string) (srv *forwarder, app string, metricsAddr string) {
	t.Helper()
	up, _ := startUpstream(t, echoHandler)
	srvCfg, err := buildForwardConfig(true, forwardAuth{pskFile: writeSecret(t, "s.hex", srvPSK+"\n", 0o600)})
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := buildForwardConfig(false, forwardAuth{pskFile: writeSecret(t, "c.hex", cliPSK+"\n", 0o600)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = startForwardServer("127.0.0.1:0", up, srvCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := startForwardClient("127.0.0.1:0", srv.Addr().String(), cliCfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	ms, err := startMetricsServer("127.0.0.1:0", "test", srv.ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ms.Close() })
	return srv, cli.Addr().String(), ms.addr.String()
}

func TestMetricsAfterGoodAndFailedHandshakes(t *testing.T) {
	psk := randomPSK(t)
	_, app, maddr := opsPair(t, psk, psk)
	c := dial(t, app)
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo through the pair: %v", err)
	}
	body := waitMetric(t, maddr, "connections_total", 1)
	if got := metric(body, "connections_active"); got != 1 {
		t.Errorf("connections_active = %d with one open connection", got)
	}
	if got := metric(body, "handshakes_refused_total"); got != 0 {
		t.Errorf("handshakes_refused_total = %d after only a good handshake", got)
	}
	if !strings.Contains(body, "quantum_tunnel_") {
		t.Error("the Prometheus exporter output is missing")
	}
	// Counts and durations only: neither this client's address nor an identity appears.
	for _, leak := range []string{c.LocalAddr().String(), strings.Split(c.LocalAddr().String(), ":")[1], "default"} {
		if strings.Contains(body, leak) {
			t.Errorf("the metrics text carries %q: counts and durations only", leak)
		}
	}
	_ = c.Close()
	waitMetric(t, maddr, "connections_active", 0)

	// A client with the wrong PSK is refused and counted, and never becomes a served connection.
	bad := randomPSK(t)
	_, app2, maddr2 := opsPair(t, psk, bad)
	c2 := dial(t, app2)
	_, _ = c2.Write([]byte("hello"))
	_ = c2.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = c2.Read(make([]byte, 8))
	body = waitMetric(t, maddr2, "handshakes_refused_total", 1)
	if got := metric(body, "connections_total"); got != 0 {
		t.Errorf("connections_total = %d after a refused handshake", got)
	}
}

func TestReadinessAroundReloadAndDrain(t *testing.T) {
	up, _ := startUpstream(t, echoHandler)
	psk := writeSecret(t, "psk.hex", randomPSK(t)+"\n", 0o600)
	auth := forwardAuth{pskFile: psk}
	cfg, err := buildForwardConfig(true, auth)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startForwardServer("127.0.0.1:0", up, cfg, testLimits, nopLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ms, err := startMetricsServer("127.0.0.1:0", "test", srv.ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ms.Close() })
	maddr := ms.addr.String()

	if code, _ := scrape(t, maddr, "/healthz"); code != 200 {
		t.Fatalf("/healthz = %d", code)
	}
	if code, _ := scrape(t, maddr, "/readyz"); code != 200 {
		t.Fatalf("/readyz = %d with the listener up and keys loaded", code)
	}

	// A failed reload keeps the previous keys, so the forwarder stays ready, and the failure is visible.
	if err := os.WriteFile(psk, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeys(srv, true, auth, nopLog); err == nil {
		t.Fatal("a corrupt file was reloaded")
	}
	if code, _ := scrape(t, maddr, "/readyz"); code != 200 {
		t.Fatalf("/readyz = %d after a failed reload that kept the old keys", code)
	}
	_, body := scrape(t, maddr, "/metrics")
	if metric(body, "key_reload_failures_total") != 1 || metric(body, "last_key_reload_ok") != 0 {
		t.Fatalf("the failed reload is not visible:\n%s", body)
	}
	if err := os.WriteFile(psk, []byte(randomPSK(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeys(srv, true, auth, nopLog); err != nil {
		t.Fatal(err)
	}
	_, body = scrape(t, maddr, "/metrics")
	if metric(body, "key_reloads_total") != 1 || metric(body, "last_key_reload_ok") != 1 {
		t.Fatalf("the good reload is not visible:\n%s", body)
	}

	// Draining reports not ready so a load balancer stops sending, while liveness stays up.
	go srv.Drain(time.Second)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if code, _ := scrape(t, maddr, "/readyz"); code == 503 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never reported not ready while draining")
		}
	}
	if code, _ := scrape(t, maddr, "/healthz"); code != 200 {
		t.Fatalf("/healthz = %d while draining", code)
	}
}

// openServed opens a connection through a pair and waits until the server counts it.
func openServed(t *testing.T, srv *forwarder, app string) net.Conn {
	t.Helper()
	c := dial(t, app)
	_, _ = c.Write([]byte("x"))
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); srv.ops.active.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the server never counted the connection")
		}
	}
	return c
}

func TestDrainFinishesEarlyWhenConnectionsEnd(t *testing.T) {
	psk := randomPSK(t)
	srv, app, _ := opsPair(t, psk, psk)
	c := openServed(t, srv, app)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = c.Close()
	}()
	start := time.Now()
	if !srv.Drain(10 * time.Second) {
		t.Fatal("the drain timed out although the only connection closed")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the drain waited %v for a connection that closed after 200 ms", took)
	}
}

func TestDrainTimesOutOnAStuckConnection(t *testing.T) {
	psk := randomPSK(t)
	srv, app, _ := opsPair(t, psk, psk)
	_ = openServed(t, srv, app) // held open for the whole test
	start := time.Now()
	if srv.Drain(300 * time.Millisecond) {
		t.Fatal("the drain reported success with a connection still open")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("a 300 ms drain took %v", took)
	}
	if srv.Drain(0) {
		t.Fatal("a zero drain reported success with a connection still open")
	}
}

func TestDrainWithNothingOpenSucceedsAtOnce(t *testing.T) {
	o := newForwardOps()
	for i := 0; i < 200; i++ {
		if !o.drain(0) {
			t.Fatal("drain(0) reported failure with no open connections")
		}
	}
	if !o.drain(time.Second) {
		t.Fatal("drain reported failure with no open connections")
	}
}

func TestOnlyTheDocumentedEndpointsAreServed(t *testing.T) {
	psk := randomPSK(t)
	_, _, maddr := opsPair(t, psk, psk)
	for _, path := range []string{"/health", "/", "/debug/vars"} {
		if code, _ := scrape(t, maddr, path); code != 404 {
			t.Errorf("%s = %d; only /metrics, /healthz and /readyz are served", path, code)
		}
	}
}

func TestMetricsCountBytesThroughTheTunnel(t *testing.T) {
	psk := randomPSK(t)
	_, app, maddr := opsPair(t, psk, psk)
	c := dial(t, app)
	_, _ = c.Write([]byte("0123456789"))
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		_, body := scrape(t, maddr, "/metrics")
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "quantum_tunnel_bytes_sent_total ") && !strings.HasSuffix(line, " 0") {
				return
			}
		}
	}
	t.Fatal("quantum_tunnel_bytes_sent_total stayed at 0 after traffic")
}
