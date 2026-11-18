package metrics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func securityCount(c *Collector, class, conf string) int64 {
	for _, e := range c.Snapshot().SecurityEvents {
		if e.Class == class && e.Confidence == conf {
			return e.Count
		}
	}
	return -1
}

func TestSecurityEventCountsByClassAndConfidence(t *testing.T) {
	c := NewCollector(nil)
	var buf bytes.Buffer
	o := NewTunnelObserver(TunnelObserverConfig{Collector: c, Logger: NewLogger(WithOutput(&buf), WithLevel(LevelWarn))})

	o.OnSecurityEvent(tunnel.SecurityEvent{Class: tunnel.SecurityPinMismatch, Confidence: tunnel.SecurityHigh})
	if got := securityCount(c, "pin_mismatch", "high"); got != 1 {
		t.Fatalf("pin_mismatch/high = %d, want 1", got)
	}
	// Exactly one series moved: every other class and confidence stays at zero.
	var total int64
	for _, e := range c.Snapshot().SecurityEvents {
		total += e.Count
	}
	if total != 1 {
		t.Fatalf("total across all series = %d, want 1", total)
	}

	// A class or confidence this build does not know is ignored, not counted anywhere.
	o.OnSecurityEvent(tunnel.SecurityEvent{Class: 200, Confidence: tunnel.SecurityHigh})
	o.OnSecurityEvent(tunnel.SecurityEvent{Class: tunnel.SecurityReplay, Confidence: 99})
	total = 0
	for _, e := range c.Snapshot().SecurityEvents {
		total += e.Count
	}
	if total != 1 {
		t.Fatalf("unknown values changed the counters: total = %d", total)
	}

	c.Reset()
	if got := securityCount(c, "pin_mismatch", "high"); got != 0 {
		t.Fatalf("after Reset = %d, want 0", got)
	}
}

func TestSecurityEventLogIsThrottledPerSeries(t *testing.T) {
	c := NewCollector(nil)
	var buf bytes.Buffer
	o := NewTunnelObserver(TunnelObserverConfig{Collector: c, Logger: NewLogger(WithOutput(&buf), WithLevel(LevelWarn))})

	replay := tunnel.SecurityEvent{Class: tunnel.SecurityReplay, Confidence: tunnel.SecurityMedium}
	for range 50 {
		o.OnSecurityEvent(replay)
	}
	o.OnSecurityEvent(tunnel.SecurityEvent{Class: tunnel.SecurityDowngrade, Confidence: tunnel.SecurityMedium})

	if got := securityCount(c, "replay", "medium"); got != 50 {
		t.Fatalf("replay/medium counted %d, want 50: throttling must not drop counts", got)
	}
	if lines := strings.Count(buf.String(), "security event"); lines != 2 {
		t.Fatalf("log lines = %d, want 2 (one per series):\n%s", lines, buf.String())
	}
	if strings.Contains(buf.String(), "remote") || strings.Contains(buf.String(), "addr") {
		t.Fatalf("log line carries an address field:\n%s", buf.String())
	}
}

func TestPrometheusExportsEverySecuritySeries(t *testing.T) {
	c := NewCollector(nil)
	c.RecordSecurityEvent(tunnel.SecurityReplay, tunnel.SecurityMedium)
	var buf bytes.Buffer
	NewPrometheusExporter(c, "qt").WriteMetrics(&buf)
	out := buf.String()

	series := len(tunnel.SecurityClasses()) * len(tunnel.SecurityConfidences())
	if got := strings.Count(out, "qt_security_events_total{"); got != series {
		t.Fatalf("series = %d, want %d", got, series)
	}
	if !strings.Contains(out, `qt_security_events_total{class="replay",confidence="medium"} 1`) {
		t.Fatalf("missing counted series:\n%s", out)
	}
	if !strings.Contains(out, `qt_security_events_total{class="pin_mismatch",confidence="high"} 0`) {
		t.Fatalf("a zero series must still be exported:\n%s", out)
	}
}

// A server builds one observer per session, so the log throttle has to live on the shared
// collector: two observers on one collector log a flood of one series once, not twice.
func TestSecurityEventLogThrottleIsSharedAcrossObservers(t *testing.T) {
	c := NewCollector(nil)
	var buf bytes.Buffer
	logger := NewLogger(WithOutput(&buf), WithLevel(LevelWarn))
	a := NewTunnelObserver(TunnelObserverConfig{Collector: c, Logger: logger})
	b := NewTunnelObserver(TunnelObserverConfig{Collector: c, Logger: logger})

	ev := tunnel.SecurityEvent{Class: tunnel.SecurityDowngrade, Confidence: tunnel.SecurityLow}
	for range 20 {
		a.OnSecurityEvent(ev)
		b.OnSecurityEvent(ev)
	}
	if got := securityCount(c, "downgrade", "low"); got != 40 {
		t.Fatalf("counted %d, want 40", got)
	}
	if lines := strings.Count(buf.String(), "security event"); lines != 1 {
		t.Fatalf("log lines = %d, want 1 across both observers:\n%s", lines, buf.String())
	}
}
