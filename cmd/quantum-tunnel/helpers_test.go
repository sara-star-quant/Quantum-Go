package main

import (
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/metrics"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

func TestParseSizeAndFormatSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"100", 100}, {"1KB", 1 << 10}, {"2k", 2 << 10}, {"100MB", 100 << 20},
		{"1m", 1 << 20}, {"1GB", 1 << 30}, {"3g", 3 << 30},
		{"60KB", 60 << 10}, {"10GiB", 10 << 30}, {"1TB", 1 << 40}, {"2MiB", 2 << 20},
	}
	for _, c := range cases {
		got, err := parseSize(c.in)
		if err != nil || got != c.want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	// A typo must be an error, not a silently tiny size.
	for _, bad := range []string{"", "abc", "10XB", "-5MB", "10 GB x", "99999999999999TB"} {
		if got, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", bad, got)
		}
	}
	for in, want := range map[int64]string{
		0: "0 B", 1023: "1023 B", 1024: "1.00 KB", 1536: "1.50 KB", 1 << 20: "1.00 MB", 5 << 30: "5.00 GB",
	} {
		if got := formatSize(in); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", in, got, want)
		}
	}
	if got := formatSize(1 << 62); got == "" {
		t.Error("formatSize of a very large value returned empty")
	}
}

func TestParseDurationValid(t *testing.T) {
	if got := parseDuration("1500ms"); got != 1500*time.Millisecond {
		t.Errorf("parseDuration = %v", got)
	}
}

func TestParseLogLevelAndFormat(t *testing.T) {
	levels := map[string]metrics.Level{
		"debug": metrics.LevelDebug, "INFO": metrics.LevelInfo, "warn": metrics.LevelWarn,
		"warning": metrics.LevelWarn, "error": metrics.LevelError, "silent": metrics.LevelSilent,
		"off": metrics.LevelSilent, "none": metrics.LevelSilent,
	}
	for in, want := range levels {
		if got, err := parseLogLevel(in); err != nil || got != want {
			t.Errorf("parseLogLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parseLogLevel("loud"); err == nil {
		t.Error("parseLogLevel accepted an unknown level")
	}
	if got, err := parseLogFormat("JSON"); err != nil || got != metrics.FormatJSON {
		t.Errorf("parseLogFormat(JSON) = %v, %v", got, err)
	}
	if got, err := parseLogFormat("text"); err != nil || got != metrics.FormatText {
		t.Errorf("parseLogFormat(text) = %v, %v", got, err)
	}
	if _, err := parseLogFormat("xml"); err == nil {
		t.Error("parseLogFormat accepted an unknown format")
	}
}

func TestRoleLabelAndRatings(t *testing.T) {
	if roleLabel(tunnel.RoleResponder) != "responder" || roleLabel(tunnel.RoleInitiator) != "initiator" {
		t.Error("roleLabel mismatch")
	}
	// The rating printers only print; run every branch to be sure none panics.
	for _, d := range []time.Duration{time.Millisecond, 3 * time.Millisecond, 7 * time.Millisecond, 20 * time.Millisecond} {
		printHandshakeRating(d)
	}
	for _, v := range []float64{600, 300, 100, 10} {
		printThroughputRating(v)
	}
}
