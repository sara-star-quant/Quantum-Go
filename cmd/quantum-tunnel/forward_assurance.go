package main

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// assuranceSchema is the version of the record. Bump it when a field changes meaning.
const assuranceSchema = 1

// assuranceRecord says what protected one finished connection: the KEM suite it negotiated, how
// the peers authenticated, whether this build ran in FIPS build mode, and which build it was. It
// reports what this process negotiated and built, nothing about the network in between. It
// carries no address, and no identity unless the operator asks for one.
type assuranceRecord struct {
	SchemaVersion  int      `json:"schema_version"`
	Time           string   `json:"time"`
	Role           string   `json:"role"`
	KEMSuite       string   `json:"kem_suite"`
	Authentication []string `json:"authentication"`
	FIPSBuildMode  bool     `json:"fips_build_mode"`
	Version        string   `json:"version"`
	Commit         string   `json:"commit,omitempty"`
	DurationMS     int64    `json:"duration_ms"`
	Identity       string   `json:"identity,omitempty"`
}

// assuranceLog appends one JSON line per finished connection.
type assuranceLog struct {
	mu       sync.Mutex
	enc      *json.Encoder
	inv      inventory
	identity bool
	logf     func(string, ...any)
	failed   atomic.Bool
}

func newAssuranceLog(w io.Writer, inv inventory, withIdentity bool, logf func(string, ...any)) *assuranceLog {
	return &assuranceLog{enc: json.NewEncoder(w), inv: inv, identity: withIdentity, logf: logf}
}

// assuranceAuth lists how the peers authenticated in a connection that completed.
func assuranceAuth(psk, staticKey bool) []string {
	var methods []string
	if psk {
		methods = append(methods, "psk")
	}
	if staticKey {
		methods = append(methods, "static-key")
	}
	if len(methods) == 0 {
		return []string{"none"}
	}
	return methods
}

// record writes the record for a finished connection. A write failure never stops forwarding:
// it is logged once.
func (l *assuranceLog) record(role string, t *tunnel.Tunnel, start time.Time, psk, staticKey bool) {
	if l == nil {
		return
	}
	p := t.Peer()
	rec := assuranceRecord{
		SchemaVersion:  assuranceSchema,
		Time:           time.Now().UTC().Format(time.RFC3339),
		Role:           role,
		KEMSuite:       suiteName(p.Suite),
		Authentication: assuranceAuth(psk, staticKey),
		FIPSBuildMode:  l.inv.FIPS.BuildMode,
		Version:        l.inv.Version,
		Commit:         l.inv.Commit,
		DurationMS:     time.Since(start).Milliseconds(),
	}
	if l.identity {
		rec.Identity = string(p.Identity)
	}
	l.mu.Lock()
	err := l.enc.Encode(rec)
	l.mu.Unlock()
	if err != nil && l.failed.CompareAndSwap(false, true) {
		l.logf("assurance log: cannot write: %v (forwarding continues; this is logged once)", err)
	}
}
