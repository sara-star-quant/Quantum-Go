package tunnel_test

import (
	"errors"
	"testing"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
	"github.com/sara-star-quant/quantum-go/pkg/tunnel"
)

// pskTable returns a PSKLookup over a fixed identity-to-key table.
func pskTable(table map[string][]byte) func([]byte) []byte {
	return func(id []byte) []byte { return table[string(id)] }
}

func requirePSKServer(table map[string][]byte) tunnel.TransportConfig {
	cfg := tunnel.DefaultTransportConfig()
	cfg.PSKLookup = pskTable(table)
	cfg.RequirePSK = true
	return cfg
}

func pskClient(id string, key []byte) tunnel.TransportConfig {
	cfg := tunnel.DefaultTransportConfig()
	if key != nil {
		cfg.PSK = key
		cfg.PSKIdentity = []byte(id)
	}
	return cfg
}

// TestRequirePSKMultipleIdentities admits two clients holding different PSKs against
// one server that keeps a key per identity.
func TestRequirePSKMultipleIdentities(t *testing.T) {
	table := map[string][]byte{"edge-a": pskOfByte(0x0A), "edge-b": pskOfByte(0x0B)}
	for id, key := range table {
		clientErr, accepted := runStaticAuthHandshake(t, requirePSKServer(table), pskClient(id, key))
		if clientErr != nil || !accepted {
			t.Fatalf("identity %q rejected: clientErr=%v accepted=%v", id, clientErr, accepted)
		}
	}
}

// TestRequirePSKRejects checks every way a client can fail to prove a PSK the server
// knows, and that the client sees the same error for an unknown identity as for a
// wrong key (no identity oracle).
func TestRequirePSKRejects(t *testing.T) {
	table := map[string][]byte{"edge-a": pskOfByte(0x0A)}
	cases := map[string]tunnel.TransportConfig{
		"no PSK":         pskClient("", nil),
		"unknown id":     pskClient("edge-z", pskOfByte(0x0A)),
		"wrong key":      pskClient("edge-a", pskOfByte(0xFF)),
		"unknown + junk": pskClient("edge-z", pskOfByte(0xFF)),
	}
	errs := map[string]string{}
	for name, clientCfg := range cases {
		clientErr, accepted := runStaticAuthHandshake(t, requirePSKServer(table), clientCfg)
		if clientErr == nil || accepted {
			t.Fatalf("%s: admitted (clientErr=%v accepted=%v)", name, clientErr, accepted)
		}
		errs[name] = clientErr.Error()
	}
	if errs["unknown id"] != errs["wrong key"] {
		t.Fatalf("unknown identity and wrong key are distinguishable: %q vs %q", errs["unknown id"], errs["wrong key"])
	}
}

// TestRequirePSKSingleKey covers RequirePSK with the plain single PSK config.
func TestRequirePSKSingleKey(t *testing.T) {
	key := pskOfByte(0x42)
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.PSK, serverCfg.PSKIdentity, serverCfg.RequirePSK = key, []byte("edge-1"), true

	if clientErr, accepted := runStaticAuthHandshake(t, serverCfg, pskClient("edge-1", key)); clientErr != nil || !accepted {
		t.Fatalf("matching client rejected: %v accepted=%v", clientErr, accepted)
	}
	if clientErr, accepted := runStaticAuthHandshake(t, serverCfg, pskClient("", nil)); clientErr == nil || accepted {
		t.Fatalf("client without a PSK admitted: %v accepted=%v", clientErr, accepted)
	}
}

// TestPSKLookupWithoutRequireAdmitsPlainClients keeps the default: a lookup alone does
// not shut out clients that carry no PSK.
func TestPSKLookupWithoutRequireAdmitsPlainClients(t *testing.T) {
	serverCfg := tunnel.DefaultTransportConfig()
	serverCfg.PSKLookup = pskTable(map[string][]byte{"edge-a": pskOfByte(0x0A)})
	if clientErr, accepted := runStaticAuthHandshake(t, serverCfg, pskClient("", nil)); clientErr != nil || !accepted {
		t.Fatalf("plain client rejected without RequirePSK: %v accepted=%v", clientErr, accepted)
	}
}

// TestRequirePSKMisconfiguredRejected fails closed when RequirePSK has no key to check.
func TestRequirePSKMisconfiguredRejected(t *testing.T) {
	listener, err := tunnel.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	cfg := tunnel.DefaultTransportConfig()
	cfg.RequirePSK = true
	listener.SetConfig(cfg)

	go func() { _, _ = tunnel.DialWithConfig("tcp", listener.Addr().String(), tunnel.DefaultTransportConfig()) }()
	if _, err := listener.Accept(); !errors.Is(err, qerrors.ErrPSKMisconfigured) {
		t.Fatalf("got %v, want ErrPSKMisconfigured", err)
	}
}

// TestRequirePSKLookupWrongSizeKey treats a lookup result of the wrong length as an
// unknown identity: rejected, and with the same error as a wrong key.
func TestRequirePSKLookupWrongSizeKey(t *testing.T) {
	table := map[string][]byte{"edge-s": []byte("short"), "edge-a": pskOfByte(0x0A)}
	clientErr, accepted := runStaticAuthHandshake(t, requirePSKServer(table), pskClient("edge-s", pskOfByte(0x0A)))
	if clientErr == nil || accepted {
		t.Fatalf("short stored key admitted: clientErr=%v accepted=%v", clientErr, accepted)
	}
	wrongErr, _ := runStaticAuthHandshake(t, requirePSKServer(table), pskClient("edge-a", pskOfByte(0xFF)))
	if wrongErr == nil || wrongErr.Error() != clientErr.Error() {
		t.Fatalf("wrong-size key distinguishable from wrong key: %v vs %v", clientErr, wrongErr)
	}
}
