# Configuration

Quantum-Go uses the `TransportConfig` struct to tune performance, security, and operational behavior.

## TransportConfig

```go
type TransportConfig struct {
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    RateLimit    RateLimitConfig
    Observer     tunnel.Observer
    ObserverFactory tunnel.ObserverFactory
    RateLimitObserver tunnel.RateLimitObserver
}
```

### Basic Settings

```go
config := tunnel.DefaultTransportConfig()

// Timeouts for underlying network operations
config.ReadTimeout = 30 * time.Second
config.WriteTimeout = 30 * time.Second
```

### Endpoint Authentication (v0.0.12+)

All authentication is opt-in; unconfigured, the handshake is encryption-only and unchanged. Generate static keys with `quantum-tunnel keygen` (see the [CLI reference](CLI.md)). See [SECURITY.md](../../SECURITY.md#authentication-modes) for the threat properties.

```go
// Static-key server pinning: the server proves possession of a long-term key,
// the client pins its public key. Authenticates the server to the client.
serverCfg.StaticKeyPair = kp                 // server: chkem.ParseTaggedKeyPair(seed)
clientCfg.PinnedServerKey = kp.PublicKey()   // client: chkem.ParseTaggedPublicKey(pin)

// Require-auth: reject any client that does not pin the server (v0.0.13+).
serverCfg.RequireStaticAuth = true           // needs StaticKeyPair set

// PSK mutual authentication: both peers share a 32-byte key (v0.0.13+).
// Authenticates both directions; composes with static-key pinning.
serverCfg.PSK, serverCfg.PSKIdentity = psk, []byte("edge-01")
clientCfg.PSK, clientCfg.PSKIdentity = psk, []byte("edge-01")

// One PSK per client, and admit only clients that hold one (server side).
serverCfg.PSKLookup = func(id []byte) []byte { return keys[string(id)] } // nil = unknown
serverCfg.RequirePSK = true                  // needs PSK or PSKLookup set
```

Datagram endpoints use options instead: `tunnel.WithStaticIdentity(kp)`, `tunnel.WithPinnedServerKey(pub)`, `tunnel.WithRequireStaticAuth()`, `tunnel.WithPSK(identity, key)`, `tunnel.WithPSKLookup(fn)`, and `tunnel.WithRequirePSK()`.

### KEM Suites (v0.0.20+)

A client offers CH-KEM-v1 (ML-KEM-1024 + X25519) first. Choose another registered suite as the first offer; X-Wing (ML-KEM-768 + X25519) has a smaller key share and ciphertext (1216 and 1120 bytes against 1600 and 1600).

From the command line, `quantum-tunnel forward --suite x-wing` on the client side does the same, and `quantum-tunnel keygen --suite x-wing` makes the matching static identity. In Go:

```go
// Stream: offer X-Wing first.
cfg := tunnel.DefaultTransportConfig()
cfg.KEMSuite = chkem.SuiteXWing
t, err := tunnel.DialWithConfig("tcp", addr, cfg)

// Datagram: the same choice as an endpoint option.
ep, err := tunnel.NewDatagramEndpoint(conn, tunnel.WithKEMSuite(chkem.SuiteXWing))
```

- The zero value means CH-KEM-v1. A suite the peer would not offer (not registered, or not FIPS approved in a FIPS build) fails before any packet is sent with `tunnel.ErrUnsupportedKEMSuite`; on the datagram transport that is at endpoint construction.
- A server that does not support the first-offered suite steers the client to a mutually supported one with a single HelloRetryRequest. The offered list is bound into the Finished transcript, so stripping a suite from it fails the handshake.
- To restrict the suites an endpoint will use, set `TransportConfig.AllowedKEMSuites` (or `WithAllowedKEMSuites` on a datagram endpoint, or `forward --allow-suite`). A server then refuses a suite outside the list and steers the client to an allowed one with a HelloRetryRequest, and a client offers only allowed suites. For example, `AllowedKEMSuites: []chkem.SuiteID{chkem.SuiteCHKEMv1}` keeps every session on ML-KEM-1024 and refuses the smaller X-Wing suite. An empty list allows every supported suite, and a list that allows none fails with `ErrUnsupportedKEMSuite` in `Dial`, `NewDatagramEndpoint`, `TransportConfig.Validate` and a listener's first `Accept` (call `Validate` at startup to fail early). A pinned or static key keeps its own suite: the list governs the ephemeral exchange only.
- Pool connections still start on the default suite; `PoolConfig` has no suite option.

#### Registering your own suite

Implement `chkem.Suite`, run the shared conformance battery against it, then register it. Both peers must register the same id.

```go
func TestMySuite(t *testing.T)      { suitetest.Run(t, mySuite{}) }       // conformance
func BenchmarkMySuite(b *testing.B) { suitetest.Bench(b, mySuite{}) }     // keygen, encapsulate, decapsulate

err := chkem.RegisterSuite(mySuite{})
```

- Ids start at `chkem.CustomSuiteMin` (`0x8000`); lower ids are reserved for built-ins. At most `chkem.MaxCustomSuites` (16) can be registered.
- Registered suites are offered after the built-ins, so CH-KEM-v1 stays first and preferred. In a FIPS build, suites that report `IsFIPSApproved() == false` are not offered.
- Build your key pair, public key and ciphertext values with `chkem.NewSuiteKeyPair`, `chkem.NewSuitePublicKey` and `chkem.NewSuiteCiphertext`.
- A registered suite runs in-process with access to handshake secrets. The library validates and tests it but cannot contain it; you own its code and supply chain (threat T11 in the [threat model](../technical/THREAT_MODEL.md)).

### Rate Limiting (v0.0.6+)

Protect your server from DoS attacks and resource exhaustion:

```go
// Max concurrent connections allowed per IP
config.RateLimit.MaxConnectionsPerIP = 100

// Global handshake rate limit (tokens per second)
config.RateLimit.HandshakeRateLimit = 5.0 

// Burst allowance for handshakes
config.RateLimit.HandshakeBurst = 10

// Connections allowed mid-handshake or waiting for Accept at once (default 1024).
// Beyond this, new connections are closed on arrival.
config.MaxPendingHandshakes = 256
```

### Observability

Attach an observer to collect metrics, tracing, and structured logs per session:

```go
collector := metrics.NewCollector(metrics.Labels{
    "service": "quantum-tunnel",
})

config.ObserverFactory = func(session *tunnel.Session) tunnel.Observer {
    role := "initiator"
    if session.Role == tunnel.RoleResponder {
        role = "responder"
    }

    return metrics.NewTunnelObserver(metrics.TunnelObserverConfig{
        Collector: collector,
        SessionID: session.ID,
        Role:      role,
    })
}
```

To record rate-limit metrics (connection and handshake rejections), attach a rate limit observer:

```go
rateObserver := metrics.NewRateLimitObserver(collector, metrics.GetLogger())
config.RateLimitObserver = rateObserver
```

