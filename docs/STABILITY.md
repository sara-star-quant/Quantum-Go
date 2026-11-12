# What you can rely on, and what may change

Pre-1.0 and unaudited. This page says which parts of Quantum-Go change only with a changelog entry, which are still moving, and which you should not depend on. It also lists the bounds the code enforces and what each error means. Every number below comes from the code at the time of writing; when a default changes, this page changes in the same commit.

## Packages

| Package | Status | Notes |
|---|---|---|
| `pkg/tunnel`: `Dial`, `DialWithConfig`, `Listen`, `Listener`, `Tunnel` (`Send`, `Receive`, `ReceiveInto`, `Close`, `Peer`, `RemoteAddr`), `TransportConfig`, `Pool`, `DatagramEndpoint`, `DatagramConn` and their options, the error values | Settled | A change needs a changelog entry. While the version is 0.x, a breaking change also needs a minor-version bump. |
| `pkg/tunnel`: observers (`Observer`, `RateLimitObserver`, `HandshakeLoadObserver`), `PeerInfo`, the rate-limit types | Evolving | Added recently and may gain fields or methods. |
| `pkg/chkem`: the suite registry (`RegisterSuite`, `Suite`), key pairs and pins | Evolving | Needed for custom suites; the interface may grow. |
| `pkg/tunnel`: `Handshake`, `InitiatorHandshake`, `ResponderHandshake`, `Session` internals, `Reassembler`, the replay windows, the limiters | Internal | Exported because Go packages need it, not because they are an API. They change without notice and are candidates to move under `internal/`. |
| `pkg/crypto`, `pkg/protocol` | Internal | Do not import them. The exceptions are the FIPS status functions described in [FIPS](FIPS.md). |
| `pkg/metrics` | Optional | A separate layer; the Prometheus output names are settled, the Go API is evolving. |
| `cmd/quantum-tunnel` flags | Evolving | `forward` flags are new in v0.0.26. |

`pkg/tunnel` exports about 70 top-level symbols and most are internal. Shrinking that surface is part of the roadmap, and it will be a breaking change announced in the changelog.

## Bounds the code enforces

| Bound | Value | Where |
|---|---|---|
| Handshakes in flight per stream listener | 1,024; a connection beyond that is closed on arrival | `TransportConfig.MaxPendingHandshakes` |
| Handshake time | 30 s by default, for the responder, and for the initiator's connect plus handshake | `TransportConfig.HandshakeTimeout` |
| Read and write timeout | 30 s by default | `TransportConfig` |
| Record and handshake message size | 65,536 bytes (a UDP payload tops out at 65,507) | constants |
| Session id and PSK identity | at most 255 bytes each | wire spec |
| Replay window | 1,024 records, stream and datagram | constants |
| Rekey | after 1 hour, 64 GiB or 2^28 packets, checked when traffic flows (an idle session does not rekey) | constants |
| Datagram size | 1,200 byte MTU, 14 byte header plus the AEAD tag per record | constants |
| Datagram handshake | messages up to 4,096 bytes; 4 concurrent reassemblies per source, 10 s timeout; retransmit from 500 ms up to 8 s, at most 8 retries | constants |
| Datagram half-open sessions | 256 per core, floor 1,024, ceiling 8,192 | `WithMaxHalfOpen` |
| Datagram idle timeout | 120 s | constants |
| Forward server | 1,024 connections, 256 per source address, 1,000 handshakes per second (burst 2,000), idle timeout 5 minutes, upstream dial 10 s, 60 KiB record | `forward` flags |

## Errors and what to do

Every error below is an exported value of `pkg/tunnel` that you can match with `errors.Is`. A malformed message or an exhausted nonce space has no exported value of its own there; treat any error not listed as fatal to the tunnel.

| Error | Meaning |
|---|---|
| `ErrHandshakeFailed` | The handshake did not complete: wrong key, wrong pin, a refused suite or a malformed message. The cause is deliberately not distinguished on the wire. |
| `ErrAuthenticationFailed` | A record or Finished failed its AEAD or MAC check. |
| `ErrReplayDetected` | A record repeated or fell behind the replay window. |
| `ErrServerKeyMismatch`, `ErrStaticAuthRequired` | The pinned server key did not match, or static authentication was required and not offered. |
| `ErrUnsupportedVersion`, `ErrUnsupportedCipherSuite`, `ErrUnsupportedKEMSuite` | Negotiation found no common version or suite. |
| `ErrInvalidPSK`, `ErrPSKMisconfigured`, `ErrStaticAuthMisconfigured` | A configuration error caught before any packet is sent. |
| `ErrTunnelClosed` | The tunnel is closed, locally or by the peer's close notice. |
| `ErrTimeout` | A read or write deadline passed. |
| `ErrRekeyRequired`, `ErrRekeyInProgress` | Key-lifetime limits; rekey, or close and redial. |
| `ErrMessageTooLarge`, `ErrInvalidState` | A message was oversized, or arrived out of sequence. |
| `ErrPoolClosed`, `ErrPoolTimeout`, `ErrPoolExhausted` | Pool conditions. |

Until the failure-behavior tests listed in [#238](https://github.com/sara-star-quant/Quantum-Go/issues/238) pin down which errors leave a tunnel usable, treat any error from `Send` or `Receive` other than `ErrTimeout` as the end of that tunnel: close it and dial again. That is guidance, not a guarantee.

## Authentication default

The library does not require authentication: `Dial` and `Listen` with no PSK and no pin give an encrypted, forward-secret tunnel to a peer nobody has identified, which an active attacker can sit in the middle of. The `forward` command refuses to start without a PSK. Whether the library should also demand an explicit opt-in is an open decision on the [roadmap](ROADMAP.md); it would be a breaking change.
