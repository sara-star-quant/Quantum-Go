# Security events

Quantum-Go reports a few local signals that an operator may want to watch. They stay on the host: nothing goes to the peer, so a prober learns nothing from them, and an event carries no address or identity.

A signal is not a detection. Each one has benign causes, listed below, and a low or medium signal alone proves nothing.

## What is reported

| Class | Raised when | Confidence | Benign causes |
| --- | --- | --- | --- |
| `pin_mismatch` | A client that pins the server key fails the handshake with it | high: the server's Finished check failed. medium: the Finished message was malformed or failed for another reason. low: the Finished record never arrived whole | The server rotated its key and the client still pins the old one. The client pins the wrong server. On low, a dropped connection |
| `downgrade` | The server answers with a KEM suite the client did not offer, or sends a second HelloRetryRequest, or a HelloRetryRequest names a suite the client never offered | medium | A server or middlebox with a bug or an older build. A mismatched suite allowlist between the two ends |
| `replay` | A stream record arrives with a sequence number already seen | medium | A buggy sender that resends a record. A proxy that retries a write |

Covered by tests: each class above has a test that raises exactly one event, and a healthy handshake or record raises none. A version mismatch raises no event, because version skew between releases is common.

## What is not reported yet

Datagram replays are not reported, because a duplicating network delivers replays all the time and the datagram signals need measuring on lossy paths first. Malformed-message failures, cookie-failure bursts, address roaming and rekey failures are also not reported. Each can be added later without changing the observer interface.

The pin mismatch signal on the datagram transport is not reported either: a failed datagram handshake with a pinned key looks the same as a network failure.

## Use

An `Observer` that also implements `tunnel.SecurityObserver` receives the events:

```go
type SecurityObserver interface {
	OnSecurityEvent(tunnel.SecurityEvent)
}
```

The callback runs on the connection's goroutine, so it must not block. Ignore a class you do not know, because new classes can appear in later releases.

`metrics.TunnelObserver` implements it. It counts each event in `security_events_total{class,confidence}`, exports every series including zeros, and logs each class and confidence at most once every ten seconds. Alert on a rising `confidence="high"` series and read the benign causes before you act. An observer that does not implement the interface changes nothing.
