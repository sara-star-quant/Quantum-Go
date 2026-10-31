# Scope

Quantum-Go is a tunnel **encryption library**, not a VPN client. It encrypts and
authenticates bytes over a `net.Conn` or UDP socket. It does not configure, capture, or
route operating-system network traffic.

**What the library gives you (connection continuity):**

- **Authenticated roaming** - a datagram session can survive the peer's IP or port
  changing (NAT rebind, Wi-Fi to cellular): it demuxes by a random connection index, not
  source address, and rebinds only after an AEAD-authenticated packet.
- **Reliable handshake** - the post-quantum handshake retransmits lost flights with
  backoff over a lossy UDP path.
- **Rekey, resumption, and idle reaping** for long-lived sessions.

**What the library does NOT do (the integrating application's responsibility):**

- **Reconnect after a full disconnect** - the library has no auto-redial loop;
  re-establishing with `Dial` / `DialDatagram` is the caller's responsibility.
- **DNS leak prevention** - the library does not control the operating-system resolver.
- **Kill-switch** - the library does not block non-tunnel traffic when the tunnel is down.
- **TUN device and system routing** - the library does not capture or route host traffic
  into the tunnel.

These properties belong to a VPN client built around the library, not to the library
itself. This text describes the software, not security or legal advice; Quantum-Go ships
under the Apache License 2.0, "as is" and without warranty (see [LICENSE](LICENSE) and the
[compliance notice](compliance/COMPLIANCE_NOTICE.md)).
