# How Quantum-Go compares

As of 2026-10-31. Quantum-Go numbers are measured (see [PERFORMANCE.md](PERFORMANCE.md)); every number or claim about another project carries a source. Where a source did not settle a point, this page says so instead of guessing. Check each project's own documentation before relying on a row, because all of these move quickly.

## Pick the right tool first

Quantum-Go is a **library**: you embed it in a Go program to encrypt a `net.Conn` or a UDP socket. WireGuard, Rosenpass, strongSwan and OpenVPN are **protocols and daemons** you run next to your application. NordVPN and Mullvad are **commercial services** that ship a client. Those are three different jobs, so the useful question is not "which is fastest" but "which job do I have".

| You want | Reach for |
|----------|-----------|
| Post-quantum encryption inside your own Go service, agent or relay, with no daemon, no kernel module and no root | **Quantum-Go** |
| A system-wide VPN interface for a host or a fleet | WireGuard, optionally with Rosenpass, or IKEv2/IPsec |
| A consumer VPN service | A provider such as NordVPN or Mullvad |
| Post-quantum protection for ordinary HTTPS | TLS 1.3 with a hybrid ML-KEM group |

## What you get with Quantum-Go

- **A post-quantum handshake in one round trip.** The client can send data after 1 RTT on both transports. Measured: 21 ms on a 20 ms link, 101 ms on a 100 ms link.
- **Hybrid security.** ML-KEM-1024 (NIST security level 5) combined with X25519, so an attacker has to break both. Traffic recorded today stays protected against a future quantum computer.
- **Two transports from one API.** Stream (TCP) and a connectionless datagram (UDP) transport with a fragmented handshake, retransmission, reliable rekey, anti-DoS cookies and roaming across IP or port changes.
- **Throughput that scales with your kernel.** About 690 MB/s on one stream tunnel. On datagrams, `SendBatch` with UDP offload reached 701 MB/s on a Linux x86-64 CI runner and 528 MB/s on arm64, against 196 and 304 MB/s for one send per datagram.
- **Authentication you opt into.** Pin a server's static key, require it on the server, or give each client its own pre-shared key. An unknown client is indistinguishable from one with a wrong key.
- **Evidence, not adjectives.** Machine-checked ProVerif models of secrecy, hybrid security, forward secrecy and authentication (including PSK), published conformance vectors, fuzz targets on every parser that sees unauthenticated bytes, a wire specification, and releases signed with cosign and attested.
- **A licence you can ship.** Apache-2.0, with an express patent grant, a licence scan on every release and full third-party notices.

## At a glance

| | Quantum-Go | WireGuard | WireGuard + Rosenpass | NordVPN / Mullvad (WireGuard-based) | IKEv2 with RFC 9370 (strongSwan) | TLS 1.3 + X25519MLKEM768 |
|---|---|---|---|---|---|---|
| Form | Go library | Kernel/userspace VPN | WireGuard plus a key-exchange daemon | Commercial service and client | IPsec daemon | Protocol in your TLS stack |
| Post-quantum | Yes, hybrid ML-KEM-1024 + X25519 (X-Wing as an option) | No | Yes, via Classic McEliece and Kyber into the WireGuard PSK | Yes, ML-KEM into the WireGuard PSK (see notes) | Yes, additional key exchange including ML-KEM | Yes, hybrid |
| Round trips until the client can send | 1 | 1 | Extra exchange alongside WireGuard's | Provider dependent | Several (IKE_SA_INIT, intermediate exchanges, IKE_AUTH) | 1 after TCP |
| Handshake size | about 1.7 KB client flight plus a matching server flight (ML-KEM-1024) | 148 B and 92 B | Large (McEliece keys) | Provider dependent | Grows with each added exchange | adds about 1,176 B client and 1,088 B server |
| Authentication | Opt-in static pin or per-client PSK | Static public keys | Static keys, McEliece for authenticity | Account and keys managed by the provider | Certificates or PSK | Certificates |
| Formal analysis | ProVerif models in-repo, run in CI | Noise-based design, published analyses | ProVerif symbolic analysis | Not published by the provider that I found | Not assessed here | Not assessed here |

## Notes and sources behind the table

**WireGuard** uses the Noise `IKpsk2` pattern with Curve25519, ChaCha20-Poly1305 and BLAKE2s. Its handshake is two messages of 148 and 92 bytes ([protocol page](https://wireguard.com/protocol)). It has no post-quantum key exchange of its own, which is why the options below exist.

**Rosenpass** runs a post-quantum key exchange and passes the result to WireGuard as its pre-shared key. It uses Classic McEliece and Kyber. Its whitepaper states that authenticity relies on Classic McEliece alone and forward secrecy on Kyber and correct zeroization, and describes a symbolic ProVerif analysis. A 2023 mailing-list post said a CryptoVerif proof was in progress, and I could not confirm whether it has since finished ([whitepaper](https://bienkma.github.io/books/rosenpass-whitepaper.pdf), [announcement](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/bY2jwmvzfqk)). I did not confirm its software licence from these sources; read its repository.

**NordVPN** added ML-KEM protection to NordLynx, its WireGuard-based protocol, starting on Linux in September 2024. It is opt-in per user, and it does not work with Meshnet, obfuscated servers, dedicated IP or the OpenVPN protocol ([TechRadar](https://www.techradar.com/pro/vpn/nordvpn-joins-the-post-quantum-revolution), [CyberInsider](https://cyberinsider.com/nordvpn-adds-nist-approved-quantum-encryption-on-the-linux-client/)). **Mullvad** used Classic McEliece plus Kyber for WireGuard and said it planned to move to ML-KEM; the sources I found do not settle whether the McEliece layer is dropped everywhere, so check its documentation ([TechRadar](https://www.techradar.com/pro/vpn/mullvad-launches-post-quantum-protection-for-iphones)). These are services, so compare them on price, jurisdiction and audits, not on a protocol benchmark.

**IKEv2 with RFC 9370** negotiates up to seven additional key exchanges after the first, run during `IKE_INTERMEDIATE`. strongSwan 6.0.0 supports this, with ML-KEM identifiers such as `mlkem768` and examples like `x25519-ke1_mlkem768`. The ML-KEM profile is an IETF draft (`draft-ietf-ipsecme-ikev2-mlkem`), and I could not confirm whether it has become an RFC ([strongSwan 6.0.0](https://strongswan.org/blog/2024/12/03/strongswan-6.0.0-released.html), [draft](https://www.ietf.org/archive/id/draft-ietf-ipsecme-ikev2-mlkem-09.txt)).

**TLS 1.3 with X25519MLKEM768** adds about 1,176 bytes to the client's handshake and 1,088 to the server's, and one test found the CPU cost under 0.1 ms per side ([Red Sift](https://redsift.com/blog/post-quantum-mlkem-performance)).

**OpenVPN** is not assessed on this page: I did not find a source I trust for its current post-quantum status.

## Where Quantum-Go is behind

Saying this plainly is part of being useful.

- **Bigger handshake.** ML-KEM-1024 carries 1,568-byte keys and ciphertexts each way, so the handshake is roughly ten times WireGuard's. The X-Wing suite (ML-KEM-768 + X25519) cuts that roughly in half.
- **Not a VPN client.** No TUN device, routing, DNS handling or kill-switch. See [Scope](SCOPE.md).
- **Young.** It is pre-1.0, has no third-party audit yet, and is not a FIPS 140-3 validated module. WireGuard and strongSwan have years of deployment and review behind them.
- **Smaller ecosystem.** No mobile apps, no management plane, one language.
- **Authentication is simpler than certificate PKI.** Static pins and per-client PSKs fit service-to-service use; large certificate-based fleets need more.

## When to choose what

- **Choose Quantum-Go** when the tunnel lives inside your program, you want post-quantum protection without operating a VPN, and you value an auditable protocol with published proofs and vectors.
- **Choose WireGuard (with Rosenpass if you need post-quantum)** for a system-level VPN on hosts you control.
- **Choose IKEv2/IPsec** when you need standards-based interoperability with existing gear and certificate PKI.
- **Choose TLS 1.3 hybrid** for web and API traffic.
- **Choose a provider** when you want a service, not software.

## A fair performance comparison

The speed figures in this repository come from our own benchmark workflow on GitHub-hosted runners over loopback ([PERFORMANCE.md](PERFORMANCE.md)). They are not a head-to-head. A fair one would run `wireguard-go` and Quantum-Go on the same runners with the same method, measuring handshake time to first byte, single-flow goodput and CPU per megabyte. That comparison is on the list; until it exists, rely on protocol-level facts (round trips and bytes) in the table above, which do not depend on hardware.

## Reproduce

- Handshake and throughput numbers: `quantum-tunnel bench --handshakes N --datagram-handshakes N --throughput`, or the [Benchmarks workflow](../.github/workflows/bench.yml).
- Proofs: `docs/formal/verify.sh` ([formal verification](formal/README.md)).
- Conformance vectors: `go test ./test/conformance/`.
