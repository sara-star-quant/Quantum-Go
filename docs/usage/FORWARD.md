# Forward mode: protect any TCP service

`quantum-tunnel forward` puts the post-quantum tunnel in front of a TCP service you cannot or do not want to change: a database, an HTTP or gRPC service, a message broker, a stack that is not written in Go. You run one side next to the service and one next to its users. Each TCP connection gets its own tunnel, keyed with ML-KEM-1024 plus X25519 after one round trip.

It is not for Go services that already speak HTTPS or gRPC with each other: Go's own TLS offers hybrid post-quantum key exchange by default (see [AI and cloud workloads](AI_AND_CLOUD.md)). It is for the services TLS does not reach.

## Where it fits

| Where | Examples | Why a wrapper helps |
|---|---|---|
| Industrial and utilities | Modbus/TCP, DNP3, plaintext SCADA links | The protocols have no security and the devices stay in service for decades. A gateway pair in front of them adds authentication and encryption without touching the device. |
| Finance and payments | FIX sessions, ISO 8583 links, HSM and batch file links | Plaintext or stunnel on private lines is common, sessions are long-lived, and the data stays sensitive for years. |
| IoT and messaging | MQTT on 1883 through a local gateway | Constrained devices talk plain TCP to a nearby gateway; the gateway tunnels to the cloud broker. |
| Infrastructure and cloud | Redis, Kafka, etcd, database links between sites, sidecars | "Trusted network" plaintext between sites and clusters gets a key-authenticated tunnel with no application change. |
| AI and research | Model serving, bulk data movement between clusters | Long connections amortize the handshake; see the throughput notes in [PERFORMANCE](../PERFORMANCE.md). |
| Satellite ground segment | Ground station to control center, VSAT and LEO backhaul | A plain TCP link like any other. Untested here, and the space link itself (CCSDS SDLS) is out of scope. |

Where it does not help: services already on TLS 1.3 with hybrid post-quantum key exchange, UDP protocols (CoAP, syslog, NTP, QUIC and HTTP/3), Bluetooth, and anything that must run on a microcontroller. A wrapper hides traffic from the network; it does not add authentication to the application behind it.

## Quick start

1. Make a pre-shared key and copy it to both hosts over a channel you trust:

   ```sh
   openssl rand -hex 32 > psk.hex && chmod 600 psk.hex
   ```

2. On the server host, next to the service (here an HTTP service on port 8080):

   ```sh
   quantum-tunnel forward --serve :9000 --upstream 127.0.0.1:8080 --psk-file psk.hex
   ```

3. On the client host, next to the application:

   ```sh
   quantum-tunnel forward --listen 127.0.0.1:8080 --connect server.example.com:9000 --psk-file psk.hex
   ```

Point the application at `127.0.0.1:8080`. It speaks plain TCP to its local forwarder, and the bytes cross the network inside the tunnel.

## What it protects, and what it does not

- **Protected:** the bytes between the two forwarders are confidential, integrity-protected and forward-secret, with a hybrid post-quantum key exchange. The two forwarders authenticate each other with the PSK, and optionally the server's pinned key.
- **Not protected:** the plain hop between the application and its local forwarder, and between the server forwarder and the service. Keep both on loopback or inside one pod or host. A bare `--listen :8080` binds `127.0.0.1`, not every interface.
- **The PSK identifies the forwarder pair, not a person.** Anyone who can reach the client's local port uses the tunnel, so guard that port with loopback, OS permissions or network policy. Authenticated per-user identity is not available yet ([#196](https://github.com/sara-star-quant/Quantum-Go/issues/196)).
- **Not hidden:** record sizes, timing and the number of connections are visible on the wire.
- **No open relay:** the server forwards only to its one `--upstream`. A peer cannot choose a destination.
- **A stranger can make the server do work.** A peer that has not authenticated yet still costs the server one ML-KEM-1024 operation per handshake, about 0.1 to 0.2 ms of CPU. The per-address and global rate limits bound that. They do not remove it: an attacker can use up the global handshake budget and keep real clients out until it stops, and sources behind one NAT share one per-address limit. Refused handshakes are logged at most once a second with a count of the rest. For anything reachable from the internet, put an allowlist or firewall in front of the server port as well.
- **A bad frame ends the connection.** After the handshake the only frame types are data and end-of-stream; any other value closes the connection and nothing reaches the upstream.
- **Logs** carry addresses, byte counts, durations and error classes, never payloads or keys.

## Authentication

Authentication is mandatory. The server refuses to start without a PSK source, because without one anyone could reach the upstream, and the client refuses to start without a PSK.

| Option | How |
|---|---|
| One shared PSK | `--psk-file` on both sides; `--identity` optional |
| One PSK per client | server `--clients-file` with `identity hexkey` lines; each client uses `--identity` and its own key in `--psk-file` |
| Pin the server's key | `quantum-tunnel keygen`, then server `--server-key server.key` and client `--pin server.pub` (the server then requires clients to pin it) |
| Development only | `--insecure-no-auth` (logs a warning; encrypted but nobody is authenticated) |

A key file is refused when its group can write it or when others can touch it. Use mode 0600 on a shared host; 0440 and 0640 pass so that container secrets, which arrive group-owned, work.

## Examples

- **HTTP and gRPC:** point the client at `127.0.0.1:8080`. For gRPC use plaintext credentials on that local hop (`insecure.NewCredentials()`), or keep TLS inside the tunnel if you also want end-to-end certificates; the forwarders pass TLS bytes through unchanged.
- **PostgreSQL:** connect to `127.0.0.1:5432` with `sslmode=disable` on the local hop, or keep TLS inside.
- **Kubernetes sidecar** (an illustration; not tested in a cluster):

  ```yaml
  spec:
    securityContext:
      fsGroup: 1000            # the image runs as uid 1000
    containers:
      - name: app
        image: your-app        # talks to 127.0.0.1:8080, unchanged
      - name: pq-forward
        image: ghcr.io/sara-star-quant/quantum-go:<version>
        args: ["forward", "--listen", "127.0.0.1:8080",
               "--connect", "pq-server.example.com:9000", "--psk-file", "/secrets/psk.hex"]
        volumeMounts:
          - { name: psk, mountPath: /secrets, readOnly: true }
    volumes:
      - name: psk
        secret: { secretName: pq-psk, defaultMode: 0440 }
  ```

## Behavior and limits

- **One tunnel per TCP connection.** Each connection costs one handshake and one round trip. That suits long-lived connections (HTTP/2 and gRPC, pooled database connections, bulk transfers). Short-lived HTTP/1.1 connections pay it every time, so keep connections alive.
- **Half-close works.** A client that finishes sending and then waits for the reply gets it. The EOF travels inside the tunnel as a one-byte frame, with no change to the wire protocol.
- **TCP only.** UDP is not forwarded, so HTTP/3, QUIC, CoAP and syslog over UDP are not covered. Modern HTTP/3 stacks negotiate hybrid post-quantum key exchange in TLS 1.3 already.
- **Limits:** `--max-conns` (default 1024), `--idle-timeout` (default 5 minutes, counted only when neither direction moves data; 0 disables it), a 10 second dial to the upstream and a 30 second client dial plus handshake. The server also caps handshakes in flight at 1024, connections per source address at `--max-conns-per-ip` (default 256) and handshakes per second across all sources at `--handshake-rate` (default 1000); 0 disables either. A client forwarder opens one tunnel per local connection, so one client can need as many connections as its own `--max-conns`: raise the per-address cap above the busiest client, or its extra connections are refused. The address is the full source address, so an attacker holding an IPv6 prefix can rotate addresses and sidestep the per-address cap. A connection over `--max-conns` still pays its handshake before it is refused.
- **Rotating keys:** write the new key file and send SIGHUP (`kill -HUP <pid>`) to each side. New connections use the new keys; open connections keep the keys they started with. A server reloads its PSKs only, so a change to `--server-key` needs a restart; a client reloads its PSK and pinned key. A file that fails to parse or has loose permissions keeps the current keys and logs the error. SIGHUP no longer ends the process, so run it under systemd, a container runtime or `nohup`, not a bare terminal.
- **Rotating without refusing anyone:** a server holds one key per identity, so reloading the server and the clients at different moments leaves a gap in which not-yet-reloaded clients are refused. To avoid it, add the new key under a new identity in `--clients-file`, reload the server, point each client at the new key and `--identity`, reload them, then delete the old line and reload the server again.
- **A compromised key:** reload does not erase the old key from memory, and connections that opened with it stay open. Restart both sides to cut them.
- **Shutdown:** SIGINT and SIGTERM close the listener and cut open connections. There is no drain.
- **Not yet measured on real hosts.** No throughput or latency numbers are published for this mode, and none should be assumed from the library's. Measure with your own workload.

## Flags

| Flag | Side | Meaning |
|---|---|---|
| `--listen`, `--connect` | client | accept plain TCP here, carry it to the server address |
| `--serve`, `--upstream` | server | accept tunnels here, hand each to this one address |
| `--psk-file`, `--identity` | both | the PSK, and the identity the client announces |
| `--clients-file` | server | one PSK per client |
| `--server-key`, `--pin` | server, client | static key pinning from `keygen` |
| `--max-conns`, `--idle-timeout` | both | connection and idle limits |
| `--max-conns-per-ip`, `--handshake-rate` | server | per-address connection cap and global handshakes per second (0 disables) |
| `--suite` | client | KEM suite to offer first: `chkem-v1` (default) or `x-wing`; the server follows |
| `--insecure-no-auth`, `--verbose` | both | development only; log every connection |
