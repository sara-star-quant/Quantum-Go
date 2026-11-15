# Trying forward mode

A one-page guide for running `quantum-tunnel forward` on a real link. It protects a plain TCP service with a post-quantum tunnel and changes nothing in the service or the application.

## Is this for you

Forward mode fits a long-lived TCP connection between two systems you cannot change, where you want the bytes protected on the network between them: a broker or database link between sites, a gateway to a device that cannot speak TLS, a file transfer. It does not fit UDP traffic, a service that needs the client's address at the other end (the upstream sees the forwarder's address), or a case where you need a validated cryptographic module.

## What to expect

- The project is pre-1.0, has had no third-party audit, and one maintainer. The FIPS build mode restricts suites and runs self-tests; it is not a validation.
- There is no support contract. Issues are read and answered on a best-effort basis. A security problem goes through [SECURITY.md](../../SECURITY.md), not a public issue.
- Releases are signed and attested. Check what you download.

## Install and check it

Download the archive for your platform from the [releases page](https://github.com/sara-star-quant/Quantum-Go/releases), then:

```sh
sha256sum -c checksums-sha256.txt --ignore-missing   # macOS: shasum -a 256 -c checksums-sha256.txt --ignore-missing
gh attestation verify quantum-tunnel-<version>-<os>-<arch>.tar.gz -R sara-star-quant/Quantum-Go
tar -xzf quantum-tunnel-<version>-<os>-<arch>.tar.gz
```

The attestation names the release workflow and the tag. A container image is published too (`ghcr.io/sara-star-quant/quantum-go:<version>`).

## Two commands

Make a key and copy it to both hosts over a channel you trust:

```sh
openssl rand -hex 32 > psk.hex && chmod 600 psk.hex
```

On the server host, next to the service (here on port 8080):

```sh
quantum-tunnel forward --serve :9000 --upstream 127.0.0.1:8080 --psk-file psk.hex --metrics-addr 127.0.0.1:9100
```

On the client host, next to the application, then point the application at `127.0.0.1:8080`:

```sh
quantum-tunnel forward --listen 127.0.0.1:8080 --connect server.example.com:9000 --psk-file psk.hex
```

With more than one client, give each its own identity and key (`--clients-file` on the server, `--identity` on each client) so you can revoke one without touching the others. See [Forward mode](FORWARD.md).

## What to watch

- `curl 127.0.0.1:9100/readyz` is 200 when the server is up and its keys are loaded. `/metrics` carries connection counts, refused handshakes and key-reload results; the series are listed in [Forward mode](FORWARD.md#running-it-unattended).
- `--assurance-log FILE` records, per finished connection, the KEM suite, how the peers authenticated and whether the build ran in FIPS build mode. It holds no addresses.
- A wrong key looks the same as no key from the client's side. If a client cannot connect, check the key and identity first.

## Rotate and revoke

Write the new key file and send SIGHUP to the server. Connections whose key is no longer in the table end at the reload; `--keep-sessions-on-reload` keeps them for routine rotation. SIGHUP does not exist on Windows: restart there.

## Roll back

Stop the forwarders and point the application back at the service's own address. Forward mode installs nothing, opens no kernel interface and changes no system setting, so nothing else needs undoing.

## Known limits

TCP only. A single tunnel flow reaches about 10 to 14 Gbps on a 20 Gbps link; several flows fill it ([Performance](../PERFORMANCE.md)). The Kubernetes sidecar example in [Forward mode](FORWARD.md) is an illustration and has not been run in a cluster.

## What we would like to hear

How long it took from download to the first byte through the tunnel, and what slowed you down. What you tried before (a VPN, IPsec, a TLS wrapper) and what stopped you. What forward mode did not do that you needed. Whether a per-connection record of the suite and authentication would go into an audit or compliance pack for you. Use the [pilot feedback form](https://github.com/sara-star-quant/Quantum-Go/issues/new?template=pilot_feedback.yml); a short answer is enough.
