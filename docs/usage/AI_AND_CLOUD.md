# Quantum-Go for AI and cloud workloads

Quantum-Go protects data in transit against an attacker who records traffic today and decrypts it once quantum computers exist ("harvest now, decrypt later"). That matters for AI workloads because some of what they move stays valuable for years: model weights, training sets that contain personal data, fine-tuning data and proprietary prompts. It does not protect the model, the prompts or the pipeline from AI-specific attacks, and for ordinary HTTPS and gRPC you may not need it. This page says where it fits and where it does not.

## Where it fits

- **Long-lived secrets on point-to-point links.** Checkpoint replication between regions or clouds, data pipelines into a training cluster, federated-learning exchanges and links to a sensitive backend. The key exchange is ML-KEM-1024 plus X25519, so recorded traffic stays confidential even if one of the two later breaks.
- **Where standard TLS does not fit.** A PSK-authenticated link instead of certificates, a FIPS-mode build, a UDP transport, or ML-KEM-1024 from an implementation independent of the Go standard library's.
- **Moving big files quickly.** On two 8 vCPU Google Cloud VMs with a 20 Gbps link, one tunnel flow carried 9.7 to 11.2 Gbps with 8 KB records and 14.2 to 17.6 Gbps with 60 KB across three runs (single-flow figures swing by up to about 20% from run to run), and four or more flows filled the link at 20.2 to 20.7 Gbps, the same as plain TCP. A 10 GB checkpoint at those rates takes about 4 to 8 seconds (an illustration, not a benchmark of your network). Numbers and caveats are in [Performance](../PERFORMANCE.md#between-two-cloud-hosts).

## Where it does not

- **HTTPS and gRPC between Go services need nothing from us.** Go's `crypto/tls` offers the `X25519MLKEM768` hybrid by default from Go 1.24, and `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` (the last one at the same security category as ML-KEM-1024) from Go 1.26. Both ends have to support it; `GODEBUG=tlsmlkem=0` turns it off. For other stacks, check that your TLS library and proxies offer a hybrid ML-KEM group. TLS still authenticates with classical certificates, which is a different and less urgent risk than harvest now, decrypt later.
- **Quantum-Go cannot serve HTTP or gRPC out of the box today.** The tunnel is message based (`Send` and `Receive`) and does not implement `net.Conn`, so `net/http` and gRPC cannot run over it directly. Until the work below lands, the practical choices are standard TLS for HTTPS and gRPC, or a small `net.Conn` wrapper of your own over `Send` and `Receive`. A `net.Conn` adapter with a gRPC credential is tracked in [#219](https://github.com/sara-star-quant/Quantum-Go/issues/219), and a forward mode that protects any TCP service without code changes, the way a sidecar would, is tracked in [#220](https://github.com/sara-star-quant/Quantum-Go/issues/220).
- **It does not touch AI-specific threats**: prompt injection, model poisoning, data leakage and supply chain. Transport encryption is one layer, not "AI security".
- **It is not for GPU fabrics.** Tens or hundreds of Gbps over RDMA or InfiniBand needs hardware offload, which a Go userspace tunnel cannot match.

## What is not done yet

There is no third-party audit and no FIPS 140-3 validation; the FIPS mode is a build with self-tests, not a validated module (see the [FIPS roadmap](../compliance/FIPS_140_3_ROADMAP.md)). The server cannot yet tell which client authenticated after a handshake, which integrators need for policy decisions ([#196](https://github.com/sara-star-quant/Quantum-Go/issues/196)).

## Try it

[`scripts/cloud-bench.sh`](CLOUD_BENCH.md) runs the whole two-host matrix on your own AWS or Google Cloud account in about ten minutes and tears it down, so you can see the numbers for your instance types before you commit to anything.
