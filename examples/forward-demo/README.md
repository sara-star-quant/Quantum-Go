# Forward demo: protect a plain TCP service in about 10 minutes

A post-quantum tunnel in front of an ordinary HTTP service, with no change to the service. You need Docker with Compose.

```
app -> qt-client (127.0.0.1:8080) ==tunnel==> qt-server (:9000) -> upstream (:8080)
```

- `upstream` is a plaintext HTTP service that knows nothing about the tunnel.
- `qt-server` and `qt-client` are `quantum-tunnel forward`, authenticated with a PSK that `psk-init` generates on first run.
- `app` shares the client forwarder's network namespace and speaks plain HTTP to `127.0.0.1:8080`.

```sh
docker compose up -d --build qt-client
docker compose run --rm app     # through the tunnel: hello from a plaintext service
docker compose run --rm probe   # without the tunnel: refused, the upstream is not reachable
docker compose logs qt-server qt-client
docker compose down -v
```

`probe` sends plain HTTP straight at the tunnel port. The server speaks only the tunnel protocol, so the request never reaches the upstream.

This is a demo, not a deployment. The PSK sits in a Docker volume, and the plain hops stay on loopback or the Compose network. For real use, read [forward mode](../../docs/usage/FORWARD.md): key files, per-client PSKs, server pinning, limits and key reload.
