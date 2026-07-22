# lancert

<p align="center">
  <img src="internal/api/static/assets/lancert-logo.svg" alt="lancert" width="320">
</p>

Local HTTPS certificates for private IP addresses.

Get browser-trusted Let’s Encrypt wildcard TLS certificates for private IP addresses on your LAN. Test local apps on real devices without a custom CA or certificate warnings.

lancert maps names such as `*.192-168-1-50.lancert.dev` to `192.168.1.50`, which is useful for service workers, mobile push notifications, and other APIs that require a secure context.

<p align="center">
  <img src="demo/demo.gif" alt="lancert demo — download certs and serve HTTPS with Caddy" width="800">
</p>

## Architecture

Single-process service with three components:

1. **DNS server** — authoritative for the `lancert.dev` zone. Resolves `*.192-168-1-50.lancert.dev` to `192.168.1.50` by parsing the IP from the subdomain. Serves TXT records for ACME challenges from an in-memory store.

2. **HTTP API** — `POST /certs/{ip}` to issue a certificate, `GET /certs/{ip}` to fetch it, `GET /certs/{ip}/fullchain.pem` and `GET /certs/{ip}/privkey.pem` for direct PEM downloads, `GET /certs/{ip}/ttl` for remaining validity.

3. **Certificate service** — ACME DNS-01 flow via Let's Encrypt. Each IP gets one certificate covering both `192-168-1-50.lancert.dev` and `*.192-168-1-50.lancert.dev`.

The public `GET /status` page reports aggregate DNS activity, serving stability,
and current certificate readiness. It observes authoritative DNS queries, not
users or unique installations. Metrics are buffered in memory and flushed to
`metrics.db` periodically; metrics failures never stop DNS or certificate
serving.

## Security

> [!WARNING]
> lancert does not provide confidentiality. The private keys are served via API to anyone who requests them. There is no ownership concept for private IPs — `192.168.1.50` on your network is the same address as `192.168.1.50` on someone else's. Anyone who knows the IP can download the same certificate and private key.
>
> The browser will show a valid HTTPS connection, but this does not mean the traffic is protected from other devices on the same network.
>
> The threat model is simple: you trust your local network enough to develop on it, and you need the browser to trust your certificate. That's it. Do not use these certificates in production.

## Usage

Issue a certificate for your LAN IP:

```bash
curl -X POST https://lancert.dev/certs/192.168.1.50
```

Fetch an existing certificate:

```bash
curl https://lancert.dev/certs/192.168.1.50
```

## Running

```bash
go build -o lancert ./cmd/lancert/
./lancert -server-ip <PUBLIC_IP> [-acme-env staging] [-email you@example.com]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server-ip` | (required) | Public IP of this server |
| `-dns-addr` | `:53` | DNS listen address |
| `-http-addr` | `:8443` | HTTP listen address (behind reverse proxy) |
| `-data-dir` | `data` | Data directory for certs and keys |
| `-email` | | Email for Let's Encrypt account |
| `-acme-env` | `production` | ACME authority: `production`, `staging`, or `local` (Pebble) |
| `-pregen` | `false` | Pre-generate certificates for common IPs at startup |

### Local development with mise

The repository includes a safe local-development profile pinned to Go 1.26.5.
The `dev` task uses Air for automatic rebuilds when source files change:

```bash
mise install
mise run setup
mise run dev
```

The dev task uses `./data` for local data and writes binaries to `./bin`.
It starts a local Pebble ACME server and Lancert through the `.mise/Procfile`,
binds DNS to `127.0.0.1:1053`, and uses HTTP on `127.0.0.1:8443`. `mise run
setup` generates a short-lived local TLS CA and key with mkcert under
`.mise/pebble/`; these files are ignored by Git.
No public DNS or Let's Encrypt account is required for local issuance.

## Supported IPs

Only RFC 1918 private IPv4 addresses:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

## License

MIT
