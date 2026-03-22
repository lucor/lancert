# lancert.dev

Real Let's Encrypt wildcard TLS certificates for private RFC 1918 IPs, designed for local development.

Solves the problem of needing valid HTTPS certificates for `*.192-168-1-50.lancert.dev` pointing at `192.168.1.50` on your LAN — needed for service workers, push notifications on mobile, and other APIs that require a secure context.

## Architecture

Single-process service with three components:

1. **DNS server** — authoritative for the `lancert.dev` zone. Resolves `*.192-168-1-50.lancert.dev` to `192.168.1.50` by parsing the IP from the subdomain. Serves TXT records for ACME challenges from an in-memory store.

2. **HTTP API** — `POST /certs/{ip}` to issue a certificate, `GET /certs/{ip}` to fetch it, `GET /certs/{ip}/ttl` for remaining validity.

3. **Certificate service** — ACME DNS-01 flow via Let's Encrypt. Each IP gets one certificate covering both `192-168-1-50.lancert.dev` and `*.192-168-1-50.lancert.dev`.

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
./lancert -server-ip <PUBLIC_IP> [-staging] [-email you@example.com]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server-ip` | (required) | Public IP of this server |
| `-dns-addr` | `:53` | DNS listen address |
| `-http-addr` | `:8443` | HTTP listen address (behind reverse proxy) |
| `-data-dir` | `data` | Data directory for certs and keys |
| `-email` | | Email for Let's Encrypt account |
| `-staging` | `false` | Use Let's Encrypt staging |
| `-no-pregen` | `false` | Skip certificate pre-generation at startup |

## Supported IPs

Only RFC 1918 private IPv4 addresses:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

## License

MIT
