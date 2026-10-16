# lancert

Lancert helps you get a trusted HTTPS certificate for an app on your private
network, with support for **private IPv4 and locally assigned IPv6 ULA addresses**.
You do not need to own a domain or configure a DNS provider.

Lancert assigns a public hostname that resolves to your private IP address and
handles the DNS records required by the standard ACME DNS-01 challenge. Your
ACME client keeps certificates and private keys on your machine.

## Use the Lancert CLI

Install the [Lancert CLI](https://github.com/lucor/lancert-cli) with Homebrew:

```console
brew install lucor/tap/lancert
```

You can also install the CLI from source with
`go install go.lucor.dev/lancert-cli/cmd/lancert@latest`.

Request a certificate for the address where your app is reachable:

```console
# IPv4
lancert 192.168.1.50

# IPv6 ULA
lancert fd12:3456:789a:1::25
```

Run `lancert` without an address to list supported addresses on your machine.
Use `lancert list` to inspect managed certificates and run `lancert renew`
regularly to renew them. The CLI uses Let's Encrypt by default; its terms,
policies, and rate limits apply.

See the [CLI guide](https://lancert.dev/docs/cli) for certificate paths,
renewal, and web server setup.

## Supported addresses

| Target | Accepted ranges | DNS records |
| --- | --- | --- |
| Private IPv4 | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918) | `A` |
| Locally assigned IPv6 ULA | `fd00::/8` | `AAAA` |

Each registration publishes records for its assigned hostname and wildcard,
such as `quiet-otter.lancert.dev` and `*.quiet-otter.lancert.dev`, using the
registered address family. Other address ranges are rejected, including public,
loopback, link-local, and CGNAT addresses.

## Use your own ACME client

Lego, Certbot, acme.sh, and other clients that support an acme-dns-compatible
API also work with Lancert. First, register your app's private address using
one of these requests. No request body is needed:

```bash
# IPv4
curl --fail-with-body -X POST https://lancert.dev/register/192.168.1.50

# IPv6 ULA
curl --fail-with-body -X POST \
  https://lancert.dev/register/fd12:3456:789a:1::25
```

A successful registration returns:

```json
{
  "hostname": "quiet-otter.lancert.dev",
  "username": "b5f7c153-8f3c-4906-a046-080c005ff8f2",
  "password": "save-this-one-time-secret",
  "subdomain": "quiet-otter",
  "fulldomain": "_acme-challenge.quiet-otter.lancert.dev"
}
```

Save the complete response securely: credentials are returned only once, and
there is no lookup, recovery, or rotation API. Use the returned hostname exactly
as provided.

Then follow the [ACME client guide](https://lancert.dev/docs/acme-clients) to
configure your client and request the certificate. The selected certificate
authority's terms, policies, and rate limits apply.

## Security model

Each credential can update only the DNS challenge TXT values for its assigned
hostname. It cannot change A or AAAA records, static zone data, or another
registration. Passwords are stored only as cryptographic digests.

Challenge values are process-local, expire after 15 minutes, and are served
with a one-second DNS TTL. They are never persisted and disappear on restart.

Possession of a credential can authorize certificate issuance for the assigned
hostname and its wildcard. Keep the credential private and use the production
API only through HTTPS. The service intentionally provides no recovery path.

## Run the service

```bash
mise run build
LANCERT_SERVER_IP=203.0.113.10 \
LANCERT_IP_HASH_SALT="$(openssl rand -hex 32)" \
./bin/lancert
```

| Flag | Default | Description |
| --- | --- | --- |
| `-server-ip` | required | Public IPv4 of the DNS service, used for zone apex and nameserver glue |
| `-dns-addr` | `:53` | Authoritative UDP/TCP DNS listen address |
| `-http-addr` | `:8443` | HTTP listen address, normally behind HTTPS ingress |
| `-data-dir` | `data` | Directory containing `core.db` and `metrics.db` |

`core.db` is essential and fail-closed. It must be stored on a durable private
volume and backed up with a SQLite-consistent method. `metrics.db` is
observational and fail-open.

See [`.env.example`](.env.example) for all environment variables and
[`internal/api/openapi.yaml`](internal/api/openapi.yaml) for the HTTP contract.

Optional configuration includes static TXT verification records
(`LANCERT_STATIC_TXT`), MX mail routes (`LANCERT_STATIC_MX`), and certificate
metrics from public Certificate Transparency logs (`SSLMATE_API_KEY`).
The static record formats and examples are in [`.env.example`](.env.example);
configuration changes require a restart.

## Development

```bash
mise install
mise run setup
mise run test
mise run race
mise run e2e
```

The E2E test uses a real Lego client and Pebble. Certificates and private keys
remain in the test client's temporary directory and never enter Lancert.

## License

MIT
