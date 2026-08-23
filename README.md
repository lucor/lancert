# lancert

Lancert helps you get a trusted HTTPS certificate for an app on your private
network. It provides a public hostname and handles the DNS challenge required
by the certificate authority.

This is the standard ACME DNS-01 flow. You can set it up with your own domain
and DNS provider; Lancert provides the DNS service for developers who do not
have or do not want to configure one.

Lancert does **not** store certificates or private keys. Your ACME client keeps
them on your machine.

## Use the Lancert CLI

The [Lancert CLI](https://github.com/lucor/lancert-cli) is the quickest path:

```console
brew install lucor/tap/lancert
lancert 192.168.1.50
```

You can also install the CLI from source with
`go install go.lucor.dev/lancert-cli/cmd/lancert@latest`.

The CLI currently uses Let's Encrypt by default. Let's Encrypt terms, policies,
and rate limits apply. Run `lancert renew` regularly to renew locally managed
certificates.

## Use your own ACME client

Lego, Certbot, acme.sh, and other clients that support an acme-dns-compatible
API also work with Lancert. This path needs a few extra setup steps.

### Register a hostname

Registration accepts no request body and returns credentials only once:

```bash
curl --fail-with-body -X POST https://lancert.dev/register/192.168.1.50
```

```json
{
  "hostname": "quiet-otter.lancert.dev",
  "username": "b5f7c153-8f3c-4906-a046-080c005ff8f2",
  "password": "save-this-one-time-secret",
  "subdomain": "quiet-otter",
  "fulldomain": "_acme-challenge.quiet-otter.lancert.dev"
}
```

Save the complete response securely. Lancert has no credential lookup,
recovery, or rotation API.

Hostname labels normally contain two curated words; a short suffix may appear
after collisions. Treat the returned label as opaque and copy it exactly.

The registration publishes:

```text
quiet-otter.lancert.dev       A 192.168.1.50
*.quiet-otter.lancert.dev     A 192.168.1.50
```

Only RFC 1918 IPv4 targets are accepted. Public, loopback, link-local, CGNAT,
and IPv6 targets are rejected.

For Lego, Certbot, acme.sh, and other compatible clients, see the
[ACME client guide](https://lancert.dev/docs/acme-clients). The selected
certificate authority's terms, policies, and rate limits apply.

## Security model

Each credential can update only the two most recent distinct TXT values at its
assigned `_acme-challenge` owner. It cannot change A records, static zone data,
or another registration. Passwords contain 240 random bits and are persisted
only as domain-separated BLAKE2b-256 digests.

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
| `-server-ip` | required | Public IPv4 for zone apex and nameserver glue |
| `-dns-addr` | `:53` | Authoritative UDP/TCP DNS listen address |
| `-http-addr` | `:8443` | HTTP listen address, normally behind HTTPS ingress |
| `-data-dir` | `data` | Directory containing `core.db` and `metrics.db` |

`core.db` is essential and fail-closed. It must be stored on a durable private
volume and backed up with a SQLite-consistent method. `metrics.db` is
observational and fail-open. Lancert v2 does not migrate v1 data; deploy it with
a new data volume.

See [`.env.example`](.env.example) for all environment variables and
[`internal/api/openapi.yaml`](internal/api/openapi.yaml) for the HTTP contract.

### Static TXT records

`LANCERT_STATIC_TXT` publishes declarative verification records. Names are
relative to `LANCERT_ZONE`; `@` is the apex:

```env
LANCERT_STATIC_TXT='{"@":{"ttl":300,"values":["verification-value"]}}'
```

Dynamic challenge owners are reserved. Configuration changes require restart.

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
