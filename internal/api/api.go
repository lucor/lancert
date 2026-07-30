// Package api implements the lancert.dev HTTP API, serving certificate
// issuance and retrieval endpoints with rate limiting, security headers,
// and panic recovery middleware.
//
// # Endpoints
//
//	POST /certs/{ip}
//	  200  certificate bundle (cert already cached and usable)
//	  202  issuance triggered, poll GET (Retry-After: 10)
//	  400  invalid or non-RFC-1918 IP
//	  429  per-client initial issuance allowance exhausted
//	  503  certificate issuance temporarily suspended
//
//	GET /certs/{ip}
//	  200  certificate bundle (issuance complete, with ETag)
//	  304  certificate unchanged when If-None-Match matches
//	  202  issuance in progress, keep polling (Retry-After: 10)
//	  404  never requested
//	  500  internal error during issuance
//	  502  ACME authorization failure (LE rejected the challenge)
//	  504  DNS propagation timeout (TXT record not visible within 5 min)
//	  5xx responses also include Retry-After: 3600
//	  503  certificate downloads temporarily suspended
//
//	GET /certs/{ip}/ttl
//	  200  remaining validity in seconds as plain text
//	  404  no certificate on disk for this IP
//
//	GET /status
//	  200  cacheable HTML view of DNS activity and certificate readiness
//
//	GET /health
//	  200  {"status": "ok"}
//
// A certificate remains usable until its NotAfter; renewal is handled by the
// background ARI worker rather than by ordinary reads.
// Certificate JSON and PEM responses support stable leaf-derived ETags and
// conditional retrieval with If-None-Match.
package api
