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
//	  503  weekly issuance budget exhausted
//
//	GET /certs/{ip}
//	  200  certificate bundle (issuance complete)
//	  202  issuance in progress, keep polling (Retry-After: 10)
//	  404  never requested
//	  500  internal error during issuance
//	  502  ACME authorization failure (LE rejected the challenge)
//	  503  weekly issuance budget exhausted
//	  504  DNS propagation timeout (TXT record not visible within 5 min)
//	  5xx responses also include Retry-After: 3600
//
//	GET /certs/{ip}/ttl
//	  200  remaining validity in seconds and human-readable form
//	  404  no certificate on disk for this IP
//
//	GET /stats
//	  200  cert_count, total_issued, budget_used, budget_limit,
//	       budget_resets_in, pending_issuances, failed_issuances, uptime
//
//	GET /health
//	  200  {"status": "ok"}
//
// "Usable" means the certificate has more than 30 days remaining. Certs inside
// the renewal window are treated as missing and trigger a new issuance.
package api
