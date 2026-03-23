package api

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/privateip"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/404.html
var notFoundHTML []byte

//go:embed static/docs.html
var docsHTML []byte

//go:embed openapi.yaml
var openapiYAML []byte

// Handler serves the lancert.dev HTTP API.
type Handler struct {
	service *certservice.Service
	mux     *http.ServeMux
	done    chan struct{}
}

// New creates an API handler wired to the given cert service.
func New(svc *certservice.Service) *Handler {
	h := &Handler{
		service: svc,
		done:    make(chan struct{}),
	}
	h.mux = http.NewServeMux()
	h.registerRoutes()
	return h
}

// Close stops background goroutines (e.g. rate limiter cleanup).
// Safe to call multiple times.
func (h *Handler) Close() {
	select {
	case <-h.done:
	default:
		close(h.done)
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// registerRoutes sets up the API routes.
// Rate limit is applied only to POST (issuance) — 1 req/s burst 3.
func (h *Handler) registerRoutes() {
	issueRL := PerIPRateLimit(1, 3, h.done)
	h.mux.Handle("POST /certs/{ip}",
		issueRL(GzipResponse(http.HandlerFunc(h.handleIssueCert))))
	h.mux.Handle("GET /certs/{ip}",
		GzipResponse(http.HandlerFunc(h.handleGetCert)))
	h.mux.Handle("GET /certs/{ip}/ttl",
		GzipResponse(http.HandlerFunc(h.handleGetTTL)))
	// PEM downloads skip GzipResponse: files are small (~2-3KB) and
	// compressing secret material adds unnecessary risk.
	h.mux.HandleFunc("GET /certs/{ip}/fullchain.pem", h.handleGetFullChain)
	h.mux.HandleFunc("GET /certs/{ip}/privkey.pem", h.handleGetPrivKey)
	h.mux.HandleFunc("GET /stats", h.handleStats)
	h.mux.HandleFunc("GET /health", h.handleHealth)
	h.mux.HandleFunc("GET /docs", handleDocs)
	h.mux.HandleFunc("GET /openapi.yaml", handleOpenAPI)
	h.mux.HandleFunc("GET /{$}", handleIndex)
	h.mux.HandleFunc("GET /", handleNotFound)
}

// handleIssueCert triggers certificate issuance for the given IP and returns
// immediately. Returns 200 if a usable cert is already cached, or 202 with
// Retry-After to indicate issuance is in progress.
func (h *Handler) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Fast path: usable cert already on disk.
	bundle, err := h.service.LoadUsable(addr)
	if err != nil {
		slog.Error("api: load cert error", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read certificate")
		return
	}
	if bundle != nil {
		writeJSON(w, http.StatusOK, certResponse(addr, bundle))
		return
	}

	// Budget precheck before triggering.
	if h.service.BudgetExhausted() {
		writeError(w, http.StatusServiceUnavailable, "certificate issuance budget exhausted, try again later")
		return
	}

	// Trigger background issuance (idempotent).
	status := h.service.TriggerIssuance(addr)

	if status.Fail != nil {
		writeError(w, status.Fail.Status, status.Fail.Msg)
		return
	}

	// Pending (newly triggered or already in progress).
	writePending(w, pendingRetryAfter)
}

// handleGetCert returns the certificate status for the given IP.
// 200 with cert JSON if usable, 202 if pending, 404 if never requested,
// or the cached failure status code on recent errors.
func (h *Handler) handleGetCert(w http.ResponseWriter, r *http.Request) {
	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, err := h.service.GetStatus(addr)
	if err != nil {
		slog.Error("api: get cert error", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read certificate")
		return
	}

	if status.Bundle != nil {
		writeJSON(w, http.StatusOK, certResponse(addr, status.Bundle))
		return
	}

	if status.Pending {
		writePending(w, pendingRetryAfter)
		return
	}

	if status.Fail != nil {
		writeError(w, status.Fail.Status, status.Fail.Msg)
		return
	}

	writeError(w, http.StatusNotFound, "no certificate found for this IP")
}

// handleGetTTL returns the remaining TTL for the certificate.
func (h *Handler) handleGetTTL(w http.ResponseWriter, r *http.Request) {
	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ttl := h.service.TTL(addr)
	if ttl == 0 {
		writeError(w, http.StatusNotFound, "no certificate found for this IP")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ip":          addr.String(),
		"ttl_seconds": int(ttl.Seconds()),
		"ttl_human":   formatDuration(ttl),
	})
}

const (
	// pendingRetryAfter is the Retry-After value (in seconds) sent with
	// 202 responses to tell clients how long to wait before polling again.
	pendingRetryAfter = 10

	pemFullChain = "fullchain"
	pemPrivKey   = "privkey"
)

// handleGetFullChain returns the certificate chain as a PEM file download.
func (h *Handler) handleGetFullChain(w http.ResponseWriter, r *http.Request) {
	h.servePEM(w, r, pemFullChain)
}

// handleGetPrivKey returns the private key as a PEM file download.
func (h *Handler) handleGetPrivKey(w http.ResponseWriter, r *http.Request) {
	h.servePEM(w, r, pemPrivKey)
}

// servePEM validates the IP, resolves cert status, and writes the selected
// PEM data as a file download. Error/status behavior mirrors handleGetCert.
func (h *Handler) servePEM(w http.ResponseWriter, r *http.Request, kind string) {
	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, err := h.service.GetStatus(addr)
	if err != nil {
		slog.Error("api: get cert error", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read certificate")
		return
	}

	if status.Bundle != nil {
		var contentType string
		var data []byte
		if kind == pemFullChain {
			contentType = "application/pem-certificate-chain"
			data = status.Bundle.FullChainPEM
		} else {
			// application/octet-stream: no standard MIME type exists for
			// PEM-encoded private keys; octet-stream triggers a download
			// in browsers rather than rendering.
			contentType = "application/octet-stream"
			data = status.Bundle.PrivKeyPEM
		}

		w.Header().Set("Content-Type", contentType)
		// Include IP in filename so downloading certs for multiple IPs
		// does not overwrite previous files.
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="%s-%s.pem"`, kind, addr.String()))
		w.Write(data)
		return
	}

	if status.Pending {
		writePending(w, pendingRetryAfter)
		return
	}

	if status.Fail != nil {
		writeError(w, status.Fail.Status, status.Fail.Msg)
		return
	}

	writeError(w, http.StatusNotFound, "no certificate found for this IP")
}

// handleStats returns public stats.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	st := h.service.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"cert_count":        st.CertCount,
		"total_issued":      st.TotalIssued,
		"budget_used":       st.BudgetUsed,
		"budget_limit":      st.BudgetLimit,
		"budget_resets_in":  formatDuration(st.BudgetResetsIn),
		"pending_issuances": st.PendingIssuances,
		"failed_issuances":  st.FailedIssuances,
		"uptime":            formatDuration(st.Uptime),
	})
}

// handleHealth is a simple liveness probe.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleIndex serves the static homepage.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// handleDocs serves the Scalar API reference page.
func handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(docsHTML)
}

// handleOpenAPI serves the OpenAPI specification.
func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(openapiYAML)
}

// handleNotFound serves a styled 404 page for unknown paths.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write(notFoundHTML)
}

// CertJSON is the JSON response for a certificate.
type CertJSON struct {
	IP        string   `json:"ip"`
	Domains   []string `json:"domains"`
	NotAfter  string   `json:"not_after"`
	PrivKey   string   `json:"privkey_pem"`
	FullChain string   `json:"fullchain_pem"`
}

// certResponse converts a CertBundle to the API response.
func certResponse(addr netip.Addr, b *certstore.CertBundle) CertJSON {
	return CertJSON{
		IP:        addr.String(),
		Domains:   b.Meta.Domains,
		NotAfter:  b.Meta.NotAfter.Format(time.RFC3339),
		PrivKey:   string(b.PrivKeyPEM),
		FullChain: string(b.FullChainPEM),
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("http: json encode error", "error", err)
	}
}

// writePending writes a 202 Accepted response with Retry-After header
// and a JSON body indicating the request is pending.
func writePending(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":      "pending",
		"retry_after": retryAfter,
	})
}

// writeError writes a JSON error response. For 5xx errors, sets
// Retry-After: 3600 to signal clients to back off for one hour.
func writeError(w http.ResponseWriter, status int, message string) {
	if status >= 500 {
		w.Header().Set("Retry-After", "3600")
	}
	writeJSON(w, status, map[string]string{"error": message})
}

// formatDuration formats a duration as "Xd Yh Zm".
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return strings.TrimSpace(
			strings.Join([]string{
				strconv.Itoa(days) + "d",
				strconv.Itoa(hours) + "h",
			}, " "),
		)
	}

	return strings.TrimSpace(
		strings.Join([]string{
			strconv.Itoa(hours) + "h",
			strconv.Itoa(minutes) + "m",
		}, " "),
	)
}

