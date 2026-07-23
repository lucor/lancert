package api

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/metrics"
	"lucor.dev/lancert/internal/privateip"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/404.html
var notFoundHTML []byte

//go:embed static/docs.html
var docsHTML []byte

//go:embed static/status.html
var statusHTML string

//go:embed openapi.yaml
var openapiYAML []byte

//go:embed static/assets
var assetsFS embed.FS

var assetsHandler http.Handler

// init parses the embedded status page template once at startup.
func init() {
	sub, err := fs.Sub(assetsFS, "static/assets")
	if err != nil {
		panic("assets: " + err.Error())
	}
	assetsHandler = http.StripPrefix("/assets", http.FileServer(http.FS(sub)))
}

// serveAssets serves embedded static files with explicit content types.
func serveAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/assets/" {
		http.NotFound(w, r)
		return
	}
	assetsHandler.ServeHTTP(w, r)
}

var statusTemplate = template.Must(template.New("status").Parse(statusHTML))
var indexTemplate = template.Must(template.New("index").Parse(string(indexHTML)))

type indexData struct {
	Analytics bool
}

// Handler serves the lancert.dev HTTP API.
type Handler struct {
	service  *certservice.Service
	mux      *http.ServeMux
	snapshot func() metrics.Snapshot
}

// New creates an API handler wired to the certificate service and status
// snapshot provider.
func New(svc *certservice.Service, snapshot func() metrics.Snapshot) *Handler {
	provider := func() metrics.Snapshot { return metrics.UnavailableSnapshot(nil) }
	if snapshot != nil {
		provider = snapshot
	}
	h := &Handler{
		service:  svc,
		snapshot: provider,
	}
	h.mux = http.NewServeMux()
	h.registerRoutes()
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// registerRoutes sets up the API routes.
func (h *Handler) registerRoutes() {
	h.mux.Handle("POST /certs/{ip}",
		GzipResponse(http.HandlerFunc(h.handleIssueCert)))
	h.mux.Handle("GET /certs/{ip}",
		GzipResponse(http.HandlerFunc(h.handleGetCert)))
	h.mux.HandleFunc("GET /certs/{ip}/ttl", h.handleGetTTL)
	// PEM downloads skip GzipResponse: files are small (~2-3KB) and
	// compressing secret material adds unnecessary risk.
	h.mux.HandleFunc("GET /certs/{ip}/fullchain.pem", h.handleGetFullChain)
	h.mux.HandleFunc("GET /certs/{ip}/privkey.pem", h.handleGetPrivKey)
	h.mux.HandleFunc("GET /status", h.handleStatus)
	h.mux.HandleFunc("GET /health", h.handleHealth)
	h.mux.HandleFunc("GET /docs", handleDocs)
	h.mux.HandleFunc("GET /openapi.yaml", handleOpenAPI)
	h.mux.HandleFunc("GET /{$}", handleIndex)
	h.mux.HandleFunc("GET /assets/", serveAssets)
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
		writeCertificateJSON(w, r, addr, bundle)
		return
	}

	// Trigger background issuance (idempotent).
	status := h.service.TriggerIssuance(addr)

	if status.Fail != nil {
		writeErrorRetry(w, status.Fail.Status, status.Fail.Msg, status.Fail.RetryAfter)
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
		writeCertificateJSON(w, r, addr, status.Bundle)
		return
	}

	if status.Pending {
		writePending(w, pendingRetryAfter)
		return
	}

	if status.Fail != nil {
		writeErrorRetry(w, status.Fail.Status, status.Fail.Msg, status.Fail.RetryAfter)
		return
	}

	writeError(w, http.StatusNotFound, "no certificate found for this IP")
}

// handleGetTTL returns the remaining TTL in seconds as plain text.
func (h *Handler) handleGetTTL(w http.ResponseWriter, r *http.Request) {
	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ttl, err := h.service.TTL(addr)
	if err != nil {
		slog.Error("api: get certificate TTL error", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read certificate")
		return
	}
	if ttl == 0 {
		writeError(w, http.StatusNotFound, "no certificate found for this IP")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, int(ttl.Seconds()))
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
		if certificateNotModified(w, r, status.Bundle) {
			return
		}
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
		writeErrorRetry(w, status.Fail.Status, status.Fail.Msg, status.Fail.RetryAfter)
		return
	}

	writeError(w, http.StatusNotFound, "no certificate found for this IP")
}

// certificateETag returns a strong digest of the leaf certificate.
func certificateETag(bundle *certstore.CertBundle) string {
	block, _ := pem.Decode(bundle.FullChainPEM)
	if block == nil {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return `"sha256-` + hex.EncodeToString(sum[:]) + `"`
}

// certificateNotModified handles If-None-Match for a certificate response.
func certificateNotModified(w http.ResponseWriter, r *http.Request, bundle *certstore.CertBundle) bool {
	etag := certificateETag(bundle)
	if etag == "" {
		return false
	}
	w.Header().Set("ETag", etag)
	for _, candidate := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	return false
}

// writeCertificateJSON writes a cache-aware certificate response.
func writeCertificateJSON(w http.ResponseWriter, r *http.Request, addr netip.Addr, bundle *certstore.CertBundle) {
	if certificateNotModified(w, r, bundle) {
		return
	}
	writeJSON(w, http.StatusOK, certResponse(addr, bundle))
}

type statusPageData struct {
	metrics.Snapshot
	SuccessPercent           string
	RecentLookups            string
	RecentPeriod             string
	ResponseP95              string
	LastUpdated              string
	CertificatesCached       string
	TotalCertificatesIssued  string
	CertificatesRenewed      string
	ARIAdoption              string
	ARIRenewalSummary        string
	ARIAdoptionDetail        string
	HasARIActivity           bool
	ARIRenewalCount          uint64
	RenewalCount             uint64
	ServingCertificatesSince string
	LookupChart              []lookupChartBar
	ChartStart               string
	ChartEnd                 string
	ChartMax                 uint64
	HasLookupData            bool
}

type lookupChartBar struct {
	X       int
	Y       int
	Height  int
	Label   string
	Queries uint64
}

// handleStatus renders the public aggregate service status page.
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	s := h.snapshot()
	data := statusPageData{
		Snapshot:                s,
		SuccessPercent:          "Not available",
		RecentLookups:           strconv.FormatUint(s.RecentQueries, 10),
		RecentPeriod:            "Last 5 minutes",
		ResponseP95:             "Not available",
		LastUpdated:             "Not available",
		CertificatesCached:      "Unavailable",
		TotalCertificatesIssued: "Unavailable",
		CertificatesRenewed:     "Unavailable",
		ARIAdoption:             "Unavailable",
		ARIAdoptionDetail:       "Certificate metrics unavailable",
	}
	data.LookupChart, data.ChartStart, data.ChartEnd, data.ChartMax, data.HasLookupData = buildLookupChart(s.DailyLookups)
	if !s.FreshAt.IsZero() {
		data.LastUpdated = s.FreshAt.Format("2 Jan 2006, 15:04 UTC")
	}
	if s.WriteAttempts24H > 0 {
		data.SuccessPercent = fmt.Sprintf("%.1f%%", float64(s.WriteSuccesses24H)*100/float64(s.WriteAttempts24H))
	}
	if s.Readiness.Available {
		data.CertificatesCached = strconv.FormatUint(s.Readiness.Ready, 10)
	}
	if !s.Unavailable {
		lifecycle := s.CertificateLifecycle
		data.TotalCertificatesIssued = strconv.FormatUint(lifecycle.TotalIssued, 10)
		data.CertificatesRenewed = strconv.FormatUint(lifecycle.Renewals, 10)
		data.ARIRenewalCount = lifecycle.ARIRenewals
		data.RenewalCount = lifecycle.Renewals
		if !lifecycle.RecordedSince.IsZero() {
			data.ServingCertificatesSince = lifecycle.RecordedSince.Format("2 Jan 2006")
		}
		if lifecycle.HasARIAdoption {
			data.ARIAdoption = fmt.Sprintf("%.1f%%", lifecycle.ARIAdoption)
			data.ARIRenewalSummary = fmt.Sprintf("%d of %d renewals", lifecycle.ARIRenewals, lifecycle.Renewals)
			data.ARIAdoptionDetail = "Renewals initiated using ACME Renewal Information."
			data.HasARIActivity = true
		} else {
			data.ARIAdoption = "—"
			data.ARIRenewalSummary = "Not available"
			data.ARIAdoptionDetail = "No certificate renewals have been recorded yet."
		}
	}
	if s.RecentWindow < 5*time.Minute {
		data.RecentPeriod = "Since startup"
	}
	if s.ResponseP95 > 0 {
		data.ResponseP95 = s.ResponseP95.String()
		if s.ResponseP95Overflow {
			data.ResponseP95 = ">" + data.ResponseP95
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=30")
	if err := statusTemplate.Execute(w, data); err != nil {
		slog.Error("status page: render failed", "error", err)
	}
}

// buildLookupChart converts daily lookup totals into status-page chart bars.
func buildLookupChart(days []metrics.DailyLookup) ([]lookupChartBar, string, string, uint64, bool) {
	if len(days) == 0 {
		return nil, "", "", 0, false
	}
	var maxQueries uint64
	for _, day := range days {
		maxQueries = max(maxQueries, day.Queries)
	}
	bars := make([]lookupChartBar, 0, len(days))
	for i, day := range days {
		height := 0
		if day.Queries > 0 {
			height = max(2, int(day.Queries*150/maxQueries))
		}
		bars = append(bars, lookupChartBar{
			X:       10 + i*29,
			Y:       160 - height,
			Height:  height,
			Label:   chartDateLabel(day.Date),
			Queries: day.Queries,
		})
	}
	return bars, chartDateLabel(days[0].Date), chartDateLabel(days[len(days)-1].Date), maxQueries, maxQueries > 0
}

// chartDateLabel formats an ISO date for the compact chart axis.
func chartDateLabel(date string) string {
	t, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return date
	}
	return t.Format("2 Jan")
}

// handleHealth is a simple liveness probe.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleIndex serves the static homepage.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Host")
	data := indexData{Analytics: analyticsHost(r.Host)}
	if err := indexTemplate.Execute(w, data); err != nil {
		slog.Error("index page: render failed", "error", err)
	}
}

// analyticsHost reports whether hostport is the public analytics hostname.
func analyticsHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "lancert.dev"
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
	writeErrorRetry(w, status, message, 0)
}

// writeErrorRetry writes an error response with an optional Retry-After header.
func writeErrorRetry(w http.ResponseWriter, status int, message string, retryAfter time.Duration) {
	if status >= 500 {
		seconds := int(retryAfter.Seconds())
		if seconds <= 0 {
			seconds = 3600
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	writeJSON(w, status, map[string]string{"error": message})
}
