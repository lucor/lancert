package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/privateip"
	"go.lucor.dev/lancert/internal/registration"
)

const maxRequestBody = 1024

// CompatibilityVersion changes only when the public registration or update
// contract becomes incompatible. It is independent from the server release.
const CompatibilityVersion = "2"

const compatibilityHeader = "X-Lancert-API-Version"

// BuildInfo identifies the running binary.
type BuildInfo struct {
	Version    string
	CommitHash string
}

// Handler serves the Lancert registration and acme-dns update API.
type Handler struct {
	store        *registration.Store
	zone         string
	snapshot     func() metrics.Snapshot
	recorder     metrics.Recorder
	build        BuildInfo
	stateHealthy atomic.Bool
	ready        atomic.Bool
	shuttingDown atomic.Bool
	mux          *http.ServeMux
}

// New creates an API handler.
func New(store *registration.Store, zone string, snapshot func() metrics.Snapshot, recorder metrics.Recorder) *Handler {
	return NewWithBuildInfo(store, zone, snapshot, recorder, BuildInfo{Version: "dev", CommitHash: "dev"})
}

// NewWithBuildInfo creates an API handler with build metadata.
func NewWithBuildInfo(store *registration.Store, zone string, snapshot func() metrics.Snapshot, recorder metrics.Recorder, build BuildInfo) *Handler {
	provider := func() metrics.Snapshot { return metrics.UnavailableSnapshot(nil) }
	if snapshot != nil {
		provider = snapshot
	}
	if recorder == nil {
		recorder = metrics.Disabled{}
	}
	h := &Handler{
		store:    store,
		zone:     strings.TrimSuffix(strings.ToLower(zone), "."),
		snapshot: provider,
		recorder: recorder,
		build:    build,
		mux:      http.NewServeMux(),
	}
	h.stateHealthy.Store(store != nil)
	h.ready.Store(store != nil)
	h.mux.HandleFunc("POST /register/{ip}", h.handleRegister)
	h.mux.HandleFunc("POST /update", h.handleUpdate)
	h.mux.HandleFunc("GET /health", h.handleHealth)
	h.mux.HandleFunc("GET /status", h.handleStatusRoute)
	h.mux.HandleFunc("GET /docs", serveHTML(docsTemplate))
	h.mux.HandleFunc("GET /docs/cli", serveHTML(docsCLITemplate))
	h.mux.HandleFunc("GET /docs/acme-clients", serveHTML(docsWebServersTemplate))
	h.mux.HandleFunc("GET /docs/api", serveHTML(docsAPITemplate))
	h.mux.HandleFunc("GET /openapi.yaml", handleOpenAPI)
	h.mux.Handle("GET /assets/", http.HandlerFunc(serveAssets))
	h.mux.HandleFunc("GET /{$}", serveHTML(indexTemplate))
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(compatibilityHeader, CompatibilityVersion)
	h.mux.ServeHTTP(w, r)
}

// PrepareStartup keeps readiness false until every public listener is ready.
func (h *Handler) PrepareStartup() {
	h.ready.Store(false)
}

// MarkReady enables readiness after every public listener is available.
func (h *Handler) MarkReady() {
	if !h.shuttingDown.Load() && h.stateHealthy.Load() {
		h.ready.Store(true)
	}
}

// BeginShutdown makes readiness fail permanently before listener shutdown starts.
func (h *Handler) BeginShutdown() {
	h.shuttingDown.Store(true)
	h.ready.Store(false)
}

type registrationResponse struct {
	Hostname   string `json:"hostname"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !emptyBody(w, r) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	addr, err := privateip.ValidateRFC1918(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ip")
		return
	}
	credentials, err := h.store.Register(r.Context(), addr)
	if err != nil {
		if errors.Is(err, registration.ErrInvalidAddress) {
			writeError(w, http.StatusBadRequest, "bad_ip")
			return
		}
		if r.Context().Err() == nil {
			h.stateHealthy.Store(false)
		}
		slog.Error("registration failed", "error", err)
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	h.stateHealthy.Store(true)
	writeJSON(w, http.StatusCreated, registrationResponse{
		Hostname:   credentials.Hostname + "." + h.zone,
		Username:   credentials.Username,
		Password:   credentials.Password,
		Subdomain:  credentials.Hostname,
		FullDomain: "_acme-challenge." + credentials.Hostname + "." + h.zone,
	})
}

type updateRequest struct {
	Subdomain string `json:"subdomain"`
	TXT       string `json:"txt"`
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Api-User")
	key := r.Header.Get("X-Api-Key")
	if len(username) == 0 || len(username) > 128 || len(key) == 0 || len(key) > 128 {
		writeError(w, http.StatusUnauthorized, "forbidden")
		return
	}
	var request updateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	registrationID, err := h.store.UpdateChallenge(r.Context(), username, key, request.Subdomain, request.TXT)
	switch {
	case err == nil:
		h.stateHealthy.Store(true)
		h.recorder.RecordChallengeUpdate(registrationID, metrics.ClientFamilyFromUserAgent(r.UserAgent()))
		writeJSON(w, http.StatusOK, map[string]string{"txt": request.TXT})
	case errors.Is(err, registration.ErrForbidden):
		writeError(w, http.StatusUnauthorized, "forbidden")
	case errors.Is(err, registration.ErrInvalidChallenge):
		writeError(w, http.StatusBadRequest, "bad_txt")
	default:
		if r.Context().Err() == nil {
			h.stateHealthy.Store(false)
		}
		slog.Error("challenge update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "db_error")
	}
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if !h.operational() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type statusResponse struct {
	Analytics  bool          `json:"-"`
	Status     string        `json:"status"`
	Version    string        `json:"version"`
	Commit     string        `json:"commit"`
	APIVersion string        `json:"api_version"`
	Metrics    statusMetrics `json:"metrics"`
}

type statusMetrics struct {
	Available                  bool      `json:"available"`
	Queries24H                 uint64    `json:"queries_24h"`
	ACMEActiveRegistrations30D uint64    `json:"acme_active_registrations_30d"`
	ResponseP95MS              float64   `json:"response_p95_ms"`
	UpdatedAt                  time.Time `json:"updated_at,omitempty"`
}

func (h *Handler) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snapshot := h.snapshot()
	status := "operational"
	if !h.operational() || snapshot.Unavailable || snapshot.Degraded {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, statusResponse{
		Status:     status,
		Version:    h.build.Version,
		Commit:     h.build.CommitHash,
		APIVersion: CompatibilityVersion,
		Metrics: statusMetrics{
			Available:                  !snapshot.Unavailable,
			Queries24H:                 snapshot.Queries24H,
			ACMEActiveRegistrations30D: snapshot.ACMEActiveRegistrations30D,
			ResponseP95MS:              float64(snapshot.ResponseP95) / float64(time.Millisecond),
			UpdatedAt:                  snapshot.FreshAt,
		},
	})
}

func (h *Handler) handleStatusRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Accept")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.handleStatusPage(w, r)
		return
	}
	h.handleStatus(w, r)
}

func (h *Handler) operational() bool {
	return h.ready.Load() && h.stateHealthy.Load() && !h.shuttingDown.Load()
}

func emptyBody(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	body, err := io.ReadAll(r.Body)
	return err == nil && len(body) == 0
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
