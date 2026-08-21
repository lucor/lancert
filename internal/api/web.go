package api

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/docs.html
var docsHTML []byte

//go:embed static/docs-cli.html
var docsCLIHTML []byte

//go:embed static/docs-api.html
var docsAPIHTML []byte

//go:embed static/docs-web-servers.html
var docsWebServersHTML []byte

//go:embed static/status.html
var statusHTML string

//go:embed openapi.yaml
var openapiYAML []byte

//go:embed static/assets
var assetsFS embed.FS

var statusTemplate = template.Must(template.New("status").Parse(statusHTML))
var embeddedAssets = mustEmbeddedAssets()

func mustEmbeddedAssets() http.Handler {
	sub, err := fs.Sub(assetsFS, "static/assets")
	if err != nil {
		panic("embedded assets: " + err.Error())
	}
	return http.StripPrefix("/assets/", http.FileServer(http.FS(sub)))
}

func serveAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/assets/" {
		http.NotFound(w, r)
		return
	}
	embeddedAssets.ServeHTTP(w, r)
}

func serveHTML(content []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	}
}

func handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapiYAML)
}

func (h *Handler) handleStatusPage(w http.ResponseWriter, _ *http.Request) {
	snapshot := h.snapshot()
	data := statusResponse{
		Status:  "operational",
		Version: h.build.Version,
		Commit:  h.build.CommitHash,
		Metrics: statusMetrics{
			Available:                  !snapshot.Unavailable,
			Queries24H:                 snapshot.Queries24H,
			ACMEActiveRegistrations30D: snapshot.ACMEActiveRegistrations30D,
			ResponseP95MS:              float64(snapshot.ResponseP95) / 1e6,
			UpdatedAt:                  snapshot.FreshAt,
		},
	}
	if !h.operational() || snapshot.Unavailable || snapshot.Degraded {
		data.Status = "degraded"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := statusTemplate.Execute(w, data); err != nil {
		slog.Error("render status page", "error", err)
	}
}
