package api

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

var indexTemplate = template.Must(template.New("index").Parse(string(indexHTML)))
var docsTemplate = template.Must(template.New("docs").Parse(string(docsHTML)))
var docsCLITemplate = template.Must(template.New("docs-cli").Parse(string(docsCLIHTML)))
var docsAPITemplate = template.Must(template.New("docs-api").Parse(string(docsAPIHTML)))
var docsWebServersTemplate = template.Must(template.New("docs-web-servers").Parse(string(docsWebServersHTML)))
var statusTemplate = template.Must(template.New("status").Parse(statusHTML))
var embeddedAssets = mustEmbeddedAssets()

type pageData struct {
	Analytics bool
}

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

func serveHTML(page *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Add("Vary", "Host")
		if err := page.Execute(w, pageData{Analytics: analyticsHost(r.Host)}); err != nil {
			slog.Error("render page", "error", err)
		}
	}
}

func analyticsHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(strings.ToLower(host), ".") == "lancert.dev"
}

func handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapiYAML)
}

func (h *Handler) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	snapshot := h.snapshot()
	data := statusResponse{
		Analytics: analyticsHost(r.Host),
		Status:    "operational",
		Version:   h.build.Version,
		Commit:    h.build.CommitHash,
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
	w.Header().Add("Vary", "Host")
	if err := statusTemplate.Execute(w, data); err != nil {
		slog.Error("render status page", "error", err)
	}
}
