package api

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/registration"
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

type statusPageData struct {
	Analytics              bool
	Status                 string
	Version                string
	Commit                 string
	UsageAvailable         bool
	MetricsAvailable       bool
	MetricsUpdatedAt       time.Time
	Usage                  registration.Usage
	RegistrationChart      []usageChartPoint
	DNSChart               []usageChartPoint
	AddressBlocks          []networkUsageView
	TopPrefixes            []networkUsageView
	TopIPs                 []privateIPUsageView
	DNSPrefixes            []networkUsageView
	DNSIPs                 []privateIPUsageView
	ClientFamilies         []metrics.ClientFamilyActivity
	RegisteredQueries30D   uint64
	RegisteredQueriesTotal uint64
}

type usageChartPoint struct {
	Date       string
	Label      string
	Hostnames  uint64
	PrivateIPs uint64
	Queries    uint64
	Height     uint64
}

type networkUsageView struct {
	registration.NetworkUsage
	DNSQueries30D uint64
	Width         uint64
}

type privateIPUsageView struct {
	registration.PrivateIPUsage
	DNSQueries30D uint64
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
	data := statusPageData{
		Analytics:              analyticsHost(r.Host),
		Status:                 "operational",
		Version:                h.build.Version,
		Commit:                 h.build.CommitHash,
		MetricsAvailable:       !snapshot.Unavailable,
		MetricsUpdatedAt:       snapshot.FreshAt,
		RegisteredQueries30D:   snapshot.RegisteredQueries30D,
		RegisteredQueriesTotal: snapshot.RegisteredQueriesTotal,
		ClientFamilies:         snapshot.ClientFamilies,
	}
	if !h.operational() || snapshot.Unavailable || snapshot.Degraded {
		data.Status = "degraded"
	}
	if h.store != nil {
		usage, err := h.store.UsageStats(r.Context())
		if err != nil {
			data.Status = "degraded"
			slog.Error("load registration usage", "error", err)
		} else {
			data.UsageAvailable = true
			data.Usage = usage
			data.RegistrationChart, data.DNSChart = usageCharts(usage.Daily, snapshot.DailyLookups, snapshot.FreshAt)
			data.AddressBlocks = networkUsageViews(usage.Blocks, usage.Hostnames, nil)
			data.TopPrefixes, data.TopIPs, data.DNSPrefixes, data.DNSIPs = usageTables(usage, snapshot.RegistrationLookups30D, 10)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Add("Vary", "Host")
	if err := statusTemplate.Execute(w, data); err != nil {
		slog.Error("render status page", "error", err)
	}
}

func usageCharts(registrations []registration.DailyUsage, lookups []metrics.DailyLookup, now time.Time) ([]usageChartPoint, []usageChartPoint) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	registrationDays := make(map[string]registration.DailyUsage, len(registrations))
	for _, day := range registrations {
		registrationDays[day.Date] = day
	}
	lookupDays := make(map[string]uint64, len(lookups))
	for _, day := range lookups {
		lookupDays[day.Date] = day.Queries
	}
	registrationChart := make([]usageChartPoint, 0, 30)
	dnsChart := make([]usageChartPoint, 0, 30)
	var maxRegistrations, maxQueries uint64
	for offset := -29; offset <= 0; offset++ {
		day := now.UTC().AddDate(0, 0, offset)
		date := day.Format("2006-01-02")
		usage := registrationDays[date]
		queries := lookupDays[date]
		registrationChart = append(registrationChart, usageChartPoint{Date: date, Label: day.Format("Jan 2"), Hostnames: usage.Hostnames, PrivateIPs: usage.PrivateIPs})
		dnsChart = append(dnsChart, usageChartPoint{Date: date, Label: day.Format("Jan 2"), Queries: queries})
		if usage.Hostnames > maxRegistrations {
			maxRegistrations = usage.Hostnames
		}
		if queries > maxQueries {
			maxQueries = queries
		}
	}
	for i := range registrationChart {
		registrationChart[i].Height = chartHeight(registrationChart[i].Hostnames, maxRegistrations)
		dnsChart[i].Height = chartHeight(dnsChart[i].Queries, maxQueries)
	}
	return registrationChart, dnsChart
}

func chartHeight(value, maxValue uint64) uint64 {
	if value == 0 || maxValue == 0 {
		return 0
	}
	height := (value*100 + maxValue - 1) / maxValue
	if height < 4 {
		return 4
	}
	return height
}

func networkUsageViews(networks []registration.NetworkUsage, total uint64, queries map[string]uint64) []networkUsageView {
	views := make([]networkUsageView, 0, len(networks))
	for _, network := range networks {
		views = append(views, networkUsageView{NetworkUsage: network, DNSQueries30D: queries[network.Network], Width: chartHeight(network.Hostnames, total)})
	}
	return views
}

func usageTables(usage registration.Usage, lookups []metrics.RegistrationLookup, limit int) ([]networkUsageView, []privateIPUsageView, []networkUsageView, []privateIPUsageView) {
	ipQueries := make(map[string]uint64)
	prefixQueries := make(map[string]uint64)
	for _, lookup := range lookups {
		targetIP, found := usage.RegistrationTargets[lookup.RegistrationID]
		if !found {
			continue
		}
		addr, err := netip.ParseAddr(targetIP)
		if err != nil {
			continue
		}
		ipQueries[targetIP] += lookup.Queries
		prefixQueries[netip.PrefixFrom(addr, 24).Masked().String()] += lookup.Queries
	}
	allPrefixes := networkUsageViews(usage.Prefixes, usage.Hostnames, prefixQueries)
	topPrefixes := allPrefixes
	if len(topPrefixes) > limit {
		topPrefixes = topPrefixes[:limit]
	}
	allIPs := make([]privateIPUsageView, 0, len(usage.IPs))
	for _, item := range usage.IPs {
		allIPs = append(allIPs, privateIPUsageView{PrivateIPUsage: item, DNSQueries30D: ipQueries[item.IP]})
	}
	topIPs := allIPs
	if len(topIPs) > limit {
		topIPs = topIPs[:limit]
	}

	dnsPrefixes := append([]networkUsageView(nil), allPrefixes...)
	sort.SliceStable(dnsPrefixes, func(i, j int) bool {
		return dnsPrefixes[i].DNSQueries30D > dnsPrefixes[j].DNSQueries30D
	})
	dnsPrefixes = activeNetworkUsage(dnsPrefixes, limit)
	dnsIPs := append([]privateIPUsageView(nil), allIPs...)
	sort.SliceStable(dnsIPs, func(i, j int) bool {
		return dnsIPs[i].DNSQueries30D > dnsIPs[j].DNSQueries30D
	})
	dnsIPs = activePrivateIPUsage(dnsIPs, limit)

	return topPrefixes, topIPs, dnsPrefixes, dnsIPs
}

func activeNetworkUsage(items []networkUsageView, limit int) []networkUsageView {
	for i, item := range items {
		if item.DNSQueries30D == 0 {
			items = items[:i]
			break
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func activePrivateIPUsage(items []privateIPUsageView, limit int) []privateIPUsageView {
	for i, item := range items {
		if item.DNSQueries30D == 0 {
			items = items[:i]
			break
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}
