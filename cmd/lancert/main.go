package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"go.lucor.dev/lancert/internal/api"
	"go.lucor.dev/lancert/internal/certmonitor"
	"go.lucor.dev/lancert/internal/dnsconfig"
	"go.lucor.dev/lancert/internal/dnssrv"
	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/registration"
)

var commitHash = "dev"
var buildVersion = "dev"

const (
	defaultZone         = "lancert.dev."
	defaultDataDir      = "data"
	defaultDNSAddr      = ":53"
	defaultHTTPAddr     = ":8443"
	coreDatabaseName    = "core.db"
	metricsDatabaseName = "metrics.db"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	_ = godotenv.Load()
	var dnsAddr, httpAddr, dataDir, serverIP string
	flag.StringVar(&dnsAddr, "dns-addr", envOr("LANCERT_DNS_ADDR", defaultDNSAddr), "DNS listen address")
	flag.StringVar(&httpAddr, "http-addr", envOr("LANCERT_HTTP_ADDR", defaultHTTPAddr), "HTTP listen address")
	flag.StringVar(&dataDir, "data-dir", envOr("LANCERT_DATA_DIR", defaultDataDir), "state and metrics directory")
	flag.StringVar(&serverIP, "server-ip", envOr("LANCERT_SERVER_IP", ""), "public IPv4 used for apex and nameserver glue")
	flag.Parse()

	if serverIP == "" {
		return errors.New("LANCERT_SERVER_IP or -server-ip is required")
	}
	publicIP, err := netip.ParseAddr(serverIP)
	if err != nil || !publicIP.Is4() {
		return fmt.Errorf("invalid public server IPv4 %q", serverIP)
	}
	publicIP = publicIP.Unmap()

	zone := envOr("LANCERT_ZONE", defaultZone)
	if zone == "" {
		return errors.New("LANCERT_ZONE must not be empty")
	}
	if zone[len(zone)-1] != '.' {
		zone += "."
	}
	staticTXT, err := dnsconfig.ParseStaticTXT(os.Getenv("LANCERT_STATIC_TXT"), zone)
	if err != nil {
		return err
	}

	// Authoritative state is fail-closed and must be loaded before listeners.
	state, err := registration.Open(filepath.Join(dataDir, coreDatabaseName))
	if err != nil {
		return err
	}
	defer func() {
		if err := state.Close(); err != nil {
			slog.Error("state shutdown error", "error", err)
		}
	}()

	// Metrics are observational and deliberately fail open.
	var metricStore *metrics.Store
	var recorder metrics.Recorder = metrics.Disabled{}
	metricStore, metricOpenErr := metrics.Open(filepath.Join(dataDir, metricsDatabaseName))
	if metricOpenErr != nil {
		slog.Error("metrics unavailable", "error", metricOpenErr)
	} else {
		recorder = metricStore
		defer func() {
			if err := metricStore.Close(context.Background()); err != nil {
				slog.Error("metrics shutdown error", "error", err)
			}
		}()
	}

	dnsServer := dnssrv.New(dnssrv.Config{
		Zone:      zone,
		NSRecords: []string{"ns1." + zone, "ns2." + zone},
		ServerIP:  publicIP,
		SOAMname:  "ns1." + zone,
		SOARname:  "admin." + zone,
		StaticTXT: staticTXT,
		Recorder:  recorder,
	}, state)

	var proxySubnet netip.Prefix
	if value := os.Getenv("LANCERT_TRUSTED_PROXY"); value != "" {
		proxySubnet, err = netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("invalid LANCERT_TRUSTED_PROXY %q: %w", value, err)
		}
	}
	ipHashSecret := os.Getenv("LANCERT_IP_HASH_SALT")
	if ipHashSecret == "" {
		return errors.New("LANCERT_IP_HASH_SALT is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// CT observations share the metrics database; keep monitoring best-effort
	// when that optional database is unavailable so DNS can still start.
	if metricStore != nil {
		registrationUsage, usageErr := state.UsageStats(ctx)
		if usageErr != nil {
			slog.Error("certificate monitor bootstrap date unavailable", "error", usageErr)
		} else if err := metricStore.InitializeSSLMate(ctx, registrationUsage.Since); err != nil {
			slog.Error("certificate monitor state unavailable", "error", err)
		} else if os.Getenv("SSLMATE_API_KEY") == "" {
			if err := metricStore.SetSSLMateMonitorStatus(ctx, time.Now(), errors.New("SSLMATE_API_KEY is not configured")); err != nil {
				slog.Error("certificate monitor status unavailable", "error", err)
			}
		} else {
			monitor, monitorErr := certmonitor.New(metricStore, zone, os.Getenv("SSLMATE_API_KEY"), registrationUsage.Since, state.CertificateRegistrations)
			if monitorErr != nil {
				slog.Error("certificate transparency monitor unavailable", "error", monitorErr)
			} else {
				go monitor.Run(ctx)
				slog.Info("SSLMate certificate monitor started")
			}
		}
	}
	realIP := api.NewRealIP(proxySubnet)
	ipHasher := api.NewIPHasher(ipHashSecret)
	limits := api.NewLimits(ctx)
	statusSnapshot := func() metrics.Snapshot {
		if metricStore == nil {
			return metrics.UnavailableSnapshot(metricOpenErr)
		}
		return metricStore.Snapshot()
	}
	apiHandler := api.NewWithBuildInfo(state, zone, statusSnapshot, recorder, api.BuildInfo{
		Version: buildVersion, CommitHash: shortCommitHash(commitHash),
	})
	apiHandler.PrepareStartup()
	handler := api.Chain(apiHandler,
		api.Recover,
		api.SecurityHeaders,
		realIP.Middleware,
		ipHasher.Middleware,
		limits.Middleware,
		api.RequestLogging,
	)
	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	serverErr := make(chan error, 2)
	dnsReady := make(chan struct{})
	go func() {
		slog.Info("dns server listening", "addr", dnsAddr, "zone", zone)
		if err := dnsServer.ListenAndServe(dnsAddr, func() { close(dnsReady) }); err != nil {
			serverErr <- fmt.Errorf("dns server: %w", err)
		}
	}()
	go func() {
		slog.Info("http server listening", "addr", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-dnsReady:
	}
	apiHandler.MarkReady()
	slog.Info("service started", "version", buildVersion+" ("+shortCommitHash(commitHash)+")")

	var crashErr error
	select {
	case <-ctx.Done():
	case err := <-serverErr:
		crashErr = err
		slog.Error("server crashed", "error", err)
	}
	slog.Info("shutting down")
	apiHandler.BeginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown error", "error", err)
	}
	if err := dnsServer.Shutdown(); err != nil {
		slog.Error("dns shutdown error", "error", err)
	}
	return crashErr
}

func shortCommitHash(hash string) string {
	return hash[:min(6, len(hash))]
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
