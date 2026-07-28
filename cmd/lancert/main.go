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

	"lucor.dev/lancert/internal/accountkey"
	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/api"
	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/metrics"
)

// commitHash is set at build time via -ldflags "-X main.commitHash=<commit-sha>".
var commitHash = "dev"

// buildVersion is set at build time via -ldflags "-X main.buildVersion=<version>".
var buildVersion = "dev"

const (
	defaultZone     = "lancert.dev."
	defaultDataDir  = "data"
	defaultDNSAddr  = ":53"
	defaultHTTPAddr = ":8443"
)

// main runs lancert and reports fatal startup errors.
func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run is the main entry point, separated for testability.
func run() error {
	// Load .env file if present (does not override existing env vars)
	_ = godotenv.Load()

	var (
		dnsAddr  string
		httpAddr string
		dataDir  string
		email    string
		serverIP string
		acmeEnv  string
		pregen   bool
	)

	flag.StringVar(&dnsAddr, "dns-addr", envOr("LANCERT_DNS_ADDR", defaultDNSAddr), "DNS listen address")
	flag.StringVar(&httpAddr, "http-addr", envOr("LANCERT_HTTP_ADDR", defaultHTTPAddr), "HTTP listen address")
	flag.StringVar(&dataDir, "data-dir", envOr("LANCERT_DATA_DIR", defaultDataDir), "data directory for certs and keys")
	flag.StringVar(&email, "email", envOr("LANCERT_EMAIL", ""), "email for Let's Encrypt account (optional)")
	flag.StringVar(&serverIP, "server-ip", envOr("LANCERT_SERVER_IP", ""), "public IP of this server (required, used for DNS A records)")
	flag.StringVar(&acmeEnv, "acme-env", envOr("LANCERT_ACME_ENV", ""), "ACME environment: production, staging, or local")
	flag.BoolVar(&pregen, "pregen", envBool("LANCERT_PREGEN"), "pre-generate certificates for common IPs at startup")
	flag.Parse()
	if acmeEnv == "" {
		acmeEnv = string(acmeissue.EnvironmentProduction)
	}
	environment := acmeissue.Environment(acmeEnv)
	if environment != acmeissue.EnvironmentProduction && environment != acmeissue.EnvironmentStaging && environment != acmeissue.EnvironmentLocal {
		return fmt.Errorf("invalid LANCERT_ACME_ENV %q (want production, staging, or local)", acmeEnv)
	}

	if serverIP == "" {
		return fmt.Errorf("LANCERT_SERVER_IP or -server-ip is required")
	}

	srvAddr, err := netip.ParseAddr(serverIP)
	if err != nil {
		return fmt.Errorf("invalid -server-ip: %w", err)
	}

	// Load or create ACME account key
	acctKeyPath := filepath.Join(dataDir, "account-key.pem")
	accountKey, err := accountkey.LoadOrCreate(acctKeyPath)
	if err != nil {
		return err
	}
	slog.Info("account key loaded", "path", acctKeyPath)

	// Certificate store
	certsDir := filepath.Join(dataDir, "certs")
	store := certstore.New(certsDir)
	if err := store.MigrateLegacy(); err != nil {
		return fmt.Errorf("migrate certificate store: %w", err)
	}
	slog.Info("cert store ready", "path", certsDir, "count", store.Count())

	// KPI collection is deliberately fail-open: metrics must never prevent DNS
	// or certificate serving from starting.
	var metricStore *metrics.Store
	var metricRecorder metrics.Recorder = metrics.Disabled{}
	var metricOpenErr error
	metricStore, metricOpenErr = metrics.Open(filepath.Join(dataDir, "metrics.db"))
	if metricOpenErr != nil {
		slog.Error("metrics unavailable", "error", metricOpenErr)
	} else {
		metricRecorder = metricStore
		entries, inventoryErr := store.Inventory()
		if inventoryErr != nil {
			slog.Error("certificate lifecycle baseline unavailable", "error", inventoryErr)
		} else {
			issued, since := certificateLifecycleBaseline(entries)
			if err := metricStore.InitializeCertificateLifecycle(context.Background(), issued, since); err != nil {
				slog.Error("certificate lifecycle baseline unavailable", "error", err)
			}
		}
	}
	defer func() {
		if metricStore != nil {
			if err := metricStore.Close(context.Background()); err != nil {
				slog.Error("metrics shutdown error", "error", err)
			}
		}
	}()

	// Zone (FQDN with trailing dot for DNS, bare for cert service)
	zone := envOr("LANCERT_ZONE", defaultZone)
	if zone == "" {
		return fmt.Errorf("LANCERT_ZONE must not be empty")
	}
	if zone[len(zone)-1] != '.' {
		zone += "."
	}
	bareZone := zone[:len(zone)-1] // e.g. "lancert.dev"
	resolver, caCertPath, err := acmeRuntimeConfig(environment, dnsAddr)
	if err != nil {
		return err
	}
	staticTXT, err := parseStaticTXT(os.Getenv("LANCERT_STATIC_TXT"), zone)
	if err != nil {
		return err
	}

	// DNS TXT challenge store
	txtStore := dnssrv.NewTXTStore()

	// DNS server
	dnsCfg := dnssrv.Config{
		Zone:       zone,
		NSRecords:  []string{"ns1." + zone, "ns2." + zone},
		ServerIP:   srvAddr,
		SOAMname:   "ns1." + zone,
		SOARname:   "admin." + zone,
		CAAIssuers: []string{"letsencrypt.org"},
		StaticTXT:  staticTXT,
		Recorder:   metricRecorder,
	}

	dnsServer := dnssrv.New(dnsCfg, txtStore)

	// Certificate service
	certSvc := certservice.New(
		certservice.Config{
			Zone:        bareZone,
			Email:       email,
			AccountKey:  accountKey,
			Environment: environment,
			CACertPath:  caCertPath,
			Resolver:    resolver,
		},
		store,
		txtStore,
		metricRecorder,
	)

	// Trusted proxy subnet for X-Forwarded-For extraction.
	// Set LANCERT_TRUSTED_PROXY to a CIDR (e.g. "172.20.0.0/16") when behind
	// a reverse proxy (Traefik, Nginx, etc.) so that real client IPs are
	// extracted from X-Forwarded-For for logging and rate limiting.
	var proxySubnet netip.Prefix
	if v := os.Getenv("LANCERT_TRUSTED_PROXY"); v != "" {
		proxySubnet, err = netip.ParsePrefix(v)
		if err != nil {
			return fmt.Errorf("invalid LANCERT_TRUSTED_PROXY: %q (must be a CIDR like 172.20.0.0/16)", v)
		}
	}

	// Secret key for IP hashing (keyed BLAKE2b). Required so that hashed IPs
	// in logs and rate-limit buckets cannot be reversed via rainbow tables.
	ipHashSecret := os.Getenv("LANCERT_IP_HASH_SALT")
	if ipHashSecret == "" {
		return fmt.Errorf("LANCERT_IP_HASH_SALT is required")
	}
	// Graceful shutdown context — created early so background goroutines
	// (e.g. rate limiter cleanup) can use it as their lifecycle signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	updateReadiness := func() {
		if metricStore == nil {
			return
		}
		entries, err := store.Inventory()
		if err != nil {
			metricStore.SetReadiness(metrics.Readiness{Available: false, Degraded: true, Error: err.Error()})
			return
		}
		metricStore.SetReadiness(readinessFromInventory(entries, time.Now()))
	}

	realIP := api.NewRealIP(proxySubnet)
	ipHasher := api.NewIPHasher(ipHashSecret)
	issuanceLimiter := api.NewRateLimiter(ctx, api.IssuanceRPS, api.IssuanceBurst)
	initialIssuanceLimiter := api.NewInitialIssuanceRateLimiter(ctx)
	certificateReadLimiter := api.NewRateLimiter(ctx, api.CertificateReadRPS, api.CertificateReadBurst)

	// HTTP API with middleware stack
	statusSnapshot := func() metrics.Snapshot {
		if metricStore == nil {
			return metrics.UnavailableSnapshot(metricOpenErr)
		}
		return metricStore.Snapshot()
	}
	apiHandler := api.NewWithBuildInfo(certSvc, statusSnapshot, api.BuildInfo{
		Version:    buildVersion,
		CommitHash: shortCommitHash(commitHash),
	}, api.WithInitialIssuanceLimiter(initialIssuanceLimiter))
	handler := api.Chain(apiHandler,
		api.Recover,
		api.SecurityHeaders,
		realIP.Middleware,
		ipHasher.Middleware,
		issuanceLimiter.Middleware,
		certificateReadLimiter.CertificateReadMiddleware,
		api.RequestLogging,
	)

	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second, // POST returns immediately; issuance is async
		IdleTimeout:       60 * time.Second,
	}

	// Start DNS and HTTP servers; fatal if either fails to bind.
	startupErr := make(chan error, 2)
	dnsReady := make(chan struct{})

	go func() {
		slog.Info("dns server listening", "addr", dnsAddr, "zone", zone)
		if err := dnsServer.ListenAndServe(dnsAddr, func() { close(dnsReady) }); err != nil {
			startupErr <- fmt.Errorf("dns server: %w", err)
		}
	}()

	go func() {
		slog.Info("http server listening", "addr", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			startupErr <- fmt.Errorf("http server: %w", err)
		}
	}()

	// Wait for DNS to bind (deterministic) or fail.
	select {
	case err := <-startupErr:
		return err
	case <-dnsReady:
	}

	// Wait for ready
	version := buildVersion + " (" + shortCommitHash(commitHash) + ")"
	slog.Info("service started", "version", version, "acme_env", environment, "certs", store.Count())
	slog.Warn("HTTP API serves private keys over plaintext — use a TLS-terminating reverse proxy in production")

	// Pre-generate certificates for common IPs in the background
	if pregen {
		go certSvc.Pregen(ctx)
	}
	certSvc.StartRenewalWorker(ctx)
	if metricStore != nil {
		updateReadiness()
		go func() {
			ticker := time.NewTicker(15 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					updateReadiness()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Block until shutdown signal or server crash
	select {
	case <-ctx.Done():
	case err := <-startupErr:
		slog.Error("server crashed", "error", err)
	}
	slog.Info("shutting down")

	// Shutdown HTTP first (stop accepting new requests)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown error", "error", err)
	}

	if err := dnsServer.Shutdown(); err != nil {
		slog.Error("dns shutdown error", "error", err)
	}

	slog.Info("shutdown complete")
	return nil
}

func shortCommitHash(hash string) string {
	return hash[:min(6, len(hash))]
}

// readinessFromInventory derives service readiness from stored certificates.
func readinessFromInventory(entries []certstore.InventoryEntry, now time.Time) metrics.Readiness {
	readiness := metrics.Readiness{Available: true}
	for _, entry := range entries {
		if entry.Addr.IsValid() {
			readiness.Total++
		}
		if entry.Err != nil {
			readiness.Degraded = true
			if readiness.Error == "" {
				readiness.Error = fmt.Sprintf("certificate bundle %s: %v", entry.Name, entry.Err)
			}
			continue
		}
		if entry.Ready && entry.Meta.NotAfter.After(now) {
			readiness.Ready++
		}
	}
	return readiness
}

func certificateLifecycleBaseline(entries []certstore.InventoryEntry) (uint64, time.Time) {
	var count uint64
	var since time.Time
	for _, entry := range entries {
		if entry.Ready && entry.Addr.IsValid() {
			count++
			if !entry.Meta.IssuedAt.IsZero() && (since.IsZero() || entry.Meta.IssuedAt.Before(since)) {
				since = entry.Meta.IssuedAt
			}
		}
	}
	return count, since
}

// envOr returns the value of the environment variable key, or fallback if unset/empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool returns true if the environment variable is set to "true" or "1".
func envBool(key string) bool {
	v := os.Getenv(key)
	return v == "true" || v == "1"
}
