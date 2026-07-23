//go:build e2e

package acme_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/api"
	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/metrics"
)

// TestPebbleAPILifecycle exercises issuance through the public HTTP contract.
func TestPebbleAPILifecycle(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	caPath := filepath.Join(repoRoot, ".mise", "pebble", "rootCA.pem")
	certPath := filepath.Join(repoRoot, ".mise", "pebble", "localhost.crt")
	keyPath := filepath.Join(repoRoot, ".mise", "pebble", "localhost.key")
	for _, path := range []string{caPath, certPath, keyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Pebble asset %s is unavailable; run `mise run setup`: %v", path, err)
		}
	}

	dnsAddr := acmeissue.PebbleDNSAddr
	txtStore := dnssrv.NewTXTStore()
	dnsServer := dnssrv.New(dnssrv.Config{
		Zone:      "lancert.dev.",
		NSRecords: []string{"ns1.lancert.dev.", "ns2.lancert.dev."},
		ServerIP:  netip.MustParseAddr("127.0.0.1"),
		SOAMname:  "ns1.lancert.dev.",
		SOARname:  "admin.lancert.dev.",
	}, txtStore)
	ready := make(chan struct{})
	dnsErr := make(chan error, 1)
	go func() { dnsErr <- dnsServer.ListenAndServe(dnsAddr, func() { close(ready) }) }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	select {
	case <-ready:
	case err := <-dnsErr:
		require.NoError(t, err, "DNS server failed to start")
	case <-time.After(5 * time.Second):
		t.Fatal("DNS server did not become ready")
	}

	stopPebble := startAPIPebble(t, certPath, keyPath, dnsAddr, caPath)
	t.Cleanup(stopPebble)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dnsAddr)
	}}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	service := certservice.New(certservice.Config{
		Zone:        "lancert.dev",
		AccountKey:  accountKey,
		Environment: acmeissue.EnvironmentLocal,
		CACertPath:  caPath,
		Resolver:    resolver,
	}, certstore.New(t.TempDir()), txtStore, metrics.Disabled{})
	server := httptest.NewServer(api.New(service, nil))
	t.Cleanup(server.Close)

	client := server.Client()
	const ip = "192.168.1.50"
	resp, err := client.Post(server.URL+"/certs/"+ip, "", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, "10", resp.Header.Get("Retry-After"))
	resp.Body.Close()

	var cert api.CertJSON
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(server.URL + "/certs/" + ip)
		require.NoError(t, err)
		if resp.StatusCode == http.StatusOK {
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&cert))
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		require.Equal(t, http.StatusAccepted, resp.StatusCode)
		time.Sleep(500 * time.Millisecond)
	}
	require.NotEmpty(t, cert.FullChain)
	require.Equal(t, ip, cert.IP)

	resp, err = client.Get(server.URL + "/certs/" + ip + "/ttl")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	ttlText, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	ttl, err := strconv.Atoi(string(ttlText))
	require.NoError(t, err)
	require.Greater(t, ttl, 0)

	resp, err = client.Get(server.URL + "/certs/" + ip + "/fullchain.pem")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	chain, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, cert.FullChain, string(chain))

	resp, err = client.Get(server.URL + "/certs/" + ip + "/privkey.pem")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	key, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, cert.PrivKey, string(key))

	etag := ""
	resp, err = client.Get(server.URL + "/certs/" + ip)
	require.NoError(t, err)
	etag = resp.Header.Get("ETag")
	resp.Body.Close()
	require.NotEmpty(t, etag)
	req, err := http.NewRequest(http.MethodGet, server.URL+"/certs/"+ip, nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", etag)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotModified, resp.StatusCode)
	resp.Body.Close()

	resp, err = client.Post(server.URL+"/certs/"+ip, "", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func startAPIPebble(t *testing.T, certPath, keyPath, dnsAddr, caPath string) func() {
	t.Helper()
	pebblePath, err := exec.LookPath("pebble")
	require.NoError(t, err, "Pebble is unavailable; run through `mise run e2e`")
	config := map[string]any{"pebble": map[string]any{
		"listenAddress":           acmeissue.PebbleListenAddress,
		"managementListenAddress": acmeissue.PebbleManagementAddr,
		"certificate":             certPath,
		"privateKey":              keyPath,
		"httpPort":                acmeissue.PebbleHTTPPort,
		"tlsPort":                 acmeissue.PebbleTLSPort,
		"retryAfter":              map[string]int{"authz": 1, "order": 1},
		"profiles":                map[string]any{"default": map[string]any{"description": "lancert API e2e", "validityPeriod": 7776000}},
	}}
	configData, err := json.Marshal(config)
	require.NoError(t, err)
	configPath := filepath.Join(t.TempDir(), "pebble.json")
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, pebblePath, "-config", configPath, "-dnsserver", dnsAddr)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	cmd.Stdout = &output
	cmd.Stderr = &output
	require.NoError(t, cmd.Start())

	client, err := pebbleHTTPClient(caPath)
	require.NoError(t, err)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, requestErr := client.Get(acmeissue.PebbleDirectoryURL)
		if requestErr == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return func() { cancel(); _ = cmd.Wait() }
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	_ = cmd.Wait()
	t.Fatalf("Pebble did not become ready: %s", output.String())
	return func() {}
}

func pebbleHTTPClient(caPath string) (*http.Client, error) {
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("parse Pebble CA certificate")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}
