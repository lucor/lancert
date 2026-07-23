//go:build e2e

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"lucor.dev/lancert/internal/dnssrv"
)

// TestPebbleIssuanceAndARI exercises DNS-01 issuance, cleanup, ARI lookup, and
// replacement against a real local Pebble process.
func TestPebbleIssuanceAndARI(t *testing.T) {
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

	dnsAddr := PebbleDNSAddr
	txtStore := dnssrv.NewTXTStore()
	dnsServer := dnssrv.New(dnssrv.Config{
		Zone:      "lancert.dev.",
		NSRecords: []string{"ns1.lancert.dev.", "ns2.lancert.dev."},
		ServerIP:  netip.MustParseAddr("127.0.0.1"),
		SOAMname:  "ns1.lancert.dev.",
		SOARname:  "admin.lancert.dev.",
	}, txtStore)
	ready := make(chan struct{})
	go func() { _ = dnsServer.ListenAndServe(dnsAddr, func() { close(ready) }) }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS server did not become ready")
	}

	stopPebble := startPebble(t, certPath, keyPath, dnsAddr, caPath)
	t.Cleanup(stopPebble)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dnsAddr)
	}}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	domains := []string{"192-168-1-50.lancert.dev", "*.192-168-1-50.lancert.dev"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, err := Issue(ctx, Request{Domains: domains, AccountKey: accountKey, Environment: EnvironmentLocal, CACertPath: caPath, TXTStore: txtStore, Resolver: resolver})
	require.NoError(t, err)
	require.NotEmpty(t, first.CertChainDER)
	assert.Empty(t, txtStore.Lookup("_acme-challenge.192-168-1-50.lancert.dev."))

	leaf, err := x509.ParseCertificate(first.CertChainDER[0])
	require.NoError(t, err)
	info, err := GetRenewalInfo(ctx, leaf, EnvironmentLocal, caPath)
	require.NoError(t, err)
	assert.True(t, info.WindowStart.Before(info.WindowEnd))

	replacement, err := Issue(ctx, Request{Domains: domains, AccountKey: accountKey, Environment: EnvironmentLocal, CACertPath: caPath, TXTStore: txtStore, Resolver: resolver, Replaces: leaf})
	require.NoError(t, err)
	require.NotEmpty(t, replacement.CertChainDER)
	assert.NotEqual(t, first.CertChainDER[0], replacement.CertChainDER[0])
	assert.Empty(t, txtStore.Lookup("_acme-challenge.192-168-1-50.lancert.dev."))
}

// startPebble starts an isolated Pebble process and waits for its directory.
func startPebble(t *testing.T, certPath, keyPath, dnsAddr, caPath string) func() {
	t.Helper()
	pebblePath, err := exec.LookPath("pebble")
	require.NoError(t, err, "Pebble is unavailable; run through `mise run e2e`")
	config := map[string]any{"pebble": map[string]any{
		"listenAddress":           PebbleListenAddress,
		"managementListenAddress": PebbleManagementAddr,
		"certificate":             certPath,
		"privateKey":              keyPath,
		"httpPort":                PebbleHTTPPort,
		"tlsPort":                 PebbleTLSPort,
		"retryAfter":              map[string]int{"authz": 1, "order": 1},
		"profiles":                map[string]any{"default": map[string]any{"description": "lancert e2e", "validityPeriod": 7776000}},
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

	client, err := localHTTPClient(caPath)
	require.NoError(t, err)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, requestErr := client.Get(PebbleDirectoryURL)
		if requestErr == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return func() {
					cancel()
					_ = cmd.Wait()
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	_ = cmd.Wait()
	t.Fatalf("Pebble did not become ready: %s", output.String())
	return func() {}
}
