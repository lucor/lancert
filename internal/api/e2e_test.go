//go:build e2e

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/dnssrv"
	"go.lucor.dev/lancert/internal/registration"
)

func TestPebbleLego(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	for _, path := range []string{
		filepath.Join(repoRoot, ".mise", "pebble", "config.json"),
		filepath.Join(repoRoot, ".mise", "pebble", "rootCA.pem"),
	} {
		_, err := os.Stat(path)
		require.NoError(t, err, "run `mise run setup` before the E2E test")
	}
	for _, executable := range []string{"pebble", "lego"} {
		_, err := exec.LookPath(executable)
		require.NoError(t, err, "%s must be available on PATH", executable)
	}

	store, err := registration.Open(filepath.Join(t.TempDir(), "core.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	httpServer := httptest.NewServer(New(store, "lancert.dev.", nil, nil))
	t.Cleanup(httpServer.Close)
	ipv4Account := registerTarget(t, httpServer.URL, "192.168.44.10")
	ipv6Target := "fd12:3456:789a:1::25"
	ipv6Account := registerTarget(t, httpServer.URL, ipv6Target)

	dnsAddr := availableDNSAddress(t)
	dnsServer := dnssrv.New(dnssrv.Config{
		Zone:      "lancert.dev.",
		NSRecords: []string{"ns1.lancert.dev."},
		ServerIP:  netip.MustParseAddr("127.0.0.1"),
		SOAMname:  "ns1.lancert.dev.",
		SOARname:  "hostmaster.lancert.dev.",
	}, store)
	dnsReady := make(chan struct{})
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- dnsServer.ListenAndServe(dnsAddr, func() { close(dnsReady) }) }()
	select {
	case <-dnsReady:
	case err := <-dnsDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out starting Lancert DNS")
	}
	t.Cleanup(func() {
		require.NoError(t, dnsServer.Shutdown())
		select {
		case <-dnsDone:
		case <-time.After(5 * time.Second):
			t.Error("timed out stopping Lancert DNS")
		}
	})
	assertARecord(t, dnsAddr, ipv4Account.Hostname+".", "192.168.44.10")
	assertAAAARecord(t, dnsAddr, ipv6Account.Hostname+".", ipv6Target)
	assertAAAARecord(t, dnsAddr, "test."+ipv6Account.Hostname+".", ipv6Target)

	pebbleOutput := &lockedBuffer{}
	pebble := exec.Command("pebble", "-config", ".mise/pebble/config.json", "-dnsserver", dnsAddr)
	pebble.Dir = repoRoot
	pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	pebble.Stdout, pebble.Stderr = pebbleOutput, pebbleOutput
	require.NoError(t, pebble.Start())
	t.Cleanup(func() { stopProcess(t, pebble) })
	waitForPebble(t, pebbleOutput)

	for _, account := range []registrationResponse{ipv4Account, ipv6Account} {
		t.Run(account.Hostname, func(t *testing.T) {
			issueWithLego(t, repoRoot, httpServer.URL, dnsAddr, filepath.Join(repoRoot, ".mise", "pebble", "rootCA.pem"), account, store, pebbleOutput)
		})
	}
	assert.NotContains(t, pebbleOutput.String(), "authorization failed")
}

func registerTarget(t *testing.T, apiURL, targetIP string) registrationResponse {
	t.Helper()
	response, err := http.Post(apiURL+"/register/"+targetIP, "", nil)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusCreated, response.StatusCode)
	var account registrationResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&account))
	return account
}

func issueWithLego(t *testing.T, repoRoot, apiURL, dnsAddr, pebbleCACert string, account registrationResponse, store *registration.Store, pebbleOutput fmt.Stringer) {
	t.Helper()
	storagePath := filepath.Join(t.TempDir(), "acmedns.json")
	storage := map[string]any{
		account.Hostname: map[string]string{
			"fulldomain": account.FullDomain,
			"subdomain":  account.Subdomain,
			"username":   account.Username,
			"password":   account.Password,
			"server_url": apiURL,
		},
	}
	storageJSON, err := json.Marshal(storage)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(storagePath, storageJSON, 0o600))

	legoPath := filepath.Join(t.TempDir(), "lego")
	lego := exec.Command(
		"lego",
		"--server", "https://localhost:14000/dir",
		"--accept-tos",
		"--email", "e2e@lancert.dev",
		"--domains", account.Hostname,
		"--domains", "*."+account.Hostname,
		"--dns", "acmedns",
		"--dns.resolvers", dnsAddr,
		"--dns.propagation-rns",
		"--dns.propagation-disable-ans",
		"--path", legoPath,
		"run",
	)
	lego.Env = append(os.Environ(),
		"ACME_DNS_API_BASE="+apiURL,
		"ACME_DNS_STORAGE_PATH="+storagePath,
		"LEGO_CA_CERTIFICATES="+pebbleCACert,
	)
	output, err := lego.CombinedOutput()
	require.NoError(t, err, "lego output:\n%s\npebble output:\n%s", output, pebbleOutput.String())
	assert.FileExists(t, filepath.Join(legoPath, "certificates", account.Hostname+".crt"))

	state, ok := store.Lookup(account.Subdomain)
	require.True(t, ok)
	require.NotEmpty(t, state.Challenges[0])
	require.NotEmpty(t, state.Challenges[1])
	assert.NotEqual(t, state.Challenges[0], state.Challenges[1])
	assertTXTRecord(t, dnsAddr, account.FullDomain+".", state.Challenges[0])
	assertTXTRecord(t, dnsAddr, account.FullDomain+".", state.Challenges[1])
}

func availableDNSAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	packet, err := net.ListenPacket("udp", addr)
	require.NoError(t, err)
	require.NoError(t, packet.Close())
	return addr
}

func assertARecord(t *testing.T, server, name, want string) {
	t.Helper()
	message := new(dns.Msg)
	dnsutil.SetQuestion(message, name, dns.TypeA)
	response, _, err := new(dns.Client).Exchange(context.Background(), message, "udp", server)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	record, ok := response.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, want, record.Addr.String())
}

func assertAAAARecord(t *testing.T, server, name, want string) {
	t.Helper()
	message := new(dns.Msg)
	dnsutil.SetQuestion(message, name, dns.TypeAAAA)
	response, _, err := new(dns.Client).Exchange(context.Background(), message, "udp", server)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	record, ok := response.Answer[0].(*dns.AAAA)
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr(want).String(), record.Addr.String())
}

func assertTXTRecord(t *testing.T, server, name, want string) {
	t.Helper()
	message := new(dns.Msg)
	dnsutil.SetQuestion(message, name, dns.TypeTXT)
	response, _, err := new(dns.Client).Exchange(context.Background(), message, "udp", server)
	require.NoError(t, err)
	require.NotEmpty(t, response.Answer)
	values := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.TXT); ok {
			values = append(values, record.Txt...)
		}
	}
	assert.Contains(t, values, want)
}

func waitForPebble(t *testing.T, output fmt.Stringer) {
	t.Helper()
	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // Test-only readiness probe.
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://localhost:14000/dir")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Pebble did not become ready:\n%s", output.String())
}

func stopProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if command.Process == nil || command.ProcessState != nil {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}
