package acme

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const (
	// These endpoints are the shared local-development Pebble profile from
	// .mise/Procfile and mise.toml. The ACME and API E2E cases use this profile
	// and are serialized by the mise e2e task because they share its ports.
	PebbleDNSAddr        = "127.0.0.1:1053"
	PebbleListenAddress  = "127.0.0.1:14000"
	PebbleManagementAddr = "127.0.0.1:15000"
	PebbleHTTPPort       = 5002
	PebbleTLSPort        = 5001
	PebbleDirectoryURL   = "https://" + PebbleListenAddress + "/dir"
	DefaultPebbleCA      = ".mise/pebble/rootCA.pem"
)

// localHTTPClient creates a client that trusts only the configured Pebble CA.
func localHTTPClient(caPath string) (*http.Client, error) {
	if caPath == "" {
		caPath = DefaultPebbleCA
	}
	data, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("read Pebble CA certificate %q: %w", caPath, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("parse Pebble CA certificate %q", caPath)
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Timeout:   acmeHTTPTimeout,
	}, nil
}
