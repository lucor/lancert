// Package certstore persists TLS certificates on disk, one directory per IP.
//
// # Layout
//
// Each IP gets a directory named after its dashed subdomain form:
//
//	data/certs/
//	└── 192-168-1-50/
//	    ├── privkey.pem    — ECDSA private key (PEM)
//	    ├── fullchain.pem  — leaf + intermediates (PEM, leaf first)
//	    └── meta.json      — domains, issued_at, not_after
//
// # Why IP-keyed
//
// The API contract is IP → certificate. Each RFC 1918 IP maps to exactly two
// domains (bare subdomain + wildcard, e.g. "192-168-1-50.lancert.dev" and
// "*.192-168-1-50.lancert.dev"), so keying by IP is unambiguous and avoids
// the indirection of a domain → IP lookup.
//
// # Why meta.json
//
// Expiry and domain list are extracted from the leaf certificate at save time
// and stored separately. This lets certservice make renewal decisions and serve
// TTL queries by reading a small JSON file rather than parsing the full X.509
// certificate chain on every request.
//
// # File permissions
//
// Files are written 0600 and directories 0700 to prevent other users on the
// host from reading the private key.
package certstore

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"lucor.dev/lancert/internal/privateip"
)

const (
	filePerm = 0o600
	dirPerm  = 0o700

	privkeyFile   = "privkey.pem"
	fullchainFile = "fullchain.pem"
	metaFile      = "meta.json"
)

// Meta holds metadata about a stored certificate.
type Meta struct {
	Domains  []string  `json:"domains"`
	IssuedAt time.Time `json:"issued_at"`
	NotAfter time.Time `json:"not_after"`
}

// CertBundle holds the PEM-encoded certificate and key for an IP.
type CertBundle struct {
	PrivKeyPEM   []byte
	FullChainPEM []byte
	Meta         Meta
}

// Store persists certificates on disk, one directory per IP.
type Store struct {
	baseDir string
}

// New creates a Store rooted at baseDir (e.g. "data/certs").
func New(baseDir string) *Store {
	return &Store{baseDir: baseDir}
}

// Save writes the certificate bundle to disk for the given IP.
// certChainDER is the DER-encoded certificate chain (leaf first).
func (s *Store) Save(addr netip.Addr, privKeyPEM []byte, certChainDER [][]byte) error {
	dir := s.ipDir(addr)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	// Encode DER chain to PEM
	var fullchain []byte
	for _, der := range certChainDER {
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}

	// Extract expiry from leaf certificate
	leaf, err := x509.ParseCertificate(certChainDER[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}

	meta := Meta{
		Domains:  leaf.DNSNames,
		IssuedAt: time.Now().UTC(),
		NotAfter: leaf.NotAfter.UTC(),
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	// Write all files
	files := map[string][]byte{
		privkeyFile:   privKeyPEM,
		fullchainFile: fullchain,
		metaFile:      metaJSON,
	}

	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, filePerm); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return nil
}

// Load reads the certificate bundle for the given IP.
// Returns nil, nil if no certificate exists.
func (s *Store) Load(addr netip.Addr) (*CertBundle, error) {
	dir := s.ipDir(addr)

	metaData, err := os.ReadFile(filepath.Join(dir, metaFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read meta: %w", err)
	}

	var meta Meta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("parse meta: %w", err)
	}

	privKey, err := os.ReadFile(filepath.Join(dir, privkeyFile))
	if err != nil {
		return nil, fmt.Errorf("read privkey: %w", err)
	}

	fullchain, err := os.ReadFile(filepath.Join(dir, fullchainFile))
	if err != nil {
		return nil, fmt.Errorf("read fullchain: %w", err)
	}

	return &CertBundle{
		PrivKeyPEM:   privKey,
		FullChainPEM: fullchain,
		Meta:         meta,
	}, nil
}

// TTL returns the remaining validity of the certificate for the given IP.
// Returns 0 if no certificate exists or it has expired.
func (s *Store) TTL(addr netip.Addr) time.Duration {
	dir := s.ipDir(addr)

	metaData, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return 0
	}

	var meta Meta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return 0
	}

	remaining := time.Until(meta.NotAfter)
	if remaining < 0 {
		return 0
	}

	return remaining
}

// Count returns the total number of stored certificates.
func (s *Store) Count() int {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() {
			count++
		}
	}
	return count
}

// ipDir returns the directory path for the given IP.
func (s *Store) ipDir(addr netip.Addr) string {
	return filepath.Join(s.baseDir, privateip.FormatSubdomain(addr))
}
