// Package certstore persists TLS certificates on disk, one directory per IP.
//
// # Layout
//
// Each IP gets a directory named after its dashed subdomain form. The current
// representation is one atomic versioned bundle:
//
//	data/certs/
//	└── 192-168-1-50/
//	    ├── bundle.json    — key, chain, metadata, and ARI state
//	    └── legacy files   — retained as migration backup when present
//
// # Why IP-keyed
//
// The API contract is IP → certificate. Each RFC 1918 IP maps to exactly two
// domains (bare subdomain + wildcard, e.g. "192-168-1-50.lancert.dev" and
// "*.192-168-1-50.lancert.dev"), so keying by IP is unambiguous and avoids
// the indirection of a domain → IP lookup.
//
// Metadata and ARI scheduling state are stored in the same bundle as the PEM
// material, so readers never observe a partially updated certificate.
//
// # File permissions
//
// Files are written 0600 and directories 0700 to prevent other users on the
// host from reading the private key.
package certstore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"lucor.dev/lancert/internal/privateip"
)

const (
	filePerm = 0o600
	dirPerm  = 0o700

	privkeyFile   = "privkey.pem"
	fullchainFile = "fullchain.pem"
	metaFile      = "meta.json"
	bundleFile    = "bundle.json"
	bundleVersion = 1
)

// Meta holds metadata about a stored certificate.
type Meta struct {
	Domains  []string  `json:"domains"`
	IssuedAt time.Time `json:"issued_at"`
	NotAfter time.Time `json:"not_after"`
}

// RenewalState contains the persisted ARI scheduling state for a certificate.
type RenewalState struct {
	CertificateID string    `json:"certificate_id,omitempty"`
	WindowStart   time.Time `json:"window_start,omitempty"`
	WindowEnd     time.Time `json:"window_end,omitempty"`
	RenewAt       time.Time `json:"renew_at,omitempty"`
	NextCheck     time.Time `json:"next_check,omitempty"`
	NextAttempt   time.Time `json:"next_attempt,omitempty"`
}

// CertBundle holds the PEM-encoded certificate and key for an IP.
type CertBundle struct {
	PrivKeyPEM   []byte
	FullChainPEM []byte
	Meta         Meta
	Renewal      RenewalState
}

type persistedBundle struct {
	Version      int          `json:"version"`
	PrivKeyPEM   []byte       `json:"private_key_pem"`
	FullChainPEM []byte       `json:"full_chain_pem"`
	Meta         Meta         `json:"metadata"`
	Renewal      RenewalState `json:"renewal"`
}

// SaveBundle atomically persists an already-loaded bundle, preserving its
// original metadata. It is used by the one-time legacy migration.
func (s *Store) SaveBundle(addr netip.Addr, bundle *CertBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is nil")
	}
	chain, err := parseChainPEM(bundle.FullChainPEM)
	if err != nil {
		return err
	}
	for i := 1; i < len(chain); i++ {
		if err := chain[i-1].CheckSignatureFrom(chain[i]); err != nil {
			return fmt.Errorf("verify certificate chain: %w", err)
		}
	}
	leaf := chain[0]
	keyBlock, _ := pem.Decode(bundle.PrivKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("private key PEM is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.X.Cmp(key.PublicKey.X) != 0 || leafKey.Y.Cmp(key.PublicKey.Y) != 0 {
		return fmt.Errorf("private key does not match leaf certificate")
	}
	bundle.Meta.Domains = append([]string(nil), leaf.DNSNames...)
	bundle.Meta.NotAfter = leaf.NotAfter.UTC()
	if bundle.Renewal.CertificateID == "" {
		bundle.Renewal.CertificateID = certificateID(leaf)
	}
	return s.writeBundle(addr, bundle.PrivKeyPEM, bundle.FullChainPEM, bundle.Meta, bundle.Renewal)
}

// InventoryEntry describes whether a certificate bundle can be loaded now.
// Name is retained so malformed store directory names can be reported even
// when Addr could not be parsed.
type InventoryEntry struct {
	Name  string
	Addr  netip.Addr
	Meta  Meta
	Ready bool
	Err   error
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
	return s.SaveWithRenewal(addr, privKeyPEM, certChainDER, RenewalState{})
}

// SaveWithRenewal validates and atomically persists a complete certificate
// bundle. The legacy files are deliberately left untouched for rollback.
func (s *Store) SaveWithRenewal(addr netip.Addr, privKeyPEM []byte, certChainDER [][]byte, renewal RenewalState) error {
	if len(certChainDER) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}
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

	// Extract and validate the leaf certificate.
	leaf, err := x509.ParseCertificate(certChainDER[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(leaf.DNSNames) == 0 {
		return fmt.Errorf("leaf certificate has no DNS SANs")
	}
	for i := 1; i < len(certChainDER); i++ {
		issuer, err := x509.ParseCertificate(certChainDER[i])
		if err != nil {
			return fmt.Errorf("parse chain certificate %d: %w", i, err)
		}
		child, _ := x509.ParseCertificate(certChainDER[i-1])
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("verify chain certificate %d: %w", i-1, err)
		}
	}
	keyBlock, _ := pem.Decode(privKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("private key PEM is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.X.Cmp(key.PublicKey.X) != 0 || leafKey.Y.Cmp(key.PublicKey.Y) != 0 {
		return fmt.Errorf("private key does not match leaf certificate")
	}

	meta := Meta{
		Domains:  leaf.DNSNames,
		IssuedAt: time.Now().UTC(),
		NotAfter: leaf.NotAfter.UTC(),
	}

	if renewal.CertificateID == "" {
		renewal.CertificateID = certificateID(leaf)
	}
	return s.writeBundle(addr, privKeyPEM, fullchain, meta, renewal)
}

func (s *Store) writeBundle(addr netip.Addr, privKeyPEM, fullchain []byte, meta Meta, renewal RenewalState) error {
	dir := s.ipDir(addr)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}
	persisted := persistedBundle{
		Version:      bundleVersion,
		PrivKeyPEM:   privKeyPEM,
		FullChainPEM: fullchain,
		Meta:         meta,
		Renewal:      renewal,
	}
	bundleJSON, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	return atomicWrite(filepath.Join(dir, bundleFile), bundleJSON)
}

func parseChainPEM(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for rest := data; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate PEM: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("certificate chain PEM is empty")
	}
	return chain, nil
}

func certificateID(leaf *x509.Certificate) string {
	serialDER, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil || len(serialDER) < 3 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serialDER[2:])
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bundle-*")
	if err != nil {
		return fmt.Errorf("create temporary bundle: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temporary bundle: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary bundle: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary bundle: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename bundle: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open bundle directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync bundle directory: %w", err)
	}
	return nil
}

// Load reads the certificate bundle for the given IP.
// Returns nil, nil if no certificate exists.
func (s *Store) Load(addr netip.Addr) (*CertBundle, error) {
	dir := s.ipDir(addr)
	if data, err := os.ReadFile(filepath.Join(dir, bundleFile)); err == nil {
		var stored persistedBundle
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, fmt.Errorf("parse bundle: %w", err)
		}
		if stored.Version != bundleVersion {
			return nil, fmt.Errorf("unsupported bundle version %d", stored.Version)
		}
		return &CertBundle{PrivKeyPEM: stored.PrivKeyPEM, FullChainPEM: stored.FullChainPEM, Meta: stored.Meta, Renewal: stored.Renewal}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read bundle: %w", err)
	}

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
		Renewal:      RenewalState{CertificateID: ""},
	}, nil
}

// TTL returns the remaining validity of the certificate for the given IP.
// Returns 0 if no certificate exists or it has expired.
func (s *Store) TTL(addr netip.Addr) time.Duration {
	bundle, err := s.Load(addr)
	if err != nil || bundle == nil {
		return 0
	}
	remaining := time.Until(bundle.Meta.NotAfter)
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

// Inventory inspects the certificate store without loading PEM contents.
// A missing base directory is an empty store. Other failures to read the base
// directory are returned as a top-level error; bundle corruption is reported
// on the corresponding entry.
func (s *Store) Inventory() ([]InventoryEntry, error) {
	dirs, err := os.ReadDir(s.baseDir)
	if os.IsNotExist(err) {
		return []InventoryEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate store: %w", err)
	}

	entries := make([]InventoryEntry, 0, len(dirs))
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}

		entry := InventoryEntry{Name: dir.Name()}
		addr, parseErr := privateip.ParseSubdomain(dir.Name())
		if parseErr != nil {
			entry.Err = parseErr
			entries = append(entries, entry)
			continue
		}
		entry.Addr = addr
		path := filepath.Join(s.baseDir, dir.Name())
		if _, err := os.Stat(filepath.Join(path, bundleFile)); err == nil {
			bundle, loadErr := s.Load(addr)
			if loadErr != nil {
				entry.Err = loadErr
			} else if bundle == nil {
				entry.Err = fmt.Errorf("bundle is missing")
			} else {
				entry.Meta = bundle.Meta
				entry.Ready = true
			}
			entries = append(entries, entry)
			continue
		}

		metaData, metaErr := os.ReadFile(filepath.Join(path, metaFile))
		if metaErr != nil {
			metaErr = fmt.Errorf("read meta: %w", metaErr)
		} else if len(metaData) == 0 {
			metaErr = fmt.Errorf("read meta: %s is empty", metaFile)
		} else if err := json.Unmarshal(metaData, &entry.Meta); err != nil {
			metaErr = fmt.Errorf("parse meta: %w", err)
		}

		entry.Err = errors.Join(metaErr, inspectPEM(filepath.Join(path, privkeyFile), privkeyFile), inspectPEM(filepath.Join(path, fullchainFile), fullchainFile))
		entry.Ready = entry.Err == nil
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Addr.IsValid() != entries[j].Addr.IsValid() {
			return entries[i].Addr.IsValid()
		}
		if entries[i].Addr.IsValid() && entries[i].Addr != entries[j].Addr {
			return entries[i].Addr.Less(entries[j].Addr)
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

func inspectPEM(path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("stat %s: not a regular file", name)
	}
	if info.Mode().Perm() != filePerm {
		return fmt.Errorf("stat %s: permissions are %04o, want %04o", name, info.Mode().Perm(), filePerm)
	}
	if info.Size() == 0 {
		return fmt.Errorf("stat %s: file is empty", name)
	}

	return nil
}

// ipDir returns the directory path for the given IP.
func (s *Store) ipDir(addr netip.Addr) string {
	return filepath.Join(s.baseDir, privateip.FormatSubdomain(addr))
}
