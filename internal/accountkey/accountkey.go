// Package accountkey manages the ECDSA P-256 private key used to authenticate
// with the ACME (Let's Encrypt) account.
//
// The account key is generated once and reused across all certificate issuances.
// It identifies lancert to Let's Encrypt — only the public half is registered
// with LE; the private key never leaves the server.
//
// This is distinct from certificate keys, which are generated fresh on every
// issuance to limit the blast radius of a compromise to a single 90-day window.
// The account key has no such requirement: it authenticates the operator, not
// the end certificate, and losing it only means re-registering a new account.
package accountkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	filePerm = 0o600
	dirPerm  = 0o700
)

// LoadOrCreate loads the ECDSA P-256 private key at path, or generates
// and persists a new one if the file does not exist.
func LoadOrCreate(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parseKey(data, path)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read account key: %w", err)
	}

	// Generate new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal account key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("create account key directory: %w", err)
	}

	if err := os.WriteFile(path, keyPEM, filePerm); err != nil {
		return nil, fmt.Errorf("write account key: %w", err)
	}

	return key, nil
}

// parseKey decodes a PEM-encoded ECDSA private key.
func parseKey(data []byte, path string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in account key file: %s", path)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}

	return key, nil
}
