package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed cert for testing.
func generateTestCert(t *testing.T, domains []string) (privKeyPEM []byte, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}

	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	privKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return privKeyPEM, certDER
}

func TestStore_SaveAndLoad(t *testing.T) {
	store := New(t.TempDir())
	addr := netip.MustParseAddr("192.168.1.50")
	domains := []string{"192-168-1-50.lancert.dev", "*.192-168-1-50.lancert.dev"}

	privKey, certDER := generateTestCert(t, domains)

	err := store.Save(addr, privKey, [][]byte{certDER})
	require.NoError(t, err)

	bundle, err := store.Load(addr)
	require.NoError(t, err)
	require.NotNil(t, bundle)

	assert.Equal(t, privKey, bundle.PrivKeyPEM)
	assert.NotEmpty(t, bundle.FullChainPEM)
	assert.Equal(t, domains, bundle.Meta.Domains)
	assert.False(t, bundle.Meta.NotAfter.IsZero())
}

func TestStore_LoadMissing(t *testing.T) {
	store := New(t.TempDir())
	addr := netip.MustParseAddr("10.0.0.1")

	bundle, err := store.Load(addr)
	assert.NoError(t, err)
	assert.Nil(t, bundle)
}

func TestStore_TTL(t *testing.T) {
	store := New(t.TempDir())
	addr := netip.MustParseAddr("192.168.1.50")
	domains := []string{"192-168-1-50.lancert.dev"}

	privKey, certDER := generateTestCert(t, domains)
	require.NoError(t, store.Save(addr, privKey, [][]byte{certDER}))

	ttl := store.TTL(addr)
	assert.Greater(t, ttl, 89*24*time.Hour)
}

func TestStore_TTL_Missing(t *testing.T) {
	store := New(t.TempDir())
	addr := netip.MustParseAddr("10.0.0.1")

	assert.Equal(t, time.Duration(0), store.TTL(addr))
}

func TestStore_Count(t *testing.T) {
	store := New(t.TempDir())

	assert.Equal(t, 0, store.Count())

	addr1 := netip.MustParseAddr("192.168.1.1")
	addr2 := netip.MustParseAddr("192.168.1.2")

	privKey, certDER := generateTestCert(t, []string{"test.lancert.dev"})
	require.NoError(t, store.Save(addr1, privKey, [][]byte{certDER}))
	assert.Equal(t, 1, store.Count())

	require.NoError(t, store.Save(addr2, privKey, [][]byte{certDER}))
	assert.Equal(t, 2, store.Count())
}

func TestStore_Inventory(t *testing.T) {
	baseDir := t.TempDir()
	store := New(baseDir)
	privKey, certDER := generateTestCert(t, []string{"test.lancert.dev"})
	require.NoError(t, store.Save(netip.MustParseAddr("192.168.1.2"), privKey, [][]byte{certDER}))
	require.NoError(t, store.Save(netip.MustParseAddr("10.0.0.10"), privKey, [][]byte{certDER}))

	// Foreign files are ignored, while malformed directories remain visible.
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "README"), []byte("foreign"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(baseDir, "not-a-certificate"), 0o700))

	entries, err := store.Inventory()
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "10.0.0.10", entries[0].Addr.String())
	assert.Equal(t, "192.168.1.2", entries[1].Addr.String())
	assert.True(t, entries[0].Ready)
	assert.True(t, entries[1].Ready)
	assert.NotEmpty(t, entries[0].Meta.Domains)
	assert.Equal(t, "not-a-certificate", entries[2].Name)
	assert.False(t, entries[2].Addr.IsValid())
	assert.Error(t, entries[2].Err)
}

func TestStore_InventoryMissingStore(t *testing.T) {
	entries, err := New(filepath.Join(t.TempDir(), "missing")).Inventory()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestStore_InventoryCorruptBundles(t *testing.T) {
	baseDir := t.TempDir()
	writeBundle := func(name string, meta, key, chain []byte) {
		t.Helper()
		dir := filepath.Join(baseDir, name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		if meta != nil {
			require.NoError(t, os.WriteFile(filepath.Join(dir, metaFile), meta, 0o600))
		}
		if key != nil {
			require.NoError(t, os.WriteFile(filepath.Join(dir, privkeyFile), key, 0o600))
		}
		if chain != nil {
			require.NoError(t, os.WriteFile(filepath.Join(dir, fullchainFile), chain, 0o600))
		}
	}
	validMeta := []byte(`{"domains":["test.lancert.dev"],"issued_at":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}`)
	writeBundle("10-0-0-1", []byte("{"), []byte("key"), []byte("chain"))
	writeBundle("10-0-0-2", validMeta, nil, []byte("chain"))
	writeBundle("10-0-0-3", validMeta, []byte{}, []byte("chain"))
	writeBundle("10-0-0-4", validMeta, []byte("key"), nil)
	writeBundle("10-0-0-5", validMeta, []byte("key"), []byte{})

	entries, err := New(baseDir).Inventory()
	require.NoError(t, err)
	require.Len(t, entries, 5)
	wants := []string{"parse meta", "open privkey.pem", "privkey.pem: file is empty", "open fullchain.pem", "fullchain.pem: file is empty"}
	for i, want := range wants {
		assert.False(t, entries[i].Ready)
		require.Error(t, entries[i].Err)
		assert.True(t, strings.Contains(entries[i].Err.Error(), want), entries[i].Err.Error())
	}
}

func TestStore_InventoryUnreadableBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(base, []byte("file"), 0o600))
	entries, err := New(base).Inventory()
	assert.Error(t, err)
	assert.Nil(t, entries)
}

func TestStore_MigrateLegacyPreservesSource(t *testing.T) {
	base := t.TempDir()
	store := New(base)
	addr := netip.MustParseAddr("192.168.1.60")
	key, cert := generateTestCert(t, []string{"192-168-1-60.lancert.dev"})
	dir := filepath.Join(base, "192-168-1-60")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	meta := `{"domains":["192-168-1-60.lancert.dev"],"issued_at":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, privkeyFile), key, filePerm))
	require.NoError(t, os.WriteFile(filepath.Join(dir, fullchainFile), chain, filePerm))
	require.NoError(t, os.WriteFile(filepath.Join(dir, metaFile), []byte(meta), filePerm))

	require.NoError(t, store.MigrateLegacy())
	bundle, err := store.Load(addr)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Equal(t, "2026-01-01T00:00:00Z", bundle.Meta.IssuedAt.Format(time.RFC3339))
	assert.FileExists(t, filepath.Join(dir, bundleFile))
	assert.FileExists(t, filepath.Join(dir, privkeyFile))
	assert.FileExists(t, filepath.Join(base, formatVersionFile))
}
