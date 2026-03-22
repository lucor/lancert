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
