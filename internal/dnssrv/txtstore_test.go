package dnssrv

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTXTStore_SetAndLookup(t *testing.T) {
	store := NewTXTStore()
	ctx := context.Background()
	fqdn := "_acme-challenge.192-168-1-50.lancert.dev."

	// Add first value (bare domain challenge)
	cleanup1, err := store.SetTXTWithCleanup(ctx, fqdn, "token-bare", 120*time.Second)
	require.NoError(t, err)

	// Add second value (wildcard challenge) — must accumulate
	cleanup2, err := store.SetTXTWithCleanup(ctx, fqdn, "token-wildcard", 120*time.Second)
	require.NoError(t, err)

	values := store.Lookup(fqdn)
	assert.ElementsMatch(t, []string{"token-bare", "token-wildcard"}, values)

	// Cleanup first value
	require.NoError(t, cleanup1(ctx))
	values = store.Lookup(fqdn)
	assert.Equal(t, []string{"token-wildcard"}, values)

	// Cleanup second value — FQDN should be fully removed
	require.NoError(t, cleanup2(ctx))
	assert.Nil(t, store.Lookup(fqdn))
}

func TestTXTStore_LookupMissing(t *testing.T) {
	store := NewTXTStore()
	assert.Nil(t, store.Lookup("nonexistent.example.com."))
}

func TestTXTStore_LookupReturnsCopy(t *testing.T) {
	store := NewTXTStore()
	ctx := context.Background()
	fqdn := "_acme-challenge.test.lancert.dev."

	_, err := store.SetTXTWithCleanup(ctx, fqdn, "val1", 0)
	require.NoError(t, err)

	// Mutating the returned slice must not affect the store
	vals := store.Lookup(fqdn)
	vals[0] = "mutated"

	assert.Equal(t, []string{"val1"}, store.Lookup(fqdn))
}
