package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPHasher_Hash(t *testing.T) {
	h := NewIPHasher("test-secret")

	// Deterministic: same input → same output
	a := h.Hash("95.12.34.56")
	b := h.Hash("95.12.34.56")
	assert.Equal(t, a, b)
	assert.Len(t, a, 32)

	// Different IPs → different hashes
	c := h.Hash("10.0.0.1")
	assert.NotEqual(t, a, c)

	// Different secrets → different hashes for the same IP
	h2 := NewIPHasher("other-secret")
	d := h2.Hash("95.12.34.56")
	assert.NotEqual(t, a, d)
}

func TestIPHasher_Hash_KnownAnswer(t *testing.T) {
	h := NewIPHasher("test-secret")
	got := h.Hash("95.12.34.56")
	// Pinned to detect accidental algorithm/output-length changes.
	assert.Equal(t, "6c4d87fbe83916df59517fa983340507", got)
}

func TestIPHasher_Hash_Concurrent(t *testing.T) {
	h := NewIPHasher("test-secret")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := h.Hash("95.12.34.56")
			assert.Len(t, got, 32)
		}()
	}
	wg.Wait()
}

func TestIPHasher_Middleware(t *testing.T) {
	h := NewIPHasher("test-secret")

	t.Run("hashes IP from context", func(t *testing.T) {
		var got string
		var ok bool
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, ok = HashedIPFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(WithClientIP(req.Context(), "95.12.34.56"))

		h.Middleware(inner).ServeHTTP(httptest.NewRecorder(), req)

		assert.True(t, ok)
		assert.Equal(t, h.Hash("95.12.34.56"), got)
	})

	t.Run("returns 500 without leaking internals when IP missing", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		h.Middleware(inner).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.False(t, strings.Contains(rec.Body.String(), "missing"))
	})
}
