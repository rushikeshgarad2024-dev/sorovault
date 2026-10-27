package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/soroworks/sorovault/internal/wasm"
	"github.com/soroworks/sorovault/internal/wasm/wasmtest"
)

// TestDownloadWasmModule proves GET /api/wasm/{hash}.wasm returns the module
// bytes, not the catalogued interface, with the headers a content-addressed
// binary deserves.
func TestDownloadWasmModule(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	module := moduleWith(t, "downloadable")
	hash := h.fake.UploadWasm(module)

	resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+hash+".wasm", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "application/wasm", resp.Header.Get("Content-Type"))
	assert.Equal(t, "public, max-age=31536000, immutable", resp.Header.Get("Cache-Control"))
	assert.Equal(t, module, raw)
	assert.Equal(t, 1, h.fake.Calls["FetchWasm"])
}

// TestDownloadWasmModuleNormalizesHash proves an uppercase hash resolves to
// the same module, and that a matching ?network is accepted.
func TestDownloadWasmModuleNormalizesHash(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	module := moduleWith(t, "downloadable")
	hash := h.fake.UploadWasm(module)

	resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+strings.ToUpper(hash)+".wasm?network=testnet", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, module, raw)
}

// TestDownloadWasmModuleMissingCode covers the 404 case.
func TestDownloadWasmModuleMissingCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sum := sha256.Sum256([]byte("code that was never uploaded"))
	hash := hex.EncodeToString(sum[:])

	resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+hash+".wasm", "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, string(raw))
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	assert.Contains(t, h.decode(t, raw)["error"], hash)
}

// TestDownloadWasmModuleRejectsMalformedHash proves a bad hash is a 400 and
// never reaches the network.
func TestDownloadWasmModuleRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	for _, hash := range []string{"not-a-hash", strings.Repeat("a", 62), strings.Repeat("a", 66)} {
		resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+hash+".wasm", "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
		assert.Equal(t, "invalid wasm hash", h.decode(t, raw)["error"])
	}
	assert.Zero(t, h.fake.Calls["FetchWasm"])
}

// TestDownloadWasmModuleRejectsOtherNetwork proves ?network cannot redirect
// the fetch: modules are not stored, so another network's hash space would
// undermine the verification the hash provides.
func TestDownloadWasmModuleRejectsOtherNetwork(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	module := moduleWith(t, "downloadable")
	hash := h.fake.UploadWasm(module)

	resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+hash+".wasm?network=public", "")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
	assert.Contains(t, h.decode(t, raw)["error"], "testnet")
	assert.Zero(t, h.fake.Calls["FetchWasm"], "a network mismatch must be refused before fetching")
}

// TestDownloadWasmModuleRejectsOversizedModule proves the reader limit holds
// for downloads, not only for cataloguing.
func TestDownloadWasmModuleRejectsOversizedModule(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	module := wasmtest.Module()
	module = append(module, make([]byte, wasm.MaxModuleSize)...)
	hash := h.fake.UploadWasm(module)

	resp, raw := h.do(t, http.MethodGet, "/api/wasm/"+hash+".wasm", "")
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, string(raw))
	assert.Contains(t, h.decode(t, raw)["error"], "limit")
}
