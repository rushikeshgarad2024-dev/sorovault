package registry_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/soroworks/sorovault/internal/registry"
	"github.com/soroworks/sorovault/internal/spec"
	"github.com/soroworks/sorovault/internal/stellar"
	"github.com/soroworks/sorovault/internal/stellar/stellartest"
	"github.com/soroworks/sorovault/internal/store"
	"github.com/soroworks/sorovault/internal/wasm"
	"github.com/soroworks/sorovault/internal/wasm/wasmtest"
)

// wasmMismatchFetcher serves different bytes than the hash the caller asked
// for, which is how a corrupt or hostile RPC response reaches Wasm.
type wasmMismatchFetcher struct {
	stellar.Fetcher
	wasm []byte
}

func (f wasmMismatchFetcher) FetchWasm(context.Context, string) ([]byte, error) {
	return f.wasm, nil
}

// TestWasmReturnsUploadedModule proves the download path fetches the module
// the hash names and returns its bytes unchanged, including for an uppercase
// hash. Each call fetches: modules are not stored.
func TestWasmReturnsUploadedModule(t *testing.T) {
	t.Parallel()

	reg, fake, _ := newRegistry(t)
	module := moduleWith(t, "downloadable")
	hash := fake.UploadWasm(module)

	for _, requested := range []string{hash, strings.ToUpper(hash)} {
		got, err := reg.Wasm(context.Background(), requested)
		require.NoError(t, err)
		assert.Equal(t, module, got)
	}
	assert.Equal(t, 2, fake.Calls["FetchWasm"])
}

// TestWasmRejectsMalformedHash proves a hash that cannot name a module is
// refused before the registry talks to the network.
func TestWasmRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("ab", sha256.Size)

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not hexadecimal", strings.Repeat("zz", sha256.Size)},
		{"too short", valid[:len(valid)-2]},
		{"too long", valid + "00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg, fake, _ := newRegistry(t)
			got, err := reg.Wasm(context.Background(), tt.hash)
			require.Nil(t, got)
			require.ErrorIs(t, err, registry.ErrInvalidWasmHash)
			assert.Contains(t, err.Error(), "invalid wasm hash")
			assert.Zero(t, fake.Calls["FetchWasm"], "a malformed hash must not trigger a fetch")
		})
	}
}

// TestWasmMissingCode covers the 404 case: the hash is well-formed but the
// network has no uploaded code for it.
func TestWasmMissingCode(t *testing.T) {
	t.Parallel()

	reg, fake, _ := newRegistry(t)
	sum := sha256.Sum256([]byte("code that was never uploaded"))
	hash := hex.EncodeToString(sum[:])

	got, err := reg.Wasm(context.Background(), hash)
	require.Nil(t, got)
	require.ErrorIs(t, err, stellar.ErrWasmNotFound)
	assert.Contains(t, err.Error(), hash)
	assert.Equal(t, 1, fake.Calls["FetchWasm"])
}

// TestWasmRejectsOversizedModule proves the reader limit still applies when a
// module is fetched for download rather than decoded.
func TestWasmRejectsOversizedModule(t *testing.T) {
	t.Parallel()

	reg, fake, _ := newRegistry(t)
	module := wasmtest.Module()
	module = append(module, make([]byte, wasm.MaxModuleSize)...)
	hash := fake.UploadWasm(module)

	got, err := reg.Wasm(context.Background(), hash)
	require.Nil(t, got)
	require.ErrorIs(t, err, wasm.ErrModuleTooLarge)
	assert.Contains(t, err.Error(), "limit")
}

// TestWasmRejectsHashMismatch proves bytes are verified against the hash
// before they are returned, so a corrupt or hostile RPC cannot substitute a
// different module under an expected hash.
func TestWasmRejectsHashMismatch(t *testing.T) {
	t.Parallel()

	requested := moduleWith(t, "claimed")
	hash := stellartest.HashOf(requested)
	served := wasmtest.Module(wasmtest.Section{Name: "producers", Body: []byte("other")})

	reg := registry.New(
		wasmMismatchFetcher{Fetcher: stellartest.New(), wasm: served},
		spec.XDRDecoder{},
		store.NewMemory(),
		registry.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
	)

	got, err := reg.Wasm(context.Background(), hash)
	require.Nil(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match hash")
	assert.Contains(t, err.Error(), hash)
}
