package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServeOverTLS proves the listener actually terminates TLS and serves the
// normal handler over HTTPS.
func TestServeOverTLS(t *testing.T) {
	t.Parallel()

	certPath, keyPath, roots := selfSignedCertificate(t)
	addr := freeLocalAddr(t)
	handler := testRouter(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, addr, handler, certPath, keyPath, log)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 2 * time.Second,
	}
	t.Cleanup(client.CloseIdleConnections)

	url := "https://" + addr + "/healthz"
	var resp *http.Response
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.NoError(t, err, "the TLS listener should answer before the deadline")
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https", resp.Request.URL.Scheme)

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after context cancellation")
	}
}

// TestServeRequiresTLSKeyPair proves half a pair is refused before anything
// binds a port.
func TestServeRequiresTLSKeyPair(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := testRouter(t)

	tests := []struct {
		name string
		cert string
		key  string
	}{
		{"certificate only", "cert.pem", ""},
		{"key only", "", "key.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := serve(context.Background(), "127.0.0.1:0", handler, tt.cert, tt.key, log)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "together")
		})
	}
}

// TestTLSConfigMinimumVersion keeps the explicit TLS floor from being lost.
func TestTLSConfigMinimumVersion(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint16(tls.VersionTLS12), newTLSConfig().MinVersion)
}

// TestIsLoopbackAddr covers the addresses operators actually put in
// HTTP_ADDR, including the empty host that binds every interface.
func TestIsLoopbackAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"LOCALHOST:8080", true},
		{":8080", false},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"192.0.2.1:8080", false},
		{"example.test:8080", false},
		{"127.0.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, isLoopbackAddr(tt.addr), tt.addr)
	}
}

// TestWarnIfPlainHTTP checks the warning fires only for a listener reachable
// beyond loopback.
func TestWarnIfPlainHTTP(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	warnIfPlainHTTP(log, "0.0.0.0:8080")
	assert.Contains(t, buf.String(), "plain HTTP")
	assert.Contains(t, buf.String(), "non-loopback")

	buf.Reset()
	warnIfPlainHTTP(log, "127.0.0.1:8080")
	assert.Empty(t, buf.String())
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// selfSignedCertificate writes a short-lived certificate for 127.0.0.1 and
// returns the roots a test client can trust.
func selfSignedCertificate(t *testing.T) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyDER,
	}), 0o600))

	roots = x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	})))
	return certPath, keyPath, roots
}
