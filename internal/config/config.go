// Package config loads SoroVault's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults applied when the corresponding variable is unset.
const (
	DefaultRPCURL             = "https://soroban-testnet.stellar.org"
	DefaultNetworkPassphrase  = "Test SDF Network ; September 2015"
	DefaultHTTPAddr           = ":8080"
	DefaultLogLevel           = "info"
	DefaultLogFormat          = "text"
	DefaultRPCTimeout         = 30 * time.Second
	DefaultRateLimitPerMinute = 30
	DefaultRateLimitBurst     = 10
)

// Log format names accepted by LOG_FORMAT.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// Config is the resolved runtime configuration.
type Config struct {
	// RPCURL is the Stellar RPC endpoint contract code is read from.
	RPCURL string
	// NetworkPassphrase is the network operators expect RPCURL to serve.
	// It is a guard, not a source of truth: the registry reads the actual
	// passphrase from the endpoint and refuses to run on a mismatch, so a
	// stale RPC_URL cannot file mainnet contracts under "testnet".
	NetworkPassphrase string
	// DatabaseURL is the Postgres connection string for the registry.
	DatabaseURL string
	// MaxConcurrentRegistrations is how many registrations and refreshes
	// may run at once, across every client. Zero means unset, and the
	// registry's own default applies.
	MaxConcurrentRegistrations int
	// HTTPAddr is the address the API and browse UI listen on.
	HTTPAddr string
	// PublicURL is the externally reachable origin for link previews and sitemaps.
	PublicURL string
	// LogLevel is one of debug, info, warn, error.
	LogLevel slog.Level
	// LogFormat selects the handler: text for people, json for log systems
	// that query fields.
	LogFormat string
	// RPCTimeout bounds a single contract fetch.
	RPCTimeout time.Duration
	// RefreshInterval, when positive, makes `serve` re-check every
	// registered contract that has not been refreshed within it. Zero turns
	// automatic refresh off.
	RefreshInterval time.Duration
	// RefreshWebhookURL, when set, is the endpoint a refresh sweep posts
	// to whenever a contract's interface changes.
	RefreshWebhookURL string
	// RefreshWebhookSecret, when set, signs webhook payloads with
	// HMAC-SHA256 so a receiver can tell them from anyone else's.
	RefreshWebhookSecret string
	// CORSOrigins are the exact browser origins allowed to call the API.
	// "*" allows every origin for read-only requests only. Empty disables
	// CORS headers, as the server has always behaved.
	CORSOrigins []string
	// RateLimitPerMinute bounds registrations and refreshes per client.
	RateLimitPerMinute int
	// RateLimitBurst is how many of those requests may arrive at once.
	RateLimitBurst int
	// TrustXForwardedFor makes the rate limiter use the first address in
	// X-Forwarded-For as the client. It must only be set behind a proxy the
	// operator controls, because a client can otherwise forge its address.
	TrustXForwardedFor bool
}

// MinRefreshInterval is the shortest REFRESH_INTERVAL accepted. Below it a
// sweep over a large registry could still be running when the next is due,
// and a public RPC endpoint would see it as abuse.
const MinRefreshInterval = time.Minute

// Bounds on MAX_CONCURRENT_REGISTRATIONS, the number of registrations and
// refreshes allowed to run at once.
const (
	// MinConcurrentRegistrationLimit is the smallest limit accepted: one
	// registration at a time is a limit, none at all is not.
	MinConcurrentRegistrationLimit = 1
	// MaxConcurrentRegistrationLimit is the largest limit accepted. Every
	// registration holds a WASM module in memory while it decodes, so a
	// limit in the thousands would defeat the point of having one.
	MaxConcurrentRegistrationLimit = 1000
)

// Load reads configuration from the process environment.
//
// The database connection string is the only setting with no usable default
// (see DatabaseURLFromEnv), so it is the only one whose absence is an error.
func Load() (*Config, error) {
	databaseURL, err := DatabaseURLFromEnv()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		RPCURL:            envOr("RPC_URL", DefaultRPCURL),
		NetworkPassphrase: envOr("NETWORK_PASSPHRASE", DefaultNetworkPassphrase),
		DatabaseURL:       databaseURL,
		HTTPAddr:          envOr("HTTP_ADDR", DefaultHTTPAddr),
		PublicURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("PUBLIC_URL")), "/"),
		RPCTimeout:        DefaultRPCTimeout,
	}

	level, err := parseLevel(envOr("LOG_LEVEL", DefaultLogLevel))
	if err != nil {
		return nil, err
	}
	cfg.LogLevel = level

	format, err := parseLogFormat(envOr("LOG_FORMAT", DefaultLogFormat))
	if err != nil {
		return nil, err
	}
	cfg.LogFormat = format

	if raw := os.Getenv("RPC_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("config: RPC_TIMEOUT %q: %w", raw, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("config: RPC_TIMEOUT must be positive, got %s", d)
		}
		cfg.RPCTimeout = d
	}

	if raw := os.Getenv("REFRESH_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("config: REFRESH_INTERVAL %q: %w", raw, err)
		}
		if d != 0 && d < MinRefreshInterval {
			return nil, fmt.Errorf("config: REFRESH_INTERVAL must be 0 (off) or at least %s, got %s",
				MinRefreshInterval, d)
		}
		cfg.RefreshInterval = d
	}

	limit, err := envInt("MAX_CONCURRENT_REGISTRATIONS",
		MinConcurrentRegistrationLimit, MaxConcurrentRegistrationLimit)
	if err != nil {
		return nil, err
	}
	cfg.MaxConcurrentRegistrations = limit

	webhookURL := strings.TrimSpace(os.Getenv("REFRESH_WEBHOOK_URL"))
	if webhookURL != "" {
		if err := checkWebhookURL(webhookURL); err != nil {
			return nil, err
		}
	}
	cfg.RefreshWebhookURL = webhookURL
	cfg.RefreshWebhookSecret = os.Getenv("REFRESH_WEBHOOK_SECRET")

	cfg.CORSOrigins, err = parseCORSOrigins(os.Getenv("CORS_ORIGINS"))
	if err != nil {
		return nil, err
	}

	cfg.RateLimitPerMinute, err = envIntDefault("RATE_LIMIT_PER_MINUTE",
		DefaultRateLimitPerMinute, 1, 100000)
	if err != nil {
		return nil, err
	}
	cfg.RateLimitBurst, err = envIntDefault("RATE_LIMIT_BURST",
		DefaultRateLimitBurst, 1, 100000)
	if err != nil {
		return nil, err
	}
	cfg.TrustXForwardedFor, err = envBool("TRUST_X_FORWARDED_FOR")
	if err != nil {
		return nil, err
	}

	if cfg.PublicURL != "" {
		parsed, err := url.Parse(cfg.PublicURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return nil, errors.New("config: PUBLIC_URL must be a public absolute HTTP(S) origin without a path, query, credentials or fragment")
		}
	}

	if cfg.DatabaseURL == "" {
		return nil, errors.New("config: DATABASE_URL or DATABASE_URL_FILE is required")
	}
	if cfg.RPCURL == "" {
		return nil, errors.New("config: RPC_URL must not be empty")
	}

	return cfg, nil
}

// checkWebhookURL rejects a webhook address that could never be delivered
// to. Catching it here means the mistake is reported when the process
// starts, rather than on the first contract that gets upgraded.
func checkWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config: REFRESH_WEBHOOK_URL %q: %w", raw, err)
	}
	if !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("config: REFRESH_WEBHOOK_URL %q must be an absolute HTTP or HTTPS URL", raw)
	}
	return nil
}

// DatabaseURLFromEnv resolves the Postgres connection string.
//
// It is DATABASE_URL, or the contents of the file named by DATABASE_URL_FILE
// when that is set instead. Docker secrets, Swarm secrets and Kubernetes
// Secret volumes hand credentials over as files; a value that never enters the
// environment cannot leak through `docker inspect`, an error report or the
// environment of every child process the way an exported variable can.
//
// Setting both is a configuration mistake rather than a preference, so it is
// an error instead of a silent pick.
func DatabaseURLFromEnv() (string, error) {
	inline := os.Getenv("DATABASE_URL")
	path := os.Getenv("DATABASE_URL_FILE")

	if inline != "" && path != "" {
		return "", errors.New("config: set either DATABASE_URL or DATABASE_URL_FILE, not both")
	}
	if path == "" {
		return inline, nil
	}

	// The read error names the path; the contents are a credential, so they
	// must not reach the error, a log line or a stack trace.
	b, err := os.ReadFile(path) //nolint:gosec // path is an operator-provided secret file setting
	if err != nil {
		return "", fmt.Errorf("config: DATABASE_URL_FILE: %w", err)
	}
	// Secret files usually end in a newline (echo adds one, and Kubernetes
	// keeps what it was given). A connection string with one on the end is
	// not the string the driver was given.
	return strings.TrimRight(string(b), "\r\n"), nil
}

// NewLogger builds the structured logger the rest of the process writes to.
//
// The format is validated by Load, so an unknown value here means a Config
// was built by hand; text is the safe default.
func (c *Config) NewLogger(w *os.File) *slog.Logger {
	opts := &slog.HandlerOptions{Level: c.LogLevel}
	if c.LogFormat == LogFormatJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// parseCORSOrigins reads the comma-separated CORS_ORIGINS value.
//
// Origins are exact scheme://host[:port] values. "*" is accepted on its own,
// never mixed with a list, because the two mean different things: a list is
// an allowlist, while "*" deliberately opens only the read-only routes.
func parseCORSOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var origins []string
	star := false
	for _, item := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(item)
		if origin == "" {
			continue
		}
		if origin == "*" {
			star = true
			continue
		}

		parsed, err := url.Parse(origin)
		if err != nil {
			return nil, fmt.Errorf("config: CORS_ORIGINS %q: %w", origin, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("config: CORS_ORIGINS %q must use http or https", origin)
		}
		if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("config: CORS_ORIGINS %q must be an origin such as https://app.example.com", origin)
		}

		normalized := strings.TrimSuffix(origin, "/")
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		origins = append(origins, normalized)
	}

	if star {
		if len(origins) > 0 {
			return nil, errors.New("config: CORS_ORIGINS must be * or a list of origins, not both")
		}
		return []string{"*"}, nil
	}
	if len(origins) == 0 {
		return nil, errors.New("config: CORS_ORIGINS must not be empty")
	}
	return origins, nil
}

func envIntDefault(name string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s %q: %w", name, raw, err)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("config: %s must be between %d and %d, got %d",
			name, min, max, n)
	}
	return n, nil
}

func envBool(name string) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: %s %q: %w", name, raw, err)
	}
	return v, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envInt reads an integer from the environment.
//
// An unset or empty variable yields zero, which means "not configured". A
// value that is not a whole number, or that falls outside the accepted
// range, is an error: a limit of zero registrations would stop the registry
// working, and one of thousands would not be a limit.
func envInt(name string, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s %q: %w", name, raw, err)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("config: %s must be between %d and %d, got %d",
			name, min, max, n)
	}
	return n, nil
}

func parseLogFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case LogFormatText:
		return LogFormatText, nil
	case LogFormatJSON:
		return LogFormatJSON, nil
	default:
		return "", fmt.Errorf("config: unknown LOG_FORMAT %q (want text or json)", s)
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("config: unknown LOG_LEVEL %q (want debug, info, warn or error)", s)
	}
}
