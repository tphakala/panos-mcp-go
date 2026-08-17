package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tphakala/panos-mcp-go/tools"
)

const serverInstructions = "PAN-OS MCP Server for Palo Alto Networks firewalls and Panorama. " +
	"Config tools (panos_address_*, panos_service_*, panos_tag_*, panos_security_rule_*, panos_nat_rule_*) " +
	"edit the CANDIDATE config only; nothing is live until panos_commit (and panos_push to device groups on Panorama). " +
	"Inspect pending changes with panos_config_diff before committing. " +
	"Locations: firewall objects default to vsys1, Panorama objects to shared; rules on Panorama take a device_group " +
	"and rulebase (pre or post) location."

const (
	readTimeout       = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 15 * time.Second
)

// buildPangoClient constructs the pango client from config. TLS verification
// stays on unless PANOS_SKIP_VERIFY is set; PANOS_CA_CERT loads a private CA.
func buildPangoClient(cfg *Config) (*pango.Client, error) {
	c := &pango.Client{
		Hostname:              cfg.Host,
		Port:                  cfg.Port,
		ApiKey:                cfg.APIKey,
		Username:              cfg.Username,
		Password:              cfg.Password,
		Protocol:              "https",
		SkipVerifyCertificate: cfg.SkipVerify,
		// Explicitly false (issues #11, #4): config.go is the single source of
		// truth for environment parsing. With this true, pango's Setup would read
		// PANOS_HOSTNAME, PANOS_USERNAME, PANOS_PASSWORD, PANOS_API_KEY,
		// PANOS_LOG_LEVEL and more behind our back (pango client.go:161-197, 1141
		// @ efa4357). Kept explicit so a future pango default change cannot
		// silently re-enable it.
		CheckEnvironment: false,
	}
	if cfg.CACert != "" {
		pool, err := loadCACertPool(cfg.CACert)
		if err != nil {
			return nil, err
		}
		// pango installs its own transport only when Transport is nil (pango Setup,
		// client.go:287-296 @ efa4357), so a supplied transport must carry the whole
		// TLS policy. Clone http.DefaultTransport to keep its proxy (NO_PROXY) and
		// dial/TLS/idle timeout defaults, and replace only the TLS config.
		// InsecureSkipVerify mirrors cfg.SkipVerify even though LoadConfig rejects
		// skip-verify together with a CA cert, so this stays correct if that guard
		// ever changes (issue #8).
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("cannot build CA transport: http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
		}
		t := dt.Clone()
		t.TLSClientConfig = &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec // G402: mirrors the explicit PANOS_SKIP_VERIFY opt-in; LoadConfig rejects the CA+skip-verify combination, so this is false whenever a CA pool is in use
			MinVersion:         tls.VersionTLS12,
		}
		c.Transport = t
	}
	if err := c.Setup(); err != nil {
		return nil, fmt.Errorf("pango setup: %w", err)
	}
	return c, nil
}

// newDeps assembles the tool dependencies from the connected client and the
// loaded config. JobWait comes from Config.JobWait (issue #30, Task 13 item),
// already validated to [1s, 24h] by LoadConfig; a zero value would make every
// commit and validate time out immediately.
func newDeps(client *pango.Client, cfg *Config, logger *slog.Logger, isPanorama bool) *tools.Deps {
	return &tools.Deps{
		Client:     client,
		Logger:     logger,
		IsPanorama: isPanorama,
		ReadOnly:   cfg.ReadOnly,
		JobWait:    cfg.JobWait,
	}
}

// buildServer creates the MCP server with all tools registered.
func buildServer(deps *tools.Deps) *mcp.Server {
	s := mcp.NewServer(
		&mcp.Implementation{Name: "panos-mcp-go", Version: version},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)
	tools.RegisterAll(s, deps)
	return s
}

// run connects to the device and serves MCP on the configured transport. The
// startup calls below are also the issue #14 warm-up: Setup, Initialize and
// RetrieveSystemInfo populate every lazily cached client field (con, api_url,
// Transport, systemInfo, Version) single-threaded, before the first concurrent
// handler runs.
func run(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	client, err := buildPangoClient(cfg)
	if err != nil {
		return err
	}
	if err := client.Initialize(ctx); err != nil {
		return fmt.Errorf("pango initialize: %w", err)
	}
	if err := client.RetrieveSystemInfo(ctx); err != nil {
		return fmt.Errorf("retrieving system info: %w", err)
	}
	pano, err := client.IsPanorama()
	if err != nil {
		return fmt.Errorf("detecting device type: %w", err)
	}
	logger.Info("connected to PAN-OS device",
		"host", cfg.Host, "panorama", pano,
		"version", client.Versioning().String(), "read_only", cfg.ReadOnly)

	s := buildServer(newDeps(client, cfg, logger, pano))
	if cfg.Transport == transportStdio {
		logger.Info("serving MCP on stdio")
		return s.Run(ctx, &mcp.StdioTransport{})
	}
	return serveHTTP(ctx, cfg, s, logger)
}

// requireBearer wraps next with bearer-token authentication (issue #5). It
// compares fixed-length SHA-256 digests of the presented and expected tokens with
// crypto/subtle.ConstantTimeCompare: comparing the raw strings would short-circuit
// on a length mismatch and leak the token length over repeated probes, whereas
// hashing to a constant 32 bytes first makes the comparison length-independent.
// The "Bearer" scheme is matched case-insensitively per RFC 6750. A mismatch gets
// 401 with a WWW-Authenticate challenge and never reaches the MCP handler.
func requireBearer(token string, next http.Handler) http.Handler {
	wantDigest := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, presented, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		gotDigest := sha256.Sum256([]byte(presented))
		if !ok || !strings.EqualFold(scheme, "Bearer") ||
			subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="panos-mcp-go"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newHTTPHandler builds the HTTP routing: the streamable MCP handler at /mcp,
// wrapped in bearer auth whenever a token is configured (loopback included:
// opt-in auth), plus an unauthenticated /health for liveness probes. The whole
// mux is wrapped in cross-origin protection (Go 1.25+), which blocks cross-site
// browser requests via Sec-Fetch-Site while allowing non-browser clients (no
// Sec-Fetch-Site) and same-origin requests; the go-sdk applies none by default in
// v1.7.0 (StreamableHTTPOptions.CrossOriginProtection is left nil), so without
// this a browser page could drive /mcp on a tokenless loopback bind (issue #5).
func newHTTPHandler(cfg *Config, s *mcp.Server, logger *slog.Logger) http.Handler {
	var mcpHandler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Logger: logger},
	)
	if cfg.HTTPToken != "" {
		mcpHandler = requireBearer(cfg.HTTPToken, mcpHandler)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": version})
	})
	return http.NewCrossOriginProtection().Handler(mux)
}

// listenAddr builds the host:port bind address, tolerating an IPv6 host the
// operator wrote with brackets (MCP_HTTP_HOST=[::1]). net.JoinHostPort adds its
// own brackets around a colon-bearing host, so a pre-bracketed host must be
// stripped first or it becomes [[::1]]:port and the bind fails. This matches the
// bracket handling in isLoopback.
func listenAddr(host string, port int) string {
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

// serveHTTP binds the configured address and serves the streamable HTTP
// transport with graceful shutdown.
func serveHTTP(ctx context.Context, cfg *Config, s *mcp.Server, logger *slog.Logger) error {
	addr := listenAddr(cfg.HTTPHost, cfg.HTTPPort)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	return serveHTTPOnListener(ctx, ln, cfg, s, logger)
}

// serveHTTPOnListener serves on an already-bound listener so a test can inject a
// port-0 listener and observe the real address. WriteTimeout is deliberately
// unset (0): the streamable transport serves long-lived text/event-stream
// responses and never overrides the server write deadline, so any non-zero
// WriteTimeout would sever active streams (verified go-sdk v1.7.0
// mcp/streamable.go). ReadTimeout and IdleTimeout still bound slow and idle
// connections.
func serveHTTPOnListener(ctx context.Context, ln net.Listener, cfg *Config, s *mcp.Server, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           newHTTPHandler(cfg, s, logger),
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	logger.Info("serving MCP on streamable HTTP",
		"addr", ln.Addr().String(), "path", "/mcp", "auth", cfg.HTTPToken != "")
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		// ctx is already Done (that is what triggered shutdown); Shutdown needs a
		// fresh deadline to drain in-flight requests. A long-lived streamable (SSE)
		// connection never becomes idle, so Shutdown can hit that deadline; force
		// the remaining connections closed so a requested shutdown still exits
		// promptly and returns a zero status rather than context.DeadlineExceeded.
		if err := srv.Shutdown(shCtx); err != nil { //nolint:contextcheck // the fresh deadline above is intentional
			logger.Warn("graceful shutdown timed out; forcing remaining connections closed", "error", err)
			_ = srv.Close()
		}
		return nil
	}
}
