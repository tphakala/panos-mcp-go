package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tphakala/panos-mcp-go/tools"
)

func TestBuildPangoClientDefaults(t *testing.T) {
	c, err := buildPangoClient(&Config{Host: "fw.example.com", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Protocol != "https" {
		t.Errorf("Protocol = %q, want https", c.Protocol)
	}
	if c.Hostname != "fw.example.com" {
		t.Errorf("Hostname = %q, want fw.example.com", c.Hostname)
	}
	if c.SkipVerifyCertificate {
		t.Error("SkipVerifyCertificate = true, want false: TLS verification must default on")
	}
	// After Setup, pango always installs a default transport (client.go:287-296),
	// so a nil check is wrong; the marker of "no custom CA transport" is that no
	// root pool was installed.
	if c.Transport == nil || c.Transport.TLSClientConfig == nil {
		t.Fatalf("Transport/TLSClientConfig unexpectedly nil: %+v", c.Transport)
	}
	if c.Transport.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs must be nil without PANOS_CA_CERT")
	}
}

// TestBuildPangoClientDoesNotReadEnvironment pins CheckEnvironment=false: pango
// fills only empty client fields from the environment, and only when
// CheckEnvironment is true, so a set PANOS_USERNAME must not leak into a client
// that was built with an empty Username (issues #11, #4).
func TestBuildPangoClientDoesNotReadEnvironment(t *testing.T) {
	t.Setenv("PANOS_USERNAME", "env-user")
	c, err := buildPangoClient(&Config{Host: "fw", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "" {
		t.Errorf("Username = %q, want empty: pango must not read PANOS_USERNAME with CheckEnvironment=false", c.Username)
	}
}

func TestBuildPangoClientCACertMissing(t *testing.T) {
	_, err := buildPangoClient(&Config{Host: "fw", APIKey: "k", CACert: "/nonexistent/ca.pem"})
	if err == nil || !strings.Contains(err.Error(), "PANOS_CA_CERT") {
		t.Fatalf("error = %v, want a PANOS_CA_CERT read error", err)
	}
}

func TestBuildPangoClientCACertInvalid(t *testing.T) {
	bad := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPangoClient(&Config{Host: "fw", APIKey: "k", CACert: bad}); err == nil {
		t.Fatal("expected an error for an invalid CA pem")
	}
}

func TestBuildPangoClientCACertValid(t *testing.T) {
	ca := writeTestCA(t)
	c, err := buildPangoClient(&Config{Host: "fw", APIKey: "k", CACert: ca})
	if err != nil {
		t.Fatal(err)
	}
	tc := c.Transport.TLSClientConfig
	if tc == nil || tc.RootCAs == nil {
		t.Fatal("a CA cert must install a RootCAs pool")
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 (%d)", tc.MinVersion, tls.VersionTLS12)
	}
	if tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false when only a CA cert is set")
	}
	// The transport is cloned from http.DefaultTransport, so its proxy and dial
	// defaults survive rather than being dropped.
	if c.Transport.Proxy == nil {
		t.Error("Proxy = nil: the custom CA transport must inherit http.DefaultTransport defaults")
	}
}

// TestBuildPangoClientCACertMirrorsSkipVerify passes a contradictory pair
// directly, bypassing LoadConfig's guard on purpose, to pin that the custom
// transport carries InsecureSkipVerify from cfg.SkipVerify (the baseline omitted
// it, issue #8). LoadConfig rejects this combination, so it never reaches here in
// production.
func TestBuildPangoClientCACertMirrorsSkipVerify(t *testing.T) {
	ca := writeTestCA(t)
	c, err := buildPangoClient(&Config{Host: "fw", APIKey: "k", CACert: ca, SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true: the custom transport must mirror cfg.SkipVerify")
	}
	if !c.SkipVerifyCertificate {
		t.Error("SkipVerifyCertificate = false, want true")
	}
}

func TestBuildPangoClientSkipVerifyWithoutCA(t *testing.T) {
	c, err := buildPangoClient(&Config{Host: "fw", APIKey: "k", SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !c.SkipVerifyCertificate {
		t.Error("SkipVerifyCertificate = false, want true")
	}
	// No CA cert: no custom transport is built, so pango's own default carries the
	// skip flag and no root pool is installed.
	if c.Transport.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs must be nil when only PANOS_SKIP_VERIFY is set")
	}
}

func TestNewDepsCopiesConfig(t *testing.T) {
	client := &pango.Client{}
	logger := slog.New(slog.DiscardHandler)
	cfg := &Config{ReadOnly: false, JobWait: 37 * time.Second}
	d := newDeps(client, cfg, logger, true)
	if d.JobWait != 37*time.Second {
		t.Errorf("JobWait = %v, want 37s (issue #30)", d.JobWait)
	}
	if d.ReadOnly {
		t.Error("ReadOnly = true, want false")
	}
	if !d.IsPanorama {
		t.Error("IsPanorama = false, want true")
	}
	if d.Client != client {
		t.Error("Client not passed through")
	}
	if d.Logger != logger {
		t.Error("Logger not passed through")
	}
}

func TestListenAddr(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 8080, "127.0.0.1:8080"},
		{"0.0.0.0", 80, "0.0.0.0:80"},
		{"::1", 8080, "[::1]:8080"},
		{"[::1]", 8080, "[::1]:8080"}, // pre-bracketed must not double-bracket
		{"localhost", 9090, "localhost:9090"},
	} {
		if got := listenAddr(tc.host, tc.port); got != tc.want {
			t.Errorf("listenAddr(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// connectInMemory wires an in-memory client session to s and returns it.
func connectInMemory(t *testing.T, s *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Errorf("server session close: %v", err)
		}
	})
	cli := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := cli.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Errorf("client session close: %v", err)
		}
	})
	return cs
}

func testDeps() *tools.Deps {
	return &tools.Deps{Client: &pango.Client{}, Logger: slog.New(slog.DiscardHandler)}
}

// TestBuildServerReportsVersion pins that the build-stamped version reaches the
// MCP server-info handshake (issue #6). version is a package var; restore it.
func TestBuildServerReportsVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	version = "9.9.9-test"

	cs := connectInMemory(t, buildServer(testDeps()))
	info := cs.InitializeResult().ServerInfo
	if info.Version != "9.9.9-test" {
		t.Errorf("ServerInfo.Version = %q, want 9.9.9-test", info.Version)
	}
	if info.Name != "panos-mcp-go" {
		t.Errorf("ServerInfo.Name = %q, want panos-mcp-go", info.Name)
	}
}

// TestBuildServerRegistersTools pins that buildServer registers the tool set.
func TestBuildServerRegistersTools(t *testing.T) {
	cs := connectInMemory(t, buildServer(testDeps()))
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range res.Tools {
		if tool.Name == "panos_address_list" {
			found = true
			break
		}
	}
	if !found {
		t.Error("panos_address_list not registered: RegisterAll was not called")
	}
}

func TestRequireBearer(t *testing.T) {
	const token = "s3cr3t-token-value"
	for _, tc := range []struct {
		name     string
		auth     string
		setAuth  bool
		wantNext bool
	}{
		{"correct token", "Bearer " + token, true, true},
		{"lowercase scheme accepted", "bearer " + token, true, true},
		{"uppercase scheme accepted", "BEARER " + token, true, true},
		{"missing header", "", false, false},
		{"wrong token equal length", "Bearer " + strings.Repeat("x", len(token)), true, false},
		{"wrong token different length", "Bearer short", true, false},
		{"token with suffix", "Bearer " + token + "extra", true, false},
		{"no scheme separator", "Bearer" + token, true, false},
		{"wrong scheme with valid token", "Basic " + token, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled := false
			h := requireBearer(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
			if tc.setAuth {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if nextCalled != tc.wantNext {
				t.Fatalf("next called = %v, want %v", nextCalled, tc.wantNext)
			}
			if tc.wantNext {
				return
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if ch := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(ch, "Bearer ") {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", ch)
			}
		})
	}
}

// TestNewHTTPHandler pins the routing: /health is open, /mcp is bearer-gated only
// when a token is set, and cross-origin browser POSTs are refused regardless
// (issue #5).
func TestNewHTTPHandler(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := buildServer(testDeps())

	do := func(h http.Handler, method, path string, headers map[string]string) int {
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader("{}"))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	withToken := newHTTPHandler(&Config{HTTPToken: "tok"}, s, logger)
	noToken := newHTTPHandler(&Config{}, s, logger)

	t.Run("health is open without auth", func(t *testing.T) {
		if code := do(withToken, http.MethodGet, "/health", nil); code != http.StatusOK {
			t.Errorf("GET /health = %d, want 200", code)
		}
	})
	t.Run("mcp requires token when set", func(t *testing.T) {
		if code := do(withToken, http.MethodPost, "/mcp", nil); code != http.StatusUnauthorized {
			t.Errorf("POST /mcp without auth = %d, want 401", code)
		}
	})
	t.Run("mcp accepts the token", func(t *testing.T) {
		code := do(withToken, http.MethodPost, "/mcp", map[string]string{"Authorization": "Bearer tok"})
		if code == http.StatusUnauthorized {
			t.Errorf("POST /mcp with the bearer = 401, want auth to pass")
		}
	})
	t.Run("mcp open when no token", func(t *testing.T) {
		if code := do(noToken, http.MethodPost, "/mcp", nil); code == http.StatusUnauthorized {
			t.Error("POST /mcp = 401 with no token configured, want auth disabled")
		}
	})
	t.Run("cross-site browser POST is refused", func(t *testing.T) {
		// Even with the correct token, a cross-site browser request is blocked
		// before auth by cross-origin protection.
		code := do(withToken, http.MethodPost, "/mcp", map[string]string{
			"Authorization":  "Bearer tok",
			"Sec-Fetch-Site": "cross-site",
		})
		if code != http.StatusForbidden {
			t.Errorf("cross-site POST /mcp = %d, want 403", code)
		}
	})
}

// TestServeHTTPGracefulShutdown binds a real loopback listener, proves the
// server answers /health, then cancels the context and requires a clean return.
func TestServeHTTPGracefulShutdown(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := buildServer(testDeps())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveHTTPOnListener(ctx, ln, &Config{}, s, slog.New(slog.DiscardHandler))
	}()

	// Prove it is actually serving before shutting it down.
	url := "http://" + ln.Addr().String() + "/health"
	var resp *http.Response
	for range 50 {
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
		if rerr != nil {
			t.Fatal(rerr)
		}
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never answered /health: %v", err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("closing health response body: %v", cerr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v, want nil", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("serveHTTPOnListener did not return after context cancel")
	}
}
