package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	healthURL := "http://" + ln.Addr().String() + "/health"
	var resp *http.Response
	for range 50 {
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodGet, healthURL, http.NoBody)
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

// TestServeHTTPBindError pins the serveHTTP wrapper's error path (issue #33): a
// failed listen must be wrapped with the address and returned, not swallowed.
// serveHTTPOnListener is tested directly elsewhere, but the wrapper's own
// listen-and-wrap body had no coverage. Holding a port and then pointing
// serveHTTP at the same one forces the bind failure.
func TestServeHTTPBindError(t *testing.T) {
	var lc net.ListenConfig
	held, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	tcpAddr, ok := held.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T, want *net.TCPAddr", held.Addr())
	}

	cfg := &Config{HTTPHost: "127.0.0.1", HTTPPort: tcpAddr.Port}
	err = serveHTTP(t.Context(), cfg, buildServer(testDeps()), slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("serveHTTP must return an error when the listen fails")
	}
	if !strings.Contains(err.Error(), "listening on 127.0.0.1:") {
		t.Fatalf("error = %v, want it to wrap the listen failure with the address", err)
	}
}

// --- issue #33: integration coverage for run() warm-up and the forced-shutdown
// path. The helpers and the panFake below are shared by the tests that follow.

// captureHandler is a minimal slog.Handler that records every message and runs
// an optional per-record hook, so a test can observe a specific log line (for
// example, snapshot state the instant the server announces it is serving).
type captureHandler struct {
	mu   *sync.Mutex
	msgs *[]string
	hook func(slog.Record)
}

func (h captureHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle takes the Record by value because slog.Handler requires that signature.
//
//nolint:gocritic // hugeParam: the slog.Handler interface fixes this signature.
func (h captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	*h.msgs = append(*h.msgs, r.Message)
	h.mu.Unlock()
	if h.hook != nil {
		h.hook(r)
	}
	return nil
}

func (h captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h captureHandler) WithGroup(string) slog.Handler      { return h }

// waitForHealth polls base+"/health" until it returns 200 so a test never races
// the listener's first Accept.
func waitForHealth(t *testing.T, base string) {
	t.Helper()
	for range 100 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/health", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server never answered /health")
}

// callToolText returns the first text content block of a tool result, or "".
func callToolText(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// callSystemInfo connects a streamable client to base, calls panos_system_info,
// closes the session, and returns the tool's text result. Closing before return
// leaves no held stream, so a following shutdown drains cleanly.
func callSystemInfo(t *testing.T, base string) string {
	t.Helper()
	cli := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := cli.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: base + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("connecting streamable client: %v", err)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_system_info"})
	if err != nil {
		_ = cs.Close()
		t.Fatalf("calling panos_system_info: %v", err)
	}
	if err := cs.Close(); err != nil {
		t.Errorf("closing client session: %v", err)
	}
	if res.IsError {
		t.Fatalf("panos_system_info returned an error result: %s", callToolText(res))
	}
	return callToolText(res)
}

// panFake is a minimal PAN-OS XML API stand-in for driving run() end to end in
// package main. It answers <show><system><info> with a canned firewall body
// (unless systemInfoFails is set) and every other request with a PAN-OS error,
// recording each request so a test can assert what the warm-up sent and when. It
// plays the same role as the tools-package fake (tools/fake_test.go),
// reimplemented here because a _test.go file is not importable across packages;
// promote to an internal test-support package if more main-package integration
// tests come to need it.
type panFake struct {
	systemInfoFails bool

	mu       sync.Mutex
	requests []url.Values
}

func (p *panFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.requests = append(p.requests, r.Form)
		p.mu.Unlock()
		if !p.systemInfoFails && r.Form.Get("type") == "op" && strings.Contains(r.Form.Get("cmd"), "<system><info") {
			_, _ = io.WriteString(w, `<response status="success"><result><system>`+
				`<hostname>dev1</hostname><model>PA-VM</model>`+
				`<serial>0123456789</serial><sw-version>11.0.2</sw-version>`+
				`</system></result></response>`)
			return
		}
		_, _ = io.WriteString(w, `<response status="error"><msg><line>unmatched fake API request</line></msg></response>`)
	}
}

// sawSystemInfo reports whether a <show><system><info> op has been recorded.
func (p *panFake) sawSystemInfo() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, form := range p.requests {
		if form.Get("type") == "op" && strings.Contains(form.Get("cmd"), "<system><info") {
			return true
		}
	}
	return false
}

// newPanFake starts a TLS fake and returns it with the host and port a Config
// needs to reach it. buildPangoClient hardcodes https, so the fake must be TLS
// and the client must skip verification (httptest uses a self-signed cert).
func newPanFake(t *testing.T, f *panFake) (host string, port int) {
	t.Helper()
	ts := httptest.NewTLSServer(f.handler())
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err = strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}

// TestRunHTTPWarmupAndServe drives run() end to end against a fake PAN-OS device
// over the HTTP transport (issue #33). It pins the issue-#14 ordering invariant:
// the warm-up (RetrieveSystemInfo) must complete before the server starts
// serving, because the shared-client-field memory-safety argument in
// tools/tools.go (the writeMu doc block, "Read handlers are also memory-safe on
// the shared *pango.Client") relies on every shared client field being written
// only during startup (Setup, Initialize, RetrieveSystemInfo, IsPanorama) and
// read-only once tool calls can be dispatched concurrently. A capturing logger
// snapshots the fake's request log at the instant run() announces it is serving;
// the snapshot must already contain the system-info op.
func TestRunHTTPWarmupAndServe(t *testing.T) {
	fake := &panFake{}
	host, port := newPanFake(t, fake)

	type serveSnapshot struct {
		addr          string
		sawSystemInfo bool
	}
	served := make(chan serveSnapshot, 1)
	var (
		mu   sync.Mutex
		msgs []string
	)
	logger := slog.New(captureHandler{
		mu:   &mu,
		msgs: &msgs,
		hook: func(r slog.Record) {
			if r.Message != "serving MCP on streamable HTTP" {
				return
			}
			var addr string
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "addr" {
					addr = a.Value.String()
					return false
				}
				return true
			})
			select {
			case served <- serveSnapshot{addr: addr, sawSystemInfo: fake.sawSystemInfo()}:
			default:
			}
		},
	})

	cfg := &Config{
		Host:       host,
		Port:       port,
		APIKey:     "test-key",
		SkipVerify: true,
		JobWait:    5 * time.Second,
		Transport:  transportHTTP,
		HTTPHost:   "127.0.0.1",
		HTTPPort:   0,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, cfg, logger) }()

	var snap serveSnapshot
	select {
	case snap = <-served:
	case err := <-runErr:
		t.Fatalf("run returned before it began serving: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("run never announced it was serving")
	}

	if !snap.sawSystemInfo {
		t.Fatal("warm-up system-info was not sent before serving began (issue #14 ordering)")
	}

	base := "http://" + snap.addr
	waitForHealth(t, base)

	// A real tool call over the streamable transport proves the tools were
	// registered against the warmed, live client end to end.
	if got := callSystemInfo(t, base); !strings.Contains(got, "11.0.2") {
		t.Fatalf("panos_system_info result = %q, want it to carry the warmed sw-version 11.0.2", got)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run returned %v after cancel, want nil", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("run did not return after context cancel")
	}
}

// TestRunSystemInfoError pins that a warm-up failure aborts run() before serving,
// wrapped so the operator sees which step failed (issue #33). The fake refuses
// the system-info op, so RetrieveSystemInfo fails and run() returns synchronously.
func TestRunSystemInfoError(t *testing.T) {
	fake := &panFake{systemInfoFails: true}
	host, port := newPanFake(t, fake)

	cfg := &Config{
		Host:       host,
		Port:       port,
		APIKey:     "test-key",
		SkipVerify: true,
		JobWait:    5 * time.Second,
		Transport:  transportHTTP,
		HTTPHost:   "127.0.0.1",
		HTTPPort:   0,
	}
	err := run(t.Context(), cfg, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("run must fail when system-info retrieval fails")
	}
	if !strings.Contains(err.Error(), "retrieving system info") {
		t.Fatalf("error = %v, want it to wrap the system-info failure", err)
	}
}

// initMCPSession performs the JSON-RPC initialize handshake over POST /mcp and
// returns the assigned Mcp-Session-Id, so a follow-up GET can open a stateful
// SSE stream.
func initMCPSession(t *testing.T, base string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"shutdown-test","version":"0"}}}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize POST /mcp = %d, want 200", resp.StatusCode)
	}
	id := resp.Header.Get("Mcp-Session-Id")
	if id == "" {
		t.Fatal("initialize response carried no Mcp-Session-Id")
	}
	return id
}

// openHeldSSEStream opens a stateful GET /mcp event stream for the session and
// returns the live response with its body still open. The caller holds it so the
// server has a non-idle connection Shutdown cannot drain within its deadline.
func openHeldSSEStream(t *testing.T, base, sessionID string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/mcp", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("GET /mcp stream = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		_ = resp.Body.Close()
		t.Fatalf("stream Content-Type = %q, want text/event-stream", ct)
	}
	return resp
}

// TestServeHTTPShutdownDeadlineForcesClose exercises the force-close escalation
// (issue #33): a held streamable (SSE) connection never becomes idle, so
// srv.Shutdown hits its deadline and the code must fall back to srv.Close() and
// still return nil. shutdownTimeout is shortened via its test seam. The plain
// graceful-shutdown test drains cleanly and so cannot reach this path.
func TestServeHTTPShutdownDeadlineForcesClose(t *testing.T) {
	old := shutdownTimeout
	shutdownTimeout = 100 * time.Millisecond
	t.Cleanup(func() { shutdownTimeout = old })

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu   sync.Mutex
		msgs []string
	)
	logger := slog.New(captureHandler{mu: &mu, msgs: &msgs})
	s := buildServer(testDeps())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPOnListener(ctx, ln, &Config{}, s, logger) }()

	base := "http://" + ln.Addr().String()
	waitForHealth(t, base)

	sessionID := initMCPSession(t, base)
	stream := openHeldSSEStream(t, base, sessionID)
	t.Cleanup(func() { _ = stream.Body.Close() })

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("forced shutdown returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPOnListener did not return after the shutdown deadline")
	}

	mu.Lock()
	warned := slices.Contains(msgs, "graceful shutdown timed out; forcing remaining connections closed")
	mu.Unlock()
	if !warned {
		t.Error("expected the force-close warning to be logged")
	}

	// srv.Close() must have severed the held stream: a read now completes quickly
	// rather than blocking forever. Any outcome (EOF, reset) proves the sever; the
	// assertion is that it does not hang.
	readDone := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(stream.Body)
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("held SSE stream was not severed by srv.Close()")
	}
}
