package tools

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeRoute matches an incoming XML API request and supplies a canned body.
type fakeRoute struct {
	Match func(v url.Values) bool
	Body  string
}

type fakeAPI struct {
	mu       sync.Mutex
	requests []url.Values
	routes   []fakeRoute
}

// Requests returns a snapshot of all recorded request form values. The slice is
// a fresh copy, but each url.Values map aliases the recorded request, so callers
// must treat the returned values as read-only.
func (f *fakeAPI) Requests() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeAPI) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.requests = append(f.requests, r.Form)
		routes := slices.Clone(f.routes)
		f.mu.Unlock()
		for _, rt := range routes {
			// A fakeRoute with a nil Match is a caller error; skip it rather than
			// panic in this server goroutine (net/http would turn the panic into
			// an opaque EOF at the client).
			if rt.Match != nil && rt.Match(r.Form) {
				_, _ = io.WriteString(w, rt.Body)
				return
			}
		}
		// An unmatched request returns a PAN-OS error, not success, so a later
		// test that forgets to register a required route fails loudly instead of
		// passing on a request it never modelled. PAN-OS signals errors with
		// HTTP 200 and status="error", which is what pango parses.
		_, _ = io.WriteString(w, `<response status="error"><msg><line>unmatched fake API request</line></msg></response>`)
	}
}

// opContains matches type=op requests whose cmd contains sub.
func opContains(sub string) func(url.Values) bool {
	return func(v url.Values) bool {
		return v.Get("type") == "op" && strings.Contains(v.Get("cmd"), sub)
	}
}

// opExact matches a type=op request whose cmd equals want exactly. Prefer it
// over opContains when a test must pin the precise command on the wire: a
// drifted or unmodelled command then falls through to the fake's
// unmatched-request error, the same way a real device rejects an unknown
// command. That leniency is what hid issue #42, where opContains("<diff")
// matched a command PAN-OS actually rejects as "invalid client cli".
func opExact(want string) func(url.Values) bool {
	return func(v url.Values) bool {
		return v.Get("type") == "op" && v.Get("cmd") == want
	}
}

// configAction matches type=config requests with the given action.
func configAction(action string) func(url.Values) bool {
	return func(v url.Values) bool {
		return v.Get("type") == "config" && v.Get("action") == action
	}
}

func systemInfoBody(model string) string {
	return `<response status="success"><result><system>` +
		`<hostname>dev1</hostname><model>` + model + `</model>` +
		`<serial>0123456789</serial><sw-version>11.0.2</sw-version>` +
		`</system></result></response>`
}

// newTestDeps builds a pango client against a fake XML API server and wraps
// it in Deps. model selects firewall ("PA-VM") or Panorama ("Panorama").
func newTestDeps(t *testing.T, model string, routes ...fakeRoute) (*Deps, *fakeAPI) {
	t.Helper()
	f := &fakeAPI{}
	// Caller routes are matched before the built-in system-info route, so a
	// caller route must be specific enough not to shadow <show><system><info>.
	// Routes are fixed here, before httptest.NewServer starts serving.
	f.routes = append(f.routes, routes...)
	f.routes = append(f.routes, fakeRoute{Match: opContains("<system><info"), Body: systemInfoBody(model)})
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	c := &pango.Client{Hostname: u.Hostname(), Port: port, Protocol: "http", ApiKey: "test-key"}
	if err := c.Setup(); err != nil {
		t.Fatalf("pango setup: %v", err)
	}
	ctx := t.Context()
	if err := c.Initialize(ctx); err != nil {
		t.Fatalf("pango initialize: %v", err)
	}
	if err := c.RetrieveSystemInfo(ctx); err != nil {
		t.Fatalf("system info: %v", err)
	}
	pano, err := c.IsPanorama()
	if err != nil {
		t.Fatalf("IsPanorama: %v", err)
	}
	return &Deps{
		Client:     c,
		Logger:     slog.New(slog.DiscardHandler),
		IsPanorama: pano,
		JobWait:    5 * time.Second,
	}, f
}

// TestLockWritesSerializes proves LockWrites gives mutual exclusion: concurrent
// writers guarded only by it must not race and must all land. Under -race an
// unlocked implementation would flag the counter write; a no-op unlock would
// deadlock the second acquirer.
func TestLockWritesSerializes(t *testing.T) {
	d := &Deps{}
	const workers = 50
	counter := 0
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			unlock := d.LockWrites()
			defer unlock()
			counter++
		}()
	}
	wg.Wait()
	if counter != workers {
		t.Fatalf("counter = %d, want %d: LockWrites must serialize writers", counter, workers)
	}
}

// TestMatchers pins the request matchers that later tools tests use to route
// fake responses. A matcher that silently stopped discriminating would make
// those tests assert against the wrong canned body.
func TestMatchers(t *testing.T) {
	// A substring other than the system-info one newTestDeps registers, so this
	// also proves opContains discriminates on an arbitrary op command.
	opReq := url.Values{"type": {"op"}, "cmd": {"<commit><partial></partial></commit>"}}
	if !opContains("<commit>")(opReq) {
		t.Error("opContains must match a type=op cmd containing the substring")
	}
	if opContains("<commit>")(url.Values{"type": {"config"}, "cmd": {"<commit>"}}) {
		t.Error("opContains must require type=op, not just the substring")
	}
	if opContains("<commit>")(url.Values{"type": {"op"}, "cmd": {"<show><config>"}}) {
		t.Error("opContains must not match a cmd lacking the substring")
	}

	// opExact routes only on the precise command, so any drift (a trailing space,
	// or an entirely different command) falls through to the fake's
	// unmatched-request error instead of matching: the strictness that would have
	// surfaced issue #42.
	exactOp := "<show><config><list><changes></changes></list></config></show>"
	if !opExact(exactOp)(url.Values{"type": {"op"}, "cmd": {exactOp}}) {
		t.Error("opExact must match a type=op cmd equal to want")
	}
	if opExact(exactOp)(url.Values{"type": {"op"}, "cmd": {exactOp + " "}}) {
		t.Error("opExact must require equality, not a prefix or trailing space")
	}
	if opExact("<validate></validate>")(url.Values{"type": {"op"}, "cmd": {exactOp}}) {
		t.Error("opExact must not match a different command")
	}
	if opExact(exactOp)(url.Values{"type": {"config"}, "cmd": {exactOp}}) {
		t.Error("opExact must require type=op, not just the cmd")
	}

	cfgReq := url.Values{"type": {"config"}, "action": {"set"}}
	if !configAction("set")(cfgReq) {
		t.Error("configAction must match type=config with the exact action")
	}
	if configAction("set")(url.Values{"type": {"config"}, "action": {"edit"}}) {
		t.Error("configAction must match the exact action, not a different one")
	}
	if configAction("set")(url.Values{"type": {"op"}, "action": {"set"}}) {
		t.Error("configAction must require type=config, not just the action")
	}
}

func TestNewTestDepsFirewall(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	if d.IsPanorama {
		t.Fatal("PA-VM must not be detected as Panorama")
	}
	if len(f.Requests()) == 0 {
		t.Fatal("expected recorded requests")
	}
}

func TestNewTestDepsPanorama(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	if !d.IsPanorama {
		t.Fatal("Panorama model must be detected as Panorama")
	}
}

// TestNilMatchRouteSkipped proves the handler skips a fakeRoute with a nil Match
// instead of panicking the server goroutine. newTestDeps registers the nil-Match
// route first, so if it were not skipped it would panic on the system-info
// request, surface as an EOF, and fail newTestDeps at RetrieveSystemInfo.
func TestNilMatchRouteSkipped(t *testing.T) {
	_, f := newTestDeps(t, "PA-VM", fakeRoute{Body: "<unused/>"})
	if len(f.Requests()) == 0 {
		t.Fatal("expected the system-info request to be recorded")
	}
}

// TestUnmatchedRequestReturnsError pins the fail-loud contract: a request that
// matches no route gets a PAN-OS error, not success, so a later test that
// forgets to register a required route cannot pass on an unmodelled request. It
// also records the request, so a test can still assert on Requests().
func TestUnmatchedRequestReturnsError(t *testing.T) {
	f := &fakeAPI{}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	form := url.Values{"type": {"op"}, "cmd": {"<unrouted/>"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `status="error"`) {
		t.Fatalf("unmatched request must get status=error, got: %s", body)
	}
	if len(f.Requests()) != 1 {
		t.Fatalf("the unmatched request should still be recorded, got %d", len(f.Requests()))
	}
}

// textContent extracts the first text content block from a result. Content
// stores pointer values because mcp.TextContent's MarshalJSON has a pointer
// receiver, so the element is *mcp.TextContent.
func textContent(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// assertNoConfigWrite fails if the fake recorded any config-write action
// (multi-config, edit, or set), naming the offending action. Used by the
// no-op update tests, where an identical overlay must issue no write.
func assertNoConfigWrite(t *testing.T, f *fakeAPI) {
	t.Helper()
	for _, req := range f.Requests() {
		if a := req.Get("action"); a == "multi-config" || a == "edit" || a == "set" {
			t.Fatalf("no-op update must not issue a config write, got action=%q", a)
		}
	}
}

// connectInMemory wires an in-memory client session to srv and returns it,
// registering both session closes as cleanups.
func connectInMemory(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Errorf("server session close: %v", err)
		}
	})
	cli := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0"}, nil)
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

// serverToolNames connects an in-memory client session to srv and returns the
// set of tool names srv exposes. Shared by all registration tests.
func serverToolNames(t *testing.T, srv *mcp.Server) map[string]bool {
	t.Helper()
	ctx := t.Context()
	cs := connectInMemory(t, srv)

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tl := range res.Tools {
		names[tl.Name] = true
	}
	return names
}
