package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRegisterAllToolCounts pins the total tool surface RegisterAll exposes per
// device type and write mode. The counts fold together every Register* gate:
// the object and policy read/write split, the Panorama-only device group and
// template lists, and the Panorama-only push. A miswired gate (a dropped
// d.ReadOnly or d.IsPanorama guard, or a missing Register* call in RegisterAll)
// shifts one of these totals.
func TestRegisterAllToolCounts(t *testing.T) {
	cases := []struct {
		model    string
		readOnly bool
		want     int
	}{
		{"PA-VM", false, 44},
		{"Panorama", false, 47},
		{"PA-VM", true, 18},
		{"Panorama", true, 20},
	}
	for _, c := range cases {
		d, _ := newTestDeps(t, c.model)
		d.ReadOnly = c.readOnly
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		RegisterAll(s, d)
		if got := len(serverToolNames(t, s)); got != c.want {
			t.Errorf("%s readOnly=%v: got %d tools, want %d", c.model, c.readOnly, got, c.want)
		}
	}
}

func TestClampList(t *testing.T) {
	cases := []struct{ limit, offset, n, lo, hi int }{
		{0, 0, 10, 0, 10},   // default limit covers all
		{3, 0, 10, 0, 3},    // limit applies
		{3, 8, 10, 8, 10},   // tail shorter than limit
		{3, 50, 10, 10, 10}, // offset beyond end
		{500, 0, 10, 0, 10}, // limit capped
		{5, -2, 10, 0, 5},   // negative offset clamped
	}
	for i, c := range cases {
		lo, hi := clampList(c.limit, c.offset, c.n)
		if lo != c.lo || hi != c.hi {
			t.Fatalf("case %d: got (%d,%d) want (%d,%d)", i, lo, hi, c.lo, c.hi)
		}
	}
}

func TestNormalizeRulebase(t *testing.T) {
	for in, want := range map[string]string{"": "pre-rulebase", "pre": "pre-rulebase", "post": "post-rulebase"} {
		got, err := normalizeRulebase(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %q err %v", in, got, err)
		}
	}
	if _, err := normalizeRulebase("sideways"); err == nil {
		t.Fatal("expected error for invalid rulebase")
	}
}

type fakeLoc struct{ kind, arg, rb string }

func fakeParts(rules bool) locParts[fakeLoc] {
	return locParts[fakeLoc]{
		shared:      func(rb string) fakeLoc { return fakeLoc{kind: "shared", rb: rb} },
		vsys:        func(v string) fakeLoc { return fakeLoc{kind: "vsys", arg: v} },
		deviceGroup: func(dg, rb string) fakeLoc { return fakeLoc{kind: "dg", arg: dg, rb: rb} },
		rules:       rules,
	}
}

func TestResolveLocationFirewall(t *testing.T) {
	d := &Deps{IsPanorama: false}
	loc, err := resolveLocation(d, LocationInput{}, fakeParts(false))
	if err != nil || loc.kind != "vsys" || loc.arg != "vsys1" {
		t.Fatalf("default: %+v err %v", loc, err)
	}
	loc, err = resolveLocation(d, LocationInput{Vsys: "vsys3"}, fakeParts(false))
	if err != nil || loc.arg != "vsys3" {
		t.Fatalf("explicit vsys: %+v err %v", loc, err)
	}
	if _, err = resolveLocation(d, LocationInput{DeviceGroup: "dg1"}, fakeParts(false)); err == nil {
		t.Fatal("device_group on firewall must error")
	}
	if _, err = resolveLocation(d, LocationInput{Rulebase: "pre"}, fakeParts(false)); err == nil {
		t.Fatal("rulebase on non-rule resource must error")
	}
	loc, err = resolveLocation(d, LocationInput{Shared: true}, fakeParts(false))
	if err != nil || loc.kind != "shared" {
		t.Fatalf("shared on firewall: %+v err %v", loc, err)
	}
	if _, err = resolveLocation(d, LocationInput{Shared: true}, fakeParts(true)); err == nil {
		t.Fatal("shared rulebase on a firewall must error")
	}
	if _, err = resolveLocation(d, LocationInput{Rulebase: "sideways"}, fakeParts(true)); err == nil {
		t.Fatal("an invalid rulebase must error through resolveLocation")
	}
}

func TestResolveLocationPanorama(t *testing.T) {
	d := &Deps{IsPanorama: true}
	loc, err := resolveLocation(d, LocationInput{}, fakeParts(false))
	if err != nil || loc.kind != "shared" {
		t.Fatalf("default: %+v err %v", loc, err)
	}
	loc, err = resolveLocation(d, LocationInput{DeviceGroup: "dg1", Rulebase: "post"}, fakeParts(true))
	if err != nil || loc.kind != "dg" || loc.arg != "dg1" || loc.rb != "post-rulebase" {
		t.Fatalf("dg rules: %+v err %v", loc, err)
	}
	loc, err = resolveLocation(d, LocationInput{DeviceGroup: "dg1"}, fakeParts(true))
	if err != nil || loc.rb != "pre-rulebase" {
		t.Fatalf("default rulebase must be pre: %+v err %v", loc, err)
	}
	if _, err = resolveLocation(d, LocationInput{Vsys: "vsys1"}, fakeParts(false)); err == nil {
		t.Fatal("vsys on Panorama must error")
	}
}

func TestResultHelpers(t *testing.T) {
	res, _ := errorResult("boom %d", 7)
	if !res.IsError {
		t.Fatal("errorResult must set IsError")
	}
	if !strings.Contains(textContent(t, res), "boom 7") {
		t.Fatal("errorResult must include the formatted message")
	}
	res, _ = jsonResult(map[string]int{"a": 1})
	if res.IsError {
		t.Fatal("jsonResult must not set IsError")
	}
	res, _ = textResult("hi")
	if res.IsError {
		t.Fatal("textResult must not set IsError")
	}
	if !strings.Contains(textContent(t, res), "hi") {
		t.Fatal("textResult content lost")
	}
}

func TestPtrAndStrVal(t *testing.T) {
	if p := ptr(42); p == nil || *p != 42 {
		t.Fatalf("ptr: got %v", p)
	}
	if strVal(nil) != "" {
		t.Fatal("strVal(nil) must be empty")
	}
	s := "x"
	if strVal(&s) != "x" {
		t.Fatal("strVal must dereference")
	}
}

// TestAnnotationHelpers pins the read/destructive/idempotent hints, which tell an
// MCP client whether a tool is safe to call: a mutator wrongly flagged read-only
// would read as safe. Every tool is open-world (it reaches the external device).
func TestAnnotationHelpers(t *testing.T) {
	cases := []struct {
		name                              string
		ann                               *mcp.ToolAnnotations
		title                             string
		readOnly, destructive, idempotent bool
	}{
		{"readOnly", readOnlyTool("Read"), "Read", true, false, false},
		{"create", createTool("Create"), "Create", false, false, false},
		{"update", updateTool("Update"), "Update", false, true, true},
		{"delete", deleteTool("Delete"), "Delete", false, true, true},
	}
	for _, c := range cases {
		a := c.ann
		if a.Title != c.title || a.ReadOnlyHint != c.readOnly || a.IdempotentHint != c.idempotent {
			t.Errorf("%s: title/readonly/idempotent = %q/%v/%v, want %q/%v/%v",
				c.name, a.Title, a.ReadOnlyHint, a.IdempotentHint, c.title, c.readOnly, c.idempotent)
		}
		if a.DestructiveHint == nil || *a.DestructiveHint != c.destructive {
			t.Errorf("%s: DestructiveHint %v, want %v", c.name, a.DestructiveHint, c.destructive)
		}
		if a.OpenWorldHint == nil || !*a.OpenWorldHint {
			t.Errorf("%s: must be open-world", c.name)
		}
	}
}

// fakeEntry and fakeSvc exercise the generic handler builders without pango.
type fakeEntry struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type fakeSvc struct {
	entries   []*fakeEntry
	deleted   []string
	created   []*fakeEntry
	updated   []*fakeEntry
	createErr error
	readErr   error
	updateErr error
	deleteErr error
	listErr   error
}

func (s *fakeSvc) Create(_ context.Context, _ fakeLoc, e *fakeEntry) (*fakeEntry, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	s.created = append(s.created, e)
	return e, nil
}

func (s *fakeSvc) Read(_ context.Context, _ fakeLoc, name, _ string) (*fakeEntry, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	for _, e := range s.entries {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("entry %q not found", name)
}

func (s *fakeSvc) Update(_ context.Context, _ fakeLoc, e *fakeEntry, _ string) (*fakeEntry, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	s.updated = append(s.updated, e)
	return e, nil
}

func (s *fakeSvc) Delete(_ context.Context, _ fakeLoc, names ...string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, names...)
	return nil
}

func (s *fakeSvc) List(_ context.Context, _ fakeLoc, _, _, _ string) ([]*fakeEntry, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.entries, nil
}

func handlerDeps() *Deps { return &Deps{Logger: slog.New(slog.DiscardHandler)} }

func okResolve(LocationInput) (fakeLoc, error) { return fakeLoc{kind: "vsys", arg: "vsys1"}, nil }

func entryName(e *fakeEntry) string { return e.Name }

func entrySummary(e *fakeEntry) any { return map[string]string{"name": e.Name} }

func TestListHandler(t *testing.T) {
	svc := &fakeSvc{entries: []*fakeEntry{{Name: "web-server"}, {Name: "db-server"}, {Name: "gateway"}}}
	h := listHandler[fakeLoc, fakeEntry](handlerDeps(), "panos_list", svc, okResolve, entryName, entrySummary)

	res, _, err := h(t.Context(), nil, ListInput{Filter: "server"})
	if err != nil || res.IsError {
		t.Fatalf("list: err=%v isErr=%v", err, res.IsError)
	}
	body := textContent(t, res)
	if !strings.Contains(body, `"total": 2`) || !strings.Contains(body, "web-server") || strings.Contains(body, "gateway") {
		t.Fatalf("filter/summary wrong: %s", body)
	}

	// A service error is surfaced as an error result, not a Go error.
	errSvc := &fakeSvc{listErr: fmt.Errorf("boom")}
	h = listHandler[fakeLoc, fakeEntry](handlerDeps(), "panos_list", errSvc, okResolve, entryName, entrySummary)
	res, _, err = h(t.Context(), nil, ListInput{})
	if err != nil || !res.IsError {
		t.Fatalf("service error must be an error result: err=%v isErr=%v", err, res.IsError)
	}
}

func TestGetHandler(t *testing.T) {
	svc := &fakeSvc{entries: []*fakeEntry{{Name: "a", Value: "1"}}}
	h := getHandler[fakeLoc, fakeEntry](handlerDeps(), "panos_get", svc, okResolve)

	if res, _, _ := h(t.Context(), nil, NameInput{}); !res.IsError {
		t.Fatal("empty name must be an error result")
	}
	res, _, err := h(t.Context(), nil, NameInput{Name: "a"})
	if err != nil || res.IsError || !strings.Contains(textContent(t, res), `"value": "1"`) {
		t.Fatalf("get existing: err=%v isErr=%v", err, res.IsError)
	}
	if res, _, _ := h(t.Context(), nil, NameInput{Name: "missing"}); !res.IsError {
		t.Fatal("missing entry must be an error result")
	}
}

func TestDeleteHandler(t *testing.T) {
	svc := &fakeSvc{}
	h := deleteHandler[fakeLoc, fakeEntry](handlerDeps(), "panos_delete", svc, okResolve)

	if res, _, _ := h(t.Context(), nil, NameInput{}); !res.IsError {
		t.Fatal("empty name must be an error result")
	}
	res, _, err := h(t.Context(), nil, NameInput{Name: "gone"})
	if err != nil || res.IsError {
		t.Fatalf("delete: err=%v isErr=%v", err, res.IsError)
	}
	if len(svc.deleted) != 1 || svc.deleted[0] != "gone" {
		t.Fatalf("delete must call the service with the name: %v", svc.deleted)
	}
}

func TestCreateHandler(t *testing.T) {
	svc := &fakeSvc{}
	build := func(in NameInput) (*fakeEntry, error) {
		if in.Name == "bad" {
			return nil, fmt.Errorf("bad input")
		}
		return &fakeEntry{Name: in.Name}, nil
	}
	loc := func(in NameInput) LocationInput { return in.Location }
	h := createHandler[fakeLoc, fakeEntry, NameInput](handlerDeps(), "panos_create", svc, okResolve, loc, build)

	if res, _, _ := h(t.Context(), nil, NameInput{Name: "bad"}); !res.IsError {
		t.Fatal("build error must be an error result")
	}
	res, _, err := h(t.Context(), nil, NameInput{Name: "new"})
	if err != nil || res.IsError {
		t.Fatalf("create: err=%v isErr=%v", err, res.IsError)
	}
	if len(svc.created) != 1 || svc.created[0].Name != "new" {
		t.Fatalf("create must call the service: %v", svc.created)
	}
}

func TestUpdateHandler(t *testing.T) {
	svc := &fakeSvc{entries: []*fakeEntry{{Name: "a", Value: "old"}}}
	name := func(in NameInput) string { return in.Name }
	loc := func(in NameInput) LocationInput { return in.Location }
	overlay := func(e *fakeEntry, _ NameInput) error { e.Value = "new"; return nil }
	h := updateHandler[fakeLoc, fakeEntry, NameInput](handlerDeps(), "panos_update", svc, okResolve, loc, name, overlay)

	if res, _, _ := h(t.Context(), nil, NameInput{}); !res.IsError {
		t.Fatal("empty name must be an error result")
	}
	res, _, err := h(t.Context(), nil, NameInput{Name: "a"})
	if err != nil || res.IsError {
		t.Fatalf("update: err=%v isErr=%v", err, res.IsError)
	}
	if len(svc.updated) != 1 || svc.updated[0].Value != "new" {
		t.Fatalf("update must apply the overlay before calling the service: %v", svc.updated)
	}
}

func errResolve(LocationInput) (fakeLoc, error) { return fakeLoc{}, fmt.Errorf("bad location") }

// TestHandlerErrorPaths pins that resolve failures, service failures, and an
// overlay failure all become error results (IsError set) rather than a Go error
// out of the handler, so the MCP layer reports them to the model as tool errors.
func TestHandlerErrorPaths(t *testing.T) {
	d := handlerDeps()
	loc := func(in NameInput) LocationInput { return in.Location }
	name := func(in NameInput) string { return in.Name }

	lh := listHandler[fakeLoc, fakeEntry](d, "l", &fakeSvc{}, errResolve, entryName, entrySummary)
	if res, _, err := lh(t.Context(), nil, ListInput{}); err != nil || !res.IsError {
		t.Fatalf("list resolve error: err=%v isErr=%v", err, res.IsError)
	}

	del := deleteHandler[fakeLoc, fakeEntry](d, "d", &fakeSvc{deleteErr: fmt.Errorf("x")}, okResolve)
	if res, _, err := del(t.Context(), nil, NameInput{Name: "a"}); err != nil || !res.IsError {
		t.Fatalf("delete svc error: err=%v isErr=%v", err, res.IsError)
	}

	build := func(NameInput) (*fakeEntry, error) { return &fakeEntry{Name: "a"}, nil }
	cr := createHandler[fakeLoc, fakeEntry, NameInput](d, "c", &fakeSvc{createErr: fmt.Errorf("x")}, okResolve, loc, build)
	if res, _, err := cr(t.Context(), nil, NameInput{Name: "a"}); err != nil || !res.IsError {
		t.Fatalf("create svc error: err=%v isErr=%v", err, res.IsError)
	}

	upRead := updateHandler[fakeLoc, fakeEntry, NameInput](d, "u", &fakeSvc{readErr: fmt.Errorf("x")}, okResolve, loc, name,
		func(*fakeEntry, NameInput) error { return nil })
	if res, _, err := upRead(t.Context(), nil, NameInput{Name: "a"}); err != nil || !res.IsError {
		t.Fatalf("update read error: err=%v isErr=%v", err, res.IsError)
	}

	upOverlay := updateHandler[fakeLoc, fakeEntry, NameInput](d, "u", &fakeSvc{entries: []*fakeEntry{{Name: "a"}}}, okResolve, loc, name,
		func(*fakeEntry, NameInput) error { return fmt.Errorf("overlay bad") })
	if res, _, err := upOverlay(t.Context(), nil, NameInput{Name: "a"}); err != nil || !res.IsError {
		t.Fatalf("update overlay error: err=%v isErr=%v", err, res.IsError)
	}

	upSvc := updateHandler[fakeLoc, fakeEntry, NameInput](d, "u", &fakeSvc{entries: []*fakeEntry{{Name: "a"}}, updateErr: fmt.Errorf("x")}, okResolve, loc, name,
		func(*fakeEntry, NameInput) error { return nil })
	if res, _, err := upSvc(t.Context(), nil, NameInput{Name: "a"}); err != nil || !res.IsError {
		t.Fatalf("update service error: err=%v isErr=%v", err, res.IsError)
	}
}

// TestMutationHandlersSerialize pins that the write lock in the mutation handlers
// actually serializes device writes: 50 concurrent createHandler calls must not
// race on the fake service and must all land. Deleting the defer d.LockWrites()()
// from createHandler makes the concurrent svc.Create calls race (the detector
// fires under -race) and lose appends.
func TestMutationHandlersSerialize(t *testing.T) {
	svc := &fakeSvc{}
	build := func(NameInput) (*fakeEntry, error) { return &fakeEntry{Name: "x"}, nil }
	loc := func(in NameInput) LocationInput { return in.Location }
	h := createHandler[fakeLoc, fakeEntry, NameInput](handlerDeps(), "c", svc, okResolve, loc, build)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, _, _ = h(t.Context(), nil, NameInput{Name: "x"})
		}()
	}
	wg.Wait()
	if len(svc.created) != n {
		t.Fatalf("createHandler must serialize writes: got %d creates, want %d", len(svc.created), n)
	}
}
