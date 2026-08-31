package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretWiring records whether an extractor was passed to withSecrets on a create
// handler registration, an update handler registration, or both.
type secretWiring struct{ create, update bool }

// TestSecretExtractorsWiredToCreateAndUpdate is a structural tripwire over the
// tools package source: every secret extractor defined in redact.go must be wired
// through withSecrets into BOTH a create-handler and an update-handler
// registration. The per-family redaction tests (for example
// TestLdapProfileCreateRedactsSecretOnError) prove each wiring works end to end,
// but they exist only because someone remembered to write them. This test enforces
// the wiring itself, so a secret-bearing family whose update path lost its
// withSecrets(...) fails here even if its per-family test was never added.
//
// It also pins the SET of secret-bearing families. Adding a new one makes this
// test fail until the extractor is listed in wantExtractors below, which is the
// point: the failure lands the author on this comment, which tells them to pass
// withSecrets on both the create and the update registration and to add a
// per-family redaction test.
//
// LIMITATION: this checks that every DECLARED extractor is wired. It does NOT
// verify that every secret-bearing input FIELD has an extractor at all. A family
// with a write-only secret field but no extractor (as device group's
// authorization_code was before it was wired) is invisible here: it has no
// extractor to list, so nothing flags it. Catching that class would need a scan of
// the tool input structs for secret-shaped fields, which is left to review and to
// the per-family tests rather than to a heuristic here. A defined-but-entirely-
// unwired extractor is separately caught by the unused-code linter.
//
// Sabotage: delete withSecrets(ikeGatewaySecrets) from either the create or the
// update registration in vpn_tools.go and this turns red.
func TestSecretExtractorsWiredToCreateAndUpdate(t *testing.T) {
	// The secret-bearing families, keyed by their extractor in redact.go. Grep to
	// re-derive the set: grep -oE 'func [a-zA-Z]+Secrets\(' tools/redact.go yields
	// these extractors plus redactSecrets, which is the one non-extractor to drop
	// (the generic gatherSecrets/collectSecrets have a type-parameter list before
	// their paren and secretVals does not end in "Secrets", so neither matches).
	wantExtractors := map[string]struct{}{
		"deviceGroupSecrets":     {},
		"ldapProfileSecrets":     {},
		"tacacsProfileSecrets":   {},
		"radiusProfileSecrets":   {},
		"emailProfileSecrets":    {},
		"snmpTrapProfileSecrets": {},
		"ikeGatewaySecrets":      {},
		"localUserSecrets":       {},
		"administratorSecrets":   {},
		"authProfileSecrets":     {},
		"mfaProfileSecrets":      {},
	}

	got := collectWithSecretsWirings(t)

	// Every expected extractor must be wired to both a create and an update
	// registration. A nil entry means the walk found no wiring at all, which also
	// fails closed if parsing or the walk ever breaks (every wantExtractors entry
	// then reports missing rather than the test passing vacuously).
	for name := range wantExtractors {
		switch w := got[name]; {
		case w == nil:
			t.Errorf("secret extractor %s is never wired through withSecrets; a secret-bearing family must pass withSecrets(%s) on both its create and update registrations", name, name)
		case !w.create:
			t.Errorf("secret extractor %s is not wired into a create handler registration", name)
		case !w.update:
			t.Errorf("secret extractor %s is not wired into an update handler registration", name)
		}
	}
	// No unexpected extractor: a new secret-bearing family must be added to
	// wantExtractors (and get its own redaction test), not slip in unnoticed.
	for name := range got {
		if _, want := wantExtractors[name]; !want {
			t.Errorf("withSecrets(%s) is wired but %s is not in wantExtractors; add it here and add a per-family redaction test", name, name)
		}
	}
}

// collectWithSecretsWirings parses every non-test source file in the tools package
// and returns, per extractor, whether it was passed to withSecrets on a create
// and/or an update handler registration. It uses parser.ParseFile per file rather
// than the deprecated parser.ParseDir; build-tag-accurate package association is
// irrelevant here, since a withSecrets(...) wiring is worth checking whatever file
// it lives in.
//
// It matches withSecrets(<ident>) only where it sits as a direct argument to a
// create- or update-handler builder call (a package-level identifier ending in
// "Handler" whose name contains "Create" or "Update"). Both the generic
// createHandler/updateHandler and the scope-specific device/net/mgt variants match
// this shape. A withSecrets wired through some other shape (a closure argument, a
// builder invoked as a method or through a package qualifier) would not be seen; no
// registration uses such a shape today, and a change to that convention should
// update this walk.
func collectWithSecretsWirings(t *testing.T) map[string]*secretWiring {
	t.Helper()
	fset := token.NewFileSet()
	got := map[string]*secretWiring{}
	parsed := 0

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading tools package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		parsed++
		ast.Inspect(f, func(n ast.Node) bool {
			return visitCallForSecrets(n, got)
		})
	}
	if parsed == 0 {
		t.Fatal("no non-test .go files parsed in the tools package; the walk would vacuously pass")
	}
	return got
}

// visitCallForSecrets is the ast.Inspect visitor: for a call to a create/update
// handler builder, it records which of its arguments is a withSecrets(extractor)
// into got.
func visitCallForSecrets(n ast.Node, got map[string]*secretWiring) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return true
	}
	name := builderIdentName(call.Fun)
	if !strings.HasSuffix(name, "Handler") {
		return true
	}
	kind := handlerKind(name)
	if kind == "" {
		return true
	}
	for _, arg := range call.Args {
		ext := withSecretsExtractor(arg)
		if ext == "" {
			continue
		}
		w := got[ext]
		if w == nil {
			w = &secretWiring{}
			got[ext] = w
		}
		if kind == "create" {
			w.create = true
		} else {
			w.update = true
		}
	}
	return true
}

// builderIdentName returns the identifier name of a call's function expression,
// unwrapping a generic instantiation. A builder called with inferred type
// arguments (deviceCreateHandler(...)) is a bare *ast.Ident; one called with
// explicit type arguments (createHandler[L, E, In](...)) is an *ast.IndexExpr or
// *ast.IndexListExpr whose X is that Ident. It returns "" for anything else (a
// selector such as pkg.Fn or a method call), which the caller treats as "not a
// recognized builder".
func builderIdentName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.IndexExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// handlerKind classifies a handler-builder name as a create or update
// registration, or "" for neither. The match is case-insensitive so it catches
// both the scope-specific builders that carry the word at a camelCase boundary
// (deviceCreateHandler) and the generic builders that begin with it in lower case
// (createHandler, updateHandler).
func handlerKind(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "create"):
		return "create"
	case strings.Contains(lower, "update"):
		return "update"
	default:
		return ""
	}
}

// withSecretsExtractor returns the extractor identifier from a withSecrets(ext)
// argument expression, or "" when arg is not such a call.
func withSecretsExtractor(arg ast.Expr) string {
	ws, ok := arg.(*ast.CallExpr)
	if !ok {
		return ""
	}
	fn, ok := ws.Fun.(*ast.Ident)
	if !ok || fn.Name != "withSecrets" || len(ws.Args) != 1 {
		return ""
	}
	ext, ok := ws.Args[0].(*ast.Ident)
	if !ok {
		return ""
	}
	return ext.Name
}
