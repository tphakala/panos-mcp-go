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
// It also pins the SET of secret-bearing families three ways: the extractors
// DECLARED in redact.go, those listed in wantExtractors below, and those actually
// WIRED must all agree. So a new fooSecrets extractor added to redact.go but never
// wired (or never listed here) fails this test rather than passing silently, which
// is the point: the failure lands the author on this comment, which tells them to
// pass withSecrets on both the create and the update registration and to add a
// per-family redaction test.
//
// LIMITATION: this checks that every DECLARED extractor is listed and wired. It
// does NOT verify that every secret-bearing input FIELD has an extractor at all. A
// family with a write-only secret field but no extractor (as device group's
// authorization_code was before it was wired) is invisible here: it has no
// extractor to declare, so nothing flags it. That class IS caught by
// TestSecretShapedInputFieldsHaveRedactionExtractor, which scans the tool input
// structs for a secret-shaped field no extractor reads; the two tripwires are
// complementary, this one over the extractor set and that one over the field set.
//
// Sabotage: delete withSecrets(ikeGatewaySecrets) from either the create or the
// update registration in vpn_tools.go and this turns red.
func TestSecretExtractorsWiredToCreateAndUpdate(t *testing.T) {
	// The secret-bearing families, keyed by their extractor in redact.go. This list
	// is cross-checked against the extractors actually declared in redact.go below,
	// so it cannot silently drift: adding an extractor there without adding it here
	// (or vice versa) fails the test.
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
	// wantExtractors must equal the extractors actually declared in redact.go.
	// Without this, a new fooSecrets extractor added to redact.go but never wired
	// appears in neither wantExtractors nor got, so the two loops above would pass
	// while its secret went unredacted on the write-error path. Deriving the
	// declared set closes that: the extractor shows up here even with no wiring.
	declared := declaredSecretExtractors(t)
	for name := range declared {
		if _, want := wantExtractors[name]; !want {
			t.Errorf("redact.go declares extractor %s but it is not in wantExtractors; add it here and wire withSecrets(%s) on both its create and update registrations", name, name)
		}
	}
	for name := range wantExtractors {
		if _, ok := declared[name]; !ok {
			t.Errorf("wantExtractors lists %s but redact.go declares no such extractor; remove it here or restore the extractor", name)
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

// declaredSecretExtractors parses redact.go and returns the set of per-family
// secret extractor functions declared there, keyed by name. An extractor is a
// package-level function whose name ends in "Secrets" with the shape
// func(*XxxInput) []string, which selects the per-family extractors and excludes
// the helpers (redactSecrets, gatherSecrets, collectSecrets, secretVals,
// isSecretBearing) that have a different signature. The extractors live in
// redact.go by convention (see its "per-family secret extractors" section), so
// parsing that one file is enough.
func declaredSecretExtractors(t *testing.T) map[string]struct{} {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "redact.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing redact.go: %v", err)
	}
	out := map[string]struct{}{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasSuffix(fn.Name.Name, "Secrets") {
			continue
		}
		if isSecretExtractorSig(fn.Type) {
			out[fn.Name.Name] = struct{}{}
		}
	}
	if len(out) == 0 {
		t.Fatal("no secret extractors found in redact.go; the signature match is broken and the cross-check would pass vacuously")
	}
	return out
}

// isSecretExtractorSig reports whether ft is the extractor shape
// func(*XxxInput) []string: no type parameters, exactly one non-variadic
// parameter that is a pointer to an identifier ending in "Input", and a single
// []string result. This is what tells a per-family extractor apart from the
// generic redaction helpers in redact.go.
func isSecretExtractorSig(ft *ast.FuncType) bool {
	if ft.TypeParams != nil && len(ft.TypeParams.List) > 0 {
		return false
	}
	if ft.Params == nil || len(ft.Params.List) != 1 {
		return false
	}
	p := ft.Params.List[0]
	if len(p.Names) > 1 {
		return false
	}
	star, ok := p.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	if !ok || !strings.HasSuffix(id.Name, "Input") {
		return false
	}
	if ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	arr, ok := ft.Results.List[0].Type.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := arr.Elt.(*ast.Ident)
	return ok && elt.Name == "string"
}
