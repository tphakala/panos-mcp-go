package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// secretVocab is the set of case-insensitive substrings that mark a tool input
// field as secret-shaped by NAME. It is deliberately the caller-facing
// vocabulary from issue #115 (password, secret, key, community, keytab, hash,
// authorization_code), matched against a field's json tag name and, as a
// fallback for a field that carries no json tag, the snake_cased Go field name.
//
// The list is intentionally narrow. Broader tokens that pervade PAN-OS config as
// plain object references rather than secrets are left OUT on purpose: "cert"
// would fire on every certificate_profile reference, "auth" on every
// authentication_profile and auth_protocol, "token" and "credential" on nothing
// that exists here. Adding a token widens what must be covered or allowlisted, so
// add one only alongside a real secret field it needs to catch.
//
// The heuristic is name-shaped, so a genuinely-secret field whose name matches no
// token is invisible to this scan. One such field exists in the tree today:
// MfaVendorConfigInput.Value (json "value"), a write-only value that may hold a
// vendor secret and is redacted by mfaProfileSecrets. It is safe not because this
// scan catches it but because the sibling wiring tripwire
// (TestSecretExtractorsWiredToCreateAndUpdate) keeps its extractor wired. A future
// secret named value/pin/code given NO extractor would slip both the vocabulary
// here and, having no extractor, that wiring tripwire; catching it is the ceiling
// of a name heuristic and is left to review and the per-family redaction tests.
var secretVocab = []string{
	"password",
	"secret",
	"key",
	"community",
	"keytab",
	"hash",
	"authorization_code",
}

// secretField locates one secret-shaped scalar string field on a tool input
// struct: its owning *Input type, the Go field name, and the json tag name (empty
// when the field carries no json tag).
type secretField struct {
	structName string
	fieldName  string
	jsonName   string
}

func (f secretField) key() string { return f.structName + "." + f.fieldName }

// TestSecretShapedInputFieldsHaveRedactionExtractor is the heuristic tripwire
// that TestSecretExtractorsWiredToCreateAndUpdate documents as its own blind
// spot: it scans the tool input structs themselves for a secret-shaped FIELD that
// no redaction extractor reads. That is the exact class the DeviceGroupInput
// authorization_code leak (PR #113, issue #115) belonged to: a write-only secret
// field with no extractor at all, so the wiring tripwire could not see it because
// there was no extractor to list.
//
// The "covered" set is derived from the bodies of the per-family extractors in
// redact.go (the fields they actually read), NOT from a hand-maintained list, so
// the check is not circular with the extractor set: a new secret-shaped field
// that no extractor reads fails here whether or not anyone added an extractor for
// it. Removing in.AuthorizationCode from deviceGroupSecrets (making it return nil)
// drops (DeviceGroupInput, AuthorizationCode) from the covered set and turns this
// test red, which is the sabotage that proves it can fail.
//
// A secret-shaped field that is genuinely NOT a secret (a reference to another
// object by name that happens to match the vocabulary) is acknowledged in
// secretFieldAllowlist with a reason. That list is itself checked for staleness,
// so an entry that stops matching the vocabulary (the field was renamed or
// removed) fails rather than lingering.
func TestSecretShapedInputFieldsHaveRedactionExtractor(t *testing.T) {
	// Acknowledged non-secret fields whose name matches the vocabulary. Each entry
	// is a reference to another object by name, returned by its get projection, not
	// a value that must be redacted. Keyed by "StructName.FieldName".
	secretFieldAllowlist := map[string]string{
		"AdministratorInput.PasswordProfile": "reference to a password-profile object by name (see panos_password_profile_list), not a secret; the get projection returns it verbatim",
		"OspfMd5KeyInput.KeyID":              "MD5 key identifier (1-255), not key material; the matching secret is OspfMd5KeyInput.Key, collected by ospfAuthProfileSecrets. The get projection returns the ID verbatim",
	}

	found := secretShapedInputFields(t)
	covered := extractorCoveredFields(t)

	// Positive control: the machinery must actually see the field whose leak
	// motivated this test, and see it as covered. If the scan or the coverage walk
	// silently stops matching it, every other assertion below could pass vacuously.
	if !containsField(found, "DeviceGroupInput", "AuthorizationCode") {
		t.Fatal("scan did not classify DeviceGroupInput.AuthorizationCode as secret-shaped; the field scan or vocabulary is broken and the test would pass vacuously")
	}
	if !covered["DeviceGroupInput.AuthorizationCode"] {
		t.Fatal("coverage walk did not find deviceGroupSecrets reading DeviceGroupInput.AuthorizationCode; the redact.go walk is broken and the test would pass vacuously")
	}

	for _, f := range found {
		if covered[f.key()] {
			continue
		}
		if reason, ok := secretFieldAllowlist[f.key()]; ok {
			t.Logf("allowlisted non-secret field %s (json %q): %s", f.key(), f.jsonName, reason)
			continue
		}
		t.Errorf("secret-shaped input field %s (json %q) has no redaction extractor reading it; add a *Secrets extractor in redact.go that reads it, wire it through withSecrets on the create and update registrations, or (if it is genuinely not a secret) add it to secretFieldAllowlist with a reason", f.key(), f.jsonName)
	}

	// Staleness guard: an allowlisted key that the scan no longer reports as
	// secret-shaped is dead weight that hides intent. Fail so it is removed.
	foundKeys := map[string]bool{}
	for _, f := range found {
		foundKeys[f.key()] = true
	}
	for key := range secretFieldAllowlist {
		if !foundKeys[key] {
			t.Errorf("secretFieldAllowlist entry %s no longer matches any secret-shaped input field; remove it", key)
		}
	}
}

// secretShapedInputFields parses every non-test source file in the tools package
// and returns the scalar string (string or *string) fields on *Input structs
// whose json tag name, or snake_cased Go name, matches secretVocab. It excludes
// slice and non-string fields on purpose: Hash (json "hash", a []string of
// authentication-algorithm names in a crypto-profile input) matches the "hash"
// vocabulary token yet is not a secret, and the scalar-string filter is what keeps
// it from being flagged.
func secretShapedInputFields(t *testing.T) []secretField {
	t.Helper()
	var out []secretField
	structsSeen := 0
	for _, f := range parseToolsPackage(t) {
		fields, seen := inputStructSecretFields(f)
		out = append(out, fields...)
		structsSeen += seen
	}

	if structsSeen == 0 {
		t.Fatal("no *Input structs found in the tools package; the scan matched nothing and the test would pass vacuously")
	}
	if len(out) == 0 {
		t.Fatal("no secret-shaped input fields found; the vocabulary or the field match is broken (the tree has known secret fields such as authorization_code)")
	}
	// Deterministic order so failures read the same across runs.
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// inputStructSecretFields walks one parsed file and returns its secret-shaped
// scalar string fields together with the count of *Input structs it saw (the
// count feeds the caller's fail-closed guard).
func inputStructSecretFields(f *ast.File) (fields []secretField, structsSeen int) {
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || !strings.HasSuffix(ts.Name.Name, "Input") {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		structsSeen++
		fields = append(fields, secretFieldsInStruct(ts.Name.Name, st)...)
		return true
	})
	return fields, structsSeen
}

// secretFieldsInStruct returns the secret-shaped scalar string fields declared on
// one struct type.
func secretFieldsInStruct(structName string, st *ast.StructType) []secretField {
	var out []secretField
	for _, field := range st.Fields.List {
		if !isScalarStringField(field.Type) {
			continue
		}
		jsonName := jsonTagName(field.Tag)
		for _, name := range field.Names {
			if isSecretShaped(jsonName, name.Name) {
				out = append(out, secretField{structName, name.Name, jsonName})
			}
		}
	}
	return out
}

// extractorCoveredFields parses redact.go and returns the (struct, field) pairs
// whose value is actually collected as a secret by a per-family extractor, keyed
// by "StructName.FieldName". It delegates to coveredFieldsFromExtractors and adds
// the fail-closed guard; reading redact.go alone is enough because the extractors
// live there by convention (see its "per-family secret extractors" section).
func extractorCoveredFields(t *testing.T) map[string]bool {
	t.Helper()
	f := parseRedactGo(t)
	covered := coveredFieldsFromExtractors(f)
	if len(covered) == 0 {
		t.Fatal("no fields read by any extractor in redact.go; the coverage walk is broken and every field would report uncovered")
	}
	return covered
}

// coveredFieldsFromExtractors is the coverage walk over a parsed source file,
// split out from the redact.go read so it can be unit-tested against synthetic
// extractors (see TestCoveredFieldsFromExtractors). For each per-family extractor
// (a package-level func whose name ends in "Secrets") it resolves the input-field
// selectors that its result actually COLLECTS, tracking each parameter's XxxInput
// type: the extractor's own parameter and each collectSecrets getter's parameter.
//
// Coverage is credited only through the two shapes a per-family extractor uses to
// build its result: an argument to secretVals(...), or the selector a
// collectSecrets(list, getter) getter returns. A selector that merely appears in a
// return expression some other way (an `if in.X != nil` guard, an ignored argument
// to an immediately-invoked closure) collects no value and is NOT counted: crediting
// it would report a field redacted when its value never enters the returned slice.
// New extractors must keep the secretVals / collectSecrets shape; one that builds
// its result another way fails the scan loudly (a false flag) rather than silently
// under-reporting a real secret.
func coveredFieldsFromExtractors(f *ast.File) map[string]bool {
	covered := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasSuffix(fn.Name.Name, "Secrets") || fn.Body == nil {
			continue
		}
		env := map[string]string{}
		addParams(env, fn.Type.Params)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				recordCollectedSecrets(call, env, covered)
			}
			return true
		})
	}
	return covered
}

// recordCollectedSecrets records the input-field selectors that one secretVals or
// collectSecrets call collects. secretVals(a, b, ...) collects each selector
// argument; collectSecrets(list, func(s Elem) *string { return s.Field }) collects
// the selectors its getter returns (the getter's parameter is added to a local env
// so per-element types like s.Secret resolve, kept per call so the three
// same-named snmpTrap getters do not collapse to one element type).
func recordCollectedSecrets(call *ast.CallExpr, env map[string]string, covered map[string]bool) {
	fnID, ok := call.Fun.(*ast.Ident)
	if !ok {
		return
	}
	switch fnID.Name {
	case "secretVals":
		for _, arg := range call.Args {
			recordSelector(arg, env, covered)
		}
	case "collectSecrets":
		if len(call.Args) != 2 {
			return
		}
		getter, ok := call.Args[1].(*ast.FuncLit)
		if !ok {
			return
		}
		inner := maps.Clone(env)
		addParams(inner, getter.Type.Params)
		ast.Inspect(getter.Body, func(n ast.Node) bool {
			if ret, ok := n.(*ast.ReturnStmt); ok {
				for _, r := range ret.Results {
					recordSelector(r, inner, covered)
				}
			}
			return true
		})
	}
}

// recordSelector records expr when it is a base-identifier selector (id.Field)
// whose identifier is an in-scope XxxInput parameter.
func recordSelector(expr ast.Expr, env map[string]string, covered map[string]bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if st := env[id.Name]; st != "" {
			covered[st+"."+sel.Sel.Name] = true
		}
	}
}

// addParams records each parameter whose type is XxxInput or *XxxInput, mapping
// the parameter name to the struct type name. Both shapes occur: the extractor's
// own parameter is a pointer (in *DeviceGroupInput), a func-literal element
// parameter is a value (s TacacsServerInput).
func addParams(env map[string]string, params *ast.FieldList) {
	if params == nil {
		return
	}
	for _, p := range params.List {
		st := inputTypeName(p.Type)
		if st == "" {
			continue
		}
		for _, name := range p.Names {
			env[name.Name] = st
		}
	}
}

// inputTypeName returns the type name for an XxxInput or *XxxInput expression, or
// "" for anything else.
func inputTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok && strings.HasSuffix(id.Name, "Input") {
		return id.Name
	}
	return ""
}

// isScalarStringField reports whether a struct field's type is string or *string
// (and not a slice, map, or other composite).
func isScalarStringField(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "string"
}

// jsonTagName returns the json field name from a struct field tag ("x" from
// `json:"x,omitzero"`), or "" when the field has no json tag.
func jsonTagName(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	name, _, _ := strings.Cut(reflect.StructTag(strings.Trim(tag.Value, "`")).Get("json"), ",")
	return name
}

// isSecretShaped reports whether a field's json name or snake_cased Go name
// contains a secretVocab token.
func isSecretShaped(jsonName, goName string) bool {
	target := strings.ToLower(jsonName) + " " + snakeCaseField(goName)
	for _, tok := range secretVocab {
		if strings.Contains(target, tok) {
			return true
		}
	}
	return false
}

// snakeCaseField lowercases a Go field name and inserts an underscore before each
// interior uppercase letter, so AuthorizationCode becomes authorization_code.
// This is a fallback so a secret field that carries no json tag is still matched;
// it need not be a perfect snake_case, only good enough for substring matching.
func snakeCaseField(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// containsField reports whether fields includes one on structName named
// fieldName.
func containsField(fields []secretField, structName, fieldName string) bool {
	for _, f := range fields {
		if f.structName == structName && f.fieldName == fieldName {
			return true
		}
	}
	return false
}

// parseToolsPackage parses every non-test .go file in the current (tools package)
// directory and returns the parsed files. It fails closed: a parse error or an
// empty package is fatal, so the scans built on it cannot pass vacuously.
func parseToolsPackage(t *testing.T) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading tools package dir: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files parsed in the tools package; the scan would vacuously pass")
	}
	return files
}

// TestIsSecretShapedMatching pins the vocabulary matcher, including the two
// branches the struct scan does not exercise on the current tree: a field with no
// json tag (decided on the snake_cased Go name) and a name that matches no token.
// Sabotage: dropping a token from secretVocab, or breaking snakeCaseField, reddens
// a row here.
func TestIsSecretShapedMatching(t *testing.T) {
	cases := []struct {
		json, goName string
		want         bool
	}{
		{"authorization_code", "AuthorizationCode", true},
		{"bind_password", "BindPassword", true},
		{"pre_shared_key", "PreSharedKey", true},
		{"community", "Community", true},
		{"", "PasswordHash", true},      // no json tag: matched via the snake_cased Go name
		{"", "AuthorizationCode", true}, // no json tag: snakeCaseField gives authorization_code
		{"value", "Value", false},       // a real secret whose name is not secret-shaped
		{"description", "Description", false},
		{"certificate_profile", "CertificateProfile", false},
	}
	for _, c := range cases {
		if got := isSecretShaped(c.json, c.goName); got != c.want {
			t.Errorf("isSecretShaped(%q, %q) = %v, want %v", c.json, c.goName, got, c.want)
		}
	}
}

// TestCoveredFieldsFromExtractors pins the coverage walk against synthetic
// extractors, including the negative controls the redact.go tree does not exercise:
// a selector used only in a condition, and a selector handed to an immediately
// invoked closure that discards it, must NOT be counted as covered, because neither
// puts the value into the returned secret slice. Without that, an extractor could
// name a secret field while redacting nothing and still report the field covered.
func TestCoveredFieldsFromExtractors(t *testing.T) {
	const src = `package tools
func directSecrets(in *DirectInput) []string { return secretVals(in.Password, in.Token) }
func elemSecrets(in *ElemProfileInput) []string {
	return collectSecrets(in.Servers, func(s ElemServerInput) *string { return s.Secret })
}
func condOnlySecrets(in *CondInput) []string {
	if in.Password != nil {
		return nil
	}
	return nil
}
func iifeSecrets(in *IifeInput) []string {
	return func(_ bool) []string { return nil }(in.Password != nil)
}
func notAnExtractor(in *OtherInput) string { return *in.Password }
`
	f, err := parser.ParseFile(token.NewFileSet(), "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parsing synthetic source: %v", err)
	}
	covered := coveredFieldsFromExtractors(f)

	for _, want := range []string{"DirectInput.Password", "DirectInput.Token", "ElemServerInput.Secret"} {
		if !covered[want] {
			t.Errorf("%s should be covered (collected by secretVals/collectSecrets) but is not", want)
		}
	}
	// Negative controls: a condition-only selector, an ignored-argument selector,
	// and a field read by a func that is not an extractor must NOT count.
	for _, notWant := range []string{"CondInput.Password", "IifeInput.Password", "OtherInput.Password"} {
		if covered[notWant] {
			t.Errorf("%s must NOT be covered: its value never enters a returned secret slice", notWant)
		}
	}
}
