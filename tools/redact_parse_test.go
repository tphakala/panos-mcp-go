package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseRedactGo parses redact.go into an AST, failing the test closed on a
// read/parse error. Both secret-redaction tripwires (declaredSecretExtractors in
// registration_redaction_test.go and extractorCoveredFields in
// secret_field_scan_test.go) read the per-family secret extractors from that one
// file (see its "per-family secret extractors" section), so they share this parse
// rather than each spelling out parser.ParseFile with its own fail-closed guard
// (issue #125).
func parseRedactGo(t *testing.T) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "redact.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing redact.go: %v", err)
	}
	return f
}
