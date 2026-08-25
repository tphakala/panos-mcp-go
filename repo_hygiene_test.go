package main

import (
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestGoVersionCoordinated fails when the Go version drifts between go.mod, the
// Dockerfile builder image, the CI and release workflows, and the README. The
// docker Dependabot ecosystem can bump "FROM golang:1.xx-alpine" on its own; when
// it does, this test goes red until go.mod, both workflows, and the README are
// bumped in the same PR. That coupling is the point (issue #40).
func TestGoVersionCoordinated(t *testing.T) {
	sources := []struct {
		path    string
		pattern string
	}{
		{"go.mod", `(?m)^go (\d+\.\d+)`}, // reference: "go 1.27.0" -> "1.27"
		{"Dockerfile", `golang:(\d+\.\d+)`},
		{".github/workflows/ci.yml", `go-version:\s*"(\d+\.\d+)`},
		{".github/workflows/release.yml", `go-version:\s*"(\d+\.\d+)`},
		{"README.md", `Requires Go (\d+\.\d+)`},
	}

	var reference string
	for _, s := range sources {
		b, err := os.ReadFile(s.path) //nolint:gosec // G304: fixed in-repo doc and config paths from a constant table, not user input
		if err != nil {
			t.Fatalf("reading %s: %v", s.path, err)
		}
		m := regexp.MustCompile(s.pattern).FindSubmatch(b)
		if m == nil {
			t.Fatalf("no Go version marker in %s (pattern %q); if the line moved or changed shape, update repo_hygiene_test.go", s.path, s.pattern)
		}
		got := string(m[1])
		if reference == "" {
			reference = got // go.mod is listed first and is the source of truth
			continue
		}
		if got != reference {
			t.Errorf("Go version drift: go.mod says %s but %s says %s; bump go.mod, Dockerfile, ci.yml, release.yml, and README.md together", reference, s.path, got)
		}
	}
}

// TestNoEmOrEnDashes enforces the repo convention that forbids em (U+2014) and
// en (U+2013) dashes in tracked files. The two runes are referenced by code
// point (rune(0x2014)/rune(0x2013)), never as literal glyphs, so this test file
// does not flag itself.
func TestNoEmOrEnDashes(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "git", "ls-files").Output()
	if err != nil {
		t.Skipf("git ls-files failed (%v); the dash guard needs a git checkout", err)
	}

	files := make([]string, 0, strings.Count(string(out), "\n")+1)
	for path := range strings.Lines(string(out)) {
		if p := strings.TrimSpace(path); p != "" {
			files = append(files, p)
		}
	}
	// Positive control: an empty or partial `git ls-files` (a non-repo archive
	// build, a sparse checkout) would otherwise let this guard pass having
	// scanned nothing. Require known-tracked files to be listed before trusting
	// a green result.
	for _, sentinel := range []string{"go.mod", "README.md"} {
		if !slices.Contains(files, sentinel) {
			t.Fatalf("git ls-files did not list %q (got %d files); the dash guard cannot scan the tree", sentinel, len(files))
		}
	}

	skip := map[string]bool{"go.sum": true} // module hashes only; binaries are skipped via utf8.Valid

	for _, path := range files {
		if skip[path] {
			continue
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // G304: paths come from `git ls-files` in this repo, not user input
		if rerr != nil {
			if os.IsNotExist(rerr) {
				continue // listed by git but absent on disk (deleted, not staged); CI scans the committed tree
			}
			t.Errorf("reading %s: %v", path, rerr)
			continue
		}
		if utf8.Valid(b) {
			scanLinesForDashes(t, path, b)
		}
	}
}

// scanLinesForDashes reports every em (U+2014) or en (U+2013) dash in b with a
// 1-based line number. The runes are named by code point (rune(0x2014)/rune(0x2013)),
// so this source never contains the glyphs it forbids.
func scanLinesForDashes(t *testing.T, path string, b []byte) {
	t.Helper()
	const (
		emDash = rune(0x2014)
		enDash = rune(0x2013)
	)
	lineNo := 0
	for line := range strings.Lines(string(b)) {
		lineNo++
		for _, r := range line {
			switch r {
			case emDash:
				t.Errorf("%s:%d: contains an em dash (U+2014); the repo forbids em and en dashes, use a hyphen or restructure the sentence", path, lineNo)
			case enDash:
				t.Errorf("%s:%d: contains an en dash (U+2013); the repo forbids em and en dashes, use a hyphen or restructure the sentence", path, lineNo)
			}
		}
	}
}
