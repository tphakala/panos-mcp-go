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
// Dockerfile builder image, and the README. The docker Dependabot ecosystem can
// bump "FROM golang:1.xx-alpine" on its own; when it does, this test goes red
// until go.mod and the README are bumped in the same PR. That coupling is the
// point (issue #40). The workflows read go.mod directly, so
// TestGoVersionTracksLatestPatch covers them instead.
func TestGoVersionCoordinated(t *testing.T) {
	sources := []struct {
		path    string
		pattern string
	}{
		{"go.mod", `(?m)^go (\d+\.\d+)`}, // reference: "go 1.27" -> "1.27"
		{"Dockerfile", `golang:(\d+\.\d+)`},
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
			t.Errorf("Go version drift: go.mod says %s but %s says %s; bump go.mod, Dockerfile, and README.md together", reference, s.path, got)
		}
	}
}

// TestGoVersionTracksLatestPatch fails when a Go patch release gets pinned
// anywhere, so builds keep picking up standard library fixes without a commit.
// go.mod names only the minor and has no toolchain line, the Dockerfile tag
// has no patch, and every setup-go step reads go.mod with check-latest.
func TestGoVersionTracksLatestPatch(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path) //nolint:gosec // G304: fixed in-repo config paths, not user input
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return string(b)
	}

	mod := read("go.mod")
	if !regexp.MustCompile(`(?m)^go \d+\.\d+$`).MatchString(mod) {
		t.Errorf("go.mod: the go line must name only the minor (go 1.N), not a patch")
	}
	if regexp.MustCompile(`(?m)^toolchain `).MatchString(mod) {
		t.Errorf("go.mod: remove the toolchain line; it pins a patch release")
	}
	if m := regexp.MustCompile(`golang:\d+\.\d+\.\d+`).FindString(read("Dockerfile")); m != "" {
		t.Errorf("Dockerfile: %s pins a patch release; use golang:1.N-<variant>", m)
	}

	for _, path := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		checkSetupGoSteps(t, path, read(path))
	}

	vuln := read(".github/workflows/govulncheck.yml")
	if !regexp.MustCompile(`(?m)^\s*go-version-input:\s*""\s*$`).MatchString(vuln) {
		t.Errorf(`govulncheck.yml: set go-version-input: "" so the action's "stable" default does not override go-version-file`)
	}
}

// checkSetupGoSteps requires each actions/setup-go step in wf to read go.mod
// with check-latest and to carry no go-version that would override it.
func checkSetupGoSteps(t *testing.T, path, wf string) {
	t.Helper()
	steps := regexp.MustCompile(`(?m)^\s*- uses: actions/setup-go@`).FindAllStringIndex(wf, -1)
	if len(steps) == 0 {
		t.Errorf("%s: no actions/setup-go step found; if setup moved, update this test", path)
	}
	nextStep := regexp.MustCompile(`(?m)^\s*- `)
	for _, s := range steps {
		// The step's with: block is the text up to the next step.
		step := wf[s[1]:]
		if next := nextStep.FindStringIndex(step); next != nil {
			step = step[:next[0]]
		}
		if !regexp.MustCompile(`(?m)^\s*go-version-file:\s*go\.mod\s*$`).MatchString(step) {
			t.Errorf("%s: setup-go must use go-version-file: go.mod", path)
		}
		if !regexp.MustCompile(`(?m)^\s*check-latest:\s*true\s*$`).MatchString(step) {
			t.Errorf("%s: setup-go must set check-latest: true", path)
		}
		if regexp.MustCompile(`(?m)^\s*go-version:`).MatchString(step) {
			t.Errorf("%s: setup-go must not set go-version; it overrides go-version-file", path)
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
