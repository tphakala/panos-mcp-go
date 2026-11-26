package main

import (
	"iter"
	"os"
	"os/exec"
	"path/filepath"
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
		m := regexp.MustCompile(s.pattern).FindStringSubmatch(readRepoFile(t, s.path))
		if m == nil {
			t.Fatalf("no Go version marker in %s (pattern %q); if the line moved or changed shape, update repo_hygiene_test.go", s.path, s.pattern)
		}
		got := m[1]
		if reference == "" {
			reference = got // go.mod is listed first and is the source of truth
			continue
		}
		if got != reference {
			t.Errorf("Go version drift: go.mod says %s but %s says %s; bump go.mod, Dockerfile, and README.md together", reference, s.path, got)
		}
	}
}

// TestGoVersionTracksLatestPatch checks the places this repo chooses its Go
// version, so builds pick up standard library fixes without a commit: go.mod
// names only the minor and has no toolchain line, the Dockerfile tag has no
// patch, every actions/setup-go step in .github/workflows reads go.mod with
// check-latest: true, and every govulncheck action step reads go.mod without
// turning check-latest off.
func TestGoVersionTracksLatestPatch(t *testing.T) {
	mod := readRepoFile(t, "go.mod")
	if !regexp.MustCompile(`(?m)^go \d+\.\d+$`).MatchString(mod) {
		t.Errorf("go.mod: the go line must name only the minor (go 1.N), not a patch")
	}
	if regexp.MustCompile(`(?m)^toolchain `).MatchString(mod) {
		t.Errorf("go.mod: remove the toolchain line; it pins a patch release")
	}
	if m := regexp.MustCompile(`golang:\d+\.\d+\.\d+`).FindString(readRepoFile(t, "Dockerfile")); m != "" {
		t.Errorf("Dockerfile: %s pins a patch release; use golang:1.N-<variant>", m)
	}

	workflows, err := filepath.Glob(".github/workflows/*.y*ml")
	if err != nil {
		t.Fatal(err)
	}
	steps := 0
	for _, path := range workflows {
		problems, n := setupGoProblems(readRepoFile(t, path))
		for _, p := range problems {
			t.Errorf("%s: %s", path, p)
		}
		steps += n
	}
	if steps == 0 {
		t.Errorf("no actions/setup-go step found in %d workflow files; if setup moved, update this test", len(workflows))
	}

	for _, p := range govulncheckProblems(readRepoFile(t, ".github/workflows/govulncheck.yml")) {
		t.Errorf("govulncheck.yml: %s", p)
	}
}

const (
	msgGoVersionFile = "setup-go must use go-version-file: go.mod"
	msgCheckLatest   = "setup-go must set check-latest: true"
	msgGoVersion     = "setup-go must not set go-version; it overrides go-version-file"
	msgUnreadable    = "an actions/setup-go reference is not on a uses line this test can read; write the step in block style with uses: actions/setup-go@<sha>"

	msgVulnNone        = "no golang/govulncheck-action step found; if the scan moved, update this test"
	msgVulnInput       = `every govulncheck-action step must set go-version-input: "" so the action's "stable" default does not override go-version-file`
	msgVulnFile        = "every govulncheck-action step must use go-version-file: go.mod"
	msgVulnCheckLatest = "govulncheck-action must leave check-latest at the action's default (true) or set it to true"
	msgVulnUnreadable  = "a golang/govulncheck-action reference is not on a uses line this test can read; write the step in block style with uses: golang/govulncheck-action@<sha>"
)

var (
	// setupGoUses and govulncheckUses match the uses line of a block-style step,
	// whether uses is the step's first key or comes after name, and whether the
	// value is quoted.
	setupGoUses      = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*["']?actions/setup-go@`)
	govulncheckUses  = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*["']?golang/govulncheck-action@`)
	stepStart        = regexp.MustCompile(`(?m)^[ \t]*-(?:[ \t]|$)`)
	goVersionFileGo  = regexp.MustCompile(`^[ \t]*go-version-file:[ \t]*(?:go\.mod|"go\.mod"|'go\.mod')[ \t]*$`)
	goVersionKey     = regexp.MustCompile(`^[ \t]*(?:-[ \t]+)?["']?go-version["']?[ \t]*:`)
	goVersionInputNo = regexp.MustCompile(`^[ \t]*go-version-input:[ \t]*(?:""|'')[ \t]*$`)
	checkLatestKey   = regexp.MustCompile(`^[ \t]*(?:-[ \t]+)?["']?check-latest["']?[ \t]*:`)
	checkLatestTrue  = regexp.MustCompile(`^[ \t]*check-latest:[ \t]*(?:true|"true"|'true')[ \t]*$`)
)

// stepsUsing returns the text of every block-style step whose uses line matches
// uses. A step runs from the sequence dash at or before its uses line to the
// next dash. unreadable reports that ref (the action name up to the @) appears
// on a non-comment line more often than uses matched, so some reference is
// written in a form this test cannot read, such as flow style.
func stepsUsing(wf string, uses *regexp.Regexp, ref string) (steps []string, unreadable bool) {
	starts := stepStart.FindAllStringIndex(wf, -1)
	found := uses.FindAllStringIndex(wf, -1)
	for _, u := range found {
		begin, end := 0, len(wf)
		for _, s := range starts {
			if s[0] <= u[0] {
				begin = s[0]
				continue
			}
			end = s[0]
			break
		}
		steps = append(steps, wf[begin:end])
	}
	refs := 0
	for line := range settingLines(wf) {
		refs += strings.Count(line, ref)
	}
	return steps, refs != len(found)
}

// setupGoProblems checks every actions/setup-go step in the workflow text wf
// and returns one message per problem, plus the number of steps it found. A
// step must have go-version-file: go.mod and check-latest: true, and no
// go-version key, since setup-go prefers go-version over go-version-file. The
// check fails closed: a setup-go reference that is not on a uses line it can
// read is a problem, and so is a go-version key written in any other form
// (quoted, spaced).
func setupGoProblems(wf string) (problems []string, steps int) {
	found, unreadable := stepsUsing(wf, setupGoUses, "actions/setup-go@")
	for _, step := range found {
		var hasFile, hasLatest bool
		for line := range settingLines(step) {
			switch {
			case goVersionFileGo.MatchString(line):
				hasFile = true
			case checkLatestTrue.MatchString(line):
				hasLatest = true
			case goVersionKey.MatchString(line):
				problems = append(problems, msgGoVersion)
			}
		}
		if !hasFile {
			problems = append(problems, msgGoVersionFile)
		}
		if !hasLatest {
			problems = append(problems, msgCheckLatest)
		}
	}
	if unreadable {
		problems = append(problems, msgUnreadable)
	}
	return problems, len(found)
}

// govulncheckProblems checks every golang/govulncheck-action step in the
// workflow text wf on its own range and returns one message per problem. The
// action defaults go-version-input to "stable", which setup-go prefers over
// go-version-file, so each step must blank it and set go-version-file: go.mod,
// and none may turn check-latest off. A workflow with no readable step is a
// problem, so a renamed or restyled action cannot pass unchecked.
func govulncheckProblems(wf string) []string {
	var problems []string
	steps, unreadable := stepsUsing(wf, govulncheckUses, "golang/govulncheck-action@")
	if len(steps) == 0 && !unreadable {
		problems = append(problems, msgVulnNone)
	}
	for _, step := range steps {
		var hasInput, hasFile bool
		for line := range settingLines(step) {
			switch {
			case goVersionInputNo.MatchString(line):
				hasInput = true
			case goVersionFileGo.MatchString(line):
				hasFile = true
			case checkLatestKey.MatchString(line) && !checkLatestTrue.MatchString(line):
				problems = append(problems, msgVulnCheckLatest)
			}
		}
		if !hasInput {
			problems = append(problems, msgVulnInput)
		}
		if !hasFile {
			problems = append(problems, msgVulnFile)
		}
	}
	if unreadable {
		problems = append(problems, msgVulnUnreadable)
	}
	return problems
}

// settingLines yields the lines of text without their line ending and without
// a trailing comment, skipping lines that are blank or only a comment, which
// cannot set a value. A comment starts at a # at the start of the line or after
// a space or tab. The scan ignores quotes, so a # inside a quoted value also
// cuts the line; the patterns above only accept whole-line values, so a cut
// value fails to match instead of matching wrongly.
func settingLines(text string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range strings.Lines(text) {
			line = strings.TrimRight(line, "\r\n")
			for i := range len(line) {
				if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
					line = line[:i]
					break
				}
			}
			line = strings.TrimRight(line, " \t")
			if line == "" {
				continue
			}
			if !yield(line) {
				return
			}
		}
	}
}

func TestSetupGoProblems(t *testing.T) {
	const good = "- uses: actions/setup-go@abc\n  with:\n    go-version-file: go.mod\n    check-latest: true\n"
	tests := []struct {
		name  string
		wf    string
		want  []string
		steps int
	}{
		{"uses first, compliant", good + "- run: go test ./...\n", nil, 1},
		{"comment mentioning go-version", "- uses: actions/setup-go@abc\n  with:\n    # go-version comes from go.mod\n    go-version-file: go.mod\n    check-latest: true\n", nil, 1},
		{"name first, pinned", "- name: Set up Go\n  uses: actions/setup-go@abc\n  with:\n    go-version-file: go.mod\n    check-latest: true\n    go-version: \"1.27.1\"\n", []string{msgGoVersion}, 1},
		{"quoted uses and quoted key", "- uses: \"actions/setup-go@abc\"\n  with:\n    go-version-file: go.mod\n    check-latest: true\n    \"go-version\": \"1.27.1\"\n", []string{msgGoVersion}, 1},
		{"spaced key", good + "    go-version : \"1.27.1\"\n", []string{msgGoVersion}, 1},
		{"second step pinned", good + "- name: Again\n  uses: actions/setup-go@abc\n  with:\n    go-version: \"1.27\"\n", []string{msgGoVersion, msgGoVersionFile, msgCheckLatest}, 2},
		{"check-latest false", "- uses: actions/setup-go@abc\n  with:\n    go-version-file: go.mod\n    check-latest: false\n", []string{msgCheckLatest}, 1},
		{"next step's keys do not count", "- uses: actions/setup-go@abc\n- run: echo\n  with:\n    go-version-file: go.mod\n    check-latest: true\n", []string{msgGoVersionFile, msgCheckLatest}, 1},
		{"quoted values and trailing comments", "- uses: actions/setup-go@abc # v7\n  with:\n    go-version-file: 'go.mod' # minor only\n    check-latest: \"true\"\n", nil, 1},
		{"bare dash step after a compliant one", good + "-\n  uses: actions/setup-go@abc\n", []string{msgGoVersionFile, msgCheckLatest}, 2},
		{"flow style", "- {uses: actions/setup-go@abc, with: {go-version: \"1.27.1\"}}\n", []string{msgUnreadable}, 0},
		{"go-version-file is another file", "- uses: actions/setup-go@abc\n  with:\n    go-version-file: .go-version\n    check-latest: true\n", []string{msgGoVersionFile}, 1},
		{"go-version-file is ./go.mod", "- uses: actions/setup-go@abc\n  with:\n    go-version-file: ./go.mod\n    check-latest: true\n", []string{msgGoVersionFile}, 1},
		{"with first, compliant", "- with:\n    go-version-file: go.mod\n    check-latest: true\n  uses: actions/setup-go@abc\n", nil, 1},
		{"step name mentioning go-version", "- name: Set up Go (go-version from go.mod)\n  uses: actions/setup-go@abc\n  with:\n    go-version-file: go.mod\n    check-latest: true\n", nil, 1},
		{"uses comment mentioning go-version", "- uses: actions/setup-go@abc # reads go-version-file\n  with:\n    go-version-file: go.mod\n    check-latest: true\n", nil, 1},
		{"comment naming setup-go", "# actions/setup-go@v7 reads go.mod\n" + good, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, steps := setupGoProblems(tt.wf)
			if !slices.Equal(got, tt.want) || steps != tt.steps {
				t.Errorf("setupGoProblems() = %q, %d steps; want %q, %d steps", got, steps, tt.want, tt.steps)
			}
		})
	}
}

func TestGovulncheckProblems(t *testing.T) {
	const good = "- uses: golang/govulncheck-action@abc\n  with:\n    go-version-input: \"\"\n    go-version-file: go.mod\n    go-package: ./...\n"
	tests := []struct {
		name string
		wf   string
		want []string
	}{
		{"compliant", good, nil},
		{"second step pinned input", good + "- uses: golang/govulncheck-action@abc\n  with:\n    go-version-input: \"1.27.1\"\n    go-version-file: go.mod\n", []string{msgVulnInput}},
		{"second step without input", good + "- uses: golang/govulncheck-action@abc\n  with:\n    go-version-file: go.mod\n    check-latest: true\n", []string{msgVulnInput}},
		{"go-version-file is another file", "- uses: golang/govulncheck-action@abc\n  with:\n    go-version-input: \"\"\n    go-version-file: .go-version\n", []string{msgVulnFile}},
		{"check-latest false", good + "    check-latest: false\n", []string{msgVulnCheckLatest}},
		{"check-latest true", good + "    check-latest: true\n", nil},
		{"quoted values and trailing comments", "- uses: golang/govulncheck-action@abc # v1\n  with:\n    go-version-input: '' # blank on purpose\n    go-version-file: 'go.mod' # minor only\n    check-latest: \"true\"\n", nil},
		{"with first, compliant", "- with:\n    go-version-input: \"\"\n    go-version-file: go.mod\n  uses: golang/govulncheck-action@abc\n", nil},
		{"next step's keys do not count", "- uses: golang/govulncheck-action@abc\n- uses: actions/setup-go@abc\n  with:\n    go-version-input: \"\"\n    go-version-file: go.mod\n", []string{msgVulnInput, msgVulnFile}},
		{"comment naming the action", "# golang/govulncheck-action@v1 runs below\n" + good, nil},
		{"no step", "- uses: actions/checkout@abc\n", []string{msgVulnNone}},
		{"flow style", "- {uses: golang/govulncheck-action@abc, with: {go-version-input: \"\"}}\n", []string{msgVulnUnreadable}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := govulncheckProblems(tt.wf); !slices.Equal(got, tt.want) {
				t.Errorf("govulncheckProblems() = %q; want %q", got, tt.want)
			}
		})
	}
}

// readRepoFile returns the contents of a file at a fixed path in this repo.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: fixed in-repo doc and config paths, not user input
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
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
