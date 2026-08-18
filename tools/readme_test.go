package tools

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// allRegisteredNames registers the full tool surface via RegisterAll (object,
// policy and device tools) on a fresh in-memory server and returns the tool
// names it exposes for the given device model and write mode. Both
// TestRegisterAllToolCounts (which needs only the count) and the README guard
// (which needs the names) build on it.
func allRegisteredNames(t *testing.T, model string, readOnly bool) map[string]bool {
	t.Helper()
	d, _ := newTestDeps(t, model)
	d.ReadOnly = readOnly
	s := mcp.NewServer(&mcp.Implementation{Name: "readme-test", Version: "0"}, nil)
	RegisterAll(s, d)
	return serverToolNames(t, s)
}

// readmeTable holds what the README's three tool tables claim: the set of tool
// names listed, which are marked Panorama-only, and the mode column value.
type readmeTable struct {
	names    map[string]bool
	panoOnly map[string]bool
	mode     map[string]string
}

// parseReadmeTables extracts the tool rows from the README. Only the three tool
// tables match: their rows begin "| `panos_...` |" at line start, whereas the
// env-var table uses uppercase PANOS_ names and prose never starts a line with
// "| `panos".
func parseReadmeTables(t *testing.T, readme string) readmeTable {
	t.Helper()
	const bt = "`"
	rowRe := regexp.MustCompile(`(?m)^\| ` + bt + `(panos_[a-z0-9_]+)` + bt + `( \*\(Panorama only\)\*)? \| (read-only|write) \|`)
	tbl := readmeTable{
		names:    map[string]bool{},
		panoOnly: map[string]bool{},
		mode:     map[string]string{},
	}
	for _, m := range rowRe.FindAllStringSubmatch(readme, -1) {
		name := m[1]
		if tbl.names[name] {
			t.Errorf("README lists tool %q in more than one table row", name)
		}
		tbl.names[name] = true
		if m[2] != "" {
			tbl.panoOnly[name] = true
		}
		tbl.mode[name] = m[3]
	}
	return tbl
}

// parseReadmeCounts pulls the four registered-tool counts from the sentence in
// the Tools section. A shape change in that sentence fails loudly here rather
// than silently skipping the count check.
func parseReadmeCounts(t *testing.T, readme string) (panoWrite, fwWrite, panoRO, fwRO int) {
	t.Helper()
	writeRe := regexp.MustCompile(`registers (\d+) tools on Panorama and (\d+) on a firewall`)
	roRe := regexp.MustCompile(`read-only tools are registered: (\d+) on Panorama, (\d+) on a firewall`)
	wm := writeRe.FindStringSubmatch(readme)
	if wm == nil {
		t.Fatalf("README write-mode count sentence not found; if the wording in the Tools section changed, update readme_test.go")
	}
	rm := roRe.FindStringSubmatch(readme)
	if rm == nil {
		t.Fatalf("README read-only count sentence not found; if the wording in the Tools section changed, update readme_test.go")
	}
	return atoiOrFail(t, wm[1]), atoiOrFail(t, wm[2]), atoiOrFail(t, rm[1]), atoiOrFail(t, rm[2])
}

func atoiOrFail(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parsing README count %q: %v", s, err)
	}
	return n
}

// diffSet returns the keys present in a but not in b.
func diffSet(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

// assertSameKeys fails for every key present in one set but not the other, in
// both directions.
func assertSameKeys(t *testing.T, aLabel string, a map[string]bool, bLabel string, b map[string]bool) {
	t.Helper()
	// Sort so a failure lists the offending tools in a stable order.
	for _, k := range slices.Sorted(maps.Keys(a)) {
		if !b[k] {
			t.Errorf("tool %q is %s but missing from %s; fix the README Tools section or the registration", k, aLabel, bLabel)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(b)) {
		if !a[k] {
			t.Errorf("tool %q is %s but missing from %s; fix the README Tools section or the registration", k, bLabel, aLabel)
		}
	}
}

func numberWord(n int) string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"}
	if n < 0 || n >= len(words) {
		return strconv.Itoa(n)
	}
	return words[n]
}

// TestReadmeToolTablesMatchRegistrations pins the README Tools section against
// the actual RegisterAll surface. Adding, renaming, or removing a tool, or
// changing its Panorama-only or read-only/write gate, must be reflected in the
// README tables and the count sentence, or this test fails. TestRegisterAllToolCounts
// pins the counts in code independently; this pins the human-facing copy.
func TestReadmeToolTablesMatchRegistrations(t *testing.T) {
	fwWrite := allRegisteredNames(t, "PA-VM", false)
	panoWrite := allRegisteredNames(t, "Panorama", false)
	fwRO := allRegisteredNames(t, "PA-VM", true)
	panoRO := allRegisteredNames(t, "Panorama", true)

	// Panorama-only tools are those RegisterAll adds on Panorama but not on a
	// firewall. Read-only tools are those registered even in read-only mode.
	panoOnly := diffSet(panoWrite, fwWrite)

	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(b)
	tbl := parseReadmeTables(t, readme)

	// The README must list exactly the full (Panorama, write-mode) tool set.
	assertSameKeys(t, "registered", panoWrite, "listed in the README", tbl.names)

	// Every listed tool's Panorama-only marking and mode column must match how
	// RegisterAll gates it. Sort for stable failure output.
	for _, name := range slices.Sorted(maps.Keys(tbl.names)) {
		wantPanoOnly := panoOnly[name]
		if tbl.panoOnly[name] != wantPanoOnly {
			t.Errorf("tool %q: README Panorama-only marking is %v, registration says %v; fix the README Tools section or the registration",
				name, tbl.panoOnly[name], wantPanoOnly)
		}
		wantMode := "write"
		if panoRO[name] {
			wantMode = "read-only"
		}
		if tbl.mode[name] != wantMode {
			t.Errorf("tool %q: README mode is %q, registration says %q; fix the README Tools section or the registration",
				name, tbl.mode[name], wantMode)
		}
	}

	// The count sentence must match the registered set sizes.
	gotPanoWrite, gotFwWrite, gotPanoRO, gotFwRO := parseReadmeCounts(t, readme)
	checkCount(t, "Panorama write-mode", gotPanoWrite, len(panoWrite))
	checkCount(t, "firewall write-mode", gotFwWrite, len(fwWrite))
	checkCount(t, "Panorama read-only", gotPanoRO, len(panoRO))
	checkCount(t, "firewall read-only", gotFwRO, len(fwRO))

	// The same sentence spells out the Panorama-only count in words.
	phrase := "the " + numberWord(len(panoOnly)) + " Panorama-only tools below"
	if !strings.Contains(readme, phrase) {
		t.Errorf("README should say %q (there are %d Panorama-only tools); update the count sentence in the Tools section", phrase, len(panoOnly))
	}
}

func checkCount(t *testing.T, label string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("README %s count is %d, RegisterAll actually registers %d; update the count sentence in the Tools section or the registration", label, got, want)
	}
}
