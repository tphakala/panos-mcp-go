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

// readmeTable holds what the README's tool tables claim: the set of tool names
// listed, which are marked Panorama-only or firewall-only, and the mode column
// value.
type readmeTable struct {
	names    map[string]bool
	panoOnly map[string]bool
	fwOnly   map[string]bool
	mode     map[string]string
}

// parseReadmeTables extracts the tool rows from the README. Only the tool
// tables match: their rows begin "| `panos_...` |" at line start, whereas the
// env-var table uses uppercase PANOS_ names and prose never starts a line with
// "| `panos". A row may carry a "(Panorama only)" or "(Firewall only)" marker
// after the tool name.
func parseReadmeTables(t *testing.T, readme string) readmeTable {
	t.Helper()
	const bt = "`"
	rowRe := regexp.MustCompile(`(?m)^\| ` + bt + `(panos_[a-z0-9_]+)` + bt + `( \*\((Panorama|Firewall) only\)\*)? \| (read-only|write) \|`)
	tbl := readmeTable{
		names:    map[string]bool{},
		panoOnly: map[string]bool{},
		fwOnly:   map[string]bool{},
		mode:     map[string]string{},
	}
	for _, m := range rowRe.FindAllStringSubmatch(readme, -1) {
		name := m[1]
		if tbl.names[name] {
			t.Errorf("README lists tool %q in more than one table row", name)
		}
		tbl.names[name] = true
		switch m[3] {
		case "Panorama":
			tbl.panoOnly[name] = true
		case "Firewall":
			tbl.fwOnly[name] = true
		}
		tbl.mode[name] = m[4]
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

// unionSet returns the keys present in either a or b.
func unionSet(a, b map[string]bool) map[string]bool {
	out := maps.Clone(a)
	for k := range b {
		out[k] = true
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
	// firewall; firewall-only tools are the reverse. Read-only tools are those
	// registered even in read-only mode. No single device type sees the whole
	// surface, so the README lists the union of both write-mode sets.
	panoOnly := diffSet(panoWrite, fwWrite)
	fwOnly := diffSet(fwWrite, panoWrite)
	allTools := unionSet(panoWrite, fwWrite)

	// A tool registered on both device types must be read-only-gated the same way
	// on each; otherwise the wantMode check below (which marks a tool read-only if
	// it is read-only on EITHER device type) would mask a tool that is write-gated
	// on one device type but read-only on the other. Firewall-only and
	// Panorama-only tools are exempt: an asymmetry across a device type that does
	// not register the tool at all is expected, not a bug.
	for _, name := range slices.Sorted(maps.Keys(allTools)) {
		if panoWrite[name] && fwWrite[name] && panoRO[name] != fwRO[name] {
			t.Errorf("tool %q is registered on both device types but read-only gated asymmetrically (Panorama read-only: %v, firewall read-only: %v); the single README mode column cannot represent this",
				name, panoRO[name], fwRO[name])
		}
	}

	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(b)
	tbl := parseReadmeTables(t, readme)

	// The README must list exactly the union of the firewall and Panorama
	// write-mode tool sets.
	assertSameKeys(t, "registered", allTools, "listed in the README", tbl.names)

	// Every listed tool's device-only marking and mode column must match how
	// RegisterAll gates it. Sort for stable failure output.
	for _, name := range slices.Sorted(maps.Keys(tbl.names)) {
		wantPanoOnly := panoOnly[name]
		if tbl.panoOnly[name] != wantPanoOnly {
			t.Errorf("tool %q: README Panorama-only marking is %v, registration says %v; fix the README Tools section or the registration",
				name, tbl.panoOnly[name], wantPanoOnly)
		}
		wantFwOnly := fwOnly[name]
		if tbl.fwOnly[name] != wantFwOnly {
			t.Errorf("tool %q: README firewall-only marking is %v, registration says %v; fix the README Tools section or the registration",
				name, tbl.fwOnly[name], wantFwOnly)
		}
		wantMode := "write"
		if panoRO[name] || fwRO[name] {
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

	// The same sentence spells out the Panorama-only and firewall-only counts in
	// words.
	phrase := "the " + numberWord(len(panoOnly)) + " Panorama-only tools below"
	if !strings.Contains(readme, phrase) {
		t.Errorf("README should say %q (there are %d Panorama-only tools); update the count sentence in the Tools section", phrase, len(panoOnly))
	}
	fwPhrase := "the " + numberWord(len(fwOnly)) + " firewall-only tools below"
	if !strings.Contains(readme, fwPhrase) {
		t.Errorf("README should say %q (there are %d firewall-only tools); update the count sentence in the Tools section", fwPhrase, len(fwOnly))
	}
}

func checkCount(t *testing.T, label string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("README %s count is %d, RegisterAll actually registers %d; update the count sentence in the Tools section or the registration", label, got, want)
	}
}

// TestReadmeRestatesScopeExceptionConsts pins the device-scope exception family
// lists in the README against their source-of-truth consts. device_scope.go
// documents that noSharedScopeProfiles and noPanoramaScopeFamilies are restated in
// README.md because a Go struct tag cannot reference a const, yet nothing checked
// that copy: TestDeviceScopeSchemaUnchanged pins the struct tag against each const,
// but the README prose could drift while the tag stayed correct. This closes that
// gap the same way, with a verbatim Contains.
//
// Sabotage: reword the README's device-scope family lists away from either const
// (for example back to "SNMP-trap and email ... authentication profile") and this
// turns red while the schema pins stay green.
func TestReadmeRestatesScopeExceptionConsts(t *testing.T) {
	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(b)
	for _, want := range []string{noSharedScopeProfiles, noPanoramaScopeFamilies} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md must restate %q verbatim (device_scope.go documents this restatement; a struct tag cannot reference the const)", want)
		}
	}
}
