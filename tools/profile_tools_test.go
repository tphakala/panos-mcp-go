package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/profiles/antivirus"
	"github.com/PaloAltoNetworks/pango/objects/profiles/fileblocking"
	"github.com/PaloAltoNetworks/pango/objects/profiles/secgroup"
	"github.com/PaloAltoNetworks/pango/objects/profiles/urlfiltering"
	"github.com/PaloAltoNetworks/pango/objects/profiles/vulnerability"
	"github.com/PaloAltoNetworks/pango/objects/profiles/wildfireanalysis"
	"github.com/PaloAltoNetworks/pango/security/profiles/spyware"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Fixtures ---------------------------------------------------------------

// minimalEntryBody is a read-back body for a create test: a bare entry pango
// parses to an Entry with just the name. Create asserts the set element it sent,
// not this projection.
func minimalEntryBody(name string) string {
	return `<response status="success"><result><entry name="` + name + `"/></result></response>`
}

// antivirusEntryXML renders a canned antivirus profile with a description and one
// decoder (see antivirus/entry.go xml tags: decoder is an entry container).
func antivirusEntryXML(name string) string {
	return `<entry name="` + name + `"><description>` + name + ` desc</description>` +
		`<decoder><entry name="http"><action>alert</action></entry></decoder></entry>`
}

var antivirusListBody = `<response status="success"><result>` +
	antivirusEntryXML("av-a") + antivirusEntryXML("av-b") + antivirusEntryXML("av-c") +
	`</result></response>`

func antivirusResolve(d *Deps) func(LocationInput) (antivirus.Location, error) {
	return func(in LocationInput) (antivirus.Location, error) { return resolveLocation(d, in, antivirusParts()) }
}

func urlFilteringResolve(d *Deps) func(LocationInput) (urlfiltering.Location, error) {
	return func(in LocationInput) (urlfiltering.Location, error) {
		return resolveLocation(d, in, urlFilteringParts())
	}
}

func fileBlockingResolve(d *Deps) func(LocationInput) (fileblocking.Location, error) {
	return func(in LocationInput) (fileblocking.Location, error) {
		return resolveLocation(d, in, fileBlockingParts())
	}
}

func profileGroupResolve(d *Deps) func(LocationInput) (secgroup.Location, error) {
	return func(in LocationInput) (secgroup.Location, error) { return resolveLocation(d, in, profileGroupParts()) }
}

func vulnerabilityResolve(d *Deps) func(LocationInput) (vulnerability.Location, error) {
	return func(in LocationInput) (vulnerability.Location, error) {
		return resolveLocation(d, in, vulnerabilityParts())
	}
}

func spywareResolve(d *Deps) func(LocationInput) (spyware.Location, error) {
	return func(in LocationInput) (spyware.Location, error) { return resolveLocation(d, in, spywareParts()) }
}

func wildfireAnalysisResolve(d *Deps) func(LocationInput) (wildfireanalysis.Location, error) {
	return func(in LocationInput) (wildfireanalysis.Location, error) {
		return resolveLocation(d, in, wildfireAnalysisParts())
	}
}

// mustMap, mustAnySlice, and mustStrSlice do the checked type assertions the
// summary unit tests need (a summary returns any wrapping these shapes).
func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value is %T, want map[string]any", v)
	}
	return m
}

func mustAnySlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	if !ok {
		t.Fatalf("value is %T, want []any", v)
	}
	return s
}

func mustStrSlice(t *testing.T, v any) []string {
	t.Helper()
	s, ok := v.([]string)
	if !ok {
		t.Fatalf("value is %T, want []string", v)
	}
	return s
}

// --- Cross-cutting: nil-vsys location resolution ----------------------------

// TestResolveLocationNilVsys pins the resolveLocation change for object types
// pango models with no vsys location (urlfiltering here): an explicit vsys is
// rejected, and the firewall default falls back to shared. A vsys-ful type
// (antivirus) still defaults to vsys1 on a firewall. Removing either nil-vsys
// guard breaks one of these arms (and would nil-panic the firewall default).
func TestResolveLocationNilVsys(t *testing.T) {
	dFW, _ := newTestDeps(t, "PA-VM")
	dPano, _ := newTestDeps(t, "Panorama")

	if _, err := resolveLocation(dFW, LocationInput{Vsys: "vsys2"}, urlFilteringParts()); err == nil {
		t.Error("explicit vsys on a vsys-less type must be rejected")
	}
	loc, err := resolveLocation(dFW, LocationInput{}, urlFilteringParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc.Shared == nil {
		t.Errorf("firewall default for a vsys-less type must be shared: %+v", loc)
	}
	locP, err := resolveLocation(dPano, LocationInput{}, urlFilteringParts())
	if err != nil {
		t.Fatal(err)
	}
	if locP.Shared == nil {
		t.Errorf("panorama default for a vsys-less type must be shared: %+v", locP)
	}
	locV, err := resolveLocation(dFW, LocationInput{}, antivirusParts())
	if err != nil {
		t.Fatal(err)
	}
	if locV.Vsys == nil || locV.Vsys.Vsys != defaultVsys {
		t.Errorf("firewall default for a vsys-ful type must be vsys1: %+v", locV)
	}
}

// --- Antivirus: unit tests --------------------------------------------------

func TestBuildAntivirusEntry(t *testing.T) {
	e, err := buildAntivirusEntry(AntivirusProfileInput{
		Name: "av1", Description: "d", PacketCapture: ptr(true),
		Decoders: []AntivirusDecoderInput{{Name: "http", Action: "drop", WildfireAction: "reset-both", MlavAction: "alert"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "av1" || strVal(e.Description) != "d" || !boolVal(e.PacketCapture) {
		t.Errorf("base fields: %+v", e)
	}
	if len(e.Decoder) != 1 || e.Decoder[0].Name != "http" || strVal(e.Decoder[0].Action) != "drop" ||
		strVal(e.Decoder[0].WildfireAction) != "reset-both" || strVal(e.Decoder[0].MlavAction) != "alert" {
		t.Errorf("decoder mapping: %+v", e.Decoder)
	}
}

func TestBuildAntivirusEntryRejects(t *testing.T) {
	if _, err := buildAntivirusEntry(AntivirusProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
	if _, err := buildAntivirusEntry(AntivirusProfileInput{Name: "av", Decoders: []AntivirusDecoderInput{{Action: "drop"}}}); err == nil {
		t.Error("decoder without a name must fail")
	}
}

func TestOverlayAntivirus(t *testing.T) {
	// Start packet_capture true so the omitted-preserve case would catch an
	// unconditional overwrite (which nils it): boolVal(nil) is false, not true.
	e := &antivirus.Entry{Name: "av1", Description: ptr("old"), PacketCapture: ptr(true), Decoder: []antivirus.Decoder{{Name: "old"}}}
	if err := overlayAntivirus(e, AntivirusProfileInput{Name: "av1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.PacketCapture) || len(e.Decoder) != 1 || e.Decoder[0].Name != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayAntivirus(e, AntivirusProfileInput{Name: "av1", Description: "new", PacketCapture: ptr(false), Decoders: []AntivirusDecoderInput{{Name: "http"}}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.PacketCapture) || len(e.Decoder) != 1 || e.Decoder[0].Name != "http" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestAntivirusSummary(t *testing.T) {
	e := &antivirus.Entry{Name: "av1", Description: ptr("d"), PacketCapture: ptr(true),
		Decoder: []antivirus.Decoder{{Name: "http", Action: ptr("drop"), WildfireAction: ptr("reset-both"), MlavAction: ptr("alert")}}}
	m := mustMap(t, antivirusSummary(e))
	if m[tagNameKey] != "av1" || m[descriptionKey] != "d" || m["packet_capture"] != true {
		t.Errorf("summary base: %+v", m)
	}
	decs := mustAnySlice(t, m["decoders"])
	if len(decs) != 1 {
		t.Fatalf("decoders: %+v", decs)
	}
	d0 := mustMap(t, decs[0])
	if d0[tagNameKey] != "http" || d0["action"] != "drop" || d0["wildfire_action"] != "reset-both" || d0["mlav_action"] != "alert" {
		t.Errorf("decoder summary: %+v", d0)
	}
}

// --- Vulnerability: unit tests ----------------------------------------------

func TestBuildVulnerabilityEntry(t *testing.T) {
	e, err := buildVulnerabilityEntry(VulnerabilityProfileInput{
		Name: "v1", Description: "d", CloudInlineAnalysis: ptr(true),
		InlineExceptionEdlURLs: []string{"edl1"}, InlineExceptionIPAddresses: []string{"1.2.3.4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "v1" || strVal(e.Description) != "d" || !boolVal(e.CloudInlineAnalysis) {
		t.Errorf("base fields: %+v", e)
	}
	if len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "edl1" ||
		len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "1.2.3.4" {
		t.Errorf("inline exceptions: %+v", e)
	}
	if _, err := buildVulnerabilityEntry(VulnerabilityProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
}

func TestOverlayVulnerability(t *testing.T) {
	// cloud_inline_analysis starts true so an unconditional overwrite (nil) is caught.
	e := &vulnerability.Entry{Name: "v1", Description: ptr("old"), CloudInlineAnalysis: ptr(true), InlineExceptionEdlUrl: []string{"old"}}
	if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1", Description: "new", CloudInlineAnalysis: ptr(false), InlineExceptionEdlURLs: []string{"new"}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "new" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestVulnerabilitySummary(t *testing.T) {
	e := &vulnerability.Entry{Name: "v1", Description: ptr("d"), CloudInlineAnalysis: ptr(true),
		InlineExceptionEdlUrl: []string{"edl1"}, InlineExceptionIpAddress: []string{"1.2.3.4"}}
	m := mustMap(t, vulnerabilitySummary(e))
	if m[tagNameKey] != "v1" || m[descriptionKey] != "d" || m["cloud_inline_analysis"] != true {
		t.Errorf("summary base: %+v", m)
	}
	if got := mustStrSlice(t, m["inline_exception_edl_urls"]); len(got) != 1 || got[0] != "edl1" {
		t.Errorf("edl exceptions: %+v", got)
	}
	if got := mustStrSlice(t, m["inline_exception_ip_addresses"]); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("ip exceptions: %+v", got)
	}
}

// --- Anti-spyware: unit tests -----------------------------------------------

func TestBuildSpywareEntry(t *testing.T) {
	e, err := buildSpywareEntry(SpywareProfileInput{
		Name: "s1", Description: "d", CloudInlineAnalysis: ptr(true),
		InlineExceptionEdlURLs: []string{"edl1"}, InlineExceptionIPAddresses: []string{"1.2.3.4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "s1" || strVal(e.Description) != "d" || !boolVal(e.CloudInlineAnalysis) ||
		len(e.InlineExceptionEdlUrl) != 1 || len(e.InlineExceptionIpAddress) != 1 {
		t.Errorf("mapping: %+v", e)
	}
	if _, err := buildSpywareEntry(SpywareProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
}

func TestOverlaySpyware(t *testing.T) {
	// cloud_inline_analysis starts true so an unconditional overwrite (nil) is caught.
	e := &spyware.Entry{Name: "s1", Description: ptr("old"), CloudInlineAnalysis: ptr(true), InlineExceptionIpAddress: []string{"old"}}
	if err := overlaySpyware(e, SpywareProfileInput{Name: "s1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlaySpyware(e, SpywareProfileInput{Name: "s1", Description: "new", CloudInlineAnalysis: ptr(false), InlineExceptionIPAddresses: []string{"new"}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "new" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestSpywareSummary(t *testing.T) {
	e := &spyware.Entry{Name: "s1", Description: ptr("d"), CloudInlineAnalysis: ptr(true), InlineExceptionIpAddress: []string{"1.2.3.4"}}
	m := mustMap(t, spywareSummary(e))
	if m[tagNameKey] != "s1" || m[descriptionKey] != "d" || m["cloud_inline_analysis"] != true {
		t.Errorf("summary: %+v", m)
	}
	if got := mustStrSlice(t, m["inline_exception_ip_addresses"]); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("ip exceptions: %+v", got)
	}
}

// --- URL filtering: unit tests ----------------------------------------------

func TestBuildURLFilteringEntry(t *testing.T) {
	e, err := buildURLFilteringEntry(URLFilteringProfileInput{
		Name: "u1", Description: "d",
		Alert: []string{"c1"}, Allow: []string{"c2"}, Block: []string{"c3"}, Continue: []string{"c4"}, Override: []string{"c5"},
		SafeSearchEnforcement: ptr(true), LogHTTPHeaderXFF: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "u1" || strVal(e.Description) != "d" || !boolVal(e.SafeSearchEnforcement) || !boolVal(e.LogHttpHdrXff) {
		t.Errorf("base fields: %+v", e)
	}
	if len(e.Alert) != 1 || e.Alert[0] != "c1" || len(e.Allow) != 1 || len(e.Block) != 1 || len(e.Continue) != 1 || len(e.Override) != 1 {
		t.Errorf("category lists: %+v", e)
	}
	if _, err := buildURLFilteringEntry(URLFilteringProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
}

func TestOverlayURLFiltering(t *testing.T) {
	// All four bool toggles start true so an unconditional overwrite (nil) is
	// caught by the omitted-preserve case; seeding all four guards every
	// log/safe-search omitted-preserve branch (issue #61 follow-up), not just xff.
	allTrue := [4]bool{true, true, true, true}
	allFalse := [4]bool{false, false, false, false}
	e := &urlfiltering.Entry{
		Name: "u1", Description: ptr("old"), Block: []string{"old"},
		SafeSearchEnforcement: ptr(true), LogHttpHdrXff: ptr(true),
		LogHttpHdrUserAgent: ptr(true), LogHttpHdrReferer: ptr(true),
	}
	if err := overlayURLFiltering(e, URLFilteringProfileInput{Name: "u1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || urlToggles(e) != allTrue || len(e.Block) != 1 || e.Block[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayURLFiltering(e, URLFilteringProfileInput{
		Name: "u1", Block: []string{"malware"},
		SafeSearchEnforcement: ptr(false), LogHTTPHeaderXFF: ptr(false),
		LogHTTPHeaderUserAgent: ptr(false), LogHTTPHeaderReferer: ptr(false),
	}); err != nil {
		t.Fatal(err)
	}
	if urlToggles(e) != allFalse || len(e.Block) != 1 || e.Block[0] != "malware" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

// urlToggles snapshots the four URL-filtering log/safe-search booleans in a fixed
// order so an assertion can compare them all with one array equality.
func urlToggles(e *urlfiltering.Entry) [4]bool {
	return [4]bool{
		boolVal(e.SafeSearchEnforcement),
		boolVal(e.LogHttpHdrXff),
		boolVal(e.LogHttpHdrUserAgent),
		boolVal(e.LogHttpHdrReferer),
	}
}

// TestOverlayProfilesClearList pins the issue #61 contract that an explicit
// empty list clears a profile's list field in place. nil (omitted) still
// preserves, which the per-resource overlay tests already cover. Each field must
// become an empty non-nil slice so pango emits an empty container that clears the
// node on the edit, not nil (which pango omits, preserving the old value).
func TestOverlayProfilesClearList(t *testing.T) {
	t.Run("url-filtering categories", func(t *testing.T) {
		e := &urlfiltering.Entry{Name: "u1", Block: []string{"old"}}
		if err := overlayURLFiltering(e, URLFilteringProfileInput{Name: "u1", Block: []string{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "Block", e.Block)
	})
	t.Run("antivirus decoders", func(t *testing.T) {
		e := &antivirus.Entry{Name: "av1", Decoder: []antivirus.Decoder{{Name: "old"}}}
		if err := overlayAntivirus(e, AntivirusProfileInput{Name: "av1", Decoders: []AntivirusDecoderInput{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "decoders", e.Decoder)
	})
	t.Run("vulnerability inline exceptions", func(t *testing.T) {
		e := &vulnerability.Entry{Name: "v1", InlineExceptionEdlUrl: []string{"old"}, InlineExceptionIpAddress: []string{"1.2.3.4"}}
		if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1", InlineExceptionEdlURLs: []string{}, InlineExceptionIPAddresses: []string{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "inline_exception_edl_urls", e.InlineExceptionEdlUrl)
		assertClearedList(t, "inline_exception_ip_addresses", e.InlineExceptionIpAddress)
	})
	t.Run("spyware inline exceptions", func(t *testing.T) {
		e := &spyware.Entry{Name: "s1", InlineExceptionEdlUrl: []string{"old"}, InlineExceptionIpAddress: []string{"1.2.3.4"}}
		if err := overlaySpyware(e, SpywareProfileInput{Name: "s1", InlineExceptionEdlURLs: []string{}, InlineExceptionIPAddresses: []string{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "inline_exception_edl_urls", e.InlineExceptionEdlUrl)
		assertClearedList(t, "inline_exception_ip_addresses", e.InlineExceptionIpAddress)
	})
	t.Run("file-blocking rules", func(t *testing.T) {
		e := &fileblocking.Entry{Name: "fb1", Rules: []fileblocking.Rules{{Name: "old"}}}
		if err := overlayFileBlocking(e, FileBlockingProfileInput{Name: "fb1", Rules: []FileBlockingRuleInput{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "rules", e.Rules)
	})
	t.Run("wildfire-analysis rules", func(t *testing.T) {
		e := &wildfireanalysis.Entry{Name: "wf1", Rules: []wildfireanalysis.Rules{{Name: "old"}}}
		if err := overlayWildfireAnalysis(e, WildfireAnalysisProfileInput{Name: "wf1", Rules: []WildfireAnalysisRuleInput{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "rules", e.Rules)
	})
}

// assertClearedList asserts a profile list field was cleared in place to an empty
// non-nil slice (pango emits an empty container that clears the node on the edit),
// the issue #61 contract, rather than left nil (which pango omits, preserving it).
func assertClearedList[T any](t *testing.T, field string, got []T) {
	t.Helper()
	if got == nil || len(got) != 0 {
		t.Errorf("explicit empty %s must clear to an empty non-nil slice, got %#v", field, got)
	}
}

func TestURLFilteringSummary(t *testing.T) {
	e := &urlfiltering.Entry{Name: "u1", Description: ptr("d"), Block: []string{"malware"}, SafeSearchEnforcement: ptr(true), LogHttpHdrReferer: ptr(true)}
	m := mustMap(t, urlFilteringSummary(e))
	if m[tagNameKey] != "u1" || m[descriptionKey] != "d" || m["safe_search_enforcement"] != true || m["log_http_header_referer"] != true {
		t.Errorf("summary: %+v", m)
	}
	if got := mustStrSlice(t, m["block"]); len(got) != 1 || got[0] != "malware" {
		t.Errorf("block: %+v", got)
	}
}

// TestURLFilteringCustomURLCategoryNameRoundTrip pins issue #64 item 4: a custom
// URL category (panos_custom_url_category_create) is referenced from a URL
// filtering profile simply by its name in a category-action list, on create and
// on update, and the name survives the summary projection.
func TestURLFilteringCustomURLCategoryNameRoundTrip(t *testing.T) {
	const custom = "my-custom-cat"
	e, err := buildURLFilteringEntry(URLFilteringProfileInput{Name: "u1", Block: []string{custom, "malware"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Block) != 2 || e.Block[0] != custom {
		t.Errorf("create must carry the custom category name into block: %+v", e.Block)
	}
	if got := mustStrSlice(t, mustMap(t, urlFilteringSummary(e))["block"]); len(got) != 2 || got[0] != custom {
		t.Errorf("summary must echo the custom category name: %+v", got)
	}
	e2 := &urlfiltering.Entry{Name: "u1", Block: []string{"old"}}
	if err := overlayURLFiltering(e2, URLFilteringProfileInput{Name: "u1", Block: []string{custom}}); err != nil {
		t.Fatal(err)
	}
	if len(e2.Block) != 1 || e2.Block[0] != custom {
		t.Errorf("update must replace block with the custom category name: %+v", e2.Block)
	}
	if got := mustStrSlice(t, mustMap(t, urlFilteringSummary(e2))["block"]); len(got) != 1 || got[0] != custom {
		t.Errorf("update summary must echo the custom category name: %+v", got)
	}
	if got := mustStrSlice(t, mustMap(t, urlFilteringSummary(e2))["alert"]); got != nil {
		t.Errorf("untouched alert list must stay nil: %+v", got)
	}
}

// --- File blocking: unit tests ----------------------------------------------

func TestBuildFileBlockingEntry(t *testing.T) {
	e, err := buildFileBlockingEntry(FileBlockingProfileInput{
		Name: "fb1", Description: "d",
		Rules: []FileBlockingRuleInput{{Name: "r1", Applications: []string{"any"}, FileTypes: []string{"exe"}, Direction: "both", Action: "block"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "fb1" || strVal(e.Description) != "d" || len(e.Rules) != 1 {
		t.Fatalf("base fields: %+v", e)
	}
	r := e.Rules[0]
	if r.Name != "r1" || len(r.Application) != 1 || len(r.FileType) != 1 || r.FileType[0] != "exe" || strVal(r.Direction) != "both" || strVal(r.Action) != "block" {
		t.Errorf("rule mapping: %+v", r)
	}
}

func TestBuildFileBlockingEntryRejects(t *testing.T) {
	if _, err := buildFileBlockingEntry(FileBlockingProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
	if _, err := buildFileBlockingEntry(FileBlockingProfileInput{Name: "fb", Rules: []FileBlockingRuleInput{{Action: "block"}}}); err == nil {
		t.Error("rule without a name must fail")
	}
}

func TestOverlayFileBlocking(t *testing.T) {
	e := &fileblocking.Entry{Name: "fb1", Description: ptr("old"), Rules: []fileblocking.Rules{{Name: "old"}}}
	if err := overlayFileBlocking(e, FileBlockingProfileInput{Name: "fb1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || len(e.Rules) != 1 || e.Rules[0].Name != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayFileBlocking(e, FileBlockingProfileInput{Name: "fb1", Rules: []FileBlockingRuleInput{{Name: "r1", Action: "alert"}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Rules) != 1 || e.Rules[0].Name != "r1" || strVal(e.Rules[0].Action) != "alert" {
		t.Errorf("provided rules must replace: %+v", e)
	}
}

func TestFileBlockingSummary(t *testing.T) {
	e := &fileblocking.Entry{Name: "fb1", Description: ptr("d"),
		Rules: []fileblocking.Rules{{Name: "r1", Application: []string{"any"}, FileType: []string{"exe"}, Direction: ptr("both"), Action: ptr("block")}}}
	m := mustMap(t, fileBlockingSummary(e))
	if m[tagNameKey] != "fb1" || m[descriptionKey] != "d" {
		t.Errorf("summary base: %+v", m)
	}
	rules := mustAnySlice(t, m["rules"])
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	r0 := mustMap(t, rules[0])
	if r0[tagNameKey] != "r1" || r0["direction"] != "both" || r0["action"] != "block" {
		t.Errorf("rule summary: %+v", r0)
	}
}

// --- WildFire analysis: unit tests ------------------------------------------

func TestBuildWildfireAnalysisEntry(t *testing.T) {
	e, err := buildWildfireAnalysisEntry(WildfireAnalysisProfileInput{
		Name: "wf1", Description: "d",
		Rules: []WildfireAnalysisRuleInput{{Name: "r1", Applications: []string{"any"}, FileTypes: []string{"pdf"}, Direction: "both", Analysis: "public-cloud"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "wf1" || strVal(e.Description) != "d" || len(e.Rules) != 1 {
		t.Fatalf("base fields: %+v", e)
	}
	r := e.Rules[0]
	if r.Name != "r1" || len(r.FileType) != 1 || strVal(r.Direction) != "both" || strVal(r.Analysis) != "public-cloud" {
		t.Errorf("rule mapping: %+v", r)
	}
	if _, err := buildWildfireAnalysisEntry(WildfireAnalysisProfileInput{Name: "wf", Rules: []WildfireAnalysisRuleInput{{Analysis: "public-cloud"}}}); err == nil {
		t.Error("rule without a name must fail")
	}
}

func TestOverlayWildfireAnalysis(t *testing.T) {
	e := &wildfireanalysis.Entry{Name: "wf1", Description: ptr("old"), Rules: []wildfireanalysis.Rules{{Name: "old"}}}
	if err := overlayWildfireAnalysis(e, WildfireAnalysisProfileInput{Name: "wf1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || len(e.Rules) != 1 || e.Rules[0].Name != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayWildfireAnalysis(e, WildfireAnalysisProfileInput{Name: "wf1", Rules: []WildfireAnalysisRuleInput{{Name: "r1", Analysis: "private-cloud"}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Rules) != 1 || e.Rules[0].Name != "r1" || strVal(e.Rules[0].Analysis) != "private-cloud" {
		t.Errorf("provided rules must replace: %+v", e)
	}
}

func TestWildfireAnalysisSummary(t *testing.T) {
	e := &wildfireanalysis.Entry{Name: "wf1", Description: ptr("d"),
		Rules: []wildfireanalysis.Rules{{Name: "r1", Direction: ptr("upload"), Analysis: ptr("public-cloud")}}}
	m := mustMap(t, wildfireAnalysisSummary(e))
	rules := mustAnySlice(t, m["rules"])
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	r0 := mustMap(t, rules[0])
	if r0[tagNameKey] != "r1" || r0["direction"] != "upload" || r0["analysis"] != "public-cloud" {
		t.Errorf("rule summary: %+v", r0)
	}
}

// --- Security profile group: unit tests -------------------------------------

func TestBuildProfileGroupEntry(t *testing.T) {
	e, err := buildProfileGroupEntry(ProfileGroupInput{
		Name: "pg1", Antivirus: "av1", AntiSpyware: "as1", Vulnerability: "vp1",
		URLFiltering: "url1", FileBlocking: "fb1", WildfireAnalysis: "wf1", DataFiltering: "df1",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Each scalar maps to a single-member list on the pango entry.
	if len(e.Virus) != 1 || e.Virus[0] != "av1" || len(e.Spyware) != 1 || e.Spyware[0] != "as1" ||
		len(e.Vulnerability) != 1 || len(e.UrlFiltering) != 1 || e.UrlFiltering[0] != "url1" ||
		len(e.FileBlocking) != 1 || len(e.WildfireAnalysis) != 1 || len(e.DataFiltering) != 1 {
		t.Errorf("member mapping: %+v", e)
	}
	if _, err := buildProfileGroupEntry(ProfileGroupInput{}); err == nil {
		t.Error("missing name must fail")
	}
}

func TestOverlayProfileGroup(t *testing.T) {
	e := &secgroup.Entry{Name: "pg1", Virus: []string{"old"}, UrlFiltering: []string{"keep"}}
	if err := overlayProfileGroup(e, ProfileGroupInput{Name: "pg1", Antivirus: ""}); err != nil {
		t.Fatal(err)
	}
	if len(e.Virus) != 1 || e.Virus[0] != "old" || len(e.UrlFiltering) != 1 || e.UrlFiltering[0] != "keep" {
		t.Errorf("omitted members must be preserved: %+v", e)
	}
	if err := overlayProfileGroup(e, ProfileGroupInput{Name: "pg1", Antivirus: "av2"}); err != nil {
		t.Fatal(err)
	}
	if len(e.Virus) != 1 || e.Virus[0] != "av2" || len(e.UrlFiltering) != 1 || e.UrlFiltering[0] != "keep" {
		t.Errorf("provided member must replace, others preserved: %+v", e)
	}
}

func TestProfileGroupSummary(t *testing.T) {
	e := &secgroup.Entry{Name: "pg1", Virus: []string{"av1"}, UrlFiltering: []string{"url1"}}
	m := mustMap(t, profileGroupSummary(e))
	if m[tagNameKey] != "pg1" || m["antivirus"] != "av1" || m["url_filtering"] != "url1" {
		t.Errorf("summary: %+v", m)
	}
	// An unset type reports the empty string, not a leaked slice.
	if m["vulnerability"] != "" {
		t.Errorf("unset type must be empty string: %+v", m["vulnerability"])
	}
}

// --- Antivirus: wire-level tests --------------------------------------------

func TestAntivirusProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("av-new")},
	)
	h := createHandler[antivirus.Location, antivirus.Entry, AntivirusProfileInput](d, "panos_antivirus_profile_create", newAntivirusService(d), antivirusResolve(d),
		func(in AntivirusProfileInput) LocationInput { return in.Location }, buildAntivirusEntry, antivirusSummary)
	res, _, err := h(t.Context(), nil, AntivirusProfileInput{Name: "av-new", Description: "d", PacketCapture: ptr(true),
		Decoders: []AntivirusDecoderInput{{Name: "http", Action: "drop"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<decoder>`, `<entry name="http">`, `<action>drop</action>`, `<description>d</description>`, "av-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "profiles/virus") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall antivirus node: %s", xs)
	}
}

func TestAntivirusProfileList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: antivirusListBody})
	h := listHandler[antivirus.Location, antivirus.Entry](d, "panos_antivirus_profile_list", newAntivirusService(d), antivirusResolve(d), func(e *antivirus.Entry) string { return e.Name }, antivirusSummary)
	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"total": 3`, `"av-a"`, `"av-a desc"`, `"http"`, `"action": "alert"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("list missing %q: %s", want, out)
		}
	}
	for _, leak := range []string{"MiscAttributes", `"Decoder"`, "PacketCapture"} {
		if strings.Contains(out, leak) {
			t.Fatalf("list leaked internal field %q: %s", leak, out)
		}
	}
}

func TestAntivirusProfileUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + antivirusEntryXML("av-a") + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[antivirus.Location, antivirus.Entry, AntivirusProfileInput](d, "panos_antivirus_profile_update", newAntivirusService(d), antivirusResolve(d),
		func(in AntivirusProfileInput) LocationInput { return in.Location },
		func(in AntivirusProfileInput) string { return in.Name }, overlayAntivirus, antivirusSummary)
	res, _, err := h(t.Context(), nil, AntivirusProfileInput{Name: "av-a", Description: "changed"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("update failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<description>changed</description>") {
		t.Fatalf("update element missing new description: %s", el)
	}
	// read-modify-write preserves the existing decoder.
	if !strings.Contains(el, `<entry name="http">`) {
		t.Fatalf("update dropped the preserved decoder: %s", el)
	}
}

func TestAntivirusProfileDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[antivirus.Location, antivirus.Entry](d, "panos_antivirus_profile_delete", newAntivirusService(d), antivirusResolve(d))
	res, _, err := h(t.Context(), nil, NameInput{Name: "av-a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "av-a") || !strings.Contains(el, "profiles/virus") {
		t.Fatalf("delete element wrong: %s", el)
	}
}

func TestAntivirusProfilePanoramaLocation(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("av-new")},
	)
	h := createHandler[antivirus.Location, antivirus.Entry, AntivirusProfileInput](d, "panos_antivirus_profile_create", newAntivirusService(d), antivirusResolve(d),
		func(in AntivirusProfileInput) LocationInput { return in.Location }, buildAntivirusEntry, antivirusSummary)
	res, _, err := h(t.Context(), nil, AntivirusProfileInput{Name: "av-new", Location: LocationInput{DeviceGroup: "dg1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "dg1") || !strings.Contains(xs, "profiles/virus") {
		t.Fatalf("panorama create did not target the device-group antivirus node: %s", xs)
	}
}

func TestAntivirusProfileGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + antivirusEntryXML("av-a") + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAntivirusProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_antivirus_profile_get", Arguments: map[string]any{"name": "av-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='av-a']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "profiles/virus") {
		t.Fatalf("registered get did not target the antivirus node: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_antivirus_profile_update", Arguments: map[string]any{"name": "av-a", "description": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "new") || !strings.Contains(el, "av-a") {
		t.Fatalf("registered update did not reach the API: %s", el)
	}
}

// --- URL filtering: wire-level tests (nil-vsys behavior) --------------------

func TestURLFilteringProfileCreateSharedOnFirewall(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("u-new")},
	)
	h := createHandler[urlfiltering.Location, urlfiltering.Entry, URLFilteringProfileInput](d, "panos_url_filtering_profile_create", newURLFilteringService(d), urlFilteringResolve(d),
		func(in URLFilteringProfileInput) LocationInput { return in.Location }, buildURLFilteringEntry, urlFilteringSummary)
	res, _, err := h(t.Context(), nil, URLFilteringProfileInput{Name: "u-new", Block: []string{"malware"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "url-filtering") || !strings.Contains(xs, "/config/shared") {
		t.Fatalf("firewall default must target shared url-filtering: %s", xs)
	}
	if strings.Contains(xs, "vsys1") {
		t.Fatalf("a vsys-less type must not target vsys1 on a firewall: %s", xs)
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<block><member>malware</member></block>") {
		t.Fatalf("create set element missing block category: %s", set)
	}
}

func TestURLFilteringProfileVsysRejected(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[urlfiltering.Location, urlfiltering.Entry, URLFilteringProfileInput](d, "panos_url_filtering_profile_create", newURLFilteringService(d), urlFilteringResolve(d),
		func(in URLFilteringProfileInput) LocationInput { return in.Location }, buildURLFilteringEntry, urlFilteringSummary)
	res, _, err := h(t.Context(), nil, URLFilteringProfileInput{Name: "u", Location: LocationInput{Vsys: "vsys1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("explicit vsys on a vsys-less type must be rejected")
	}
	assertNoConfigWrite(t, f)
}

// --- File blocking and profile group: create wire shape ---------------------

func TestFileBlockingProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("fb-new")},
	)
	h := createHandler[fileblocking.Location, fileblocking.Entry, FileBlockingProfileInput](d, "panos_file_blocking_profile_create", newFileBlockingService(d), fileBlockingResolve(d),
		func(in FileBlockingProfileInput) LocationInput { return in.Location }, buildFileBlockingEntry, fileBlockingSummary)
	res, _, err := h(t.Context(), nil, FileBlockingProfileInput{Name: "fb-new",
		Rules: []FileBlockingRuleInput{{Name: "r1", FileTypes: []string{"exe"}, Direction: "both", Action: "block"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<rules><entry name="r1">`, "<action>block</action>", "<direction>both</direction>", "<file-type><member>exe</member></file-type>"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "profiles/file-blocking") {
		t.Fatalf("create did not target the file-blocking node: %s", xs)
	}
}

func TestProfileGroupCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("pg-new")},
	)
	h := createHandler[secgroup.Location, secgroup.Entry, ProfileGroupInput](d, "panos_profile_group_create", newProfileGroupService(d), profileGroupResolve(d),
		func(in ProfileGroupInput) LocationInput { return in.Location }, buildProfileGroupEntry, profileGroupSummary)
	res, _, err := h(t.Context(), nil, ProfileGroupInput{Name: "pg-new", Antivirus: "av1", URLFiltering: "url1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{"<virus><member>av1</member></virus>", "<url-filtering><member>url1</member></url-filtering>"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "profile-group") {
		t.Fatalf("create did not target the profile-group node: %s", xs)
	}
}

// --- Vulnerability, anti-spyware, WildFire: create wire shape + location -----

func TestVulnerabilityProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("v-new")},
	)
	h := createHandler[vulnerability.Location, vulnerability.Entry, VulnerabilityProfileInput](d, "panos_vulnerability_profile_create", newVulnerabilityService(d), vulnerabilityResolve(d),
		func(in VulnerabilityProfileInput) LocationInput { return in.Location }, buildVulnerabilityEntry, vulnerabilitySummary)
	res, _, err := h(t.Context(), nil, VulnerabilityProfileInput{Name: "v-new", CloudInlineAnalysis: ptr(true), InlineExceptionIPAddresses: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<inline-exception-ip-address><member>1.2.3.4</member></inline-exception-ip-address>") {
		t.Fatalf("create set element missing inline exception: %s", set)
	}
	// vulnerability has no vsys location: a firewall default targets shared.
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "profiles/vulnerability") || !strings.Contains(xs, "/config/shared") {
		t.Fatalf("create did not target the shared vulnerability node: %s", xs)
	}
	if strings.Contains(xs, "vsys1") {
		t.Fatalf("a vsys-less type must not target vsys1 on a firewall: %s", xs)
	}
}

func TestSpywareProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("s-new")},
	)
	h := createHandler[spyware.Location, spyware.Entry, SpywareProfileInput](d, "panos_anti_spyware_profile_create", newSpywareService(d), spywareResolve(d),
		func(in SpywareProfileInput) LocationInput { return in.Location }, buildSpywareEntry, spywareSummary)
	res, _, err := h(t.Context(), nil, SpywareProfileInput{Name: "s-new", Description: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<description>d</description>") {
		t.Fatalf("create set element missing description: %s", set)
	}
	// anti-spyware DOES have a vsys location: a firewall default targets vsys1.
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "profiles/spyware") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall vsys spyware node: %s", xs)
	}
}

func TestWildfireAnalysisProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("wf-new")},
	)
	h := createHandler[wildfireanalysis.Location, wildfireanalysis.Entry, WildfireAnalysisProfileInput](d, "panos_wildfire_analysis_profile_create", newWildfireAnalysisService(d), wildfireAnalysisResolve(d),
		func(in WildfireAnalysisProfileInput) LocationInput { return in.Location }, buildWildfireAnalysisEntry, wildfireAnalysisSummary)
	res, _, err := h(t.Context(), nil, WildfireAnalysisProfileInput{Name: "wf-new",
		Rules: []WildfireAnalysisRuleInput{{Name: "r1", FileTypes: []string{"pdf"}, Direction: "both", Analysis: "public-cloud"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<rules><entry name="r1">`, "<analysis>public-cloud</analysis>", "<direction>both</direction>"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	// wildfire-analysis has no vsys location: a firewall default targets shared.
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "profiles/wildfire-analysis") || !strings.Contains(xs, "/config/shared") {
		t.Fatalf("create did not target the shared wildfire-analysis node: %s", xs)
	}
	if strings.Contains(xs, "vsys1") {
		t.Fatalf("a vsys-less type must not target vsys1 on a firewall: %s", xs)
	}
}

// --- Read-only gate for every profile resource ------------------------------

func TestRegisterProfileToolsReadOnly(t *testing.T) {
	prefixes := []string{
		"panos_antivirus_profile", "panos_vulnerability_profile", "panos_anti_spyware_profile",
		"panos_url_filtering_profile", "panos_file_blocking_profile", "panos_wildfire_analysis_profile",
		"panos_profile_group",
	}
	for _, p := range prefixes {
		reads := []string{p + "_list", p + "_get"}
		writes := []string{p + "_create", p + "_update", p + "_delete"}
		assertReadOnlyGate(t, reads, writes)
	}
}
