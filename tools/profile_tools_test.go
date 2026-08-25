package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/profiles/antivirus"
	"github.com/PaloAltoNetworks/pango/objects/profiles/decryption"
	"github.com/PaloAltoNetworks/pango/objects/profiles/fileblocking"
	"github.com/PaloAltoNetworks/pango/objects/profiles/logforwarding"
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
		Name: "av1", Description: "d", PacketCapture: new(true),
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
	e := &antivirus.Entry{Name: "av1", Description: new("old"), PacketCapture: new(true), Decoder: []antivirus.Decoder{{Name: "old"}}}
	if err := overlayAntivirus(e, AntivirusProfileInput{Name: "av1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.PacketCapture) || len(e.Decoder) != 1 || e.Decoder[0].Name != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayAntivirus(e, AntivirusProfileInput{Name: "av1", Description: "new", PacketCapture: new(false), Decoders: []AntivirusDecoderInput{{Name: "http"}}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.PacketCapture) || len(e.Decoder) != 1 || e.Decoder[0].Name != "http" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestAntivirusSummary(t *testing.T) {
	e := &antivirus.Entry{Name: "av1", Description: new("d"), PacketCapture: new(true),
		Decoder: []antivirus.Decoder{{Name: "http", Action: new("drop"), WildfireAction: new("reset-both"), MlavAction: new("alert")}}}
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
		Name: "v1", Description: "d", CloudInlineAnalysis: new(true),
		InlineExceptionEdlURLs: []string{"edl1"}, InlineExceptionIPAddresses: []string{"ip-edl-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "v1" || strVal(e.Description) != "d" || !boolVal(e.CloudInlineAnalysis) {
		t.Errorf("base fields: %+v", e)
	}
	if len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "edl1" ||
		len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "ip-edl-1" {
		t.Errorf("inline exceptions: %+v", e)
	}
	if _, err := buildVulnerabilityEntry(VulnerabilityProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
}

func TestOverlayVulnerability(t *testing.T) {
	// cloud_inline_analysis starts true so an unconditional overwrite (nil) is caught.
	e := &vulnerability.Entry{Name: "v1", Description: new("old"), CloudInlineAnalysis: new(true), InlineExceptionEdlUrl: []string{"old"}}
	if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1", Description: "new", CloudInlineAnalysis: new(false), InlineExceptionEdlURLs: []string{"new"}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionEdlUrl) != 1 || e.InlineExceptionEdlUrl[0] != "new" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestVulnerabilitySummary(t *testing.T) {
	e := &vulnerability.Entry{Name: "v1", Description: new("d"), CloudInlineAnalysis: new(true),
		InlineExceptionEdlUrl: []string{"edl1"}, InlineExceptionIpAddress: []string{"ip-edl-1"}}
	m := mustMap(t, vulnerabilitySummary(e))
	if m[tagNameKey] != "v1" || m[descriptionKey] != "d" || m["cloud_inline_analysis"] != true {
		t.Errorf("summary base: %+v", m)
	}
	if got := mustStrSlice(t, m["inline_exception_edl_urls"]); len(got) != 1 || got[0] != "edl1" {
		t.Errorf("edl exceptions: %+v", got)
	}
	if got := mustStrSlice(t, m["inline_exception_ip_addresses"]); len(got) != 1 || got[0] != "ip-edl-1" {
		t.Errorf("ip exceptions: %+v", got)
	}
}

// --- Anti-spyware: unit tests -----------------------------------------------

func TestBuildSpywareEntry(t *testing.T) {
	e, err := buildSpywareEntry(SpywareProfileInput{
		Name: "s1", Description: "d", CloudInlineAnalysis: new(true),
		InlineExceptionEdlURLs: []string{"edl1"}, InlineExceptionIPAddresses: []string{"ip-edl-1"},
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
	e := &spyware.Entry{Name: "s1", Description: new("old"), CloudInlineAnalysis: new(true), InlineExceptionIpAddress: []string{"old"}}
	if err := overlaySpyware(e, SpywareProfileInput{Name: "s1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlaySpyware(e, SpywareProfileInput{Name: "s1", Description: "new", CloudInlineAnalysis: new(false), InlineExceptionIPAddresses: []string{"new"}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.CloudInlineAnalysis) || len(e.InlineExceptionIpAddress) != 1 || e.InlineExceptionIpAddress[0] != "new" {
		t.Errorf("provided fields must replace: %+v", e)
	}
}

func TestSpywareSummary(t *testing.T) {
	e := &spyware.Entry{Name: "s1", Description: new("d"), CloudInlineAnalysis: new(true), InlineExceptionIpAddress: []string{"ip-edl-1"}}
	m := mustMap(t, spywareSummary(e))
	if m[tagNameKey] != "s1" || m[descriptionKey] != "d" || m["cloud_inline_analysis"] != true {
		t.Errorf("summary: %+v", m)
	}
	if got := mustStrSlice(t, m["inline_exception_ip_addresses"]); len(got) != 1 || got[0] != "ip-edl-1" {
		t.Errorf("ip exceptions: %+v", got)
	}
}

// --- URL filtering: unit tests ----------------------------------------------

func TestBuildURLFilteringEntry(t *testing.T) {
	e, err := buildURLFilteringEntry(URLFilteringProfileInput{
		Name: "u1", Description: "d",
		Alert: []string{"c1"}, Allow: []string{"c2"}, Block: []string{"c3"}, Continue: []string{"c4"}, Override: []string{"c5"},
		SafeSearchEnforcement: new(true), LogHTTPHeaderXFF: new(true),
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
		Name: "u1", Description: new("old"), Block: []string{"old"},
		SafeSearchEnforcement: new(true), LogHttpHdrXff: new(true),
		LogHttpHdrUserAgent: new(true), LogHttpHdrReferer: new(true),
	}
	if err := overlayURLFiltering(e, URLFilteringProfileInput{Name: "u1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || urlToggles(e) != allTrue || len(e.Block) != 1 || e.Block[0] != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayURLFiltering(e, URLFilteringProfileInput{
		Name: "u1", Block: []string{"malware"},
		SafeSearchEnforcement: new(false), LogHTTPHeaderXFF: new(false),
		LogHTTPHeaderUserAgent: new(false), LogHTTPHeaderReferer: new(false),
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
		e := &vulnerability.Entry{Name: "v1", InlineExceptionEdlUrl: []string{"old"}, InlineExceptionIpAddress: []string{"ip-edl-1"}}
		if err := overlayVulnerability(e, VulnerabilityProfileInput{Name: "v1", InlineExceptionEdlURLs: []string{}, InlineExceptionIPAddresses: []string{}}); err != nil {
			t.Fatal(err)
		}
		assertClearedList(t, "inline_exception_edl_urls", e.InlineExceptionEdlUrl)
		assertClearedList(t, "inline_exception_ip_addresses", e.InlineExceptionIpAddress)
	})
	t.Run("spyware inline exceptions", func(t *testing.T) {
		e := &spyware.Entry{Name: "s1", InlineExceptionEdlUrl: []string{"old"}, InlineExceptionIpAddress: []string{"ip-edl-1"}}
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
	e := &urlfiltering.Entry{Name: "u1", Description: new("d"), Block: []string{"malware"}, SafeSearchEnforcement: new(true), LogHttpHdrReferer: new(true)}
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
	e := &fileblocking.Entry{Name: "fb1", Description: new("old"), Rules: []fileblocking.Rules{{Name: "old"}}}
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
	e := &fileblocking.Entry{Name: "fb1", Description: new("d"),
		Rules: []fileblocking.Rules{{Name: "r1", Application: []string{"any"}, FileType: []string{"exe"}, Direction: new("both"), Action: new("block")}}}
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
	e := &wildfireanalysis.Entry{Name: "wf1", Description: new("old"), Rules: []wildfireanalysis.Rules{{Name: "old"}}}
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
	e := &wildfireanalysis.Entry{Name: "wf1", Description: new("d"),
		Rules: []wildfireanalysis.Rules{{Name: "r1", Direction: new("upload"), Analysis: new("public-cloud")}}}
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
	res, _, err := h(t.Context(), nil, AntivirusProfileInput{Name: "av-new", Description: "d", PacketCapture: new(true),
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
	res, _, err := h(t.Context(), nil, VulnerabilityProfileInput{Name: "v-new", CloudInlineAnalysis: new(true), InlineExceptionIPAddresses: []string{"ip-edl-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<inline-exception-ip-address><member>ip-edl-1</member></inline-exception-ip-address>") {
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
		"panos_profile_group", "panos_log_forwarding_profile", "panos_decryption_profile",
	}
	for _, p := range prefixes {
		reads := []string{p + "_list", p + "_get"}
		writes := []string{p + "_create", p + "_update", p + "_delete"}
		assertReadOnlyGate(t, reads, writes)
	}
}

// --- Log forwarding ----------------------------------------------------------

func logForwardingResolve(d *Deps) func(LocationInput) (logforwarding.Location, error) {
	return func(in LocationInput) (logforwarding.Location, error) {
		return resolveLocation(d, in, logForwardingParts())
	}
}

//nolint:gocyclo // exhaustive field-mapping assertions across the built match list.
func TestBuildLogForwardingEntry(t *testing.T) {
	e, err := buildLogForwardingEntry(LogForwardingProfileInput{
		Name:                       "lf",
		Description:                "d",
		EnhancedApplicationLogging: new(true),
		MatchLists: []LogForwardingMatchListInput{{
			Name: "m1", LogType: "traffic", Filter: "addr.src in 10.0.0.0/8", Description: "md",
			SendToPanorama: new(true), Quarantine: new(false), SendSyslog: []string{"sys1"},
			SendSnmptrap: []string{"snmp1"}, SendEmail: []string{"mail1"}, SendHTTP: []string{"http1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "lf" || strVal(e.Description) != "d" || !boolVal(e.EnhancedApplicationLogging) {
		t.Fatalf("entry header wrong: %+v", e)
	}
	if len(e.MatchList) != 1 {
		t.Fatalf("want 1 match list, got %d", len(e.MatchList))
	}
	ml := e.MatchList[0]
	if ml.Name != "m1" || strVal(ml.LogType) != "traffic" || strVal(ml.Filter) != "addr.src in 10.0.0.0/8" ||
		strVal(ml.ActionDesc) != "md" || !boolVal(ml.SendToPanorama) {
		t.Fatalf("match list scalars mapped wrong: %+v", ml)
	}
	if ml.Quarantine == nil || *ml.Quarantine {
		t.Fatalf("quarantine present-false must map to a non-nil false: %v", ml.Quarantine)
	}
	// Each server-profile reference list maps to its own field; a swap or dropped
	// line turns one of these red.
	for name, got := range map[string][]string{
		"send_syslog": ml.SendSyslog, "send_snmptrap": ml.SendSnmptrap,
		"send_email": ml.SendEmail, "send_http": ml.SendHttp,
	} {
		if len(got) != 1 {
			t.Fatalf("%s must carry its one member, got %v", name, got)
		}
	}
	if ml.SendSyslog[0] != "sys1" || ml.SendSnmptrap[0] != "snmp1" || ml.SendEmail[0] != "mail1" || ml.SendHttp[0] != "http1" {
		t.Fatalf("server-profile reference lists mapped to the wrong fields: %+v", ml)
	}
}

func TestBuildLogForwardingEntryRejects(t *testing.T) {
	if _, err := buildLogForwardingEntry(LogForwardingProfileInput{}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("empty name must be rejected, got %v", err)
	}
	_, err := buildLogForwardingEntry(LogForwardingProfileInput{Name: "lf", MatchLists: []LogForwardingMatchListInput{{LogType: "traffic"}}})
	if err == nil || !strings.Contains(err.Error(), "each match list requires a name") {
		t.Fatalf("unnamed match list must be rejected, got %v", err)
	}
}

func TestOverlayLogForwarding(t *testing.T) {
	t.Run("nil match_lists preserves existing", func(t *testing.T) {
		e := &logforwarding.Entry{Name: "lf", MatchList: []logforwarding.MatchList{{Name: "keep", Actions: []logforwarding.MatchListActions{{Name: "act"}}}}}
		if err := overlayLogForwarding(e, LogForwardingProfileInput{Description: "d"}); err != nil {
			t.Fatal(err)
		}
		if len(e.MatchList) != 1 || e.MatchList[0].Name != "keep" || len(e.MatchList[0].Actions) != 1 {
			t.Fatalf("nil match_lists must preserve the existing list and its actions: %+v", e.MatchList)
		}
	})
	t.Run("explicit empty clears", func(t *testing.T) {
		e := &logforwarding.Entry{Name: "lf", MatchList: []logforwarding.MatchList{{Name: "old"}}}
		if err := overlayLogForwarding(e, LogForwardingProfileInput{MatchLists: []LogForwardingMatchListInput{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.MatchList) != 0 {
			t.Fatalf("explicit empty match_lists must clear the set: %+v", e.MatchList)
		}
	})
	t.Run("provided list replaces", func(t *testing.T) {
		e := &logforwarding.Entry{Name: "lf", MatchList: []logforwarding.MatchList{{Name: "old"}}}
		if err := overlayLogForwarding(e, LogForwardingProfileInput{MatchLists: []LogForwardingMatchListInput{{Name: "new"}}}); err != nil {
			t.Fatal(err)
		}
		if len(e.MatchList) != 1 || e.MatchList[0].Name != "new" {
			t.Fatalf("provided list must replace: %+v", e.MatchList)
		}
	})
	t.Run("omitted EAL preserves existing", func(t *testing.T) {
		e := &logforwarding.Entry{Name: "lf", EnhancedApplicationLogging: new(true)}
		if err := overlayLogForwarding(e, LogForwardingProfileInput{Description: "d"}); err != nil {
			t.Fatal(err)
		}
		if !boolVal(e.EnhancedApplicationLogging) {
			t.Fatal("omitted enhanced_application_logging must leave the existing value untouched")
		}
	})
}

//nolint:gocyclo,gocognit // exhaustive summary assertions across the omit and present-value scenarios.
func TestLogForwardingSummary(t *testing.T) {
	t.Run("nil toggles omit keys", func(t *testing.T) {
		m := asMap(t, logForwardingSummary(&logforwarding.Entry{Name: "lf"}))
		if _, ok := m["enhanced_application_logging"]; ok {
			t.Fatal("a nil enhanced_application_logging must be omitted, not coerced to false")
		}
		mls, ok := m["match_lists"].([]any)
		if !ok || len(mls) != 0 {
			t.Fatalf("match_lists must be an empty list, got %v", m["match_lists"])
		}
	})
	t.Run("present-false emitted, actions surfaced", func(t *testing.T) {
		e := &logforwarding.Entry{
			Name:                       "lf",
			EnhancedApplicationLogging: new(false),
			MatchList: []logforwarding.MatchList{{
				Name: "m1", SendToPanorama: new(false), Quarantine: new(true),
				LogType: new("traffic"), ActionDesc: new("md"),
				SendSyslog: []string{"sys1"}, SendSnmptrap: []string{"snmp1"},
				SendEmail: []string{"mail1"}, SendHttp: []string{"http1"},
				Actions: []logforwarding.MatchListActions{{Name: "act"}},
			}},
		}
		m := asMap(t, logForwardingSummary(e))
		if v, ok := m["enhanced_application_logging"].(bool); !ok || v {
			t.Fatalf("present-false enhanced_application_logging must be emitted as false: %v", m["enhanced_application_logging"])
		}
		mls, ok := m["match_lists"].([]any)
		if !ok || len(mls) == 0 {
			t.Fatalf("match_lists must carry the entry: %v", m["match_lists"])
		}
		ml, ok := mls[0].(map[string]any)
		if !ok {
			t.Fatalf("match list summary must be a map: %v", mls[0])
		}
		if v, ok := ml["send_to_panorama"].(bool); !ok || v {
			t.Fatalf("present-false send_to_panorama must be emitted as false: %v", ml["send_to_panorama"])
		}
		if v, ok := ml["quarantine"].(bool); !ok || !v {
			t.Fatalf("present-true quarantine must be emitted as true: %v", ml["quarantine"])
		}
		if ml["log_type"] != "traffic" || ml["description"] != "md" {
			t.Fatalf("match list scalars wrong: log_type=%v description=%v", ml["log_type"], ml["description"])
		}
		for name, want := range map[string]string{"send_syslog": "sys1", "send_snmptrap": "snmp1", "send_email": "mail1", "send_http": "http1"} {
			got, ok := ml[name].([]string)
			if !ok || len(got) != 1 || got[0] != want {
				t.Fatalf("%s summarized to the wrong field: %v", name, ml[name])
			}
		}
		if v, ok := ml["has_actions"].(bool); !ok || !v {
			t.Fatalf("has_actions must be true when actions present: %v", ml["has_actions"])
		}
	})
}

func TestLogForwardingProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("lf-new")},
	)
	h := createHandler[logforwarding.Location, logforwarding.Entry, LogForwardingProfileInput](d, "panos_log_forwarding_profile_create", newLogForwardingService(d), logForwardingResolve(d),
		func(in LogForwardingProfileInput) LocationInput { return in.Location }, buildLogForwardingEntry, logForwardingSummary)
	res, _, err := h(t.Context(), nil, LogForwardingProfileInput{Name: "lf-new", MatchLists: []LogForwardingMatchListInput{{
		Name: "m1", LogType: "traffic", SendToPanorama: new(true), SendSyslog: []string{"sys1"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<entry name="m1">`, `<log-type>traffic</log-type>`, `<send-syslog><member>sys1</member></send-syslog>`, `<send-to-panorama>yes</send-to-panorama>`, "lf-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "log-settings/profiles") || !strings.Contains(xs, "/config/shared") {
		t.Fatalf("firewall default must target shared log-settings/profiles: %s", xs)
	}
	if strings.Contains(xs, "vsys1") {
		t.Fatalf("a vsys-less type must not target vsys1 on a firewall: %s", xs)
	}
}

func TestLogForwardingProfileVsysRejected(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[logforwarding.Location, logforwarding.Entry, LogForwardingProfileInput](d, "panos_log_forwarding_profile_create", newLogForwardingService(d), logForwardingResolve(d),
		func(in LogForwardingProfileInput) LocationInput { return in.Location }, buildLogForwardingEntry, logForwardingSummary)
	res, _, err := h(t.Context(), nil, LogForwardingProfileInput{Name: "lf", Location: LocationInput{Vsys: "vsys1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("explicit vsys on a vsys-less type must be rejected")
	}
	assertNoConfigWrite(t, f)
}

func TestLogForwardingProfileGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	lfEntry := `<entry name="lf-a"><enhanced-application-logging>yes</enhanced-application-logging>` +
		`<match-list><entry name="ml1"><log-type>traffic</log-type><send-syslog><member>sys1</member></send-syslog></entry></match-list></entry>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + lfEntry + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterLogForwardingProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_log_forwarding_profile_get", Arguments: map[string]any{"name": "lf-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='lf-a']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "log-settings/profiles") {
		t.Fatalf("registered get did not target the log-forwarding node: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_log_forwarding_profile_update", Arguments: map[string]any{"name": "lf-a", "description": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	// read-modify-write preserves the existing match list when match_lists is omitted.
	if el := multiConfigElement(t, f); !strings.Contains(el, "new") || !strings.Contains(el, `<entry name="ml1">`) {
		t.Fatalf("registered update did not preserve the match list: %s", el)
	}
}

// --- Decryption profile ------------------------------------------------------

func decryptionProfileResolve(d *Deps) func(LocationInput) (decryption.Location, error) {
	return func(in LocationInput) (decryption.Location, error) {
		return resolveLocation(d, in, decryptionProfileParts())
	}
}

func TestBuildDecryptionProfileEntry(t *testing.T) {
	e, err := buildDecryptionProfileEntry(DecryptionProfileInput{Name: "dp", ForwardedOnly: new(true), SslMinVersion: "tls1-2", SslMaxVersion: "max"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "dp" || !boolVal(e.ForwardedOnly) {
		t.Fatalf("entry header wrong: %+v", e)
	}
	if e.SslProtocolSettings == nil || strVal(e.SslProtocolSettings.MinVersion) != "tls1-2" || strVal(e.SslProtocolSettings.MaxVersion) != "max" {
		t.Fatalf("ssl protocol settings mapped wrong: %+v", e.SslProtocolSettings)
	}
	bare, err := buildDecryptionProfileEntry(DecryptionProfileInput{Name: "dp"})
	if err != nil {
		t.Fatal(err)
	}
	if bare.SslProtocolSettings != nil {
		t.Fatal("no ssl version input must leave ssl-protocol-settings unset")
	}
}

func TestBuildDecryptionProfileEntryRejects(t *testing.T) {
	if _, err := buildDecryptionProfileEntry(DecryptionProfileInput{}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("empty name must be rejected, got %v", err)
	}
}

func TestOverlayDecryptionProfile(t *testing.T) {
	t.Run("version update preserves deferred toggles and proxy subtrees", func(t *testing.T) {
		// Seed a profile whose deferred per-algorithm toggle and proxy subtree must
		// survive a version-only update; in-place mutation of the existing struct
		// and touching only the modeled fields is what preserves them.
		e := &decryption.Entry{Name: "dp",
			SslProtocolSettings: &decryption.SslProtocolSettings{EncAlgoRc4: new(false), MinVersion: new("tls1-0")},
			SslForwardProxy:     &decryption.SslForwardProxy{BlockExpiredCertificate: new(true)},
		}
		if err := overlayDecryptionProfile(e, DecryptionProfileInput{SslMinVersion: "tls1-2"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.SslProtocolSettings.MinVersion) != "tls1-2" {
			t.Fatalf("min version not updated: %v", strVal(e.SslProtocolSettings.MinVersion))
		}
		if e.SslProtocolSettings.EncAlgoRc4 == nil || *e.SslProtocolSettings.EncAlgoRc4 {
			t.Fatalf("deferred enc-algo toggle must survive in-place update: %+v", e.SslProtocolSettings)
		}
		if e.SslProtocolSettings.MaxVersion != nil {
			t.Fatalf("untouched max version must stay nil: %v", strVal(e.SslProtocolSettings.MaxVersion))
		}
		if e.SslForwardProxy == nil || !boolVal(e.SslForwardProxy.BlockExpiredCertificate) {
			t.Fatalf("deferred proxy subtree must survive a version-only update: %+v", e.SslForwardProxy)
		}
	})
	t.Run("forwarded_only replaces and preserves", func(t *testing.T) {
		e := &decryption.Entry{Name: "dp", ForwardedOnly: new(false)}
		if err := overlayDecryptionProfile(e, DecryptionProfileInput{ForwardedOnly: new(true)}); err != nil {
			t.Fatal(err)
		}
		if !boolVal(e.ForwardedOnly) {
			t.Fatalf("provided forwarded_only must replace: %v", e.ForwardedOnly)
		}
		if err := overlayDecryptionProfile(e, DecryptionProfileInput{SslMinVersion: "tls1-2"}); err != nil {
			t.Fatal(err)
		}
		if !boolVal(e.ForwardedOnly) {
			t.Fatal("omitted forwarded_only must leave the existing value untouched")
		}
	})
}

func TestDecryptionProfileSummary(t *testing.T) {
	m := asMap(t, decryptionProfileSummary(&decryption.Entry{Name: "dp"}))
	if _, ok := m["description"]; ok {
		t.Fatal("decryption profile has no description; the key must never appear")
	}
	if _, ok := m["forwarded_only"]; ok {
		t.Fatal("a nil forwarded_only must be omitted")
	}
	if _, ok := m["ssl_min_version"]; ok {
		t.Fatal("ssl_min_version must be absent when ssl-protocol-settings is unset")
	}
	for _, k := range []string{"has_ssl_forward_proxy", "has_ssl_inbound_proxy", "has_ssl_no_proxy", "has_ssh_proxy"} {
		if v, ok := m[k].(bool); !ok || v {
			t.Fatalf("%s must be present and false for a bare entry: %v", k, m[k])
		}
	}
	full := asMap(t, decryptionProfileSummary(&decryption.Entry{
		Name: "dp", ForwardedOnly: new(true),
		SslProtocolSettings: &decryption.SslProtocolSettings{MinVersion: new("tls1-2")},
		SslForwardProxy:     &decryption.SslForwardProxy{},
	}))
	if v, ok := full["forwarded_only"].(bool); !ok || !v {
		t.Fatalf("present-true forwarded_only must be emitted: %v", full["forwarded_only"])
	}
	if full["ssl_min_version"] != "tls1-2" {
		t.Fatalf("ssl_min_version wrong: %v", full["ssl_min_version"])
	}
	if v, ok := full["has_ssl_forward_proxy"].(bool); !ok || !v {
		t.Fatalf("has_ssl_forward_proxy must be true when set: %v", full["has_ssl_forward_proxy"])
	}
}

func TestDecryptionProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("dp-new")},
	)
	h := createHandler[decryption.Location, decryption.Entry, DecryptionProfileInput](d, "panos_decryption_profile_create", newDecryptionProfileService(d), decryptionProfileResolve(d),
		func(in DecryptionProfileInput) LocationInput { return in.Location }, buildDecryptionProfileEntry, decryptionProfileSummary)
	res, _, err := h(t.Context(), nil, DecryptionProfileInput{Name: "dp-new", ForwardedOnly: new(true), SslMinVersion: "tls1-2"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<ssl-protocol-settings>`, `<min-version>tls1-2</min-version>`, `<forwarded-only>yes</forwarded-only>`, "dp-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "profiles/decryption") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall decryption node: %s", xs)
	}
}

func TestDecryptionProfileGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	dpEntry := `<entry name="dp-a"><ssl-forward-proxy><block-expired-certificate>yes</block-expired-certificate></ssl-forward-proxy>` +
		`<ssl-protocol-settings><enc-algo-rc4>no</enc-algo-rc4><min-version>tls1-0</min-version></ssl-protocol-settings></entry>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + dpEntry + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterDecryptionProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_decryption_profile_get", Arguments: map[string]any{"name": "dp-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='dp-a']")

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_decryption_profile_update", Arguments: map[string]any{"name": "dp-a", "ssl_min_version": "tls1-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	// read-modify-write preserves the deferred per-algorithm toggle AND the
	// SDK-only proxy subtree across a version-only update.
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<min-version>tls1-2</min-version>") || !strings.Contains(el, "<enc-algo-rc4>no</enc-algo-rc4>") {
		t.Fatalf("update dropped the preserved enc-algo toggle: %s", el)
	}
	if !strings.Contains(el, "<ssl-forward-proxy>") || !strings.Contains(el, "<block-expired-certificate>yes</block-expired-certificate>") {
		t.Fatalf("update dropped the preserved ssl-forward-proxy subtree: %s", el)
	}
}
