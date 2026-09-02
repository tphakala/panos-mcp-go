package tools

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/profiles/datafiltering"
	"github.com/PaloAltoNetworks/pango/objects/profiles/dataobjects"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Data filtering profile: unit tests -------------------------------------

func TestBuildDataFilteringEntry(t *testing.T) {
	e, err := buildDataFilteringEntry(DataFilteringProfileInput{
		Name: "df1", Description: "d", DataCapture: new(true), DisableOverride: new("no"),
		Rules: []DataFilteringRuleInput{{
			Name: "r1", DataObject: new("dp1"), Direction: new("both"),
			AlertThreshold: new(int64(1)), BlockThreshold: new(int64(5)), LogSeverity: new("high"),
			Application: []string{"any"}, FileType: []string{"any"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &datafiltering.Entry{
		Name: "df1", Description: new("d"), DataCapture: new(true), DisableOverride: new("no"),
		Rules: []datafiltering.Rules{{
			Name: "r1", DataObject: new("dp1"), Direction: new("both"),
			AlertThreshold: new(int64(1)), BlockThreshold: new(int64(5)), LogSeverity: new("high"),
			Application: []string{"any"}, FileType: []string{"any"},
		}},
	}
	if !reflect.DeepEqual(e, want) {
		t.Errorf("build mismatch:\n got %+v\nwant %+v", e, want)
	}
}

func TestBuildDataFilteringEntryRejects(t *testing.T) {
	if _, err := buildDataFilteringEntry(DataFilteringProfileInput{}); err == nil {
		t.Error("missing name must fail")
	}
	if _, err := buildDataFilteringEntry(DataFilteringProfileInput{Name: "df", Rules: []DataFilteringRuleInput{{DataObject: new("dp1")}}}); err == nil {
		t.Error("rule without a name must fail")
	}
}

func TestOverlayDataFiltering(t *testing.T) {
	// data_capture starts true so the omitted-preserve case catches an
	// unconditional overwrite (which nils it): boolVal(nil) is false, not true.
	e := &datafiltering.Entry{Name: "df1", Description: new("old"), DataCapture: new(true),
		Rules: []datafiltering.Rules{{Name: "old"}}}
	if err := overlayDataFiltering(e, DataFilteringProfileInput{Name: "df1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "old" || !boolVal(e.DataCapture) || len(e.Rules) != 1 || e.Rules[0].Name != "old" {
		t.Errorf("omitted fields must be preserved: %+v", e)
	}
	if err := overlayDataFiltering(e, DataFilteringProfileInput{Name: "df1", Description: "new", DataCapture: new(false),
		Rules: []DataFilteringRuleInput{{Name: "r2"}}}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || boolVal(e.DataCapture) || len(e.Rules) != 1 || e.Rules[0].Name != "r2" {
		t.Errorf("provided fields must replace: %+v", e)
	}
	// An explicit empty rules list clears the set.
	if err := overlayDataFiltering(e, DataFilteringProfileInput{Name: "df1", Rules: []DataFilteringRuleInput{}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Rules) != 0 {
		t.Errorf("an explicit empty rules list must clear the set: %+v", e.Rules)
	}
}

func TestDataFilteringSummary(t *testing.T) {
	e := &datafiltering.Entry{Name: "df1", Description: new("d"), DataCapture: new(true), DisableOverride: new("yes"),
		Rules: []datafiltering.Rules{{Name: "r1", DataObject: new("dp1"), Direction: new("upload"),
			AlertThreshold: new(int64(2)), LogSeverity: new("medium"), Application: []string{"ftp"}, FileType: []string{"any"}}}}
	m := mustMap(t, dataFilteringSummary(e))
	if m[tagNameKey] != "df1" || m[descriptionKey] != "d" || m["data_capture"] != true || m["disable_override"] != "yes" {
		t.Errorf("summary base: %+v", m)
	}
	rules := mustAnySlice(t, m["rules"])
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	r0 := mustMap(t, rules[0])
	if r0[tagNameKey] != "r1" || r0["data_object"] != "dp1" || r0["direction"] != "upload" ||
		r0["log_severity"] != "medium" || r0["alert_threshold"] != int64(2) {
		t.Errorf("rule summary: %+v", r0)
	}
	if got := mustStrSlice(t, r0["application"]); len(got) != 1 || got[0] != "ftp" {
		t.Errorf("application: %+v", got)
	}
	// block_threshold was unset: a tri-state summary omits the key entirely.
	if _, ok := r0["block_threshold"]; ok {
		t.Errorf("unset block_threshold must be omitted, not zero: %+v", r0)
	}
}

// --- Data pattern (data objects): unit tests --------------------------------

func TestBuildDataPatternBranches(t *testing.T) {
	// Each branch builds only its own sub-tree; a full DeepEqual also proves the
	// other two branches stay nil (the one-of).
	fp, err := buildDataPattern(DataPatternInput{Name: "dp1", Description: "d",
		FileProperties: &DataPatternFilePropertiesInput{Patterns: []DataPatternFilePropertyInput{
			{Name: "p1", FileType: new("pdf"), FileProperty: new("pdf-title"), PropertyValue: new("secret")}}}})
	if err != nil {
		t.Fatal(err)
	}
	wantFP := &dataobjects.Entry{Name: "dp1", Description: new("d"), PatternType: &dataobjects.PatternType{
		FileProperties: &dataobjects.PatternTypeFileProperties{Pattern: []dataobjects.PatternTypeFilePropertiesPattern{
			{Name: "p1", FileType: new("pdf"), FileProperty: new("pdf-title"), PropertyValue: new("secret")}}}}}
	if !reflect.DeepEqual(fp, wantFP) {
		t.Errorf("file_properties build mismatch:\n got %+v\nwant %+v", fp, wantFP)
	}

	rx, err := buildDataPattern(DataPatternInput{Name: "dp2",
		Regex: &DataPatternRegexListInput{Patterns: []DataPatternRegexInput{{Name: "p1", Regex: new("[0-9]{16}"), FileType: []string{"any"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	wantRX := &dataobjects.Entry{Name: "dp2", PatternType: &dataobjects.PatternType{
		Regex: &dataobjects.PatternTypeRegex{Pattern: []dataobjects.PatternTypeRegexPattern{
			{Name: "p1", Regex: new("[0-9]{16}"), FileType: []string{"any"}}}}}}
	if !reflect.DeepEqual(rx, wantRX) {
		t.Errorf("regex build mismatch:\n got %+v\nwant %+v", rx, wantRX)
	}

	pd, err := buildDataPattern(DataPatternInput{Name: "dp3",
		Predefined: &DataPatternPredefinedListInput{Patterns: []DataPatternPredefinedInput{{Name: "Credit Card Numbers", FileType: []string{"any"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	wantPD := &dataobjects.Entry{Name: "dp3", PatternType: &dataobjects.PatternType{
		Predefined: &dataobjects.PatternTypePredefined{Pattern: []dataobjects.PatternTypePredefinedPattern{
			{Name: "Credit Card Numbers", FileType: []string{"any"}}}}}}
	if !reflect.DeepEqual(pd, wantPD) {
		t.Errorf("predefined build mismatch:\n got %+v\nwant %+v", pd, wantPD)
	}
}

func TestBuildDataPatternRejects(t *testing.T) {
	if _, err := buildDataPattern(DataPatternInput{}); err == nil {
		t.Error("missing name must fail")
	}
	// more than one pattern-type branch is rejected.
	if _, err := buildDataPattern(DataPatternInput{Name: "dp",
		Predefined: &DataPatternPredefinedListInput{}, Regex: &DataPatternRegexListInput{}}); err == nil {
		t.Error("two pattern-type branches must fail")
	}
	// a pattern entry without a name is rejected.
	if _, err := buildDataPattern(DataPatternInput{Name: "dp",
		Regex: &DataPatternRegexListInput{Patterns: []DataPatternRegexInput{{Regex: new("x")}}}}); err == nil {
		t.Error("a regex pattern without a name must fail")
	}
}

func TestOverlayDataPatternBranchSwitch(t *testing.T) {
	// Start on the regex branch; switching to predefined must clear regex.
	e := &dataobjects.Entry{Name: "dp1", PatternType: &dataobjects.PatternType{
		Regex: &dataobjects.PatternTypeRegex{Pattern: []dataobjects.PatternTypeRegexPattern{{Name: "old"}}}}}
	if err := overlayDataPattern(e, DataPatternInput{Name: "dp1",
		Predefined: &DataPatternPredefinedListInput{Patterns: []DataPatternPredefinedInput{{Name: "CCN"}}}}); err != nil {
		t.Fatal(err)
	}
	if e.PatternType.Regex != nil {
		t.Errorf("switching branch must clear regex: %+v", e.PatternType)
	}
	if e.PatternType.Predefined == nil || len(e.PatternType.Predefined.Pattern) != 1 || e.PatternType.Predefined.Pattern[0].Name != "CCN" {
		t.Errorf("predefined must be set: %+v", e.PatternType)
	}
}

func TestOverlayDataPatternPreserves(t *testing.T) {
	// Providing no branch leaves the stored pattern type untouched; description
	// still applies. Start with a regex branch that must survive.
	e := &dataobjects.Entry{Name: "dp1", Description: new("old"), PatternType: &dataobjects.PatternType{
		Regex: &dataobjects.PatternTypeRegex{Pattern: []dataobjects.PatternTypeRegexPattern{{Name: "keep", Regex: new("[0-9]+")}}}}}
	if err := overlayDataPattern(e, DataPatternInput{Name: "dp1", Description: "new"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" {
		t.Errorf("description must update: %+v", e)
	}
	if e.PatternType == nil || e.PatternType.Regex == nil || len(e.PatternType.Regex.Pattern) != 1 || e.PatternType.Regex.Pattern[0].Name != "keep" {
		t.Errorf("omitting all branches must preserve the stored pattern type: %+v", e.PatternType)
	}

	// Selecting the same branch with no patterns list keeps the stored entries
	// (seedBranch): send {} to reselect regex without changing its patterns.
	if err := overlayDataPattern(e, DataPatternInput{Name: "dp1", Regex: &DataPatternRegexListInput{}}); err != nil {
		t.Fatal(err)
	}
	if e.PatternType.Regex == nil || len(e.PatternType.Regex.Pattern) != 1 || e.PatternType.Regex.Pattern[0].Name != "keep" {
		t.Errorf("same-branch reselect with no patterns must keep stored entries: %+v", e.PatternType)
	}
}

func TestDataPatternSummary(t *testing.T) {
	e := &dataobjects.Entry{Name: "dp1", Description: new("d"), DisableOverride: new("no"),
		PatternType: &dataobjects.PatternType{Regex: &dataobjects.PatternTypeRegex{
			Pattern: []dataobjects.PatternTypeRegexPattern{{Name: "p1", Regex: new("[0-9]{16}"), FileType: []string{"any"}}}}}}
	m := mustMap(t, dataPatternSummary(e))
	if m[tagNameKey] != "dp1" || m[descriptionKey] != "d" || m["disable_override"] != "no" || m["pattern_type"] != "regex" {
		t.Errorf("summary base: %+v", m)
	}
	pats := mustAnySlice(t, m["patterns"])
	if len(pats) != 1 {
		t.Fatalf("patterns: %+v", pats)
	}
	p0 := mustMap(t, pats[0])
	if p0[tagNameKey] != "p1" || p0["regex"] != "[0-9]{16}" {
		t.Errorf("regex pattern summary: %+v", p0)
	}
	if got := mustStrSlice(t, p0["file_type"]); len(got) != 1 || got[0] != "any" {
		t.Errorf("file_type: %+v", got)
	}
}

func TestDataPatternTypeStringEmpty(t *testing.T) {
	if s := dataPatternTypeString(nil); s != "" {
		t.Errorf("nil pattern type must be empty, got %q", s)
	}
	if s := dataPatternTypeString(&dataobjects.PatternType{}); s != "" {
		t.Errorf("empty pattern type must be empty, got %q", s)
	}
}

// --- Scope resolution -------------------------------------------------------

func TestDataFilteringAndPatternScope(t *testing.T) {
	dFW, _ := newTestDeps(t, "PA-VM")
	dPano, _ := newTestDeps(t, "Panorama")

	// datafiltering has no vsys location: a firewall default falls back to shared,
	// and an explicit vsys is rejected.
	if _, err := resolveLocation(dFW, LocationInput{Vsys: "vsys2"}, dataFilteringParts()); err == nil {
		t.Error("explicit vsys on data-filtering (vsys-less) must be rejected")
	}
	loc, err := resolveLocation(dFW, LocationInput{}, dataFilteringParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc.Shared == nil {
		t.Errorf("firewall default for data-filtering must be shared: %+v", loc)
	}
	dgLoc, err := resolveLocation(dPano, LocationInput{DeviceGroup: "dg1"}, dataFilteringParts())
	if err != nil {
		t.Fatal(err)
	}
	if dgLoc.DeviceGroup == nil || dgLoc.DeviceGroup.DeviceGroup != "dg1" {
		t.Errorf("panorama device_group for data-filtering must resolve: %+v", dgLoc)
	}

	// dataobjects has a vsys location: a firewall default is vsys1.
	pLoc, err := resolveLocation(dFW, LocationInput{}, dataPatternParts())
	if err != nil {
		t.Fatal(err)
	}
	if pLoc.Vsys == nil || pLoc.Vsys.Vsys != defaultVsys {
		t.Errorf("firewall default for data-pattern must be vsys1: %+v", pLoc)
	}
}

// --- End-to-end through the fake device -------------------------------------

func TestDataFilteringProfileCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("df-new")},
	)
	resolve := func(in LocationInput) (datafiltering.Location, error) {
		return resolveLocation(d, in, dataFilteringParts())
	}
	h := createHandler[datafiltering.Location, datafiltering.Entry, DataFilteringProfileInput](d, "panos_data_filtering_profile_create", newDataFilteringService(d), resolve,
		func(in DataFilteringProfileInput) LocationInput { return in.Location }, buildDataFilteringEntry, dataFilteringSummary)
	res, _, err := h(t.Context(), nil, DataFilteringProfileInput{Name: "df-new", Description: "d",
		Rules: []DataFilteringRuleInput{{Name: "r1", DataObject: new("dp1"), Direction: new("both")}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<rules>`, `<entry name="r1">`, `<data-object>dp1</data-object>`, `<direction>both</direction>`, "df-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	// Firewall data-filtering is managed at shared, not vsys.
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "profiles/data-filtering") || !strings.Contains(xs, "shared") {
		t.Fatalf("create did not target the firewall shared data-filtering node: %s", xs)
	}
}

func TestDataFilteringProfileUpdatePreservesRules(t *testing.T) {
	stored := `<entry name="df-a"><description>df-a desc</description><data-capture>yes</data-capture>` +
		`<rules><entry name="r1"><data-object>dp1</data-object><direction>both</direction></entry></rules></entry>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + stored + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	resolve := func(in LocationInput) (datafiltering.Location, error) {
		return resolveLocation(d, in, dataFilteringParts())
	}
	h := updateHandler[datafiltering.Location, datafiltering.Entry, DataFilteringProfileInput](d, "panos_data_filtering_profile_update", newDataFilteringService(d), resolve,
		func(in DataFilteringProfileInput) LocationInput { return in.Location },
		func(in DataFilteringProfileInput) string { return in.Name }, overlayDataFiltering, dataFilteringSummary)
	res, _, err := h(t.Context(), nil, DataFilteringProfileInput{Name: "df-a", Description: "changed"})
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
	// read-modify-write preserves the stored rule (rules omitted on this update).
	if !strings.Contains(el, `<entry name="r1">`) || !strings.Contains(el, "<data-object>dp1</data-object>") {
		t.Fatalf("update dropped the preserved rule: %s", el)
	}
}

func TestDataPatternCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("dp-new")},
	)
	resolve := func(in LocationInput) (dataobjects.Location, error) {
		return resolveLocation(d, in, dataPatternParts())
	}
	h := createHandler[dataobjects.Location, dataobjects.Entry, DataPatternInput](d, "panos_data_pattern_create", newDataPatternService(d), resolve,
		func(in DataPatternInput) LocationInput { return in.Location }, buildDataPattern, dataPatternSummary)
	res, _, err := h(t.Context(), nil, DataPatternInput{Name: "dp-new",
		Regex: &DataPatternRegexListInput{Patterns: []DataPatternRegexInput{{Name: "ccn", Regex: new("[0-9]{16}")}}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`<pattern-type>`, `<regex>`, `<entry name="ccn">`, `<regex>[0-9]{16}</regex>`, "dp-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	xs := strings.Join(getConfigXpaths(f), " ")
	if !strings.Contains(xs, "profiles/data-objects") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall vsys data-objects node: %s", xs)
	}
}

func TestDataFilteringRegisteredToolsRoundTrip(t *testing.T) {
	ctx := t.Context()
	stored := `<entry name="df-a"><description>df-a desc</description></entry>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result>` + stored + `</result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterDataFilteringProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_data_filtering_profile_get", Arguments: map[string]any{"name": "df-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "profiles/data-filtering") {
		t.Fatalf("registered get did not target the data-filtering node: %s", joined)
	}
}
