package tools

import (
	"maps"
	"slices"
	"strings"
	"testing"

	lsconfig "github.com/PaloAltoNetworks/pango/device/logsettings/config"
	lscorrelation "github.com/PaloAltoNetworks/pango/device/logsettings/correlation"
	lsgp "github.com/PaloAltoNetworks/pango/device/logsettings/globalprotect"
	lship "github.com/PaloAltoNetworks/pango/device/logsettings/hipmatch"
	lsiptag "github.com/PaloAltoNetworks/pango/device/logsettings/iptag"
	lssystem "github.com/PaloAltoNetworks/pango/device/logsettings/system"
	lsuserid "github.com/PaloAltoNetworks/pango/device/logsettings/userid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// logMatchCommonKeys are the seven keys every log-settings summary always emits.
var logMatchCommonKeys = []string{
	tagNameKey, descriptionKey, filterKey,
	"send_email", "send_http", "send_snmptrap", "send_syslog",
}

// TestSetListSemantics pins the profile-list overlay: a nil (omitted) list keeps
// the stored value, an explicit empty list clears it, and a non-empty list
// replaces it. Sabotage: change setList's guard to `if len(in) > 0` and the
// empty-clears case reddens (an empty list would no longer clear).
func TestSetListSemantics(t *testing.T) {
	dst := []string{"stored"}
	setList(&dst, nil)
	if len(dst) != 1 || dst[0] != "stored" {
		t.Fatalf("a nil list must keep the stored value, got %v", dst)
	}
	setList(&dst, []string{})
	if dst == nil || len(dst) != 0 {
		t.Fatalf("an explicit empty list must clear to a non-nil empty slice, got %v", dst)
	}
	setList(&dst, []string{"a", "b"})
	if len(dst) != 2 || dst[0] != "a" {
		t.Fatalf("a non-empty list must replace, got %v", dst)
	}
}

// TestLogMatchCommonSummaryUnset pins that an unset entry renders "" for the
// scalar strings and [] for every forwarding list, never null. Sabotage: return
// the raw pointer/slice from logMatchCommonSummary (drop strVal/strList) and an
// unset field renders null instead.
func TestLogMatchCommonSummaryUnset(t *testing.T) {
	m := logMatchCommonSummary("m1", nil, nil, nil, nil, nil, nil)
	if m[tagNameKey] != "m1" {
		t.Fatalf("name wrong: %v", m[tagNameKey])
	}
	if m[descriptionKey] != "" || m[filterKey] != "" {
		t.Fatalf("unset strings must render \"\": %v", m)
	}
	for _, k := range []string{"send_email", "send_http", "send_snmptrap", "send_syslog"} {
		lst, ok := m[k].([]string)
		if !ok || lst == nil {
			t.Fatalf("unset list %q must render a non-nil []string, got %#v", k, m[k])
		}
		if len(lst) != 0 {
			t.Fatalf("unset list %q must be empty, got %v", k, lst)
		}
	}
}

// TestLogSettingsSummaryTristateOmitted pins that an unset per-family toggle is
// omitted from the summary (tri-state, issue #67), not coerced to false.
// Sabotage: replace putBool with a hard `m[key] = *v`-style assignment (or emit
// the key unconditionally) and the absent toggles appear as false.
func TestLogSettingsSummaryTristateOmitted(t *testing.T) {
	m := asMap(t, logSettingsGlobalProtectSummary(&lsgp.Entry{Name: "m1"}))
	if _, ok := m[quarantineKey]; ok {
		t.Fatalf("an unset quarantine toggle must be omitted, got %v", m[quarantineKey])
	}
	if _, ok := m[sendToPanoramaKey]; ok {
		t.Fatalf("an unset send_to_panorama toggle must be omitted, got %v", m[sendToPanoramaKey])
	}
	// The common keys are still present even when the toggles are absent.
	for _, k := range logMatchCommonKeys {
		if _, ok := m[k]; !ok {
			t.Fatalf("common key %q must always be present, got %v", k, m)
		}
	}
}

// TestLogSettingsListEmptyClears pins the forwarding-list overlay end to end: an
// omitted list keeps the stored one and an explicit empty list clears it.
// Sabotage: change setList to `if len(in) > 0` and the empty-clears assertion
// reddens.
func TestLogSettingsListEmptyClears(t *testing.T) {
	// Omitted list keeps the stored one.
	e := &lsgp.Entry{Name: "m1", SendSyslog: []string{"syslog1"}}
	if err := overlayLogSettingsGlobalProtect(e, LogSettingsFullInput{Name: "m1"}); err != nil {
		t.Fatal(err)
	}
	if len(e.SendSyslog) != 1 || e.SendSyslog[0] != "syslog1" {
		t.Fatalf("an omitted list must keep the stored value, got %v", e.SendSyslog)
	}
	// Explicit empty list clears it.
	if err := overlayLogSettingsGlobalProtect(e, LogSettingsFullInput{
		Name: "m1", SendSyslog: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.SendSyslog) != 0 {
		t.Fatalf("an explicit empty list must clear the stored value, got %v", e.SendSyslog)
	}
}

// TestLogSettingsOverlaySummaryPerFamily pins, for all seven families, that the
// overlay lands the shared fields and each family's own toggles, and that the
// summary emits exactly the common keys plus that family's toggle keys (no more,
// no fewer). This catches a dropped setPtr/setList in applyLogMatchCommon (every
// row reddens), a dropped toggle setPtr in one family's overlay (that toggle
// goes missing), and a wrong or dropped putBool in one family's summary (the key
// set mismatches). Sabotage any one of those and the matching row fails.
func TestLogSettingsOverlaySummaryPerFamily(t *testing.T) {
	common := LogMatchCommon{
		Description:  new("desc"),
		Filter:       new("(zone.src eq trust)"),
		SendEmail:    []string{"email1"},
		SendHttp:     []string{"http1"},
		SendSnmptrap: []string{"snmp1"},
		SendSyslog:   []string{"syslog1"},
	}
	cases := []struct {
		name    string
		run     func() map[string]any // build fresh entry, overlay a fully-set input, return summary
		toggles map[string]bool       // toggle keys expected beyond the common seven, all true
	}{
		{"config", func() map[string]any {
			e := &lsconfig.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsConfig(e, LogSettingsStdInput{Name: "m1", LogMatchCommon: common, SendToPanorama: new(true)}))
			return asMap(t, logSettingsConfigSummary(e))
		}, map[string]bool{sendToPanoramaKey: true}},
		{"system", func() map[string]any {
			e := &lssystem.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsSystem(e, LogSettingsStdInput{Name: "m1", LogMatchCommon: common, SendToPanorama: new(true)}))
			return asMap(t, logSettingsSystemSummary(e))
		}, map[string]bool{sendToPanoramaKey: true}},
		{"correlation", func() map[string]any {
			e := &lscorrelation.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsCorrelation(e, LogSettingsCorrelationInput{Name: "m1", LogMatchCommon: common, Quarantine: new(true)}))
			return asMap(t, logSettingsCorrelationSummary(e))
		}, map[string]bool{quarantineKey: true}},
		{"globalprotect", func() map[string]any {
			e := &lsgp.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsGlobalProtect(e, LogSettingsFullInput{Name: "m1", LogMatchCommon: common, Quarantine: new(true), SendToPanorama: new(true)}))
			return asMap(t, logSettingsGlobalProtectSummary(e))
		}, map[string]bool{quarantineKey: true, sendToPanoramaKey: true}},
		{"hip_match", func() map[string]any {
			e := &lship.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsHipMatch(e, LogSettingsFullInput{Name: "m1", LogMatchCommon: common, Quarantine: new(true), SendToPanorama: new(true)}))
			return asMap(t, logSettingsHipMatchSummary(e))
		}, map[string]bool{quarantineKey: true, sendToPanoramaKey: true}},
		{"ip_tag", func() map[string]any {
			e := &lsiptag.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsIptag(e, LogSettingsFullInput{Name: "m1", LogMatchCommon: common, Quarantine: new(true), SendToPanorama: new(true)}))
			return asMap(t, logSettingsIptagSummary(e))
		}, map[string]bool{quarantineKey: true, sendToPanoramaKey: true}},
		{"user_id", func() map[string]any {
			e := &lsuserid.Entry{Name: "m1"}
			mustOverlay(t, overlayLogSettingsUserid(e, LogSettingsFullInput{Name: "m1", LogMatchCommon: common, Quarantine: new(true), SendToPanorama: new(true)}))
			return asMap(t, logSettingsUseridSummary(e))
		}, map[string]bool{quarantineKey: true, sendToPanoramaKey: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertFamilySummary(t, c.run(), c.toggles) })
	}
}

// assertFamilySummary checks that a family summary landed the shared fields set
// by the common overlay input above and carries exactly the common keys plus the
// family's expected toggle keys (all true). Extracted from the table loop to keep
// its cognitive complexity in check.
func assertFamilySummary(t *testing.T, m map[string]any, toggles map[string]bool) {
	t.Helper()
	if m[descriptionKey] != "desc" || m[filterKey] != "(zone.src eq trust)" {
		t.Fatalf("common scalars not applied: %v", m)
	}
	assertStrList(t, m, "send_email", "email1")
	assertStrList(t, m, "send_http", "http1")
	assertStrList(t, m, "send_snmptrap", "snmp1")
	assertStrList(t, m, "send_syslog", "syslog1")
	for k := range toggles {
		if m[k] != true {
			t.Fatalf("toggle %q must be true after overlay, got %v", k, m[k])
		}
	}
	want := append(slices.Clone(logMatchCommonKeys), slices.Collect(maps.Keys(toggles))...)
	if len(m) != len(want) {
		t.Fatalf("summary key set = %v, want %v", sortedKeys(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("summary missing expected key %q: %v", k, sortedKeys(m))
		}
	}
}

// TestLogSettingsBuildRequiresName drives a create with an empty name through the
// registered handler and expects the build's own client-side rejection, before
// the entry reaches pango. The scope is valid (template edge), so the only thing
// that can fail the call client-side is the name guard, and the message must be
// the guard's "name is required" rather than pango's own "name is not specified"
// (which the entry would hit only if the guard were removed). Sabotage: delete
// the name guard in registerLogSettingsFamily's build and the message becomes
// pango's, reddening the message assertion.
func TestLogSettingsBuildRequiresName(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_settings_globalprotect_create", Arguments: map[string]any{"name": "", "template": "edge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a create with an empty name must surface as a tool error")
	}
	if out := textContent(t, res); !strings.Contains(out, "name is required") {
		t.Fatalf("the build name guard must reject an empty name before pango does, got %q", out)
	}
}

// TestLogSettingsGetSingleWrap pins that a get reaches the API with the entry
// name wrapped exactly once by nameFixAdapter. Sabotage: drop the
// util.AsEntryXpath wrap in nameFixAdapter.Read and the wrap disappears.
func TestLogSettingsGetSingleWrap(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("get"), Body: `<response status="error"><msg><line>Object not found</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_settings_globalprotect_get", Arguments: map[string]any{"name": "nope", "template": "edge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a missing entry must surface as a tool error")
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// TestLogSettingsScopeResolves pins the device-scope constructors for a
// representative family: a Panorama template resolves to the Template location
// and the panorama scope resolves to the Panorama location. Sabotage: build a
// wrong sub-location in the parts constructor.
func TestLogSettingsScopeResolves(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	parts := logSettingsGlobalProtectParts()

	loc, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "edge"}, parts)
	if err != nil || loc.Template == nil {
		t.Fatalf("panorama template must resolve to Template: loc=%+v err=%v", loc, err)
	}
	if loc.Template.Template != "edge" || loc.Template.PanoramaDevice != defaultPanoramaDevice {
		t.Fatalf("template location contents wrong: %+v", loc.Template)
	}

	loc, err = resolveDeviceScope(pano, DeviceScopeInput{Template: "edge", TemplateVsys: "vsys2"}, parts)
	if err != nil || loc.TemplateVsys == nil {
		t.Fatalf("panorama template_vsys must resolve to TemplateVsys: loc=%+v err=%v", loc, err)
	}
	if loc.TemplateVsys.Template != "edge" || loc.TemplateVsys.Vsys != "vsys2" || loc.TemplateVsys.NgfwDevice != defaultNgfwDevice {
		t.Fatalf("template_vsys location contents wrong: %+v", loc.TemplateVsys)
	}

	loc, err = resolveDeviceScope(pano, DeviceScopeInput{Panorama: true}, parts)
	if err != nil || loc.Panorama == nil {
		t.Fatalf("panorama scope must resolve to Panorama: loc=%+v err=%v", loc, err)
	}
}

// TestLogSettingsFirewallScopeRejected pins the nil-vsys guard in
// resolveDeviceScope: a Panorama-only family (vsys constructor nil) on a firewall
// connection must return a clear error, not panic. Sabotage: remove the
// `if p.vsys == nil` guard in resolveDeviceScope and this call panics on a nil
// function value.
func TestLogSettingsFirewallScopeRejected(t *testing.T) {
	fw, _ := newTestDeps(t, "PA-VM")
	_, err := resolveDeviceScope(fw, DeviceScopeInput{}, logSettingsGlobalProtectParts())
	if err == nil {
		t.Fatal("a Panorama-only family on a firewall must be rejected, not resolved")
	}
}

// TestLogSettingsReadOnlyGating pins that all seven families are Panorama-only,
// expose their read tools in read-only mode, and withhold their write tools.
// Sabotage: move a create/update/delete registration above the `if d.ReadOnly`
// guard in registerLogSettingsFamily, or drop the `if !d.IsPanorama` guard in
// RegisterLogSettingsTools.
func TestLogSettingsReadOnlyGating(t *testing.T) {
	families := []string{"config", "system", "correlation", "globalprotect", "hip_match", "ip_tag", "user_id"}
	reads := make([]string, 0, 2*len(families))
	writes := make([]string, 0, 3*len(families))
	for _, fam := range families {
		p := "panos_log_settings_" + fam
		reads = append(reads, p+"_list", p+"_get")
		writes = append(writes, p+"_create", p+"_update", p+"_delete")
	}
	assertPanoramaOnlyGating(t, RegisterLogSettingsTools, reads, writes)
}

// mustOverlay fails the test if an overlay returned an error.
func mustOverlay(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("overlay failed: %v", err)
	}
}

// assertStrList asserts m[key] is a []string with exactly the wanted elements.
func assertStrList(t *testing.T, m map[string]any, key string, want ...string) {
	t.Helper()
	got, ok := m[key].([]string)
	if !ok {
		t.Fatalf("key %q is not a []string: %#v", key, m[key])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("key %q = %v, want %v", key, got, want)
	}
}

// sortedKeys returns the keys of m sorted, for stable failure messages.
func sortedKeys(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}
