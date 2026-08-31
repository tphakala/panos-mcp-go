package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/panorama/template_stack"
	"github.com/PaloAltoNetworks/pango/panorama/template_variable"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertPanoramaOnlyGating pins a Panorama-only tool group: absent on a
// firewall, present on Panorama write mode, and read-only mode drops the write
// tools while keeping the read tools.
func assertPanoramaOnlyGating(t *testing.T, register func(*mcp.Server, *Deps), reads, writes []string) {
	t.Helper()
	names := func(model string, readOnly bool) map[string]bool {
		d, _ := newTestDeps(t, model)
		d.ReadOnly = readOnly
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		register(srv, d)
		return serverToolNames(t, srv)
	}
	fw := names("PA-VM", false)
	for _, n := range slices.Concat(reads, writes) {
		if fw[n] {
			t.Errorf("firewall must not expose Panorama-only tool %q", n)
		}
	}
	panoWrite := names("Panorama", false)
	for _, n := range slices.Concat(reads, writes) {
		if !panoWrite[n] {
			t.Errorf("Panorama write mode must expose %q", n)
		}
	}
	panoRO := names("Panorama", true)
	for _, n := range reads {
		if !panoRO[n] {
			t.Errorf("Panorama read-only mode must still expose read tool %q", n)
		}
	}
	for _, n := range writes {
		if panoRO[n] {
			t.Errorf("Panorama read-only mode must not expose write tool %q", n)
		}
	}
}

// --- device group -------------------------------------------------------------

func TestBuildDeviceGroup(t *testing.T) {
	e, err := buildDeviceGroup(DeviceGroupInput{Name: "dg1", Description: new("edge"), Templates: []string{"t1", "t2"}, AuthorizationCode: new("AUTH123")})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Templates) != 2 || e.Templates[0] != "t1" {
		t.Fatalf("templates not preserved: %v", e.Templates)
	}
	m := asMap(t, deviceGroupDetail(e))
	if m["has_authorization_code"] != true {
		t.Fatalf("has_authorization_code must be true: %v", m)
	}
	// The authorization code is write-only, never surfaced.
	for k, v := range m {
		if s, ok := v.(string); ok && strings.Contains(s, "AUTH123") {
			t.Fatalf("detail leaked the authorization code in %q: %v", k, v)
		}
	}
}

func TestDeviceGroupGetSingleWrap(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="dg1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDeviceGroupWriteTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_device_group_get", Arguments: map[string]any{"name": "dg1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("get failed: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='dg1']")
}

func TestDeviceGroupGating(t *testing.T) {
	assertPanoramaOnlyGating(t, RegisterDeviceGroupWriteTools,
		[]string{"panos_device_group_get"},
		[]string{"panos_device_group_create", "panos_device_group_update", "panos_device_group_delete"})
}

// --- template -----------------------------------------------------------------

func TestTemplateDetail(t *testing.T) {
	e, err := buildTemplate(TemplateInput{Name: "tmpl", Description: new("d"), DefaultVsys: new("vsys1")})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, templateDetail(e))
	if m["default_vsys"] != "vsys1" {
		t.Fatalf("default_vsys wrong: %v", m)
	}
}

func TestTemplateGating(t *testing.T) {
	assertPanoramaOnlyGating(t, RegisterTemplateWriteTools,
		[]string{"panos_template_get"},
		[]string{"panos_template_create", "panos_template_update", "panos_template_delete"})
}

// --- template stack -----------------------------------------------------------

// TestTemplateStackBuildPreservesOrder is a sabotage target: removing the
// e.Templates = in.Templates assignment in applyTemplateStack drops the ordered
// member list and this fails.
func TestTemplateStackBuildPreservesOrder(t *testing.T) {
	e, err := buildTemplateStack(TemplateStackInput{Name: "stack", Templates: []string{"low", "mid", "high"}, Devices: []string{"001", "002"}, MasterDevice: new("001")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"low", "mid", "high"}
	if !slices.Equal(e.Templates, want) {
		t.Fatalf("template stack member order not preserved: got %v want %v", e.Templates, want)
	}
	if len(e.Devices) != 2 || e.Devices[0].Name != "001" {
		t.Fatalf("devices not built: %+v", e.Devices)
	}
	if e.UserGroupSource == nil || e.UserGroupSource.MasterDevice == nil || *e.UserGroupSource.MasterDevice != "001" {
		t.Fatalf("master device not set: %+v", e.UserGroupSource)
	}
	m := asMap(t, templateStackSummary(e))
	if names, ok := m["templates"].([]string); !ok || !slices.Equal(names, want) {
		t.Fatalf("summary templates order wrong: %v", m["templates"])
	}
	if m["master_device"] != "001" {
		t.Fatalf("summary master_device wrong: %v", m["master_device"])
	}
}

func TestTemplateStackOverlayReplacesMembers(t *testing.T) {
	e := &template_stack.Entry{Name: "stack", Templates: []string{"a", "b"}}
	if err := overlayTemplateStack(e, TemplateStackInput{Templates: []string{"c"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.Templates, []string{"c"}) {
		t.Fatalf("a provided templates list must replace fully: %v", e.Templates)
	}
}

func TestTemplateStackGating(t *testing.T) {
	assertPanoramaOnlyGating(t, RegisterTemplateStackTools,
		[]string{"panos_template_stack_list", "panos_template_stack_get"},
		[]string{"panos_template_stack_create", "panos_template_stack_update", "panos_template_stack_delete"})
}

// --- template variable --------------------------------------------------------

func TestBuildTemplateVariable(t *testing.T) {
	e, err := buildTemplateVariable(TemplateVariableInput{Name: "$wan-ip", VarType: "ip-netmask", Value: "203.0.113.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Type == nil || e.Type.IpNetmask == nil || *e.Type.IpNetmask != "203.0.113.1/32" {
		t.Fatalf("ip-netmask value not set: %+v", e.Type)
	}
	m := asMap(t, templateVariableSummary(e))
	if m["type"] != "ip-netmask" || m["value"] != "203.0.113.1/32" {
		t.Fatalf("summary type/value wrong: %v", m)
	}
}

func TestBuildTemplateVariableRejects(t *testing.T) {
	if _, err := buildTemplateVariable(TemplateVariableInput{Name: "wan-ip", VarType: "ip-netmask", Value: "203.0.113.1/32"}); err == nil || !strings.Contains(err.Error(), "must start with a dollar sign") {
		t.Fatalf("a name without the dollar-sign prefix must be rejected: %v", err)
	}
	if _, err := buildTemplateVariable(TemplateVariableInput{Name: "$v", VarType: "ip-netmask"}); err == nil || !strings.Contains(err.Error(), "var_type and value are required") {
		t.Fatalf("value must be required: %v", err)
	}
	if _, err := buildTemplateVariable(TemplateVariableInput{Name: "$v", VarType: "bogus", Value: "x"}); err == nil || !strings.Contains(err.Error(), "var_type must be one of") {
		t.Fatalf("unknown var_type must be rejected: %v", err)
	}
}

// TestTemplateVariableOverlayReplacesBranch pins the zone-style replace-branch:
// switching var_type clears the previous type branch.
func TestTemplateVariableOverlayReplacesBranch(t *testing.T) {
	e := &template_variable.Entry{Name: "$v", Type: &template_variable.Type{IpNetmask: new("10.0.0.1/32")}}
	if err := overlayTemplateVariable(e, TemplateVariableInput{VarType: "fqdn", Value: "host.example.com"}); err != nil {
		t.Fatal(err)
	}
	if e.Type.IpNetmask != nil {
		t.Fatalf("switching var_type must clear the old branch, got %v", *e.Type.IpNetmask)
	}
	if e.Type.Fqdn == nil || *e.Type.Fqdn != "host.example.com" {
		t.Fatalf("new branch not set: %+v", e.Type)
	}
	// A value without a var_type is rejected rather than silently ignored.
	if err := overlayTemplateVariable(&template_variable.Entry{Name: "$v"}, TemplateVariableInput{Value: "x"}); err == nil || !strings.Contains(err.Error(), "must be provided together") {
		t.Fatalf("value without var_type must be rejected: %v", err)
	}
}

func TestTemplateVariableGating(t *testing.T) {
	assertPanoramaOnlyGating(t, RegisterTemplateVariableTools,
		[]string{"panos_template_variable_list", "panos_template_variable_get"},
		[]string{"panos_template_variable_create", "panos_template_variable_update", "panos_template_variable_delete"})
}

// TestOverlayDeviceGroupPreservesOnOmit pins the read-modify-write contract for
// the Panorama container overlay: a provided field replaces, an omitted one is
// left untouched, and the write-only authorization code survives an update that
// does not mention it.
func TestOverlayDeviceGroupPreservesOnOmit(t *testing.T) {
	e, err := buildDeviceGroup(DeviceGroupInput{Name: "dg", Description: new("orig"),
		Templates: []string{"t1", "t2"}, AuthorizationCode: new("AUTH123")})
	if err != nil {
		t.Fatal(err)
	}
	// Overlay only the description: templates and the auth code must survive.
	if err := overlayDeviceGroup(e, DeviceGroupInput{Name: "dg", Description: new("updated")}); err != nil {
		t.Fatal(err)
	}
	if e.Description == nil || *e.Description != "updated" {
		t.Fatalf("provided description must replace: %+v", e.Description)
	}
	if !slices.Equal(e.Templates, []string{"t1", "t2"}) {
		t.Fatalf("omitted templates must be preserved: %v", e.Templates)
	}
	if e.AuthorizationCode == nil || *e.AuthorizationCode != "AUTH123" {
		t.Fatalf("omitted authorization code must be preserved: %+v", e.AuthorizationCode)
	}
	// A provided templates list replaces the members fully.
	if err := overlayDeviceGroup(e, DeviceGroupInput{Name: "dg", Templates: []string{"t9"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.Templates, []string{"t9"}) {
		t.Fatalf("provided templates must replace fully: %v", e.Templates)
	}
}

// TestOverlayTemplatePreservesOnOmit covers the template overlay path: a
// provided description replaces while an omitted default_vsys is preserved.
func TestOverlayTemplatePreservesOnOmit(t *testing.T) {
	e, err := buildTemplate(TemplateInput{Name: "tpl", Description: new("orig"), DefaultVsys: new("vsys1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayTemplate(e, TemplateInput{Name: "tpl", Description: new("updated")}); err != nil {
		t.Fatal(err)
	}
	m := asMap(t, templateDetail(e))
	if m["description"] != "updated" {
		t.Fatalf("provided description must replace: %v", m["description"])
	}
	if m["default_vsys"] != "vsys1" {
		t.Fatalf("omitted default_vsys must be preserved: %v", m["default_vsys"])
	}
}

// TestTemplateStackDeleteViaRegisteredTool drives panos_template_stack_delete
// over a registered Panorama server so the delete handler reaches the API.
func TestTemplateStackDeleteViaRegisteredTool(t *testing.T) {
	d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterTemplateStackTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_template_stack_delete", Arguments: map[string]any{"name": "ts1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("template stack delete failed: %s", textContent(t, res))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "template-stack") || !strings.Contains(el, "ts1") {
		t.Fatalf("delete must target the template-stack entry xpath: %s", el)
	}
}

// TestDeviceGroupCreateRedactsAuthCodeOnError drives panos_device_group_create
// through the registered handler. DeviceGroupInput.AuthorizationCode is a
// write-only secret (the get projection reports only has_authorization_code), so
// a device write error echoing it must not reach the tool result. This pins that
// withSecrets(deviceGroupSecrets) is wired into the create registration.
// Sabotage: remove withSecrets(deviceGroupSecrets) from the
// panos_device_group_create registration in RegisterDeviceGroupWriteTools
// (tools/panorama_container_tools.go); this test turns red.
func TestDeviceGroupCreateRedactsAuthCodeOnError(t *testing.T) {
	const fixture = "AUTHCODE-SECRET-abc123"
	d, _ := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for authorization-code ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDeviceGroupWriteTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_device_group_create", Arguments: map[string]any{
		"name":               "dg1",
		"authorization_code": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}

// TestDeviceGroupUpdateRedactsAuthCodeOnError is the update-path twin: the seed
// read succeeds, then the write is rejected with an error echoing the submitted
// authorization code, which must not reach the tool result. Sabotage: remove
// withSecrets(deviceGroupSecrets) from the panos_device_group_update
// registration in RegisterDeviceGroupWriteTools; this test turns red.
func TestDeviceGroupUpdateRedactsAuthCodeOnError(t *testing.T) {
	const fixture = "AUTHCODE-SECRET-def456"
	d, _ := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="dg1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for authorization-code ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for authorization-code ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDeviceGroupWriteTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_device_group_update", Arguments: map[string]any{
		"name":               "dg1",
		"authorization_code": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}
