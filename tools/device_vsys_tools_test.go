package tools

import (
	"testing"

	"github.com/PaloAltoNetworks/pango/device/vsys"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestBuildVsysRequiresName pins the client-side name guard. Sabotage: delete the
// name check in buildVsys and an empty-name create is attempted.
func TestBuildVsysRequiresName(t *testing.T) {
	if _, err := buildVsys(VsysInput{}); err == nil {
		t.Fatal("a create without a name must be rejected")
	}
	e, err := buildVsys(VsysInput{Name: "vsys3"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "vsys3" {
		t.Fatalf("name not set: %+v", e)
	}
}

// TestVsysSummary pins that the summary reports the entry name. Sabotage: return
// a wrong key or value from vsysSummary.
func TestVsysSummary(t *testing.T) {
	m := asMap(t, vsysSummary(&vsys.Entry{Name: "vsys2"}))
	if m[tagNameKey] != "vsys2" {
		t.Fatalf("summary name wrong: %v", m)
	}
}

// TestVsysScopeResolves pins the vsys net-scope constructors: a Panorama template
// resolves to the Template location and a template_stack to the TemplateStack
// location. Sabotage: build a wrong sub-location in vsysParts.
func TestVsysScopeResolves(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	parts := vsysParts()
	loc, err := resolveNetScope(pano, NetScopeInput{Template: "edge"}, parts)
	if err != nil || loc.Template == nil {
		t.Fatalf("panorama template must resolve to Template: loc=%+v err=%v", loc, err)
	}
	if loc.Template.Template != "edge" || loc.Template.PanoramaDevice != defaultPanoramaDevice || loc.Template.NgfwDevice != defaultNgfwDevice {
		t.Fatalf("template location contents wrong: %+v", loc.Template)
	}
	loc, err = resolveNetScope(pano, NetScopeInput{TemplateStack: "stack1"}, parts)
	if err != nil || loc.TemplateStack == nil {
		t.Fatalf("panorama template_stack must resolve to TemplateStack: loc=%+v err=%v", loc, err)
	}
	if loc.TemplateStack.TemplateStack != "stack1" || loc.TemplateStack.PanoramaDevice != defaultPanoramaDevice {
		t.Fatalf("template_stack location contents wrong: %+v", loc.TemplateStack)
	}
}

// TestVsysFirewallScopeRejected pins that vsys has no firewall-local scope: with
// a nil ngfw constructor, a bare firewall request is an error, not a resolved
// (invalid) location. Sabotage: add an ngfw constructor to vsysParts and a
// firewall request would resolve instead of erroring.
func TestVsysFirewallScopeRejected(t *testing.T) {
	fw, _ := newTestDeps(t, "PA-VM")
	if _, err := resolveNetScope(fw, NetScopeInput{}, vsysParts()); err == nil {
		t.Fatal("a bare firewall vsys request must be rejected (no firewall-local scope)")
	}
}

// TestVsysGetSingleWrap pins that a get reaches the API with the entry name
// wrapped exactly once by nameFixAdapter. Sabotage: drop the util.AsEntryXpath
// wrap in nameFixAdapter.Read and the wrap disappears.
func TestVsysGetSingleWrap(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("get"), Body: `<response status="error"><msg><line>Object not found</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVsysTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_vsys_get", Arguments: map[string]any{"name": "nope", "template": "edge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a missing entry must surface as a tool error")
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// TestVsysReadOnlyGating pins that the vsys tools are Panorama-only, expose the
// read tools in read-only mode, and withhold create. Sabotage: move the create
// registration above the `if d.ReadOnly` guard, or drop the `if !d.IsPanorama`
// guard in RegisterVsysTools.
func TestVsysReadOnlyGating(t *testing.T) {
	assertPanoramaOnlyGating(t, RegisterVsysTools,
		[]string{"panos_vsys_list", "panos_vsys_get"},
		[]string{"panos_vsys_create"})
}
