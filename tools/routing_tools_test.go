package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/virtual_router"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- build / summary ----------------------------------------------------------

// TestBuildVirtualRouter pins the core field mapping: interfaces flow to
// Entry.Interface in order; a provided administrative distance lands in the
// matching AdminDists field and nowhere else. Sabotage mapping the distance to
// any other AdminDists field turns these red.
func TestBuildVirtualRouter(t *testing.T) {
	e, err := buildVirtualRouter(VirtualRouterInput{
		Name:             "vr1",
		Interfaces:       []string{"ethernet1/1", "ethernet1/2"},
		AdminDistOspfInt: new(int64(110)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Interface) != 2 || e.Interface[0] != "ethernet1/1" || e.Interface[1] != "ethernet1/2" {
		t.Fatalf("interfaces not mapped in order to Entry.Interface: %v", e.Interface)
	}
	if e.AdminDists == nil || e.AdminDists.OspfInt == nil || *e.AdminDists.OspfInt != 110 {
		t.Fatalf("admin_dist_ospf_int not mapped to AdminDists.OspfInt: %+v", e.AdminDists)
	}
	if e.AdminDists.Static != nil || e.AdminDists.Ospfv3Int != nil || e.AdminDists.Ibgp != nil {
		t.Fatalf("unrelated admin distances must stay nil: %+v", e.AdminDists)
	}
}

// TestVirtualRouterSummary pins the summary projection: interfaces render as an
// ordered []string via strList, a set distance is surfaced via putInt under its
// own key, and an unset distance is omitted (never coerced to zero).
func TestVirtualRouterSummary(t *testing.T) {
	e, err := buildVirtualRouter(VirtualRouterInput{
		Name:             "vr1",
		Interfaces:       []string{"ethernet1/1", "ethernet1/2"},
		AdminDistOspfInt: new(int64(110)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, virtualRouterSummary(e))
	ifaces, ok := m[interfacesKey].([]string)
	if !ok || len(ifaces) != 2 || ifaces[0] != "ethernet1/1" {
		t.Fatalf("summary interfaces wrong: %v", m[interfacesKey])
	}
	if m["admin_dist_ospf_int"] != int64(110) {
		t.Fatalf("summary must surface admin_dist_ospf_int: %v", m["admin_dist_ospf_int"])
	}
	if _, ok := m["admin_dist_static"]; ok {
		t.Fatalf("an unset distance must be omitted from the summary: %v", m["admin_dist_static"])
	}
}

// TestBuildVirtualRouterNoDistances proves AdminDists stays nil when the caller
// provides no distance, and the summary renders interfaces as [] (not null) for
// an empty binding. Sabotage: unconditionally allocating AdminDists in
// applyVirtualRouterAdminDists makes the nil check fail; dropping strList makes
// the [] check fail.
func TestBuildVirtualRouterNoDistances(t *testing.T) {
	e, err := buildVirtualRouter(VirtualRouterInput{Name: "vr1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.AdminDists != nil {
		t.Fatalf("AdminDists must be nil when no distance is provided: %+v", e.AdminDists)
	}
	m := asMap(t, virtualRouterSummary(e))
	ifaces, ok := m[interfacesKey].([]string)
	if !ok {
		t.Fatalf("interfaces must be a []string, got %T", m[interfacesKey])
	}
	if ifaces == nil || len(ifaces) != 0 {
		t.Fatalf("an absent interface list must render as [], got %v", ifaces)
	}
}

func TestBuildVirtualRouterEmptyName(t *testing.T) {
	if _, err := buildVirtualRouter(VirtualRouterInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- wire-level create --------------------------------------------------------

// TestVirtualRouterCreateFirewallXpath drives a registered firewall create and
// pins that the set request targets the virtual-router node. Sabotage: pointing
// virtualRouterParts at a different pango resource shifts the xpath and this
// fails.
func TestVirtualRouterCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="vr1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVirtualRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_virtual_router_create",
		Arguments: map[string]any{"name": "vr1", "interfaces": []string{"ethernet1/1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			sawSet = true
			if xp := req.Get("xpath"); !strings.Contains(xp, "virtual-router") {
				t.Fatalf("create must target the virtual-router xpath: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestVirtualRouterCreatePanoramaTemplateXpath drives a registered Panorama
// create under a template and pins that the set request reaches the
// virtual-router node inside that template's config. Sabotage: dropping the
// template branch of virtualRouterParts (or the template arg wiring) drops the
// "template" segment and this fails.
func TestVirtualRouterCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="vr1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVirtualRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_virtual_router_create",
		Arguments: map[string]any{"name": "vr1", "template": "tmpl-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			sawSet = true
			xp := req.Get("xpath")
			if !strings.Contains(xp, "virtual-router") {
				t.Fatalf("create must target the virtual-router xpath: %s", xp)
			}
			if !strings.Contains(xp, "template") || !strings.Contains(xp, "tmpl-a") {
				t.Fatalf("panorama create must resolve into the template scope: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// --- net-scope gating ---------------------------------------------------------

// TestVirtualRouterNetScopeGating pins the two rejection paths the net-scope
// resolver enforces for this family: Panorama with no template/template_stack,
// and a template supplied against a firewall.
func TestVirtualRouterNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterVirtualRouterTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_virtual_router_list", Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("Panorama list without a template must error")
		}
		if msg := textContent(t, res); !strings.Contains(msg, "template or template_stack is required on Panorama") {
			t.Fatalf("wrong error for Panorama-no-template: %s", msg)
		}
	})
	t.Run("template on firewall errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterVirtualRouterTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_virtual_router_list", Arguments: map[string]any{"template": "tmpl-a"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("a template against a firewall must error")
		}
		if msg := textContent(t, res); !strings.Contains(msg, "template requires a Panorama connection") {
			t.Fatalf("wrong error for template-on-firewall: %s", msg)
		}
	})
}

// --- no-op update -------------------------------------------------------------

// TestVirtualRouterNoOpUpdateNoWrite drives a registered update that changes
// nothing (name only) and asserts no config-write action reaches the wire.
// pango's UpdateWithXpath short-circuits on SpecMatches when the overlaid entry
// equals the current one, so an update applying no field must issue no
// multi-config. Sabotage: having overlayVirtualRouter mutate the entry (e.g.
// clearing Interface unconditionally) would produce a differing spec and a
// write, failing assertNoConfigWrite.
func TestVirtualRouterNoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="vr1"><interface><member>ethernet1/1</member></interface></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVirtualRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_virtual_router_update", Arguments: map[string]any{"name": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- deferred subtree preservation -------------------------------------------

// TestOverlayVirtualRouterPreservesDeferred pins the read-modify-write contract
// that makes the unmanaged routing subtree safe: an update setting only one
// administrative distance must leave an existing bound interface, an existing
// sibling distance, and the deferred Protocol subtree exactly as read. Sabotage:
// rebuilding the entry in overlayVirtualRouter (instead of overlaying in place)
// drops Interface, the sibling distance, and Protocol, turning these red.
func TestOverlayVirtualRouterPreservesDeferred(t *testing.T) {
	// Simulate the entry returned by the get: a bound interface, an existing
	// OSPF-internal distance, and a deferred Protocol subtree this server does
	// not manage.
	e := &virtual_router.Entry{
		Name:       "vr1",
		Interface:  []string{"ethernet1/1"},
		AdminDists: &virtual_router.AdminDists{OspfInt: new(int64(110))},
		Protocol:   &virtual_router.Protocol{},
	}
	if err := overlayVirtualRouter(e, VirtualRouterInput{Name: "vr1", AdminDistStatic: new(int64(15))}); err != nil {
		t.Fatal(err)
	}
	// The provided distance is applied.
	if e.AdminDists.Static == nil || *e.AdminDists.Static != 15 {
		t.Fatalf("provided admin_dist_static must be applied: %+v", e.AdminDists)
	}
	// Everything the update did not touch survives.
	if len(e.Interface) != 1 || e.Interface[0] != "ethernet1/1" {
		t.Fatalf("existing bound interface must be preserved: %v", e.Interface)
	}
	if e.AdminDists.OspfInt == nil || *e.AdminDists.OspfInt != 110 {
		t.Fatalf("existing sibling distance must be preserved: %+v", e.AdminDists)
	}
	if e.Protocol == nil {
		t.Fatal("the deferred Protocol subtree must be preserved across an update")
	}
}

// --- read-only gating ---------------------------------------------------------

func TestVirtualRouterReadOnlyGating(t *testing.T) {
	reads := []string{"panos_virtual_router_list", "panos_virtual_router_get"}
	writes := []string{"panos_virtual_router_create", "panos_virtual_router_update", "panos_virtual_router_delete"}
	assertReadOnlyGating(t, RegisterVirtualRouterTools, reads, writes)
}
