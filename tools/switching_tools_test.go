package tools

import (
	"slices"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/virtualwire"
	"github.com/PaloAltoNetworks/pango/network/vlan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mustStrPtr fails unless got points to want.
func mustStrPtr(t *testing.T, got *string, want, label string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s: want %q, got %v", label, want, got)
	}
}

// ---------------------------------------------------------------------------
// Virtual Wire
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestVirtualWireBuild(t *testing.T) {
	e, err := buildVirtualWire(VirtualWireInput{
		Name:       "vw1",
		Interface1: new("ethernet1/1"),
		Interface2: new("ethernet1/2"),
		TagAllowed: new("100-200"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "vw1" {
		t.Fatalf("name wrong: got %q, want %q", e.Name, "vw1")
	}
	mustStrPtr(t, e.Interface1, "ethernet1/1", "interface1 -> Entry.Interface1")
	mustStrPtr(t, e.Interface2, "ethernet1/2", "interface2 -> Entry.Interface2")
	mustStrPtr(t, e.TagAllowed, "100-200", "tag_allowed -> Entry.TagAllowed")

	e2, err := buildVirtualWire(VirtualWireInput{Name: "vw2"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Interface1 != nil || e2.Interface2 != nil || e2.TagAllowed != nil {
		t.Fatalf("unset pointers must stay nil: %+v", e2)
	}

	if _, err := buildVirtualWire(VirtualWireInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestVirtualWireSummary(t *testing.T) {
	e := &virtualwire.Entry{
		Name:       "vw1",
		Interface1: new("ethernet1/1"),
		Interface2: new("ethernet1/2"),
		TagAllowed: new("100-200"),
	}
	m := asMap(t, virtualWireSummary(e))
	if m[tagNameKey] != "vw1" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	if m["interface1"] != "ethernet1/1" {
		t.Fatalf("summary interface1 wrong: %v", m["interface1"])
	}
	if m["interface2"] != "ethernet1/2" {
		t.Fatalf("summary interface2 wrong: %v", m["interface2"])
	}
	if m["tag_allowed"] != "100-200" {
		t.Fatalf("summary tag_allowed wrong: %v", m["tag_allowed"])
	}

	e2 := &virtualwire.Entry{Name: "vw2"}
	m2 := asMap(t, virtualWireSummary(e2))
	if m2["interface1"] != "" || m2["interface2"] != "" || m2["tag_allowed"] != "" {
		t.Fatalf("summary for unset fields must be empty strings: %+v", m2)
	}
}

// --- wire-level create xpath --------------------------------------------------

func TestVirtualWireCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="vw1"/></result></response>`
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  []string
	}{
		{"firewall ngfw", "PA-VM", map[string]any{"name": "vw1", "interface1": "ethernet1/1", "interface2": "ethernet1/2"}, []string{"virtual-wire"}},
		{"panorama template", "Panorama", map[string]any{"name": "vw1", "interface1": "ethernet1/1", "interface2": "ethernet1/2", "template": "tmpl-a"},
			[]string{"virtual-wire", "template", "tmpl-a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterVirtualWireTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_virtual_wire_create", Arguments: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("create failed: %s", textContent(t, res))
			}
			assertSetXpathContains(t, f, c.want)
		})
	}
}

// --- read-only gating ---------------------------------------------------------

func TestVirtualWireReadOnlyGating(t *testing.T) {
	base := "panos_virtual_wire"
	assertReadOnlyGating(t, RegisterVirtualWireTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// ---------------------------------------------------------------------------
// VLAN object
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestVlanBuild(t *testing.T) {
	e, err := buildVlan(VlanInput{
		Name:       "vlan1",
		Interfaces: []string{"ethernet1/1", "ethernet1/2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "vlan1" {
		t.Fatalf("name wrong: got %q, want %q", e.Name, "vlan1")
	}
	if !slices.Equal(e.Interface, []string{"ethernet1/1", "ethernet1/2"}) {
		t.Fatalf("interfaces not mapped to Entry.Interface in order: %+v", e.Interface)
	}

	e2, err := buildVlan(VlanInput{Name: "vlan2"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Interface != nil {
		t.Fatalf("unset interfaces must stay nil, got %+v", e2.Interface)
	}

	if _, err := buildVlan(VlanInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestVlanSummary(t *testing.T) {
	e := &vlan.Entry{
		Name:      "vlan1",
		Interface: []string{"ethernet1/1", "ethernet1/2"},
	}
	m := asMap(t, vlanSummary(e))
	if m[tagNameKey] != "vlan1" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	interfaces, ok := m["interfaces"].([]string)
	if !ok || !slices.Equal(interfaces, []string{"ethernet1/1", "ethernet1/2"}) {
		t.Fatalf("summary interfaces wrong: %v", m["interfaces"])
	}

	e2 := &vlan.Entry{Name: "vlan2"}
	m2 := asMap(t, vlanSummary(e2))
	interfaces2, ok2 := m2["interfaces"].([]string)
	if !ok2 || len(interfaces2) != 0 {
		t.Fatalf("summary for unset interfaces must render as empty []string: %v", m2["interfaces"])
	}
}

// --- wire-level create xpath --------------------------------------------------

func TestVlanCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="vlan1"/></result></response>`
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  []string
	}{
		{"firewall ngfw", "PA-VM", map[string]any{"name": "vlan1", "interfaces": []string{"ethernet1/1"}}, []string{"vlan"}},
		{"panorama template", "Panorama", map[string]any{"name": "vlan1", "interfaces": []string{"ethernet1/1"}, "template": "tmpl-a"},
			[]string{"vlan", "template", "tmpl-a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterVlanTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_vlan_create", Arguments: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("create failed: %s", textContent(t, res))
			}
			assertSetXpathContains(t, f, c.want)
		})
	}
}

// --- read-only gating ---------------------------------------------------------

func TestVlanReadOnlyGating(t *testing.T) {
	base := "panos_vlan"
	assertReadOnlyGating(t, RegisterVlanTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// --- name collision check -----------------------------------------------------

func TestVlanNamesDistinctFromVlanInterface(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVlanTools(srv, d)
	RegisterVlanInterfaceTools(srv, d)
	names := serverToolNames(t, srv)
	for _, want := range []string{"panos_vlan_get", "panos_vlan_interface_get"} {
		if !names[want] {
			t.Fatalf("expected tool %q to be registered", want)
		}
	}
}
