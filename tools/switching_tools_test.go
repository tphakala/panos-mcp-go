package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/virtualwire"
	"github.com/PaloAltoNetworks/pango/network/vlan"
	vlanmac "github.com/PaloAltoNetworks/pango/network/vlan/mac"
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

// ---------------------------------------------------------------------------
// VLAN MAC table entry (two-component: parent VLAN)
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestVlanMacBuild(t *testing.T) {
	e, err := buildVlanMac(VlanMacInput{Vlan: "vlan1", Name: "00:1b:17:00:01:02", Interface: new("ethernet1/1")})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "00:1b:17:00:01:02" {
		t.Fatalf("name wrong: got %q", e.Name)
	}
	mustStrPtr(t, e.Interface, "ethernet1/1", "interface -> Entry.Interface")

	e2, err := buildVlanMac(VlanMacInput{Vlan: "vlan1", Name: "00:1b:17:00:01:03"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Interface != nil {
		t.Fatalf("unset interface must stay nil, got %+v", e2.Interface)
	}

	if _, err := buildVlanMac(VlanMacInput{Vlan: "vlan1"}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestVlanMacSummary(t *testing.T) {
	m := asMap(t, vlanMacSummary(&vlanmac.Entry{Name: "00:1b:17:00:01:02", Interface: new("ethernet1/1")}))
	if m[tagNameKey] != "00:1b:17:00:01:02" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	if m["interface"] != "ethernet1/1" {
		t.Fatalf("summary interface wrong: %v", m["interface"])
	}
	m2 := asMap(t, vlanMacSummary(&vlanmac.Entry{Name: "00:1b:17:00:01:03"}))
	if m2["interface"] != "" {
		t.Fatalf("unset interface must summarize as empty string: %v", m2["interface"])
	}
}

// --- wire-level create xpath (two-component) ----------------------------------

// TestVlanMacCreateXpath pins that the two-component create set reaches the mac
// collection under the parent VLAN. Sabotage: pointing vlanMacParts at another
// resource, or dropping the parent component, shifts the xpath off the mac node
// under vlan1.
func TestVlanMacCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="00:1b:17:00:01:02"/></result></response>`
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  func(xp string) bool
	}{
		{"firewall ngfw", "PA-VM", map[string]any{"vlan": "vlan1", "name": "00:1b:17:00:01:02", "interface": "ethernet1/1"},
			func(xp string) bool {
				return strings.Contains(xp, "vlan") && strings.Contains(xp, "vlan1") && strings.Contains(xp, "mac")
			}},
		{"panorama template", "Panorama", map[string]any{"vlan": "vlan1", "name": "00:1b:17:00:01:02", "interface": "ethernet1/1", "template": "tmpl-a"},
			func(xp string) bool {
				return strings.Contains(xp, "mac") && strings.Contains(xp, "vlan1") && strings.Contains(xp, "template") && strings.Contains(xp, "tmpl-a")
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterVlanMacTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_vlan_mac_create", Arguments: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("create failed: %s", textContent(t, res))
			}
			assertSawSet(t, f, c.want)
		})
	}
}

// --- parent requirement -------------------------------------------------------

// TestVlanMacMissingParentErrors pins that a MAC tool without its parent vlan
// errors. The vlan field is schema-required, so the call is rejected at input
// validation before it can resolve to a one-component xpath. Sabotage: making
// vlan optional (json:"vlan,omitempty") lets the call through to build an
// invalid xpath instead of failing here.
func TestVlanMacMissingParentErrors(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVlanMacTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_vlan_mac_list", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a MAC list without a vlan must error")
	}
	if msg := textContent(t, res); !strings.Contains(msg, "vlan") {
		t.Fatalf("the missing-vlan error should name the vlan field: %s", msg)
	}
}

// --- no-op update -------------------------------------------------------------

// TestVlanMacNoOpUpdateNoWrite drives an update that changes nothing (vlan +
// name only) and asserts no config-write reaches the wire. Sabotage: having
// overlayVlanMac mutate Interface unconditionally produces a differing spec and
// a write.
func TestVlanMacNoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="00:1b:17:00:01:02"><interface>ethernet1/1</interface></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("edit"), Body: configSuccessBody},
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVlanMacTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_vlan_mac_update", Arguments: map[string]any{"vlan": "vlan1", "name": "00:1b:17:00:01:02"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- read-only gating ---------------------------------------------------------

func TestVlanMacReadOnlyGating(t *testing.T) {
	base := "panos_vlan_mac"
	assertReadOnlyGating(t, RegisterVlanMacTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}
