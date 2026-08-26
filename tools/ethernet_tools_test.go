package tools

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/generic"
	"github.com/PaloAltoNetworks/pango/network/interface/aggregate"
	"github.com/PaloAltoNetworks/pango/network/interface/ethernet"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Ethernet interface: build / summary unit tests --------------------------

// TestBuildEthernetInterface pins the field mapping: ips land under
// Layer3.Ip[].Name in order, mtu under Layer3.Mtu, ipv6_enabled through the
// tri-state pointer, and the ethernet-only link_* / aggregate_group fields at
// the Entry root. An empty name is rejected.
func TestBuildEthernetInterface(t *testing.T) {
	e, err := buildEthernetInterface(EthernetInterfaceInput{
		Name:                       "ethernet1/3",
		Comment:                    new("uplink"),
		Mtu:                        new(int64(1500)),
		Ips:                        []string{"10.0.0.1/24", "10.0.1.1/24"},
		InterfaceManagementProfile: new("mgmt"),
		Ipv6Enabled:                new(true),
		LinkState:                  new("up"),
		LinkSpeed:                  new("1000"),
		LinkDuplex:                 new("full"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Layer3 == nil {
		t.Fatal("create must build a Layer3 block for a standalone port")
	}
	ethWantIPNames(t, e.Layer3.Ip, "10.0.0.1/24", "10.0.1.1/24")
	mustInt64(t, e.Layer3.Mtu, 1500, "mtu -> Layer3.Mtu")
	ethMustStrPtr(t, e.Layer3.InterfaceManagementProfile, "mgmt", "interface_management_profile")
	ethMustBoolPtr(t, ethLayer3Ipv6Enabled(e.Layer3.Ipv6), true, "ipv6_enabled -> Layer3.Ipv6.Enabled")
	// Ethernet-only Entry-root fields.
	ethMustStrPtr(t, e.LinkState, "up", "link_state")
	ethMustStrPtr(t, e.LinkSpeed, "1000", "link_speed")
	ethMustStrPtr(t, e.LinkDuplex, "full", "link_duplex")

	// A member port (aggregate_group set, no layer3 fields) maps aggregate_group to
	// the Entry root and carries no layer3 block.
	mem, err := buildEthernetInterface(EthernetInterfaceInput{Name: "ethernet1/4", AggregateGroup: new("ae1")})
	if err != nil {
		t.Fatal(err)
	}
	ethMustStrPtr(t, mem.AggregateGroup, "ae1", "aggregate_group")
	if mem.Layer3 != nil {
		t.Fatal("a member port must not carry a Layer3 block")
	}

	// aggregate_group combined with any layer3 field is rejected up front.
	if _, err := buildEthernetInterface(EthernetInterfaceInput{
		Name:           "ethernet1/5",
		AggregateGroup: new("ae1"),
		Mtu:            new(int64(1500)),
	}); err == nil {
		t.Fatal("aggregate_group with a layer3 field must be rejected")
	}

	if _, err := buildEthernetInterface(EthernetInterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// ethWantIPNames asserts a Layer3 IP slice carries exactly the given names in order.
func ethWantIPNames(t *testing.T, got []ethernet.Layer3Ip, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ips length: want %d, got %+v", len(want), got)
	}
	for i, w := range want {
		if got[i].Name != w {
			t.Fatalf("ip[%d]: want %q, got %q", i, w, got[i].Name)
		}
	}
}

// ethLayer3Ipv6Enabled reads the tri-state Enabled pointer through a possibly-nil
// Ipv6 block, keeping the nil-guard out of the test body.
func ethLayer3Ipv6Enabled(v6 *ethernet.Layer3Ipv6) *bool {
	if v6 == nil {
		return nil
	}
	return v6.Enabled
}

func ethMustStrPtr(t *testing.T, got *string, want, label string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s: want %q, got %v", label, want, got)
	}
}

func ethMustBoolPtr(t *testing.T, got *bool, want bool, label string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s: want %v, got %v", label, want, got)
	}
}

// TestEthernetInterfaceSummaryTriState pins that ipv6_enabled is emitted through
// putBool (present-true / present-false / absent-omitted) and that the link_*
// and aggregate_group fields surface. Sabotage: coercing Ipv6.Enabled to a hard
// bool would make the nil case report false and trip the "omitted" subtest.
func TestEthernetInterfaceSummaryTriState(t *testing.T) {
	t.Run("nil ipv6_enabled is omitted", func(t *testing.T) {
		// Ipv6 block present but Enabled unset: putBool must omit the key rather
		// than report a coerced false (and a hard *Enabled deref would panic).
		m := asMap(t, ethernetInterfaceSummary(&ethernet.Entry{Name: "e",
			Layer3: &ethernet.Layer3{Ipv6: &ethernet.Layer3Ipv6{}}}))
		if _, ok := m["ipv6_enabled"]; ok {
			t.Fatalf("a nil ipv6_enabled must be omitted, got %v", m["ipv6_enabled"])
		}
	})
	t.Run("explicit false reports false", func(t *testing.T) {
		m := asMap(t, ethernetInterfaceSummary(&ethernet.Entry{Name: "e",
			Layer3: &ethernet.Layer3{Ipv6: &ethernet.Layer3Ipv6{Enabled: new(false)}}}))
		if v, ok := m["ipv6_enabled"]; !ok || v != false {
			t.Fatalf("an explicit false ipv6_enabled must report false, got ok=%v v=%v", ok, v)
		}
	})
	t.Run("link and aggregate fields surface", func(t *testing.T) {
		m := asMap(t, ethernetInterfaceSummary(&ethernet.Entry{Name: "e",
			LinkState: new("down"), LinkSpeed: new("100"), LinkDuplex: new("half"), AggregateGroup: new("ae2"),
			Layer3: &ethernet.Layer3{Mtu: new(int64(9000)), Ip: []ethernet.Layer3Ip{{Name: "192.0.2.1/24"}}}}))
		if m["link_state"] != "down" || m["link_speed"] != "100" || m["link_duplex"] != "half" || m["aggregate_group"] != "ae2" {
			t.Fatalf("link/aggregate fields wrong: %v", m)
		}
		if m["mtu"] != int64(9000) {
			t.Fatalf("mtu wrong: %v", m["mtu"])
		}
		ips, ok := m["ips"].([]string)
		if !ok || len(ips) != 1 || ips[0] != "192.0.2.1/24" {
			t.Fatalf("ips wrong: %v", m["ips"])
		}
	})
}

// --- Aggregate interface: build / summary unit tests -------------------------

// TestBuildAggregateInterface pins the same Layer3 mapping for the aggregate
// family (a distinct pango type) and confirms it carries no link_* fields.
func TestBuildAggregateInterface(t *testing.T) {
	e, err := buildAggregateInterface(AggregateInterfaceInput{
		Name:        "ae1",
		Mtu:         new(int64(1500)),
		Ips:         []string{"10.9.0.1/24"},
		Ipv6Enabled: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Layer3 == nil {
		t.Fatal("create must build a Layer3 block")
	}
	if len(e.Layer3.Ip) != 1 || e.Layer3.Ip[0].Name != "10.9.0.1/24" {
		t.Fatalf("ips not mapped to Layer3.Ip[].Name: %+v", e.Layer3.Ip)
	}
	if e.Layer3.Mtu == nil || *e.Layer3.Mtu != 1500 {
		t.Fatalf("mtu not mapped to Layer3.Mtu: %+v", e.Layer3.Mtu)
	}
	if e.Layer3.Ipv6 == nil || e.Layer3.Ipv6.Enabled == nil || *e.Layer3.Ipv6.Enabled != true {
		t.Fatalf("ipv6_enabled not mapped: %+v", e.Layer3.Ipv6)
	}
	if _, err := buildAggregateInterface(AggregateInterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestAggregateInterfaceSummaryTriState(t *testing.T) {
	t.Run("nil ipv6_enabled is omitted", func(t *testing.T) {
		m := asMap(t, aggregateInterfaceSummary(&aggregate.Entry{Name: "ae1",
			Layer3: &aggregate.Layer3{Ipv6: &aggregate.Layer3Ipv6{}}}))
		if _, ok := m["ipv6_enabled"]; ok {
			t.Fatalf("a nil ipv6_enabled must be omitted, got %v", m["ipv6_enabled"])
		}
	})
	t.Run("explicit false reports false", func(t *testing.T) {
		m := asMap(t, aggregateInterfaceSummary(&aggregate.Entry{Name: "ae1",
			Layer3: &aggregate.Layer3{Ipv6: &aggregate.Layer3Ipv6{Enabled: new(false)}}}))
		if v, ok := m["ipv6_enabled"]; !ok || v != false {
			t.Fatalf("an explicit false ipv6_enabled must report false, got ok=%v v=%v", ok, v)
		}
	})
}

// --- Wire-level create xpath tests -------------------------------------------

// TestEthernetInterfaceCreateFirewallXpath pins that a firewall create targets
// the ethernet interface node (never aggregate-ethernet). The "/aggregate-"
// guard makes the check fail loud if the tool were wired to the aggregate
// service by mistake, since "interface/ethernet" is not a substring of
// "interface/aggregate-ethernet".
func TestEthernetInterfaceCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ethernet1/3"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEthernetInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ethernet_interface_create",
		Arguments: map[string]any{"name": "ethernet1/3", "ips": []string{"10.0.0.1/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertEthAggCreateNodeXpath(t, f, "interface/ethernet")
}

// TestEthernetInterfaceCreatePanoramaTemplateXpath pins that a Panorama create
// resolves through the template scope AND still targets the ethernet node.
func TestEthernetInterfaceCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ethernet1/3"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEthernetInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ethernet_interface_create",
		Arguments: map[string]any{"name": "ethernet1/3", "template": "edge", "mtu": 1500}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	xp := assertEthAggCreateNodeXpath(t, f, "interface/ethernet")
	if !strings.Contains(xp, "/template/entry[@name='edge']") {
		t.Fatalf("panorama create must resolve through the template scope: %s", xp)
	}
}

func TestAggregateInterfaceCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ae1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAggregateInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_aggregate_interface_create",
		Arguments: map[string]any{"name": "ae1", "ips": []string{"10.0.0.1/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertEthAggCreateNodeXpath(t, f, "interface/aggregate-ethernet")
}

// assertEthAggCreateNodeXpath asserts the recorded config "set" (create) request
// targets the given interface node and returns the xpath for further checks. It
// pins the exact node token so a location drift (or a wrong-service wiring) fails
// rather than silently writing to the wrong tree.
func assertEthAggCreateNodeXpath(t *testing.T, f *fakeAPI, node string) string {
	t.Helper()
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			xp := req.Get("xpath")
			if !strings.Contains(xp, node) {
				t.Fatalf("create must target the %q node, got xpath %s", node, xp)
			}
			return xp
		}
	}
	t.Fatal("no config set recorded")
	return ""
}

// --- Net-scope gating --------------------------------------------------------

// TestEthernetInterfaceScopeGating pins the resolver wiring for the ethernet
// family: a firewall resolves to the device (Ngfw) scope, a Panorama with no
// template errors, and a template on a firewall errors. Sabotage: leaving the
// ngfw part nil (as the template-only variable does) turns the firewall subtest
// red.
func TestEthernetInterfaceScopeGating(t *testing.T) {
	assertEthAggScopeGating(t, ethernetInterfaceParts())
}

func TestAggregateInterfaceScopeGating(t *testing.T) {
	assertEthAggScopeGating(t, aggregateInterfaceParts())
}

func assertEthAggScopeGating[L any](t *testing.T, parts netScopeParts[L]) {
	t.Helper()
	t.Run("firewall resolves to device scope", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		if _, err := resolveNetScope(d, NetScopeInput{}, parts); err != nil {
			t.Fatalf("a firewall must resolve to the device scope, got %v", err)
		}
	})
	t.Run("panorama without a template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		if _, err := resolveNetScope(d, NetScopeInput{}, parts); err == nil ||
			!strings.Contains(err.Error(), "template or template_stack is required on Panorama") {
			t.Fatalf("panorama without a template must error, got %v", err)
		}
	})
	t.Run("template on a firewall errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		if _, err := resolveNetScope(d, NetScopeInput{Template: "edge"}, parts); err == nil ||
			!strings.Contains(err.Error(), "template requires a Panorama connection") {
			t.Fatalf("a template on a firewall must error, got %v", err)
		}
	})
}

// --- No-op update: issues no write -------------------------------------------

// TestEthernetInterfaceUpdateNoop pins pango's SpecMatches short-circuit: an
// update that provides no Layer3 field leaves the entry byte-identical to the
// one read back (the overlay does not fabricate an empty Layer3), so pango issues
// no write. Only a get route is registered; a stray write would trip the fake's
// fail-loud on the unmatched request.
func TestEthernetInterfaceUpdateNoop(t *testing.T) {
	current := `<response status="success"><result><entry name="ethernet1/1"><layer3><mtu>1500</mtu></layer3></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: current})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEthernetInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ethernet_interface_update",
		Arguments: map[string]any{"name": "ethernet1/1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- Deferred / sibling subtrees untouched -----------------------------------

// TestOverlayEthernetInterfaceDeferredUntouched proves the update is a genuine
// read-modify-write: setting only mtu preserves an existing Layer3.Ip and
// interface_management_profile, and never clears a sibling mode block. Sabotage:
// rebuilding the Entry (or the Layer3) from scratch in overlayEthernetInterface
// drops the existing Ip and imp; auto-clearing siblings nils VirtualWire. Either
// turns this red.
func TestOverlayEthernetInterfaceDeferredUntouched(t *testing.T) {
	e := &ethernet.Entry{
		Name:           "ethernet1/1",
		VirtualWire:    &ethernet.VirtualWire{}, // a sibling mode block that must survive
		Misc:           []generic.Xml{{}},       // nested unknown XML pango round-trips
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "abc-123"}},
		Layer3: &ethernet.Layer3{
			Ip:                         []ethernet.Layer3Ip{{Name: "10.0.0.1/24"}},
			InterfaceManagementProfile: new("mgmt"),
		},
	}
	if err := overlayEthernetInterface(e, EthernetInterfaceInput{
		Name: "ethernet1/1",
		Mtu:  new(int64(9000)),
	}); err != nil {
		t.Fatal(err)
	}
	if e.Layer3.Mtu == nil || *e.Layer3.Mtu != 9000 {
		t.Fatalf("provided mtu must be applied: %+v", e.Layer3.Mtu)
	}
	if len(e.Layer3.Ip) != 1 || e.Layer3.Ip[0].Name != "10.0.0.1/24" {
		t.Fatalf("existing Layer3.Ip must be preserved when only mtu is updated: %+v", e.Layer3.Ip)
	}
	if e.Layer3.InterfaceManagementProfile == nil || *e.Layer3.InterfaceManagementProfile != "mgmt" {
		t.Fatalf("existing interface_management_profile must be preserved: %+v", e.Layer3.InterfaceManagementProfile)
	}
	if e.VirtualWire == nil {
		t.Fatal("a sibling mode block (virtual-wire) must not be cleared on a layer3 update")
	}
	// Nested unknown XML preserved by the in-place read-modify-write: rebuilding
	// the Entry from scratch would drop these.
	if len(e.Misc) != 1 {
		t.Fatalf("nested unknown XML (Misc) must survive a layer3 update: %+v", e.Misc)
	}
	if len(e.MiscAttributes) != 1 || e.MiscAttributes[0].Value != "abc-123" {
		t.Fatalf("unknown entry attributes (MiscAttributes) must survive a layer3 update: %+v", e.MiscAttributes)
	}
}

// TestOverlayEthernetInterfaceAggregateGroupOnLayer3 pins the state-transition
// guard: setting aggregate_group on a port that already carries a Layer3 block is
// rejected up front (the invalid combination would otherwise be caught only at
// commit), while setting it on a member port (no Layer3) is allowed. Sabotage:
// deleting the guard in overlayEthernetInterface lets the first case through.
func TestOverlayEthernetInterfaceAggregateGroupOnLayer3(t *testing.T) {
	l3 := &ethernet.Entry{Name: "ethernet1/1", Layer3: &ethernet.Layer3{}}
	if err := overlayEthernetInterface(l3, EthernetInterfaceInput{Name: "ethernet1/1", AggregateGroup: new("ae1")}); err == nil {
		t.Fatal("setting aggregate_group on an interface with an existing layer3 block must be rejected")
	}
	member := &ethernet.Entry{Name: "ethernet1/2"}
	if err := overlayEthernetInterface(member, EthernetInterfaceInput{Name: "ethernet1/2", AggregateGroup: new("ae1")}); err != nil {
		t.Fatalf("aggregate_group on a member port (no layer3) must be allowed: %v", err)
	}
	ethMustStrPtr(t, member.AggregateGroup, "ae1", "aggregate_group on member port")
}

func TestOverlayAggregateInterfaceDeferredUntouched(t *testing.T) {
	e := &aggregate.Entry{
		Name:        "ae1",
		VirtualWire: &aggregate.VirtualWire{},
		Layer3: &aggregate.Layer3{
			Ip:                         []aggregate.Layer3Ip{{Name: "10.0.0.1/24"}},
			InterfaceManagementProfile: new("mgmt"),
		},
	}
	if err := overlayAggregateInterface(e, AggregateInterfaceInput{
		Name: "ae1",
		Mtu:  new(int64(9000)),
	}); err != nil {
		t.Fatal(err)
	}
	if e.Layer3.Mtu == nil || *e.Layer3.Mtu != 9000 {
		t.Fatalf("provided mtu must be applied: %+v", e.Layer3.Mtu)
	}
	if len(e.Layer3.Ip) != 1 || e.Layer3.Ip[0].Name != "10.0.0.1/24" {
		t.Fatalf("existing Layer3.Ip must be preserved: %+v", e.Layer3.Ip)
	}
	if e.Layer3.InterfaceManagementProfile == nil || *e.Layer3.InterfaceManagementProfile != "mgmt" {
		t.Fatalf("existing interface_management_profile must be preserved: %+v", e.Layer3.InterfaceManagementProfile)
	}
	if e.VirtualWire == nil {
		t.Fatal("a sibling mode block (virtual-wire) must not be cleared on a layer3 update")
	}
}

// TestOverlayEthernetInterfaceReplacesIps pins that a provided ips list replaces
// the current addresses fully (not appends), while an omitted ips list leaves
// them in place.
func TestOverlayEthernetInterfaceReplacesIps(t *testing.T) {
	e := &ethernet.Entry{Name: "ethernet1/1", Layer3: &ethernet.Layer3{Ip: []ethernet.Layer3Ip{{Name: "10.0.0.1/24"}}}}
	if err := overlayEthernetInterface(e, EthernetInterfaceInput{Name: "ethernet1/1",
		Ips: []string{"192.0.2.1/24", "192.0.2.2/24"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Layer3.Ip) != 2 || e.Layer3.Ip[0].Name != "192.0.2.1/24" || e.Layer3.Ip[1].Name != "192.0.2.2/24" {
		t.Fatalf("ips must replace fully in order: %+v", e.Layer3.Ip)
	}
	// Omitting ips on a later update leaves the current addresses in place.
	if err := overlayEthernetInterface(e, EthernetInterfaceInput{Name: "ethernet1/1",
		Mtu: new(int64(1400))}); err != nil {
		t.Fatal(err)
	}
	if len(e.Layer3.Ip) != 2 || e.Layer3.Ip[0].Name != "192.0.2.1/24" {
		t.Fatalf("omitted ips must be preserved: %+v", e.Layer3.Ip)
	}
}

// --- read-only gating --------------------------------------------------------

func TestEthernetAggregateReadOnlyGating(t *testing.T) {
	cases := []struct {
		register func(*mcp.Server, *Deps)
		base     string
	}{
		{RegisterEthernetInterfaceTools, "panos_ethernet_interface"},
		{RegisterAggregateInterfaceTools, "panos_aggregate_interface"},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			reads := []string{c.base + "_list", c.base + "_get"}
			writes := []string{c.base + "_create", c.base + "_update", c.base + "_delete"}
			assertReadOnlyGating(t, c.register, reads, writes)
		})
	}
}
