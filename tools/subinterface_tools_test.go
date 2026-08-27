package tools

import (
	"strings"
	"testing"

	aggsub "github.com/PaloAltoNetworks/pango/network/interface/aggregate/subinterface/layer3"
	ethsub "github.com/PaloAltoNetworks/pango/network/interface/ethernet/subinterface/layer3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- build / summary ----------------------------------------------------------

// TestBuildSubinterfaceTag pins that tag maps to Entry.Tag and ips maps to
// Entry.Ip[].Name for a subinterface build. Sabotage: dropping the
// `if in.Tag != nil { e.Tag = in.Tag }` line leaves Tag nil and fails the tag
// assertion.
func TestBuildSubinterfaceTag(t *testing.T) {
	e, err := buildEthernetSubinterface(SubinterfaceInput{
		Name: "ethernet1/1.100", Tag: new(int64(100)),
		Ips: []string{"10.0.0.1/24"}, Comment: new("unit"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Tag == nil || *e.Tag != 100 {
		t.Fatalf("tag not mapped to Entry.Tag: %+v", e.Tag)
	}
	if len(e.Ip) != 1 || e.Ip[0].Name != "10.0.0.1/24" {
		t.Fatalf("ips not mapped to Ip[].Name: %+v", e.Ip)
	}
	if e.Comment == nil || *e.Comment != "unit" {
		t.Fatalf("comment not mapped: %+v", e.Comment)
	}
	m := asMap(t, ethernetSubinterfaceSummary(e))
	if m["tag"] != int64(100) {
		t.Fatalf("summary tag wrong: %v", m["tag"])
	}
	ips, ok := m["ips"].([]string)
	if !ok || len(ips) != 1 || ips[0] != "10.0.0.1/24" {
		t.Fatalf("summary ips wrong: %v", m["ips"])
	}
}

func TestBuildSubinterfaceEmptyName(t *testing.T) {
	if _, err := buildEthernetSubinterface(SubinterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, err := buildAggregateSubinterface(SubinterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- wire-level create --------------------------------------------------------

// TestEthernetSubinterfaceCreateXpath pins the ethernet family reaches the
// ethernet/<parent>/layer3/units node. Sabotage: swapping the ethernet and
// aggregate service constructors flips the segment to aggregate-ethernet.
func TestEthernetSubinterfaceCreateXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ethernet1/1.100"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEthernetSubinterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_ethernet_subinterface_create",
		Arguments: map[string]any{"name": "ethernet1/1.100", "parent_interface": "ethernet1/1", "tag": 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertSawSet(t, f, func(xp string) bool {
		return strings.Contains(xp, "ethernet") && strings.Contains(xp, "ethernet1/1") &&
			strings.Contains(xp, "units") && !strings.Contains(xp, "aggregate-ethernet")
	})
}

// TestAggregateSubinterfaceCreateXpath pins the aggregate family reaches the
// aggregate-ethernet/<parent>/layer3/units node. Sabotage: swapping the service
// constructors flips the segment to ethernet.
func TestAggregateSubinterfaceCreateXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ae1.100"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAggregateSubinterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_aggregate_subinterface_create",
		Arguments: map[string]any{"name": "ae1.100", "parent_interface": "ae1", "tag": 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertSawSet(t, f, func(xp string) bool {
		return strings.Contains(xp, "aggregate-ethernet") && strings.Contains(xp, "ae1") && strings.Contains(xp, "units")
	})
}

// --- net-scope gating ---------------------------------------------------------

func TestEthernetSubinterfaceNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterEthernetSubinterfaceTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_ethernet_subinterface_list", Arguments: map[string]any{"parent_interface": "ethernet1/1"},
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
	t.Run("missing parent_interface errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterEthernetSubinterfaceTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_ethernet_subinterface_list", Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("a list without a parent_interface must error")
		}
	})
}

// --- no-op update -------------------------------------------------------------

// TestEthernetSubinterfaceNoOpUpdateNoWrite drives a registered update that
// changes nothing and asserts no config-write reaches the wire. Sabotage: having
// the overlay mutate the entry unconditionally produces a differing spec and a
// write.
func TestEthernetSubinterfaceNoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="ethernet1/1.100"><tag>100</tag></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEthernetSubinterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_ethernet_subinterface_update",
		Arguments: map[string]any{"name": "ethernet1/1.100", "parent_interface": "ethernet1/1"},
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

// TestOverlayEthernetSubinterfacePreservesUnmanaged pins that an update setting
// only one field leaves an unmanaged typed field (Arp) and a managed sibling
// (Comment) as read. Sabotage: rebuilding the entry in the overlay drops them.
func TestOverlayEthernetSubinterfacePreservesUnmanaged(t *testing.T) {
	e := &ethsub.Entry{
		Name:    "ethernet1/1.100",
		Comment: new("keep"),
		Tag:     new(int64(100)),
		Arp:     []ethsub.Arp{{Name: "10.0.0.9"}},
	}
	if err := overlayEthernetSubinterface(e, SubinterfaceInput{Name: "ethernet1/1.100", Mtu: new(int64(1400))}); err != nil {
		t.Fatal(err)
	}
	if e.Mtu == nil || *e.Mtu != 1400 {
		t.Fatalf("provided mtu must be applied: %+v", e.Mtu)
	}
	if e.Comment == nil || *e.Comment != "keep" {
		t.Fatalf("existing comment must be preserved: %+v", e.Comment)
	}
	if e.Tag == nil || *e.Tag != 100 {
		t.Fatalf("existing tag must be preserved: %+v", e.Tag)
	}
	if len(e.Arp) != 1 || e.Arp[0].Name != "10.0.0.9" {
		t.Fatalf("unmanaged Arp must be preserved: %+v", e.Arp)
	}
}

// --- read-only gating ---------------------------------------------------------

func TestEthernetSubinterfaceReadOnlyGating(t *testing.T) {
	reads := []string{"panos_ethernet_subinterface_list", "panos_ethernet_subinterface_get"}
	writes := []string{"panos_ethernet_subinterface_create", "panos_ethernet_subinterface_update", "panos_ethernet_subinterface_delete"}
	assertReadOnlyGating(t, RegisterEthernetSubinterfaceTools, reads, writes)
}

func TestAggregateSubinterfaceReadOnlyGating(t *testing.T) {
	reads := []string{"panos_aggregate_subinterface_list", "panos_aggregate_subinterface_get"}
	writes := []string{"panos_aggregate_subinterface_create", "panos_aggregate_subinterface_update", "panos_aggregate_subinterface_delete"}
	assertReadOnlyGating(t, RegisterAggregateSubinterfaceTools, reads, writes)
}

// TestAggregateSubinterfaceNoOpUpdateNoWrite drives a registered aggregate update
// that changes nothing and asserts no config-write reaches the wire; see
// TestEthernetSubinterfaceNoOpUpdateNoWrite. Sabotage: having the overlay mutate
// the entry unconditionally produces a differing spec and a write.
func TestAggregateSubinterfaceNoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="ae1.100"><tag>100</tag></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAggregateSubinterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_aggregate_subinterface_update",
		Arguments: map[string]any{"name": "ae1.100", "parent_interface": "ae1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// TestOverlayAggregateSubinterfacePreservesUnmanaged pins that an aggregate
// update setting only one field leaves an unmanaged typed field (Arp) and a
// managed sibling (Comment) as read; see
// TestOverlayEthernetSubinterfacePreservesUnmanaged. Sabotage: rebuilding the
// entry in the overlay drops them.
func TestOverlayAggregateSubinterfacePreservesUnmanaged(t *testing.T) {
	e := &aggsub.Entry{
		Name:    "ae1.100",
		Comment: new("keep"),
		Tag:     new(int64(100)),
		Arp:     []aggsub.Arp{{Name: "10.0.0.9"}},
	}
	if err := overlayAggregateSubinterface(e, SubinterfaceInput{Name: "ae1.100", Mtu: new(int64(1400))}); err != nil {
		t.Fatal(err)
	}
	if e.Mtu == nil || *e.Mtu != 1400 {
		t.Fatalf("provided mtu must be applied: %+v", e.Mtu)
	}
	if e.Comment == nil || *e.Comment != "keep" {
		t.Fatalf("existing comment must be preserved: %+v", e.Comment)
	}
	if e.Tag == nil || *e.Tag != 100 {
		t.Fatalf("existing tag must be preserved: %+v", e.Tag)
	}
	if len(e.Arp) != 1 || e.Arp[0].Name != "10.0.0.9" {
		t.Fatalf("unmanaged Arp must be preserved: %+v", e.Arp)
	}
}
