package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/interface/loopback"
	"github.com/PaloAltoNetworks/pango/network/interface/tunnel"
	"github.com/PaloAltoNetworks/pango/network/interface/vlan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The three interface families share the same Layer3-on-Entry surface, so the
// tests below pin the same guarantees for each: the []string -> Entry.Ip[].Name
// mapping, the mtu pass-through, the tri-state ipv6_enabled summary, that an
// absent ips list renders [] and not null, empty-name rejection, the create
// xpath node, net-scope gating on both device types, and that a no-op update
// issues no config write.

// --- Loopback -----------------------------------------------------------------

func TestBuildLoopbackInterfaceAndSummary(t *testing.T) {
	e, err := buildLoopbackInterface(LoopbackInterfaceInput{
		Name: "loopback.1", Comment: new("edge"), Mtu: new(int64(1400)),
		Ips: []string{"10.0.0.1/24"}, InterfaceManagementProfile: new("mgmt"), Ipv6Enabled: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	// ips must map to Entry.Ip[].Name, not any other field. Sabotage: mapping to
	// the wrong field leaves Ip empty and this fails.
	if len(e.Ip) != 1 || e.Ip[0].Name != "10.0.0.1/24" {
		t.Fatalf("ips not mapped to Ip[].Name: %+v", e.Ip)
	}
	if e.Mtu == nil || *e.Mtu != 1400 {
		t.Fatalf("mtu not set: %+v", e.Mtu)
	}
	if e.Ipv6 == nil || e.Ipv6.Enabled == nil || !*e.Ipv6.Enabled {
		t.Fatalf("ipv6_enabled not mapped to Ipv6.Enabled: %+v", e.Ipv6)
	}
	m := asMap(t, loopbackInterfaceSummary(e))
	ips, ok := m["ips"].([]string)
	if !ok || len(ips) != 1 || ips[0] != "10.0.0.1/24" {
		t.Fatalf("summary ips wrong: %v", m["ips"])
	}
	if m["mtu"] != int64(1400) {
		t.Fatalf("summary mtu wrong: %v", m["mtu"])
	}
	if m["ipv6_enabled"] != true {
		t.Fatalf("summary ipv6_enabled wrong: %v", m["ipv6_enabled"])
	}
}

func TestLoopbackInterfaceSummaryTriStateAndEmptyList(t *testing.T) {
	// A bare interface: no ipv6 subtree, no ips. ipv6_enabled must be omitted
	// (sabotage: forcing it false makes the key appear); ips must be [] not null.
	m := asMap(t, loopbackInterfaceSummary(&loopback.Entry{Name: "loopback.1"}))
	if _, ok := m["ipv6_enabled"]; ok {
		t.Fatalf("ipv6_enabled must be omitted when there is no ipv6 subtree: %v", m["ipv6_enabled"])
	}
	ips, ok := m["ips"].([]string)
	if !ok || ips == nil {
		t.Fatalf("ips must render as a non-nil empty slice, got %#v", m["ips"])
	}
	if len(ips) != 0 {
		t.Fatalf("ips must be empty for a bare interface: %v", ips)
	}
	// ipv6 present but Enabled nil: still omitted.
	m = asMap(t, loopbackInterfaceSummary(&loopback.Entry{Name: "loopback.1", Ipv6: &loopback.Ipv6{}}))
	if _, ok := m["ipv6_enabled"]; ok {
		t.Fatalf("a nil Ipv6.Enabled must be omitted: %v", m["ipv6_enabled"])
	}
}

func TestBuildLoopbackInterfaceEmptyNameRejected(t *testing.T) {
	if _, err := buildLoopbackInterface(LoopbackInterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestLoopbackInterfaceCreateXpath(t *testing.T) {
	t.Run("firewall device scope", func(t *testing.T) {
		xp := loopbackCreateSetXpath(t, "PA-VM", map[string]any{"name": "loopback.1"})
		if !strings.Contains(xp, "interface/loopback") {
			t.Fatalf("create must target the loopback node xpath: %s", xp)
		}
	})
	t.Run("panorama template scope", func(t *testing.T) {
		xp := loopbackCreateSetXpath(t, "Panorama", map[string]any{"name": "loopback.1", "template": "edge"})
		if !strings.Contains(xp, "interface/loopback") || !strings.Contains(xp, "template") {
			t.Fatalf("panorama create must target the template loopback xpath: %s", xp)
		}
	})
}

func loopbackCreateSetXpath(t *testing.T, model string, args map[string]any) string {
	t.Helper()
	d, f := newTestDeps(t, model,
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="loopback.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLoopbackInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_loopback_interface_create", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			return req.Get("xpath")
		}
	}
	t.Fatal("no config set recorded")
	return ""
}

func TestLoopbackInterfaceScopeGating(t *testing.T) {
	// Panorama with no template must error.
	if _, err := resolveNetScope(mustDeps(t, "Panorama"), NetScopeInput{}, loopbackInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template or template_stack is required on Panorama") {
		t.Fatalf("panorama with no scope must error: %v", err)
	}
	// A template on a firewall must error.
	if _, err := resolveNetScope(mustDeps(t, "PA-VM"), NetScopeInput{Template: "edge"}, loopbackInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template requires a Panorama connection") {
		t.Fatalf("template on a firewall must error: %v", err)
	}
}

func TestLoopbackInterfaceNoOpUpdateIssuesNoWrite(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="loopback.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLoopbackInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_loopback_interface_update", Arguments: map[string]any{"name": "loopback.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- VLAN ---------------------------------------------------------------------

func TestBuildVlanInterfaceAndSummary(t *testing.T) {
	e, err := buildVlanInterface(VlanInterfaceInput{
		Name: "vlan.1", Comment: new("core"), Mtu: new(int64(1500)),
		Ips: []string{"192.0.2.1/24"}, InterfaceManagementProfile: new("mgmt"), Ipv6Enabled: new(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ip) != 1 || e.Ip[0].Name != "192.0.2.1/24" {
		t.Fatalf("ips not mapped to Ip[].Name: %+v", e.Ip)
	}
	if e.Mtu == nil || *e.Mtu != 1500 {
		t.Fatalf("mtu not set: %+v", e.Mtu)
	}
	if e.Ipv6 == nil || e.Ipv6.Enabled == nil || *e.Ipv6.Enabled {
		t.Fatalf("ipv6_enabled not mapped to Ipv6.Enabled: %+v", e.Ipv6)
	}
	m := asMap(t, vlanInterfaceSummary(e))
	if ips, ok := m["ips"].([]string); !ok || len(ips) != 1 || ips[0] != "192.0.2.1/24" {
		t.Fatalf("summary ips wrong: %v", m["ips"])
	}
	if m["mtu"] != int64(1500) {
		t.Fatalf("summary mtu wrong: %v", m["mtu"])
	}
	// An explicit false must be reported, not omitted.
	if v, ok := m["ipv6_enabled"]; !ok || v != false {
		t.Fatalf("explicit ipv6_enabled false must be reported: ok=%v v=%v", ok, v)
	}
}

func TestVlanInterfaceSummaryTriStateAndEmptyList(t *testing.T) {
	m := asMap(t, vlanInterfaceSummary(&vlan.Entry{Name: "vlan.1"}))
	if _, ok := m["ipv6_enabled"]; ok {
		t.Fatalf("ipv6_enabled must be omitted with no ipv6 subtree: %v", m["ipv6_enabled"])
	}
	if ips, ok := m["ips"].([]string); !ok || ips == nil || len(ips) != 0 {
		t.Fatalf("ips must render as an empty slice: %#v", m["ips"])
	}
}

func TestBuildVlanInterfaceEmptyNameRejected(t *testing.T) {
	if _, err := buildVlanInterface(VlanInterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestVlanInterfaceCreateXpath(t *testing.T) {
	t.Run("firewall device scope", func(t *testing.T) {
		xp := vlanCreateSetXpath(t, "PA-VM", map[string]any{"name": "vlan.1"})
		if !strings.Contains(xp, "interface/vlan") {
			t.Fatalf("create must target the vlan node xpath: %s", xp)
		}
	})
	t.Run("panorama template scope", func(t *testing.T) {
		xp := vlanCreateSetXpath(t, "Panorama", map[string]any{"name": "vlan.1", "template": "edge"})
		if !strings.Contains(xp, "interface/vlan") || !strings.Contains(xp, "template") {
			t.Fatalf("panorama create must target the template vlan xpath: %s", xp)
		}
	})
}

func vlanCreateSetXpath(t *testing.T, model string, args map[string]any) string {
	t.Helper()
	d, f := newTestDeps(t, model,
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="vlan.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVlanInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_vlan_interface_create", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			return req.Get("xpath")
		}
	}
	t.Fatal("no config set recorded")
	return ""
}

func TestVlanInterfaceScopeGating(t *testing.T) {
	if _, err := resolveNetScope(mustDeps(t, "Panorama"), NetScopeInput{}, vlanInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template or template_stack is required on Panorama") {
		t.Fatalf("panorama with no scope must error: %v", err)
	}
	if _, err := resolveNetScope(mustDeps(t, "PA-VM"), NetScopeInput{TemplateStack: "s"}, vlanInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template_stack requires a Panorama connection") {
		t.Fatalf("template_stack on a firewall must error: %v", err)
	}
}

func TestVlanInterfaceNoOpUpdateIssuesNoWrite(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="vlan.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVlanInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_vlan_interface_update", Arguments: map[string]any{"name": "vlan.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- Tunnel -------------------------------------------------------------------

func TestBuildTunnelInterfaceAndSummary(t *testing.T) {
	e, err := buildTunnelInterface(TunnelInterfaceInput{
		Name: "tunnel.1", Comment: new("vpn"), Mtu: new(int64(1400)),
		Ips: []string{"10.1.1.1/32"}, InterfaceManagementProfile: new("mgmt"),
		Ipv6Enabled: new(true), LinkTag: new("tag7"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ip) != 1 || e.Ip[0].Name != "10.1.1.1/32" {
		t.Fatalf("ips not mapped to Ip[].Name: %+v", e.Ip)
	}
	if e.Mtu == nil || *e.Mtu != 1400 {
		t.Fatalf("mtu not set: %+v", e.Mtu)
	}
	// link_tag is tunnel-only; it must map to Entry.LinkTag.
	if e.LinkTag == nil || *e.LinkTag != "tag7" {
		t.Fatalf("link_tag not mapped to Entry.LinkTag: %+v", e.LinkTag)
	}
	m := asMap(t, tunnelInterfaceSummary(e))
	if ips, ok := m["ips"].([]string); !ok || len(ips) != 1 || ips[0] != "10.1.1.1/32" {
		t.Fatalf("summary ips wrong: %v", m["ips"])
	}
	if m["mtu"] != int64(1400) {
		t.Fatalf("summary mtu wrong: %v", m["mtu"])
	}
	if m["link_tag"] != "tag7" {
		t.Fatalf("summary link_tag wrong: %v", m["link_tag"])
	}
	if m["ipv6_enabled"] != true {
		t.Fatalf("summary ipv6_enabled wrong: %v", m["ipv6_enabled"])
	}
}

func TestTunnelInterfaceSummaryTriStateAndEmptyList(t *testing.T) {
	m := asMap(t, tunnelInterfaceSummary(&tunnel.Entry{Name: "tunnel.1"}))
	if _, ok := m["ipv6_enabled"]; ok {
		t.Fatalf("ipv6_enabled must be omitted with no ipv6 subtree: %v", m["ipv6_enabled"])
	}
	if ips, ok := m["ips"].([]string); !ok || ips == nil || len(ips) != 0 {
		t.Fatalf("ips must render as an empty slice: %#v", m["ips"])
	}
}

func TestBuildTunnelInterfaceEmptyNameRejected(t *testing.T) {
	if _, err := buildTunnelInterface(TunnelInterfaceInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestTunnelInterfaceCreateXpath(t *testing.T) {
	t.Run("firewall device scope", func(t *testing.T) {
		xp := tunnelCreateSetXpath(t, "PA-VM", map[string]any{"name": "tunnel.1"})
		if !strings.Contains(xp, "interface/tunnel") {
			t.Fatalf("create must target the tunnel node xpath: %s", xp)
		}
	})
	t.Run("panorama template scope", func(t *testing.T) {
		xp := tunnelCreateSetXpath(t, "Panorama", map[string]any{"name": "tunnel.1", "template": "edge"})
		if !strings.Contains(xp, "interface/tunnel") || !strings.Contains(xp, "template") {
			t.Fatalf("panorama create must target the template tunnel xpath: %s", xp)
		}
	})
}

func tunnelCreateSetXpath(t *testing.T, model string, args map[string]any) string {
	t.Helper()
	d, f := newTestDeps(t, model,
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="tunnel.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterTunnelInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_tunnel_interface_create", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			return req.Get("xpath")
		}
	}
	t.Fatal("no config set recorded")
	return ""
}

func TestTunnelInterfaceScopeGating(t *testing.T) {
	if _, err := resolveNetScope(mustDeps(t, "Panorama"), NetScopeInput{}, tunnelInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template or template_stack is required on Panorama") {
		t.Fatalf("panorama with no scope must error: %v", err)
	}
	if _, err := resolveNetScope(mustDeps(t, "PA-VM"), NetScopeInput{Template: "edge"}, tunnelInterfaceParts()); err == nil ||
		!strings.Contains(err.Error(), "template requires a Panorama connection") {
		t.Fatalf("template on a firewall must error: %v", err)
	}
}

func TestTunnelInterfaceNoOpUpdateIssuesNoWrite(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="tunnel.1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterTunnelInterfaceTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_tunnel_interface_update", Arguments: map[string]any{"name": "tunnel.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- read-only gating ---------------------------------------------------------

func TestLoopbackVlanTunnelReadOnlyGating(t *testing.T) {
	cases := []struct {
		register func(*mcp.Server, *Deps)
		base     string
	}{
		{RegisterLoopbackInterfaceTools, "panos_loopback_interface"},
		{RegisterVlanInterfaceTools, "panos_vlan_interface"},
		{RegisterTunnelInterfaceTools, "panos_tunnel_interface"},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			reads := []string{c.base + "_list", c.base + "_get"}
			writes := []string{c.base + "_create", c.base + "_update", c.base + "_delete"}
			assertReadOnlyGating(t, c.register, reads, writes)
		})
	}
}

// mustDeps builds a test Deps for the given model, failing the test on setup
// error. It keeps the scope-gating tests free of the fake-route boilerplate.
func mustDeps(t *testing.T, model string) *Deps {
	t.Helper()
	d, _ := newTestDeps(t, model)
	return d
}
