package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/dnsproxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// DHCP interface config
// ---------------------------------------------------------------------------

// TestDhcpCreateXpath drives the create tool over a registered server on a
// firewall (Ngfw scope) and a Panorama template, and asserts the set reaches the
// per-interface dhcp node. The node-name substring "dhcp" is the sabotage
// anchor: if dhcpParts' pango location node drifts the firewall case fails, and
// if the net-scope template wiring drifts the Panorama case (which also requires
// the template name in the xpath) fails. The firewall case also proves the Ngfw
// scope is accepted without a template.
func TestDhcpCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="ethernet1/2"/></result></response>`
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  []string
	}{
		{"firewall ngfw", "PA-VM", map[string]any{"name": "ethernet1/2", "relay_enabled": true}, []string{"dhcp", "interface"}},
		{"panorama template", "Panorama", map[string]any{"name": "ethernet1/2", "relay_enabled": true, "template": "tmpl-a"},
			[]string{"dhcp", "template", "tmpl-a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterDhcpTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dhcp_create", Arguments: c.args})
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

// TestDhcpNetScopeGating pins resolveNetScope's routing through the registered
// create/list handlers: on Panorama a missing template/template_stack is
// rejected before any write, a template supplied against a firewall is rejected,
// and a firewall create without a template is accepted (dhcp has an Ngfw scope).
func TestDhcpNetScopeGating(t *testing.T) {
	mustErr := func(t *testing.T, res *mcp.CallToolResult, want string) {
		t.Helper()
		if !res.IsError || !strings.Contains(textContent(t, res), want) {
			t.Fatalf("must error with %q: isErr=%v %s", want, res.IsError, textContent(t, res))
		}
	}

	t.Run("panorama create without template errors", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterDhcpTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dhcp_create", Arguments: map[string]any{"name": "ethernet1/2", "relay_enabled": true}})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConfigWrite(t, f)
		mustErr(t, res, "template or template_stack is required on Panorama")
	})
	t.Run("template on a firewall errors", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterDhcpTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dhcp_create", Arguments: map[string]any{"name": "ethernet1/2", "relay_enabled": true, "template": "tmpl-a"}})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConfigWrite(t, f)
		mustErr(t, res, "template requires a Panorama connection")
	})
	t.Run("firewall create without template is accepted", func(t *testing.T) {
		entryBody := `<response status="success"><result><entry name="ethernet1/2"/></result></response>`
		d, _ := newTestDeps(t, "PA-VM",
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: entryBody},
		)
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterDhcpTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dhcp_create", Arguments: map[string]any{"name": "ethernet1/2", "relay_enabled": true}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("firewall create must be accepted (dhcp has an Ngfw scope): %s", textContent(t, res))
		}
	})
}

// TestDhcpMutualExclusion pins the relay-vs-server mutual exclusion: build (used
// by create) rejects a request that mixes relay_* and server_* fields.
func TestDhcpMutualExclusion(t *testing.T) {
	if _, err := buildDhcp(DhcpInput{Name: "ethernet1/2", RelayEnabled: new(true), ServerMode: new("enabled")}); err == nil {
		t.Fatal("a DHCP config with both relay_* and server_* fields must be rejected")
	}
	if _, err := buildDhcp(DhcpInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestDhcpServerModeBuild pins the server-mode field mapping in applyDhcpServer,
// which no tool-level test exercises (the mutual-exclusion test errors out before
// applyDhcpServer runs, and every other DHCP test drives relay mode). Sabotage:
// dropping a setPtr in applyDhcpServer fails the matching assertion.
func TestDhcpServerModeBuild(t *testing.T) {
	e, err := buildDhcp(DhcpInput{
		Name:          "ethernet1/3",
		ServerMode:    new("enabled"),
		ServerIpPools: []string{"10.0.0.100-10.0.0.200"},
		ServerProbeIp: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Relay != nil {
		t.Fatalf("server-mode config must not allocate a relay block: %+v", e.Relay)
	}
	if e.Server == nil || e.Server.Mode == nil || *e.Server.Mode != "enabled" {
		t.Fatalf("server mode not mapped: %+v", e.Server)
	}
	if len(e.Server.IpPool) != 1 || e.Server.IpPool[0] != "10.0.0.100-10.0.0.200" {
		t.Fatalf("server ip pool not mapped: %+v", e.Server)
	}
	if e.Server.ProbeIp == nil || !*e.Server.ProbeIp {
		t.Fatalf("server probe_ip not mapped: %+v", e.Server)
	}
}

// ---------------------------------------------------------------------------
// DNS proxy
// ---------------------------------------------------------------------------

// TestDnsProxyCreateXpath drives the create tool over a registered server on a
// Panorama template and asserts the set reaches the dns-proxy node. The node
// substring "dns-proxy" is the sabotage anchor: if dnsProxyParts' pango location
// node drifts, or the net-scope template wiring drifts, the case fails. dns-proxy
// is template-only, so there is no firewall case here (see the gating test).
func TestDnsProxyCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="dp1"/></result></response>`
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: entryBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDnsProxyTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dns_proxy_create",
		Arguments: map[string]any{"name": "dp1", "enabled": true, "template": "tmpl-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertSetXpathContains(t, f, []string{"dns-proxy", "template", "tmpl-a"})
}

// TestDnsProxyNetScopeGating pins resolveNetScope's routing for the template-only
// dns-proxy: a firewall request without a template is rejected (dnsProxyParts
// leaves ngfw nil, so there is no firewall-local scope), and on Panorama a
// missing template/template_stack is rejected too. Neither reaches a write.
func TestDnsProxyNetScopeGating(t *testing.T) {
	mustErr := func(t *testing.T, res *mcp.CallToolResult, want string) {
		t.Helper()
		if !res.IsError || !strings.Contains(textContent(t, res), want) {
			t.Fatalf("must error with %q: isErr=%v %s", want, res.IsError, textContent(t, res))
		}
	}

	t.Run("firewall without template is rejected", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterDnsProxyTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dns_proxy_create", Arguments: map[string]any{"name": "dp1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConfigWrite(t, f)
		mustErr(t, res, "template or template_stack is required")
	})
	t.Run("panorama create without template errors", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterDnsProxyTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dns_proxy_create", Arguments: map[string]any{"name": "dp1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConfigWrite(t, f)
		mustErr(t, res, "template or template_stack is required on Panorama")
	})
}

// TestDnsProxySummaryShowsNestedDetail pins that a get/list surfaces the nested
// static-entry and domain-server detail, not just their names: these tools are
// the only way to view that config. Sabotage: reverting dnsProxySummary to emit
// only names() drops the domain/address/primary fields and fails this test.
func TestDnsProxySummaryShowsNestedDetail(t *testing.T) {
	e := &dnsproxy.Entry{
		Name:          "dp",
		StaticEntries: []dnsproxy.StaticEntries{{Name: "s1", Domain: new("a.example.com"), Address: []string{"10.0.0.1"}}},
		DomainServers: []dnsproxy.DomainServers{{Name: "d1", Primary: new("8.8.8.8"), DomainName: []string{"corp.local"}, Cacheable: new(true)}},
	}
	m := asMap(t, dnsProxySummary(e))
	se, ok := m["static_entries"].([]any)
	if !ok || len(se) != 1 {
		t.Fatalf("static_entries shape: %v", m["static_entries"])
	}
	seItem, ok := se[0].(map[string]any)
	if !ok || seItem["domain"] != "a.example.com" {
		t.Fatalf("static entry detail hidden: %v", se[0])
	}
	ds, ok := m["domain_servers"].([]any)
	if !ok || len(ds) != 1 {
		t.Fatalf("domain_servers shape: %v", m["domain_servers"])
	}
	dsItem, ok := ds[0].(map[string]any)
	if !ok || dsItem["primary"] != "8.8.8.8" {
		t.Fatalf("domain server detail hidden: %v", ds[0])
	}
}
