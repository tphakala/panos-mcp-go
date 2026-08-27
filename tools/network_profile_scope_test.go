package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// LLDP profile (network/profiles/lldp)
// ---------------------------------------------------------------------------

// TestLldpProfileCreateFirewallXpath drives a registered firewall create and
// pins that the set request targets the lldp-profile node. Sabotage: pointing
// lldpProfileParts at a different pango resource shifts the xpath and this fails.
func TestLldpProfileCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="lldp1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLldpProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_lldp_profile_create",
		Arguments: map[string]any{"name": "lldp1", "mode": "transmit-receive"},
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
			if xp := req.Get("xpath"); !strings.Contains(xp, "lldp-profile") {
				t.Fatalf("create must target the lldp-profile xpath: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestLldpProfileCreatePanoramaTemplateXpath drives a registered Panorama
// create under a template and pins that the set request reaches the
// lldp-profile node inside that template's config. Sabotage: dropping the
// template branch of lldpProfileParts (or the template arg wiring) drops the
// "template" segment and this fails.
func TestLldpProfileCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="lldp1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLldpProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_lldp_profile_create",
		Arguments: map[string]any{"name": "lldp1", "template": "tmpl-a"},
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
			if !strings.Contains(xp, "lldp-profile") {
				t.Fatalf("create must target the lldp-profile xpath: %s", xp)
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

// TestLldpProfileNetScopeGating pins the two rejection paths the net-scope
// resolver enforces for this family: Panorama with no template/template_stack,
// and a template supplied against a firewall.
func TestLldpProfileNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterLldpProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_lldp_profile_list", Arguments: map[string]any{},
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
		RegisterLldpProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_lldp_profile_list", Arguments: map[string]any{"template": "tmpl-a"},
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

// ---------------------------------------------------------------------------
// BFD profile (network/profiles/bfd)
// ---------------------------------------------------------------------------

// TestBfdProfileCreateFirewallXpath drives a registered firewall create and
// pins that the set request targets the bfd-profile node. Sabotage: pointing
// bfdProfileParts at a different pango resource shifts the xpath and this fails.
func TestBfdProfileCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="bfd1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterBfdProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_bfd_profile_create",
		Arguments: map[string]any{"name": "bfd1", "mode": "active"},
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
			if xp := req.Get("xpath"); !strings.Contains(xp, "bfd-profile") {
				t.Fatalf("create must target the bfd-profile xpath: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestBfdProfileCreatePanoramaTemplateXpath drives a registered Panorama
// create under a template and pins that the set request reaches the
// bfd-profile node inside that template's config. Sabotage: dropping the
// template branch of bfdProfileParts (or the template arg wiring) drops the
// "template" segment and this fails.
func TestBfdProfileCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="bfd1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterBfdProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_bfd_profile_create",
		Arguments: map[string]any{"name": "bfd1", "template": "tmpl-a"},
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
			if !strings.Contains(xp, "bfd-profile") {
				t.Fatalf("create must target the bfd-profile xpath: %s", xp)
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

// TestBfdProfileNetScopeGating pins the two rejection paths the net-scope
// resolver enforces for this family: Panorama with no template/template_stack,
// and a template supplied against a firewall.
func TestBfdProfileNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterBfdProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_bfd_profile_list", Arguments: map[string]any{},
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
		RegisterBfdProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_bfd_profile_list", Arguments: map[string]any{"template": "tmpl-a"},
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

// ---------------------------------------------------------------------------
// Monitor profile (network/profiles/monitor)
// ---------------------------------------------------------------------------

// TestMonitorProfileCreateFirewallXpath drives a registered firewall create and
// pins that the set request targets the monitor-profile node. Sabotage: pointing
// monitorProfileParts at a different pango resource shifts the xpath and this fails.
func TestMonitorProfileCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="mon1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterMonitorProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_monitor_profile_create",
		Arguments: map[string]any{"name": "mon1", "action": "wait-recover"},
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
			if xp := req.Get("xpath"); !strings.Contains(xp, "monitor-profile") {
				t.Fatalf("create must target the monitor-profile xpath: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestMonitorProfileCreatePanoramaTemplateXpath drives a registered Panorama
// create under a template and pins that the set request reaches the
// monitor-profile node inside that template's config. Sabotage: dropping the
// template branch of monitorProfileParts (or the template arg wiring) drops the
// "template" segment and this fails.
func TestMonitorProfileCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="mon1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterMonitorProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_monitor_profile_create",
		Arguments: map[string]any{"name": "mon1", "template": "tmpl-a"},
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
			if !strings.Contains(xp, "monitor-profile") {
				t.Fatalf("create must target the monitor-profile xpath: %s", xp)
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

// TestMonitorProfileNetScopeGating pins the two rejection paths the net-scope
// resolver enforces for this family: Panorama with no template/template_stack,
// and a template supplied against a firewall.
func TestMonitorProfileNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterMonitorProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_monitor_profile_list", Arguments: map[string]any{},
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
		RegisterMonitorProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_monitor_profile_list", Arguments: map[string]any{"template": "tmpl-a"},
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
