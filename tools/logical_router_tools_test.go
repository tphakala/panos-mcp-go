package tools

import (
	"strings"
	"testing"

	logical_router "github.com/PaloAltoNetworks/pango/network/logical_router"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestBuildLogicalRouter pins that create carries only the name and an empty
// shell (no VRF configuration invented by this server).
func TestBuildLogicalRouter(t *testing.T) {
	e, err := buildLogicalRouter(LogicalRouterInput{Name: "lr1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "lr1" {
		t.Fatalf("name not mapped: %q", e.Name)
	}
	if len(e.Vrf) != 0 {
		t.Fatalf("create must not invent VRF config: %v", e.Vrf)
	}
}

func TestBuildLogicalRouterEmptyName(t *testing.T) {
	if _, err := buildLogicalRouter(LogicalRouterInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestLogicalRouterSummary pins that the summary reports the VRF count without
// unpacking the unmanaged per-VRF subtree.
func TestLogicalRouterSummary(t *testing.T) {
	m := asMap(t, logicalRouterSummary(&logical_router.Entry{
		Name: "lr1",
		Vrf:  []logical_router.Vrf{{Name: "default"}, {Name: "vrf-b"}},
	}))
	if m[tagNameKey] != "lr1" {
		t.Fatalf("name wrong: %v", m[tagNameKey])
	}
	if m["vrf_count"] != 2 {
		t.Fatalf("vrf_count must be 2: %v", m["vrf_count"])
	}
}

// TestLogicalRouterNoUpdateTool asserts there is no update tool: Name is the
// only scalar and it is the entry key, so an update would be a no-op. Sabotage:
// registering a panos_logical_router_update handler makes this fail.
func TestLogicalRouterNoUpdateTool(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogicalRouterTools(srv, d)
	names := serverToolNames(t, srv)
	if names["panos_logical_router_update"] {
		t.Fatal("logical router must not register an update tool")
	}
	for _, want := range []string{
		"panos_logical_router_list", "panos_logical_router_get",
		"panos_logical_router_create", "panos_logical_router_delete",
	} {
		if !names[want] {
			t.Fatalf("missing expected tool %q", want)
		}
	}
}

// TestLogicalRouterCreateFirewallXpath drives a firewall create and pins the set
// reaches the logical-router node.
func TestLogicalRouterCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="lr1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogicalRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_logical_router_create",
		Arguments: map[string]any{"name": "lr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "logical-router") {
		t.Fatalf("create must target the logical-router xpath: %s", joined)
	}
}

// TestLogicalRouterCreatePanoramaTemplateXpath drives a Panorama create under a
// template and pins the set reaches the logical-router node inside that
// template's config.
func TestLogicalRouterCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="lr1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogicalRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_logical_router_create",
		Arguments: map[string]any{"name": "lr1", "template": "tmpl-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "logical-router") || !strings.Contains(joined, "tmpl-a") {
		t.Fatalf("panorama create must resolve into the template scope: %s", joined)
	}
}

// TestLogicalRouterNetScopeGating pins the two net-scope rejection paths.
func TestLogicalRouterNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterLogicalRouterTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_logical_router_list", Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textContent(t, res), "template or template_stack is required on Panorama") {
			t.Fatalf("Panorama list without a template must error: %v", textContent(t, res))
		}
	})
	t.Run("template on firewall errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterLogicalRouterTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_logical_router_list", Arguments: map[string]any{"template": "tmpl-a"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textContent(t, res), "template requires a Panorama connection") {
			t.Fatalf("a template against a firewall must error: %v", textContent(t, res))
		}
	})
}
