package tools

import (
	"maps"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Net-scoped profile scope tests (lldp, bfd, monitor)
// ---------------------------------------------------------------------------
//
// The three families (network/profiles/{lldp,bfd,monitor}) share the
// resolveNetScope gating and the {Ngfw|Template|TemplateStack} location model,
// differing only in their Register function, tool-name prefix, target xpath
// segment and the extra create argument each requires. The scope behaviour is
// therefore exercised once, table-driven, rather than in three copied blocks.
type netProfileScopeCase struct {
	name         string                   // subtest label
	register     func(*mcp.Server, *Deps) // family Register* entry point
	toolPrefix   string                   // e.g. "panos_lldp_profile"
	xpathSegment string                   // e.g. "lldp-profile"
	entryName    string                   // create name + get-response entry name
	createArgs   map[string]any           // extra create args beyond name/template
}

var netProfileScopeCases = []netProfileScopeCase{
	{
		name:         "lldp",
		register:     RegisterLldpProfileTools,
		toolPrefix:   "panos_lldp_profile",
		xpathSegment: "lldp-profile",
		entryName:    "lldp1",
		createArgs:   map[string]any{"mode": "transmit-receive"},
	},
	{
		name:         "bfd",
		register:     RegisterBfdProfileTools,
		toolPrefix:   "panos_bfd_profile",
		xpathSegment: "bfd-profile",
		entryName:    "bfd1",
		createArgs:   map[string]any{"mode": "active"},
	},
	{
		name:         "monitor",
		register:     RegisterMonitorProfileTools,
		toolPrefix:   "panos_monitor_profile",
		xpathSegment: "monitor-profile",
		entryName:    "mon1",
		createArgs:   map[string]any{"action": "wait-recover"},
	},
}

// createArguments merges the row's fixed create args with the per-test extras
// (e.g. a template) on top of the required name.
func (c *netProfileScopeCase) createArguments(extra map[string]any) map[string]any {
	args := map[string]any{"name": c.entryName}
	maps.Copy(args, c.createArgs)
	maps.Copy(args, extra)
	return args
}

// assertSetXpath asserts a config set was recorded and every want substring is
// present in its xpath. This is the pin shared by the firewall and Panorama
// create bodies: the firewall row asserts only the profile segment, the
// Panorama row also asserts the template scope.
func assertSetXpath(t *testing.T, f *fakeAPI, want ...string) {
	t.Helper()
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			sawSet = true
			xp := req.Get("xpath")
			for _, sub := range want {
				if !strings.Contains(xp, sub) {
					t.Fatalf("set xpath missing %q: %s", sub, xp)
				}
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestNetProfileCreateFirewallXpath drives a registered firewall create for
// each family and pins that the set request targets the family's profile node.
// Sabotage: pointing a family's *Parts at a different pango resource shifts the
// xpath and that row fails.
func TestNetProfileCreateFirewallXpath(t *testing.T) {
	for _, c := range netProfileScopeCases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM",
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="` + c.entryName + `"/></result></response>`},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			c.register(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      c.toolPrefix + "_create",
				Arguments: c.createArguments(nil),
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("create failed: %s", textContent(t, res))
			}
			assertSetXpath(t, f, c.xpathSegment)
		})
	}
}

// TestNetProfileCreatePanoramaTemplateXpath drives a registered Panorama create
// under a template for each family and pins that the set request reaches the
// family's profile node inside that template's config. Sabotage: dropping the
// template branch of a family's *Parts (or the template arg wiring) drops the
// "template" segment and that row fails.
func TestNetProfileCreatePanoramaTemplateXpath(t *testing.T) {
	for _, c := range netProfileScopeCases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, "Panorama",
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="` + c.entryName + `"/></result></response>`},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			c.register(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      c.toolPrefix + "_create",
				Arguments: c.createArguments(map[string]any{"template": "tmpl-a"}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("panorama create failed: %s", textContent(t, res))
			}
			assertSetXpath(t, f, c.xpathSegment, "template", "tmpl-a")
		})
	}
}

// assertListRejects registers the family on a device of the given model, calls
// its list tool with the given args, and asserts the result is an error whose
// message contains want. It is the shared body of the two gating checks.
func (c *netProfileScopeCase) assertListRejects(t *testing.T, model string, args map[string]any, want string) {
	t.Helper()
	d, _ := newTestDeps(t, model)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	c.register(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: c.toolPrefix + "_list", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("%s must error", want)
	}
	if msg := textContent(t, res); !strings.Contains(msg, want) {
		t.Fatalf("wrong error: want %q, got %s", want, msg)
	}
}

// TestNetProfileNetScopeGating pins the two rejection paths the net-scope
// resolver enforces for each family: Panorama with no template/template_stack,
// and a template supplied against a firewall.
func TestNetProfileNetScopeGating(t *testing.T) {
	for _, c := range netProfileScopeCases {
		t.Run(c.name, func(t *testing.T) {
			t.Run("panorama without template errors", func(t *testing.T) {
				c.assertListRejects(t, "Panorama", map[string]any{}, "template or template_stack is required on Panorama")
			})
			t.Run("template on firewall errors", func(t *testing.T) {
				c.assertListRejects(t, "PA-VM", map[string]any{"template": "tmpl-a"}, "template requires a Panorama connection")
			})
		})
	}
}
