package tools

import (
	"strings"
	"testing"

	srv4 "github.com/PaloAltoNetworks/pango/network/virtual_router/ipv4/staticroute"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestParentFixAdapterCreateXpathTwoComponents drives a registered static-route
// create against the fake and pins that the "set" request targets the
// static-route COLLECTION node (parent+child xpath minus its last component),
// carrying both the parent virtual-router predicate and the static-route
// segment. Sabotage: changing path[:len(path)-1] to path in
// parentFixAdapter.Create makes the set target the child entry node instead, so
// the recorded xpath ends at the route entry and this assertion shifts.
func TestParentFixAdapterCreateXpathTwoComponents(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="r1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_create",
		Arguments: map[string]any{"name": "r1", "virtual_router": "vr1", "destination": "10.0.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") != "set" {
			continue
		}
		sawSet = true
		xp := req.Get("xpath")
		if !strings.Contains(xp, "virtual-router") || !strings.Contains(xp, "vr1") {
			t.Fatalf("set must resolve under the parent virtual-router: %s", xp)
		}
		if !strings.HasSuffix(xp, "static-route") {
			t.Fatalf("set must target the static-route collection node, got: %s", xp)
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestParentFixAdapterDeleteViaMultiConfig drives a registered static-route
// delete and pins that it reaches the wire as a multi-config carrying a <delete>
// against the full two-component xpath (parent virtual-router plus the route
// entry). The adapter implements Delete itself (the SDK has no DeleteWithXpath)
// via client.MultiConfig, mirroring the SDK's own delete. Sabotage: dropping
// util.AsEntryXpath(ps.parent) from the Delete path assembly makes
// XpathWithComponents receive a single component and error, so no delete reaches
// the wire and this fails.
func TestParentFixAdapterDeleteViaMultiConfig(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_delete",
		Arguments: map[string]any{"name": "route-a", "virtual_router": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	var sawDelete bool
	for _, req := range f.Requests() {
		if req.Get("action") != "multi-config" {
			continue
		}
		el := req.Get("element")
		// The child route name "route-a" is asserted specifically: it is not a
		// substring of the parent "vr1", so this fails for a collection-level
		// delete that drops the child component (a plain "r1" would be satisfied
		// by the parent predicate entry[@name='vr1'] and prove nothing).
		if strings.Contains(el, "<delete") && strings.Contains(el, "virtual-router") &&
			strings.Contains(el, "vr1") && strings.Contains(el, "static-route") &&
			strings.Contains(el, "route-a") {
			sawDelete = true
			break
		}
	}
	if !sawDelete {
		t.Fatal("no multi-config delete against the two-component xpath recorded")
	}
}

// TestParentFixAdapterDeleteRejectsEmptyName pins that the adapter's own Delete
// rejects a blank name up front, before assembling any xpath or reaching the
// wire, mirroring the SDK's own NameNotSpecifiedError guard. Sabotage: deleting
// the `if n == "" { return ... }` guard lets the blank name build a
// collection-node xpath and issue a multi-config delete, which
// assertNoConfigWrite then catches.
func TestParentFixAdapterDeleteRejectsEmptyName(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	svc := newStaticRouteV4Service(d)
	ps := parentScopeLoc[srv4.Location]{loc: staticRouteV4Parts().ngfw(), parent: "vr1"}
	if err := svc.Delete(t.Context(), ps, ""); err == nil {
		t.Fatal("a blank name must be rejected")
	}
	assertNoConfigWrite(t, f)
}

// TestParentFixAdapterListXpath drives a registered static-route list and pins
// that parentFixAdapter.List assembles the collection xpath under the parent
// virtual-router (the two-component list path), carrying both the parent
// predicate and the static-route segment. Sabotage: dropping
// util.AsEntryXpath(ps.parent) from the List path assembly makes
// XpathWithComponents receive a single component and error, so no list get
// reaches the wire and this fails.
func TestParentFixAdapterListXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="r1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_list",
		Arguments: map[string]any{"virtual_router": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("list failed: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, "r1") {
		t.Fatalf("list must return the entry: %s", body)
	}
	var sawGet bool
	for _, req := range f.Requests() {
		if req.Get("action") != "get" {
			continue
		}
		xp := req.Get("xpath")
		if strings.Contains(xp, "virtual-router") && strings.Contains(xp, "vr1") &&
			strings.Contains(xp, "static-route") {
			sawGet = true
			break
		}
	}
	if !sawGet {
		t.Fatal("no list get against the parent virtual-router static-route collection recorded")
	}
}

// TestResolveParentNetScopeRequiresParent pins that a blank parent is rejected
// before any location is built, so a two-component xpath is never assembled with
// a missing parent component. Sabotage: deleting the if parent == "" guard makes
// resolveNetScope succeed and this returns no error.
func TestResolveParentNetScopeRequiresParent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	if _, err := resolveParentNetScope(d, NetScopeInput{}, "", staticRouteV4Parts()); err == nil {
		t.Fatal("a blank parent must be rejected")
	}
	// A non-blank parent on a firewall resolves fine (control).
	if _, err := resolveParentNetScope(d, NetScopeInput{}, "vr1", staticRouteV4Parts()); err != nil {
		t.Fatalf("a valid parent must resolve: %v", err)
	}
}
