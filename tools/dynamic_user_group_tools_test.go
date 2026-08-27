package tools

import (
	"strings"
	"testing"

	dug "github.com/PaloAltoNetworks/pango/device/dynamicusergroups"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- build / summary ----------------------------------------------------------

// TestBuildDynamicUserGroup pins the field mapping: description and filter reach
// the pointer fields, and tags map to Entry.Tag. Sabotage: mapping filter to
// Description (or vice versa) turns these red.
func TestBuildDynamicUserGroup(t *testing.T) {
	e, err := buildDynamicUserGroup(DynamicUserGroupInput{
		Name:        "dug1",
		Description: "contractors",
		Filter:      "'contractor' and 'emea'",
		Tags:        []string{"t1", "t2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Description == nil || *e.Description != "contractors" {
		t.Fatalf("description not mapped: %v", e.Description)
	}
	if e.Filter == nil || *e.Filter != "'contractor' and 'emea'" {
		t.Fatalf("filter not mapped: %v", e.Filter)
	}
	if len(e.Tag) != 2 || e.Tag[0] != "t1" || e.Tag[1] != "t2" {
		t.Fatalf("tags not mapped to Entry.Tag: %v", e.Tag)
	}
}

// TestBuildDynamicUserGroupBare proves a name-only create omits the optional
// pointer fields (so the XML carries no empty description/filter) and the
// summary renders tags as [] not null.
func TestBuildDynamicUserGroupBare(t *testing.T) {
	e, err := buildDynamicUserGroup(DynamicUserGroupInput{Name: "dug1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Description != nil || e.Filter != nil {
		t.Fatalf("bare create must leave description/filter nil: %v %v", e.Description, e.Filter)
	}
	m := asMap(t, dynamicUserGroupSummary(e))
	tags, ok := m["tags"].([]string)
	if !ok || tags == nil || len(tags) != 0 {
		t.Fatalf("absent tags must render as []: %v", m["tags"])
	}
	if m["filter"] != "" {
		t.Fatalf("absent filter must render as empty string: %v", m["filter"])
	}
}

func TestBuildDynamicUserGroupEmptyName(t *testing.T) {
	if _, err := buildDynamicUserGroup(DynamicUserGroupInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestOverlayDynamicUserGroupReplacesAndPreserves pins the update contract: a
// provided tags list replaces fully, an omitted filter keeps the stored value,
// and a provided filter overwrites it. Sabotage: dropping the in.Tags != nil
// guard (always replacing) or clearing Filter unconditionally turns these red.
func TestOverlayDynamicUserGroupReplacesAndPreserves(t *testing.T) {
	e := &dug.Entry{Name: "dug1", Filter: new("old"), Tag: []string{"keep"}}
	// Omitted filter and omitted tags: both preserved.
	if err := overlayDynamicUserGroup(e, DynamicUserGroupInput{Name: "dug1"}); err != nil {
		t.Fatal(err)
	}
	if e.Filter == nil || *e.Filter != "old" {
		t.Fatalf("omitted filter must be preserved: %v", e.Filter)
	}
	if len(e.Tag) != 1 || e.Tag[0] != "keep" {
		t.Fatalf("omitted tags must be preserved: %v", e.Tag)
	}
	// Provided filter overwrites; provided tags replace fully.
	if err := overlayDynamicUserGroup(e, DynamicUserGroupInput{Name: "dug1", Filter: "new", Tags: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if e.Filter == nil || *e.Filter != "new" {
		t.Fatalf("provided filter must overwrite: %v", e.Filter)
	}
	if len(e.Tag) != 1 || e.Tag[0] != "a" {
		t.Fatalf("provided tags must replace fully: %v", e.Tag)
	}
}

// --- wire-level create --------------------------------------------------------

// TestDynamicUserGroupCreateFirewallXpath drives a registered firewall create at
// the default vsys and pins the set targets the dynamic-user-group node under a
// vsys. Sabotage: pointing dynamicUserGroupParts at another pango resource
// shifts the xpath.
func TestDynamicUserGroupCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="dug1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUserGroupTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_dynamic_user_group_create",
		Arguments: map[string]any{"name": "dug1", "filter": "'x'"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "dynamic-user-group") {
		t.Fatalf("create must target the dynamic-user-group xpath: %s", joined)
	}
	if !strings.Contains(joined, "vsys") {
		t.Fatalf("firewall create must resolve to a vsys xpath: %s", joined)
	}
}

// TestDynamicUserGroupCreatePanoramaSharedXpath drives a registered Panorama
// create at the default (shared) scope and pins the set targets the shared
// dynamic-user-group node, not a vsys. Sabotage: nil-ing the shared branch of
// dynamicUserGroupParts makes this an error result.
func TestDynamicUserGroupCreatePanoramaSharedXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="dug1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUserGroupTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_dynamic_user_group_create",
		Arguments: map[string]any{"name": "dug1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "/shared/") {
		t.Fatalf("panorama default create must target the shared xpath: %s", joined)
	}
	if strings.Contains(joined, "/vsys/") {
		t.Fatalf("panorama create must not target a vsys xpath: %s", joined)
	}
}
