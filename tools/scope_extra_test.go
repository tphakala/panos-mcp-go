package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestProjectList pins the shared list-projection helper extracted from the
// three list handlers (#90): the case-insensitive name filter, offset/limit
// clamping, and the {total, offset, count, entries} envelope.
func TestProjectList(t *testing.T) {
	type item struct{ n string }
	entries := []*item{{"alpha"}, {"beta"}, {"gamma"}, {"also"}}
	name := func(i *item) string { return i.n }
	sum := func(i *item) any { return i.n }

	// "AL" matches "alpha" and "also" case-insensitively; total counts after the
	// filter, before clamping.
	m := projectList(entries, 50, 0, "AL", name, sum)
	if m[totalKey] != 2 {
		t.Fatalf("filter should keep 2 of 4, got total=%v", m[totalKey])
	}
	got, ok := m[entriesKey].([]any)
	if !ok || len(got) != 2 || got[0] != "alpha" || got[1] != "also" {
		t.Fatalf("filtered entries wrong: %v", m[entriesKey])
	}

	// Offset+limit clamp on the unfiltered set: total stays 4, one entry returned
	// starting at offset 1.
	m2 := projectList(entries, 1, 1, "", name, sum)
	if m2[totalKey] != 4 || m2[offsetKey] != 1 || m2[countKey] != 1 {
		t.Fatalf("clamp envelope wrong: %v", m2)
	}
	if e, ok := m2[entriesKey].([]any); !ok || len(e) != 1 || e[0] != "beta" {
		t.Fatalf("clamped window wrong: %v", m2[entriesKey])
	}
}

// TestDeviceProfileDeleteHappyPath drives a device-scoped delete to success
// through the registered handler and the fake (#90 coverage gap: the delete
// success path was never exercised, only its read-only-mode absence).
func TestDeviceProfileDeleteHappyPath(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_delete", Arguments: map[string]any{"name": "p"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete should succeed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "deleted") {
		t.Fatalf("expected a deleted confirmation: %s", textContent(t, res))
	}
}

// TestNetFamilyDeleteHappyPath is the net-scoped counterpart (#90 coverage gap).
func TestNetFamilyDeleteHappyPath(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDhcpTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dhcp_delete", Arguments: map[string]any{"name": "ethernet1/1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete should succeed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "deleted") {
		t.Fatalf("expected a deleted confirmation: %s", textContent(t, res))
	}
}
