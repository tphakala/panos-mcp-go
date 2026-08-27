package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestVirtualRouterDeleteHappyPath drives the net-scoped virtual router delete
// tool through a registered server on a firewall, proving that a valid delete
// resolves scope, issues a config delete reaching svc.Delete, records a delete
// request whose xpath carries the entry name, and returns a success result.
func TestVirtualRouterDeleteHappyPath(t *testing.T) {
	// pango routes delete operations through multi-config requests containing
	// <delete xpath="..." /> elements.
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
		fakeRoute{Match: configAction("delete"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterVirtualRouterTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_virtual_router_delete",
		Arguments: map[string]any{"name": "vr-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	var sawDelete bool
	for _, req := range f.Requests() {
		if req.Get("action") == "delete" && strings.Contains(req.Get("xpath"), "vr-test") {
			sawDelete = true
			break
		}
		if req.Get("action") == "multi-config" && strings.Contains(req.Get("element"), "<delete") && strings.Contains(req.Get("element"), "vr-test") {
			sawDelete = true
			break
		}
	}
	if !sawDelete {
		t.Fatal("no config delete recorded")
	}
}

// TestLdapProfileDeleteHappyPath drives the device-scoped LDAP profile delete
// tool through a registered server on a firewall, proving that a valid delete
// resolves scope, issues a config delete reaching svc.Delete, records a delete
// request whose xpath carries the entry name, and returns a success result.
func TestLdapProfileDeleteHappyPath(t *testing.T) {
	// pango routes delete operations through multi-config requests containing
	// <delete xpath="..." /> elements.
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
		fakeRoute{Match: configAction("delete"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_ldap_profile_delete",
		Arguments: map[string]any{"name": "ldap-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	var sawDelete bool
	for _, req := range f.Requests() {
		if req.Get("action") == "delete" && strings.Contains(req.Get("xpath"), "ldap-test") {
			sawDelete = true
			break
		}
		if req.Get("action") == "multi-config" && strings.Contains(req.Get("element"), "<delete") && strings.Contains(req.Get("element"), "ldap-test") {
			sawDelete = true
			break
		}
	}
	if !sawDelete {
		t.Fatal("no config delete recorded")
	}
}
