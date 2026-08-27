package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/generic"
	srv4 "github.com/PaloAltoNetworks/pango/network/virtual_router/ipv4/staticroute"
	srv6 "github.com/PaloAltoNetworks/pango/network/virtual_router/ipv6/staticroute"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- build / summary ----------------------------------------------------------

// TestBuildStaticRouteV4 pins the scalar field mapping: destination, interface,
// admin_dist and metric each land in the matching Entry field. Sabotage: mapping
// in.Metric to e.AdminDist (or any cross-wire) turns this red.
func TestBuildStaticRouteV4(t *testing.T) {
	e, err := buildStaticRouteV4(StaticRouteInput{
		Name:        "r1",
		Destination: new("10.0.0.0/24"),
		Interface:   new("ethernet1/1"),
		AdminDist:   new(int64(15)),
		Metric:      new(int64(100)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Destination == nil || *e.Destination != "10.0.0.0/24" {
		t.Fatalf("destination not mapped: %+v", e.Destination)
	}
	if e.Interface == nil || *e.Interface != "ethernet1/1" {
		t.Fatalf("interface not mapped: %+v", e.Interface)
	}
	if e.AdminDist == nil || *e.AdminDist != 15 {
		t.Fatalf("admin_dist not mapped to AdminDist: %+v", e.AdminDist)
	}
	if e.Metric == nil || *e.Metric != 100 {
		t.Fatalf("metric not mapped to Metric: %+v", e.Metric)
	}
}

// TestBuildStaticRouteV4NexthopOneOf pins the nexthop one-of: providing
// nexthop_ip_address sets Nexthop.IpAddress and leaves the siblings nil;
// providing two nexthop_* fields is rejected. Sabotage: removing the
// sibling-nil (allocating siblings) fails the "siblings nil" assertion; removing
// the >1 count check fails the error assertion.
func TestBuildStaticRouteV4NexthopOneOf(t *testing.T) {
	e, err := buildStaticRouteV4(StaticRouteInput{Name: "r1", NexthopIpAddress: new("192.168.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	if e.Nexthop == nil || e.Nexthop.IpAddress == nil || *e.Nexthop.IpAddress != "192.168.1.1" {
		t.Fatalf("nexthop_ip_address must set Nexthop.IpAddress: %+v", e.Nexthop)
	}
	if e.Nexthop.NextVr != nil || e.Nexthop.Fqdn != nil || e.Nexthop.Discard != nil {
		t.Fatalf("the nexthop siblings must be nil: %+v", e.Nexthop)
	}

	if _, err := buildStaticRouteV4(StaticRouteInput{
		Name:             "r1",
		NexthopIpAddress: new("192.168.1.1"),
		NexthopNextVr:    new("vr2"),
	}); err == nil {
		t.Fatal("two nexthop_* fields must be rejected")
	}
}

// TestBuildStaticRouteV4NexthopDiscard pins that nexthop_discard=true maps to the
// discard branch and leaves the address/next-vr/fqdn siblings nil.
func TestBuildStaticRouteV4NexthopDiscard(t *testing.T) {
	e, err := buildStaticRouteV4(StaticRouteInput{Name: "r1", NexthopDiscard: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Nexthop == nil || e.Nexthop.Discard == nil {
		t.Fatalf("nexthop_discard must set Nexthop.Discard: %+v", e.Nexthop)
	}
	if e.Nexthop.IpAddress != nil || e.Nexthop.NextVr != nil || e.Nexthop.Fqdn != nil {
		t.Fatalf("discard must clear the other nexthop siblings: %+v", e.Nexthop)
	}
}

// --- wire-level create --------------------------------------------------------

// TestStaticRouteV4CreateFirewallXpath drives a registered firewall create and
// pins that the set reaches the static-route node under the parent VR. Sabotage:
// pointing staticRouteV4Parts at a different resource shifts the xpath.
func TestStaticRouteV4CreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="r1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_create",
		Arguments: map[string]any{"name": "r1", "virtual_router": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertSawSet(t, f, func(xp string) bool {
		// Require the slash-bounded "/ip/" segment and exclude ipv6: a bare
		// Contains(xp, "ip") also matches the ipv6 routing table, so it would not
		// catch a v4->v6 package mis-wire.
		return strings.Contains(xp, "static-route") && strings.Contains(xp, "routing-table") &&
			strings.Contains(xp, "/ip/") && !strings.Contains(xp, "ipv6") && strings.Contains(xp, "vr1")
	})
}

// TestStaticRouteV4CreatePanoramaTemplateXpath drives a Panorama create under a
// template and pins the template scope resolves in. Sabotage: dropping the
// template branch of staticRouteV4Parts drops the template segment.
func TestStaticRouteV4CreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="r1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_create",
		Arguments: map[string]any{"name": "r1", "virtual_router": "vr1", "template": "tmpl-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	assertSawSet(t, f, func(xp string) bool {
		return strings.Contains(xp, "static-route") && strings.Contains(xp, "template") && strings.Contains(xp, "tmpl-a")
	})
}

// --- net-scope gating ---------------------------------------------------------

func TestStaticRouteV4NetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterStaticRouteV4Tools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_static_route_list", Arguments: map[string]any{"virtual_router": "vr1"},
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
		RegisterStaticRouteV4Tools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_static_route_list", Arguments: map[string]any{"virtual_router": "vr1", "template": "tmpl-a"},
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
	t.Run("missing virtual_router errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterStaticRouteV4Tools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_static_route_list", Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("a list without a virtual_router must error")
		}
	})
}

// --- no-op update -------------------------------------------------------------

// TestStaticRouteV4NoOpUpdateNoWrite drives a registered update that changes
// nothing (name + virtual_router only) and asserts no config-write reaches the
// wire. Sabotage: having overlayStaticRouteV4 mutate the entry unconditionally
// produces a differing spec and a write.
func TestStaticRouteV4NoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="r1"><destination>10.0.0.0/24</destination></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV4Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_static_route_update", Arguments: map[string]any{"name": "r1", "virtual_router": "vr1"},
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

// TestOverlayStaticRouteV4PreservesDeferred pins that an update setting only one
// field leaves the deferred PathMonitor and RouteTable, the stored Bfd, and an
// existing Nexthop exactly as read. Bfd is only partly deferred now that
// bfd_profile is settable, so this covers the case where the caller does not
// provide it; TestStaticRouteV4BfdProfilePreservesMisc covers the case where
// they do. Sabotage: rebuilding the entry in overlayStaticRouteV4 drops them.
func TestOverlayStaticRouteV4PreservesDeferred(t *testing.T) {
	e := &srv4.Entry{
		Name:        "r1",
		Destination: new("10.0.0.0/24"),
		PathMonitor: &srv4.PathMonitor{Enable: new(true)},
		Bfd:         &srv4.Bfd{Profile: new("bfd-a")},
		RouteTable:  &srv4.RouteTable{Unicast: &srv4.RouteTableUnicast{}},
		Nexthop:     &srv4.Nexthop{IpAddress: new("192.168.1.1")},
	}
	if err := overlayStaticRouteV4(e, StaticRouteInput{Name: "r1", Metric: new(int64(50))}); err != nil {
		t.Fatal(err)
	}
	if e.Metric == nil || *e.Metric != 50 {
		t.Fatalf("provided metric must be applied: %+v", e.Metric)
	}
	if e.Destination == nil || *e.Destination != "10.0.0.0/24" {
		t.Fatalf("existing destination must be preserved: %+v", e.Destination)
	}
	if e.PathMonitor == nil || e.Bfd == nil || e.RouteTable == nil {
		t.Fatalf("deferred PathMonitor/Bfd/RouteTable must be preserved: %+v", e)
	}
	if e.Nexthop == nil || e.Nexthop.IpAddress == nil || *e.Nexthop.IpAddress != "192.168.1.1" {
		t.Fatalf("an untouched next hop must be preserved: %+v", e.Nexthop)
	}
}

// --- read-only gating ---------------------------------------------------------

func TestStaticRouteV4ReadOnlyGating(t *testing.T) {
	reads := []string{"panos_static_route_list", "panos_static_route_get"}
	writes := []string{"panos_static_route_create", "panos_static_route_update", "panos_static_route_delete"}
	assertReadOnlyGating(t, RegisterStaticRouteV4Tools, reads, writes)
}

// --- ipv6 family --------------------------------------------------------------

// TestBuildStaticRouteV6NexthopOneOf pins that ipv6 nexthop_ip_address maps to
// Nexthop.Ipv6Address (not a shared v4 field) and that nexthop_fqdn is rejected
// for ipv6.
func TestBuildStaticRouteV6NexthopOneOf(t *testing.T) {
	e, err := buildStaticRouteV6(StaticRouteInput{Name: "r1", NexthopIpAddress: new("2001:db8::1")})
	if err != nil {
		t.Fatal(err)
	}
	if e.Nexthop == nil || e.Nexthop.Ipv6Address == nil || *e.Nexthop.Ipv6Address != "2001:db8::1" {
		t.Fatalf("ipv6 nexthop_ip_address must set Nexthop.Ipv6Address: %+v", e.Nexthop)
	}
	if _, err := buildStaticRouteV6(StaticRouteInput{Name: "r1", NexthopFqdn: new("host.example")}); err == nil {
		t.Fatal("nexthop_fqdn must be rejected for ipv6 static routes")
	}
}

// TestStaticRouteV6CreateFirewallXpath proves the ipv6 family is wired to its own
// pango package: the set xpath carries the ipv6 routing-table segment, not ip.
// Sabotage: aliasing newStaticRouteV6Service to the v4 package shifts "ipv6" to
// "ip".
func TestStaticRouteV6CreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="r1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV6Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_static_route_v6_create",
		Arguments: map[string]any{"name": "r1", "virtual_router": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	assertSawSet(t, f, func(xp string) bool {
		return strings.Contains(xp, "static-route") && strings.Contains(xp, "ipv6")
	})
}

func TestStaticRouteV6ReadOnlyGating(t *testing.T) {
	reads := []string{"panos_static_route_v6_list", "panos_static_route_v6_get"}
	writes := []string{"panos_static_route_v6_create", "panos_static_route_v6_update", "panos_static_route_v6_delete"}
	assertReadOnlyGating(t, RegisterStaticRouteV6Tools, reads, writes)
}

// TestStaticRouteV6NoOpUpdateNoWrite drives a registered ipv6 update that changes
// nothing (name + virtual_router only) and asserts no config-write reaches the
// wire. Sabotage: having overlayStaticRouteV6 mutate the entry unconditionally
// produces a differing spec and a write.
func TestStaticRouteV6NoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="r1"><destination>2001:db8::/64</destination></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterStaticRouteV6Tools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_static_route_v6_update", Arguments: map[string]any{"name": "r1", "virtual_router": "vr1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// TestOverlayStaticRouteV6PreservesDeferred pins that an ipv6 update setting only
// one field leaves the deferred PathMonitor, Bfd, RouteTable and an existing
// Nexthop exactly as read; see TestOverlayStaticRouteV4PreservesDeferred.
// Sabotage: rebuilding the entry in overlayStaticRouteV6 drops them.
func TestOverlayStaticRouteV6PreservesDeferred(t *testing.T) {
	e := &srv6.Entry{
		Name:        "r1",
		Destination: new("2001:db8::/64"),
		PathMonitor: &srv6.PathMonitor{Enable: new(true)},
		Bfd:         &srv6.Bfd{Profile: new("bfd-a")},
		RouteTable:  &srv6.RouteTable{Unicast: &srv6.RouteTableUnicast{}},
		Nexthop:     &srv6.Nexthop{Ipv6Address: new("2001:db8::1")},
	}
	if err := overlayStaticRouteV6(e, StaticRouteInput{Name: "r1", Metric: new(int64(50))}); err != nil {
		t.Fatal(err)
	}
	if e.Metric == nil || *e.Metric != 50 {
		t.Fatalf("provided metric must be applied: %+v", e.Metric)
	}
	if e.Destination == nil || *e.Destination != "2001:db8::/64" {
		t.Fatalf("existing destination must be preserved: %+v", e.Destination)
	}
	if e.PathMonitor == nil || e.Bfd == nil || e.RouteTable == nil {
		t.Fatalf("deferred PathMonitor/Bfd/RouteTable must be preserved: %+v", e)
	}
	if e.Nexthop == nil || e.Nexthop.Ipv6Address == nil || *e.Nexthop.Ipv6Address != "2001:db8::1" {
		t.Fatalf("an untouched next hop must be preserved: %+v", e.Nexthop)
	}
}

// assertSawSet fails unless a config "set" request was recorded whose xpath
// satisfies want. Shared by the parent-scoped create xpath tests.
func assertSawSet(t *testing.T, f *fakeAPI, want func(xpath string) bool) {
	t.Helper()
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") != "set" {
			continue
		}
		sawSet = true
		if xp := req.Get("xpath"); !want(xp) {
			t.Fatalf("set xpath did not match expectation: %s", xp)
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// --- BFD profile --------------------------------------------------------------

// TestStaticRouteV4BfdProfile pins that the BFD profile name is applied on both
// families. This is what makes panos_bfd_profile_create reachable from a route
// rather than an object nothing in this server references.
//
// Sabotage: delete the setPtr(&e.Bfd.Profile, in.BfdProfile) line in
// applyStaticRouteV4 (or applyStaticRouteV6) and the matching subtest goes red.
func TestStaticRouteV4BfdProfile(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		e, err := buildStaticRouteV4(StaticRouteInput{Name: "r1", BfdProfile: new("bfd-a")})
		if err != nil {
			t.Fatal(err)
		}
		if e.Bfd == nil || strVal(e.Bfd.Profile) != "bfd-a" {
			t.Fatalf("bfd_profile must be applied: %+v", e.Bfd)
		}
	})
	t.Run("ipv6", func(t *testing.T) {
		e, err := buildStaticRouteV6(StaticRouteInput{Name: "r1", BfdProfile: new("bfd-a")})
		if err != nil {
			t.Fatal(err)
		}
		if e.Bfd == nil || strVal(e.Bfd.Profile) != "bfd-a" {
			t.Fatalf("bfd_profile must be applied: %+v", e.Bfd)
		}
	})
}

// TestStaticRouteV4BfdProfilePreservesMisc pins that setting the profile overlays
// the stored BFD block rather than replacing it, so XML this server does not
// model survives alongside the field it does set.
//
// Sabotage: replace the in-place overlay in applyStaticRouteV4 with
// e.Bfd = &srv4.Bfd{Profile: in.BfdProfile} and this goes red.
func TestStaticRouteV4BfdProfilePreservesMisc(t *testing.T) {
	e := &srv4.Entry{Name: "r1", Bfd: &srv4.Bfd{Profile: new("bfd-old"), Misc: []generic.Xml{{}}}}
	if err := overlayStaticRouteV4(e, StaticRouteInput{Name: "r1", BfdProfile: new("bfd-new")}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Bfd.Profile) != "bfd-new" {
		t.Fatalf("bfd_profile must be updated: %q", strVal(e.Bfd.Profile))
	}
	if len(e.Bfd.Misc) != 1 {
		t.Fatalf("unmodeled XML under bfd must survive the update: %+v", e.Bfd)
	}
}

// TestStaticRouteBfdProfileOmittedPreserved pins that an update which does not
// mention bfd_profile leaves the stored profile alone, so an unrelated edit
// cannot detach BFD from a route.
//
// Sabotage: drop the "if in.BfdProfile != nil" guard in applyStaticRouteV4 so
// the overlay runs unconditionally, and this goes red.
func TestStaticRouteBfdProfileOmittedPreserved(t *testing.T) {
	e := &srv4.Entry{Name: "r1", Bfd: &srv4.Bfd{Profile: new("bfd-a")}}
	if err := overlayStaticRouteV4(e, StaticRouteInput{Name: "r1", Metric: new(int64(10))}); err != nil {
		t.Fatal(err)
	}
	if e.Bfd == nil || strVal(e.Bfd.Profile) != "bfd-a" {
		t.Fatalf("an omitted bfd_profile must leave the stored profile untouched: %+v", e.Bfd)
	}
}

// TestStaticRouteBfdProfileNotAddedWhenAbsent pins that a route with no BFD block
// does not gain an empty one just because some other field was updated.
//
// Sabotage: allocate e.Bfd outside the "if in.BfdProfile != nil" guard in
// applyStaticRouteV4 and this goes red.
func TestStaticRouteBfdProfileNotAddedWhenAbsent(t *testing.T) {
	e := &srv4.Entry{Name: "r1"}
	if err := overlayStaticRouteV4(e, StaticRouteInput{Name: "r1", Metric: new(int64(10))}); err != nil {
		t.Fatal(err)
	}
	if e.Bfd != nil {
		t.Fatalf("an update that does not mention bfd_profile must not create a bfd block: %+v", e.Bfd)
	}
}
