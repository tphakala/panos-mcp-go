package tools

import (
	"errors"

	srv4 "github.com/PaloAltoNetworks/pango/network/virtual_router/ipv4/staticroute"
	srv6 "github.com/PaloAltoNetworks/pango/network/virtual_router/ipv6/staticroute"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Static routes (network/virtual-router/routing-table/{ip|ipv6}/static-route)
// ---------------------------------------------------------------------------
//
// A static route lives under a parent virtual-router, addressed by a
// two-component xpath (the VR entry, then the route entry). Both families are
// net-scoped (firewall-local, or on Panorama under a template or
// template-stack) and share the parent-scoped adapter in parent_scope.go, with
// the parent virtual-router name carried in parentScopeLoc.parent.
//
// This server manages the route's destination, egress interface, administrative
// distance, metric and next hop. The path-monitor, BFD and route-table subtrees
// are TYPED pango fields this server does not set; they are not stored in Misc,
// but they survive an update because the update path is a read-modify-write that
// re-marshals the full entry read back from the device, and the overlay never
// touches them. Truly unmodeled XML rides in Entry.Misc and survives the same
// round-trip.
//
// Nexthop is a one-of: at most one of nexthop_ip_address / nexthop_next_vr /
// nexthop_fqdn / nexthop_discard may be provided. Providing one sets that branch
// and clears the siblings; providing none leaves the existing Nexthop untouched.
// The ipv6 family has no FQDN next hop, so nexthop_fqdn is rejected there, and
// nexthop_ip_address maps to the ipv6 next-hop address.

// StaticRouteInput is the create/update input, shared by the ipv4 and ipv6
// static route families.
type StaticRouteInput struct {
	NetScopeInput
	VirtualRouter string  `json:"virtual_router" jsonschema:"Parent virtual router name"`
	Name          string  `json:"name" jsonschema:"Static route name"`
	Destination   *string `json:"destination,omitzero" jsonschema:"Destination prefix (CIDR)"`
	Interface     *string `json:"interface,omitzero" jsonschema:"Egress interface"`
	AdminDist     *int64  `json:"admin_dist,omitzero" jsonschema:"Administrative distance"`
	Metric        *int64  `json:"metric,omitzero" jsonschema:"Route metric"`
	// nexthop one-of (at most one; providing one clears the siblings).
	NexthopIpAddress *string `json:"nexthop_ip_address,omitzero" jsonschema:"Next hop IP address (mutually exclusive with the other nexthop_* fields)"`
	NexthopNextVr    *string `json:"nexthop_next_vr,omitzero" jsonschema:"Next hop next-vr name (mutually exclusive)"`
	NexthopFqdn      *string `json:"nexthop_fqdn,omitzero" jsonschema:"Next hop FQDN (mutually exclusive; ipv4 only)"`
	NexthopDiscard   *bool   `json:"nexthop_discard,omitzero" jsonschema:"Discard traffic (mutually exclusive)"`
}

// StaticRouteListInput is the list input for both static route families.
type StaticRouteListInput struct {
	NetScopeInput
	VirtualRouter string `json:"virtual_router" jsonschema:"Parent virtual router name"`
	Limit         int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset        int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter        string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// StaticRouteNameInput is the get/delete input for both static route families.
type StaticRouteNameInput struct {
	NetScopeInput
	VirtualRouter string `json:"virtual_router" jsonschema:"Parent virtual router name"`
	Name          string `json:"name" jsonschema:"Static route name"`
}

// nexthopCount reports how many of the four nexthop one-of fields the caller
// provided, so the apply functions can reject more than one.
func (in *StaticRouteInput) nexthopCount() int {
	n := 0
	if in.NexthopIpAddress != nil {
		n++
	}
	if in.NexthopNextVr != nil {
		n++
	}
	if in.NexthopFqdn != nil {
		n++
	}
	if in.NexthopDiscard != nil {
		n++
	}
	return n
}

// ---------------------------------------------------------------------------
// Family A1: ipv4 static route
// ---------------------------------------------------------------------------

func newStaticRouteV4Service(d *Deps) parentFixAdapter[srv4.Location, srv4.Entry] {
	return parentFixAdapter[srv4.Location, srv4.Entry]{
		svc:    srv4.NewService(d.Client),
		client: d.Client,
		name:   func(e *srv4.Entry) string { return e.Name },
	}
}

func staticRouteV4Parts() netScopeParts[srv4.Location] {
	return netScopeParts[srv4.Location]{
		ngfw: func() srv4.Location {
			return srv4.Location{Ngfw: &srv4.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) srv4.Location {
			return srv4.Location{Template: &srv4.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) srv4.Location {
			return srv4.Location{TemplateStack: &srv4.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// applyStaticRouteV4Nexthop applies the nexthop one-of. It rejects more than one
// provided branch; sets the single provided branch with its siblings nil; and
// leaves e.Nexthop untouched when none is provided (preserve on update).
func applyStaticRouteV4Nexthop(e *srv4.Entry, in *StaticRouteInput) error {
	switch in.nexthopCount() {
	case 0:
		return nil
	case 1:
		switch {
		case in.NexthopIpAddress != nil:
			e.Nexthop = &srv4.Nexthop{IpAddress: in.NexthopIpAddress}
		case in.NexthopNextVr != nil:
			e.Nexthop = &srv4.Nexthop{NextVr: in.NexthopNextVr}
		case in.NexthopFqdn != nil:
			e.Nexthop = &srv4.Nexthop{Fqdn: in.NexthopFqdn}
		case in.NexthopDiscard != nil && *in.NexthopDiscard:
			e.Nexthop = &srv4.Nexthop{Discard: &srv4.NexthopDiscard{}}
		default:
			// nexthop_discard was provided as false: clear the next hop.
			e.Nexthop = &srv4.Nexthop{}
		}
		return nil
	default:
		return errors.New("at most one of nexthop_ip_address, nexthop_next_vr, nexthop_fqdn, nexthop_discard may be set")
	}
}

// applyStaticRouteV4 overlays the managed fields onto e, applying only what the
// caller provided. Shared by build and overlay; it never rebuilds e, so the
// deferred path-monitor, BFD and route-table subtrees survive an update.
func applyStaticRouteV4(e *srv4.Entry, in *StaticRouteInput) error {
	setPtr(&e.Destination, in.Destination)
	setPtr(&e.Interface, in.Interface)
	setPtr(&e.AdminDist, in.AdminDist)
	setPtr(&e.Metric, in.Metric)
	return applyStaticRouteV4Nexthop(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildStaticRouteV4(in StaticRouteInput) (*srv4.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &srv4.Entry{Name: in.Name}
	if err := applyStaticRouteV4(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayStaticRouteV4(e *srv4.Entry, in StaticRouteInput) error {
	return applyStaticRouteV4(e, &in)
}

func staticRouteV4Summary(e *srv4.Entry) any {
	m := map[string]any{
		tagNameKey:     e.Name,
		destinationKey: strVal(e.Destination),
		interfaceKey:   strVal(e.Interface),
	}
	putInt(m, "admin_dist", e.AdminDist)
	putInt(m, "metric", e.Metric)
	if e.Nexthop != nil {
		switch {
		case e.Nexthop.IpAddress != nil:
			m["nexthop"] = map[string]any{typeKey: "ip-address", valueKey: *e.Nexthop.IpAddress}
		case e.Nexthop.NextVr != nil:
			m["nexthop"] = map[string]any{typeKey: "next-vr", valueKey: *e.Nexthop.NextVr}
		case e.Nexthop.Fqdn != nil:
			m["nexthop"] = map[string]any{typeKey: "fqdn", valueKey: *e.Nexthop.Fqdn}
		case e.Nexthop.Discard != nil:
			m["nexthop"] = map[string]any{typeKey: "discard"}
		}
	}
	return m
}

// RegisterStaticRouteV4Tools registers the ipv4 static route CRUD tools. They
// are net-scoped and parent-scoped (a virtual_router is required). Mutating
// tools are skipped entirely in read-only mode.
func RegisterStaticRouteV4Tools(s *mcp.Server, d *Deps) {
	svc := newStaticRouteV4Service(d)
	parts := staticRouteV4Parts()
	listScope := func(in StaticRouteListInput) NetScopeInput { return in.NetScopeInput }
	listParent := func(in StaticRouteListInput) string { return in.VirtualRouter }
	nameScope := func(in StaticRouteNameInput) NetScopeInput { return in.NetScopeInput }
	nameParent := func(in StaticRouteNameInput) string { return in.VirtualRouter }
	scope := func(in StaticRouteInput) NetScopeInput { return in.NetScopeInput }
	parent := func(in StaticRouteInput) string { return in.VirtualRouter }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_list",
		Description: "List IPv4 static routes under a virtual router. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List IPv4 static routes"),
	}, parentListHandler(d, "panos_static_route_list", svc, parts, listScope, listParent,
		func(in StaticRouteListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		svc.name, staticRouteV4Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_get",
		Description: "Get one IPv4 static route (destination, interface, admin distance, metric, next hop). Read-only.",
		Annotations: readOnlyTool("Get IPv4 static route"),
	}, parentGetHandler(d, "panos_static_route_get", svc, parts, nameScope, nameParent,
		func(in StaticRouteNameInput) string { return in.Name }, staticRouteV4Summary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_create",
		Description: "Create an IPv4 static route under a virtual router. name and virtual_router are required; the next hop is a one-of (ip_address, next_vr, fqdn, or discard). Run panos_commit to apply.",
		Annotations: createTool("Create IPv4 static route"),
	}, parentCreateHandler(d, "panos_static_route_create", svc, parts, scope, parent, buildStaticRouteV4, staticRouteV4Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_update",
		Description: "Update an IPv4 static route: read-modify-write, only provided fields change. Providing a next hop replaces it; path-monitor, BFD and route-table settings are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update IPv4 static route"),
	}, parentUpdateHandler(d, "panos_static_route_update", svc, parts, scope, parent,
		func(in StaticRouteInput) string { return in.Name }, overlayStaticRouteV4, staticRouteV4Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_delete",
		Description: "Delete an IPv4 static route from the candidate config. name and virtual_router are required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IPv4 static route"),
	}, parentDeleteHandler(d, "panos_static_route_delete", svc, parts, nameScope, nameParent,
		func(in StaticRouteNameInput) string { return in.Name }))
}

// ---------------------------------------------------------------------------
// Family A2: ipv6 static route
// ---------------------------------------------------------------------------

func newStaticRouteV6Service(d *Deps) parentFixAdapter[srv6.Location, srv6.Entry] {
	return parentFixAdapter[srv6.Location, srv6.Entry]{
		svc:    srv6.NewService(d.Client),
		client: d.Client,
		name:   func(e *srv6.Entry) string { return e.Name },
	}
}

func staticRouteV6Parts() netScopeParts[srv6.Location] {
	return netScopeParts[srv6.Location]{
		ngfw: func() srv6.Location {
			return srv6.Location{Ngfw: &srv6.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) srv6.Location {
			return srv6.Location{Template: &srv6.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) srv6.Location {
			return srv6.Location{TemplateStack: &srv6.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// applyStaticRouteV6Nexthop applies the nexthop one-of for ipv6. The ipv6
// next-hop has no FQDN form, so nexthop_fqdn is rejected; nexthop_ip_address
// maps to the ipv6 next-hop address (Nexthop.Ipv6Address).
func applyStaticRouteV6Nexthop(e *srv6.Entry, in *StaticRouteInput) error {
	if in.NexthopFqdn != nil {
		return errors.New("nexthop_fqdn is not supported for IPv6 static routes")
	}
	switch in.nexthopCount() {
	case 0:
		return nil
	case 1:
		switch {
		case in.NexthopIpAddress != nil:
			e.Nexthop = &srv6.Nexthop{Ipv6Address: in.NexthopIpAddress}
		case in.NexthopNextVr != nil:
			e.Nexthop = &srv6.Nexthop{NextVr: in.NexthopNextVr}
		case in.NexthopDiscard != nil && *in.NexthopDiscard:
			e.Nexthop = &srv6.Nexthop{Discard: &srv6.NexthopDiscard{}}
		default:
			// nexthop_discard was provided as false: clear the next hop.
			e.Nexthop = &srv6.Nexthop{}
		}
		return nil
	default:
		return errors.New("at most one of nexthop_ip_address, nexthop_next_vr, nexthop_discard may be set")
	}
}

// applyStaticRouteV6 overlays the managed fields onto e; see applyStaticRouteV4.
func applyStaticRouteV6(e *srv6.Entry, in *StaticRouteInput) error {
	setPtr(&e.Destination, in.Destination)
	setPtr(&e.Interface, in.Interface)
	setPtr(&e.AdminDist, in.AdminDist)
	setPtr(&e.Metric, in.Metric)
	return applyStaticRouteV6Nexthop(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildStaticRouteV6(in StaticRouteInput) (*srv6.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &srv6.Entry{Name: in.Name}
	if err := applyStaticRouteV6(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayStaticRouteV6(e *srv6.Entry, in StaticRouteInput) error {
	return applyStaticRouteV6(e, &in)
}

func staticRouteV6Summary(e *srv6.Entry) any {
	m := map[string]any{
		tagNameKey:     e.Name,
		destinationKey: strVal(e.Destination),
		interfaceKey:   strVal(e.Interface),
	}
	putInt(m, "admin_dist", e.AdminDist)
	putInt(m, "metric", e.Metric)
	if e.Nexthop != nil {
		switch {
		case e.Nexthop.Ipv6Address != nil:
			m["nexthop"] = map[string]any{typeKey: "ipv6-address", valueKey: *e.Nexthop.Ipv6Address}
		case e.Nexthop.NextVr != nil:
			m["nexthop"] = map[string]any{typeKey: "next-vr", valueKey: *e.Nexthop.NextVr}
		case e.Nexthop.Discard != nil:
			m["nexthop"] = map[string]any{typeKey: "discard"}
		}
	}
	return m
}

// RegisterStaticRouteV6Tools registers the ipv6 static route CRUD tools; see
// RegisterStaticRouteV4Tools.
func RegisterStaticRouteV6Tools(s *mcp.Server, d *Deps) {
	svc := newStaticRouteV6Service(d)
	parts := staticRouteV6Parts()
	listScope := func(in StaticRouteListInput) NetScopeInput { return in.NetScopeInput }
	listParent := func(in StaticRouteListInput) string { return in.VirtualRouter }
	nameScope := func(in StaticRouteNameInput) NetScopeInput { return in.NetScopeInput }
	nameParent := func(in StaticRouteNameInput) string { return in.VirtualRouter }
	scope := func(in StaticRouteInput) NetScopeInput { return in.NetScopeInput }
	parent := func(in StaticRouteInput) string { return in.VirtualRouter }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_v6_list",
		Description: "List IPv6 static routes under a virtual router. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List IPv6 static routes"),
	}, parentListHandler(d, "panos_static_route_v6_list", svc, parts, listScope, listParent,
		func(in StaticRouteListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		svc.name, staticRouteV6Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_v6_get",
		Description: "Get one IPv6 static route (destination, interface, admin distance, metric, next hop). Read-only.",
		Annotations: readOnlyTool("Get IPv6 static route"),
	}, parentGetHandler(d, "panos_static_route_v6_get", svc, parts, nameScope, nameParent,
		func(in StaticRouteNameInput) string { return in.Name }, staticRouteV6Summary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_v6_create",
		Description: "Create an IPv6 static route under a virtual router. name and virtual_router are required; the next hop is a one-of (ip_address, next_vr, or discard). Run panos_commit to apply.",
		Annotations: createTool("Create IPv6 static route"),
	}, parentCreateHandler(d, "panos_static_route_v6_create", svc, parts, scope, parent, buildStaticRouteV6, staticRouteV6Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_v6_update",
		Description: "Update an IPv6 static route: read-modify-write, only provided fields change. Providing a next hop replaces it; path-monitor, BFD and route-table settings are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update IPv6 static route"),
	}, parentUpdateHandler(d, "panos_static_route_v6_update", svc, parts, scope, parent,
		func(in StaticRouteInput) string { return in.Name }, overlayStaticRouteV6, staticRouteV6Summary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_static_route_v6_delete",
		Description: "Delete an IPv6 static route from the candidate config. name and virtual_router are required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IPv6 static route"),
	}, parentDeleteHandler(d, "panos_static_route_v6_delete", svc, parts, nameScope, nameParent,
		func(in StaticRouteNameInput) string { return in.Name }))
}
