package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/virtual_router"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Virtual router (network/virtual-router)
// ---------------------------------------------------------------------------
//
// A virtual router lives at the same network scope as the site-to-site VPN
// resources: firewall-local (Ngfw), or on Panorama under a template or
// template-stack. pango also models template/template-stack/vsys variants, but
// this server exposes only the three standard net-scope parts, mirroring the
// VPN resources. The router's routing protocol subtree (BGP, OSPF, OSPFv3,
// RIP), ECMP and multicast configuration are not managed here: they are
// preserved verbatim across an update through pango's Misc round-trip, so an
// overlay must apply only the caller-provided fields and never rebuild the
// entry.

func newVirtualRouterService(d *Deps) nameFixAdapter[virtual_router.Location, virtual_router.Entry] {
	return nameFixAdapter[virtual_router.Location, virtual_router.Entry]{
		svc:    virtual_router.NewService(d.Client),
		client: d.Client,
		name:   func(e *virtual_router.Entry) string { return e.Name },
	}
}

func virtualRouterParts() netScopeParts[virtual_router.Location] {
	return netScopeParts[virtual_router.Location]{
		ngfw: func() virtual_router.Location {
			return virtual_router.Location{Ngfw: &virtual_router.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) virtual_router.Location {
			return virtual_router.Location{Template: &virtual_router.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) virtual_router.Location {
			return virtual_router.Location{TemplateStack: &virtual_router.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// VirtualRouterInput is the input for the virtual router create and update
// tools. interfaces is an ordered list of the member interfaces bound to the
// router; it is replaced fully when provided. The nine administrative distances
// map onto the router's admin-dists node; each is optional and omitting all of
// them leaves that node untouched. The BGP/OSPF/OSPFv3/RIP routing protocol
// configuration, ECMP and multicast are not managed by this server and survive
// an update unchanged.
type VirtualRouterInput struct {
	NetScopeInput
	Name       string   `json:"name" jsonschema:"Virtual router name"`
	Interfaces []string `json:"interfaces,omitzero" jsonschema:"Member interfaces bound to the router (replaces the current list fully when provided)"`

	AdminDistStatic     *int64 `json:"admin_dist_static,omitzero" jsonschema:"Administrative distance for static routes"`
	AdminDistStaticIpv6 *int64 `json:"admin_dist_static_ipv6,omitzero" jsonschema:"Administrative distance for static IPv6 routes"`
	AdminDistOspfInt    *int64 `json:"admin_dist_ospf_int,omitzero" jsonschema:"Administrative distance for OSPF intra-area routes"`
	AdminDistOspfExt    *int64 `json:"admin_dist_ospf_ext,omitzero" jsonschema:"Administrative distance for OSPF inter/external routes"`
	AdminDistOspfv3Int  *int64 `json:"admin_dist_ospfv3_int,omitzero" jsonschema:"Administrative distance for OSPFv3 intra-area routes"`
	AdminDistOspfv3Ext  *int64 `json:"admin_dist_ospfv3_ext,omitzero" jsonschema:"Administrative distance for OSPFv3 inter/external routes"`
	AdminDistIbgp       *int64 `json:"admin_dist_ibgp,omitzero" jsonschema:"Administrative distance for iBGP routes"`
	AdminDistEbgp       *int64 `json:"admin_dist_ebgp,omitzero" jsonschema:"Administrative distance for eBGP routes"`
	AdminDistRip        *int64 `json:"admin_dist_rip,omitzero" jsonschema:"Administrative distance for RIP routes"`
}

// interfacesKey is the shared summary key for a bound-interface list, pulled
// into a constant so the same literal is not repeated across summaries (goconst).
const interfacesKey = "interfaces"

// applyVirtualRouterAdminDists overlays the nine caller-provided administrative
// distances onto the router's admin-dists node. It allocates AdminDists only
// when at least one distance is provided, so an update touching no distance
// leaves an existing (or absent) node exactly as it was. Each field is applied
// with setPtr, preserving any sibling distance the caller omits.
func applyVirtualRouterAdminDists(e *virtual_router.Entry, in *VirtualRouterInput) {
	anyDist := in.AdminDistStatic != nil || in.AdminDistStaticIpv6 != nil ||
		in.AdminDistOspfInt != nil || in.AdminDistOspfExt != nil ||
		in.AdminDistOspfv3Int != nil || in.AdminDistOspfv3Ext != nil ||
		in.AdminDistIbgp != nil || in.AdminDistEbgp != nil || in.AdminDistRip != nil
	if !anyDist {
		return
	}
	if e.AdminDists == nil {
		e.AdminDists = &virtual_router.AdminDists{}
	}
	setPtr(&e.AdminDists.Static, in.AdminDistStatic)
	setPtr(&e.AdminDists.StaticIpv6, in.AdminDistStaticIpv6)
	setPtr(&e.AdminDists.OspfInt, in.AdminDistOspfInt)
	setPtr(&e.AdminDists.OspfExt, in.AdminDistOspfExt)
	setPtr(&e.AdminDists.Ospfv3Int, in.AdminDistOspfv3Int)
	setPtr(&e.AdminDists.Ospfv3Ext, in.AdminDistOspfv3Ext)
	setPtr(&e.AdminDists.Ibgp, in.AdminDistIbgp)
	setPtr(&e.AdminDists.Ebgp, in.AdminDistEbgp)
	setPtr(&e.AdminDists.Rip, in.AdminDistRip)
}

// applyVirtualRouter overlays the managed fields (bound interfaces and the
// administrative distances) onto e, applying only what the caller provided. It
// is shared by build and overlay so create and update agree on the mapping. It
// never rebuilds e, so the unmanaged routing protocol, ECMP and multicast
// subtrees carried in Misc survive an update.
func applyVirtualRouter(e *virtual_router.Entry, in *VirtualRouterInput) {
	// A non-nil interfaces list replaces fully; a nil (omitted) list preserves
	// the current binding. An explicit empty list clears the binding.
	if in.Interfaces != nil {
		e.Interface = in.Interfaces
	}
	applyVirtualRouterAdminDists(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildVirtualRouter(in VirtualRouterInput) (*virtual_router.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &virtual_router.Entry{Name: in.Name}
	applyVirtualRouter(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayVirtualRouter(e *virtual_router.Entry, in VirtualRouterInput) error {
	applyVirtualRouter(e, &in)
	return nil
}

func virtualRouterSummary(e *virtual_router.Entry) any {
	m := map[string]any{
		tagNameKey:    e.Name,
		interfacesKey: strList(e.Interface),
	}
	if e.AdminDists != nil {
		putInt(m, "admin_dist_static", e.AdminDists.Static)
		putInt(m, "admin_dist_static_ipv6", e.AdminDists.StaticIpv6)
		putInt(m, "admin_dist_ospf_int", e.AdminDists.OspfInt)
		putInt(m, "admin_dist_ospf_ext", e.AdminDists.OspfExt)
		putInt(m, "admin_dist_ospfv3_int", e.AdminDists.Ospfv3Int)
		putInt(m, "admin_dist_ospfv3_ext", e.AdminDists.Ospfv3Ext)
		putInt(m, "admin_dist_ibgp", e.AdminDists.Ibgp)
		putInt(m, "admin_dist_ebgp", e.AdminDists.Ebgp)
		putInt(m, "admin_dist_rip", e.AdminDists.Rip)
	}
	return m
}

// RegisterVirtualRouterTools registers the virtual router CRUD tools. They are
// net-scoped: firewall-local or, on Panorama, under a template or
// template-stack. Mutating tools are skipped in read-only mode.
func RegisterVirtualRouterTools(s *mcp.Server, d *Deps) {
	svc := newVirtualRouterService(d)
	parts := virtualRouterParts()
	scope := func(in VirtualRouterInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_router_list",
		Description: "List virtual routers at a network scope. Firewall: the firewall-local scope; Panorama: a template or template_stack is required (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("List virtual routers"),
	}, netListHandler(d, "panos_virtual_router_list", svc, parts, svc.name, virtualRouterSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_router_get",
		Description: "Get one virtual router (bound interfaces and administrative distances). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get virtual router"),
	}, netGetHandler(d, "panos_virtual_router_get", svc, parts, virtualRouterSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_router_create",
		Description: "Create a virtual router in the candidate config. Only the name is required; interfaces and administrative distances are optional. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create virtual router"),
	}, netCreateHandler(d, "panos_virtual_router_create", svc, parts, scope, buildVirtualRouter, virtualRouterSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_router_update",
		Description: "Update a virtual router: read-modify-write, only provided fields change. A provided interfaces list replaces the current binding fully. BGP, OSPF, OSPFv3, RIP, ECMP and multicast configuration are preserved and not managed here. Run panos_commit to apply.",
		Annotations: updateTool("Update virtual router"),
	}, netUpdateHandler(d, "panos_virtual_router_update", svc, parts, scope,
		func(in VirtualRouterInput) string { return in.Name }, overlayVirtualRouter, virtualRouterSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_router_delete",
		Description: "Delete a virtual router from the candidate config. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete virtual router"),
	}, netDeleteHandler(d, "panos_virtual_router_delete", svc, parts))
}
