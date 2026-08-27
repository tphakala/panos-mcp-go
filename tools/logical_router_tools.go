package tools

import (
	"errors"

	logical_router "github.com/PaloAltoNetworks/pango/network/logical_router"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Logical router (network/logical_router)
// ---------------------------------------------------------------------------
// The advanced routing engine's logical router. Its configuration lives almost
// entirely in per-VRF subtrees (interfaces, BGP, OSPF, static routes, and so
// on), which this server does not model. Name is the only top-level scalar and
// it is the XML key, so there is no in-place field to update: the tools cover
// create (an empty shell), list, get and delete, and the per-VRF configuration
// is preserved and managed elsewhere. It is net-scoped: firewall-local or, on
// Panorama, under a template or template-stack.

func newLogicalRouterService(d *Deps) nameFixAdapter[logical_router.Location, logical_router.Entry] {
	return nameFixAdapter[logical_router.Location, logical_router.Entry]{
		svc:    logical_router.NewService(d.Client),
		client: d.Client,
		name:   func(e *logical_router.Entry) string { return e.Name },
	}
}

func logicalRouterParts() netScopeParts[logical_router.Location] {
	return netScopeParts[logical_router.Location]{
		ngfw: func() logical_router.Location {
			return logical_router.Location{Ngfw: &logical_router.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) logical_router.Location {
			return logical_router.Location{Template: &logical_router.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) logical_router.Location {
			return logical_router.Location{TemplateStack: &logical_router.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// LogicalRouterInput is the input for the logical router create tool. Only the
// name is meaningful: the per-VRF routing configuration is not modeled here.
type LogicalRouterInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Logical router name"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLogicalRouter(in LogicalRouterInput) (*logical_router.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	return &logical_router.Entry{Name: in.Name}, nil
}

func logicalRouterSummary(e *logical_router.Entry) any {
	// vrf_count reports how many VRFs the router carries without unpacking the
	// unmanaged per-VRF subtree.
	return map[string]any{tagNameKey: e.Name, "vrf_count": len(e.Vrf)}
}

// RegisterLogicalRouterTools registers the logical router tools. There is no
// update tool: Name is the only scalar and it is the entry key, so an update
// would be a no-op. Mutating tools are skipped entirely in read-only mode.
func RegisterLogicalRouterTools(s *mcp.Server, d *Deps) {
	svc := newLogicalRouterService(d)
	parts := logicalRouterParts()
	scope := func(in LogicalRouterInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_logical_router_list",
		Description: "List logical routers at a network scope. Firewall: the firewall-local scope; Panorama: a template or template_stack is required (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("List logical routers"),
	}, netListHandler(d, "panos_logical_router_list", svc, parts, svc.name, logicalRouterSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_logical_router_get",
		Description: "Get one logical router (name and VRF count). The per-VRF routing configuration is not returned. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get logical router"),
	}, netGetHandler(d, "panos_logical_router_get", svc, parts, logicalRouterSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_logical_router_create",
		Description: "Create an empty logical router in the candidate config. Only the name is set; per-VRF routing (interfaces, BGP, OSPF, static routes) is configured elsewhere and preserved. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create logical router"),
	}, netCreateHandler(d, "panos_logical_router_create", svc, parts, scope, buildLogicalRouter, logicalRouterSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_logical_router_delete",
		Description: "Delete a logical router (and its VRF configuration) from the candidate config. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete logical router"),
	}, netDeleteHandler(d, "panos_logical_router_delete", svc, parts))
}
