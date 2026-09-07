package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/vsys"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Virtual systems (device/vsys)
// ---------------------------------------------------------------------------
//
// A vsys entry is a virtual system: an administrative partition of a firewall.
// pango models the vsys list only under a Panorama template or template-stack
// (Location is Template or TemplateStack, with no firewall-local scope), so
// these tools are registered on Panorama only and resolve through the net-scope
// resolver with a nil ngfw constructor.
//
// The pango entry carries only a name (the vsys's contents live under other
// config subtrees this server exposes through their own scoped tools), so the
// tools are list, get and create. There is no update (nothing on the entry to
// change) and no delete (removing a vsys entry would drop the whole vsys config
// subtree, which belongs to a deliberate, separate workflow).

func newVsysService(d *Deps) nameFixAdapter[vsys.Location, vsys.Entry] {
	return nameFixAdapter[vsys.Location, vsys.Entry]{
		svc:    vsys.NewService(d.Client),
		client: d.Client,
		name:   func(e *vsys.Entry) string { return e.Name },
	}
}

// vsysParts supplies the vsys locations for resolveNetScope. ngfw is nil: pango
// has no firewall-local vsys location, so a bare firewall request is an error
// (and RegisterVsysTools registers nothing on a firewall anyway).
func vsysParts() netScopeParts[vsys.Location] {
	return netScopeParts[vsys.Location]{
		template: func(tmpl string) vsys.Location {
			return vsys.Location{Template: &vsys.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) vsys.Location {
			return vsys.Location{TemplateStack: &vsys.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// VsysInput is the input for creating a vsys entry: a name plus the net scope.
type VsysInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Virtual system name (e.g. vsys1)"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildVsys(in VsysInput) (*vsys.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	return &vsys.Entry{Name: in.Name}, nil
}

// vsysSummary projects a vsys entry. The pango entry carries only a name.
func vsysSummary(e *vsys.Entry) any {
	return map[string]any{tagNameKey: e.Name}
}

// RegisterVsysTools registers the virtual-system tools. They exist only under
// Panorama, so nothing is registered on a firewall. The create tool is skipped
// in read-only mode.
func RegisterVsysTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	svc := newVsysService(d)
	parts := vsysParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vsys_list",
		Description: "List virtual systems (vsys) defined in a Panorama template or template_stack (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List virtual systems"),
	}, netListHandler(d, "panos_vsys_list", svc, parts, svc.name, vsysSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vsys_get",
		Description: "Get one virtual system entry by name from a Panorama template or template_stack. Read-only.",
		Annotations: readOnlyTool("Get virtual system"),
	}, netGetHandler(d, "panos_vsys_get", svc, parts, vsysSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vsys_create",
		Description: "Create a virtual system entry in a Panorama template or template_stack candidate config. Only name is required. Run panos_commit to apply.",
		Annotations: createTool("Create virtual system"),
	}, netCreateHandler(d, "panos_vsys_create", svc, parts, buildVsys, vsysSummary))
}
