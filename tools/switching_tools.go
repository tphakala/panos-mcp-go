package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/virtualwire"
	"github.com/PaloAltoNetworks/pango/network/vlan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file registers CRUD tools for the two layer-2 switching objects pango
// models under the network config: the virtual wire (network/virtualwire) and
// the VLAN object (network/vlan). Both are net-scoped: {Ngfw | Template |
// TemplateStack}, resolved by resolveNetScope, and registered on both firewall
// and Panorama.
//
// The VLAN object here is the switching node `vlan`, distinct from the VLAN
// interface `interface/vlan` (panos_vlan_interface_*): this object groups layer-2
// member interfaces into a broadcast domain, whereas the VLAN interface is the
// routed layer-3 SVI.

// ---------------------------------------------------------------------------
// Virtual wire (network/virtualwire)
// ---------------------------------------------------------------------------

func newVirtualWireService(d *Deps) nameFixAdapter[virtualwire.Location, virtualwire.Entry] {
	return nameFixAdapter[virtualwire.Location, virtualwire.Entry]{
		svc:    virtualwire.NewService(d.Client),
		client: d.Client,
		name:   func(e *virtualwire.Entry) string { return e.Name },
	}
}

func virtualWireParts() netScopeParts[virtualwire.Location] {
	return netScopeParts[virtualwire.Location]{
		ngfw: func() virtualwire.Location {
			return virtualwire.Location{Ngfw: &virtualwire.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) virtualwire.Location {
			return virtualwire.Location{Template: &virtualwire.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) virtualwire.Location {
			return virtualwire.Location{TemplateStack: &virtualwire.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// VirtualWireInput is the input for the virtual wire create and update tools. The
// link-state-pass-through and multicast-firewalling blocks are not modeled here
// and are preserved across updates.
type VirtualWireInput struct {
	NetScopeInput
	Name       string  `json:"name" jsonschema:"Virtual wire name"`
	Interface1 *string `json:"interface1,omitzero" jsonschema:"First bound interface, e.g. ethernet1/1"`
	Interface2 *string `json:"interface2,omitzero" jsonschema:"Second bound interface, e.g. ethernet1/2"`
	TagAllowed *string `json:"tag_allowed,omitzero" jsonschema:"Allowed VLAN tags/ranges, e.g. 0 or 100-200 (comma-separated)"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyVirtualWire(e *virtualwire.Entry, in VirtualWireInput) {
	setPtr(&e.Interface1, in.Interface1)
	setPtr(&e.Interface2, in.Interface2)
	setPtr(&e.TagAllowed, in.TagAllowed)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildVirtualWire(in VirtualWireInput) (*virtualwire.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &virtualwire.Entry{Name: in.Name}
	applyVirtualWire(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayVirtualWire(e *virtualwire.Entry, in VirtualWireInput) error {
	applyVirtualWire(e, in)
	return nil
}

func virtualWireSummary(e *virtualwire.Entry) any {
	return map[string]any{
		tagNameKey:    e.Name,
		"interface1":  strVal(e.Interface1),
		"interface2":  strVal(e.Interface2),
		"tag_allowed": strVal(e.TagAllowed),
	}
}

// RegisterVirtualWireTools registers the virtual wire tools on both firewall and
// Panorama.
func RegisterVirtualWireTools(s *mcp.Server, d *Deps) {
	svc := newVirtualWireService(d)
	parts := virtualWireParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_wire_list",
		Description: "List virtual wires. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List virtual wires"),
	}, netListHandler(d, "panos_virtual_wire_list", svc, parts, svc.name, virtualWireSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_wire_get",
		Description: "Get one virtual wire (its two bound interfaces and allowed tags). The link-state-pass-through and multicast-firewalling settings are not modeled and are preserved on update. Read-only.",
		Annotations: readOnlyTool("Get virtual wire"),
	}, netGetHandler(d, "panos_virtual_wire_get", svc, parts, virtualWireSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_wire_create",
		Description: "Create a virtual wire in the candidate config binding two layer-2 interfaces. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create virtual wire"),
	}, netCreateHandler(d, "panos_virtual_wire_create", svc, parts, buildVirtualWire, virtualWireSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_wire_update",
		Description: "Update a virtual wire: read-modify-write, only provided fields change. The link-state and multicast settings are preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update virtual wire"),
	}, netUpdateHandler(d, "panos_virtual_wire_update", svc, parts,
		func(in VirtualWireInput) string { return in.Name }, overlayVirtualWire, virtualWireSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_virtual_wire_delete",
		Description: "Delete a virtual wire from the candidate config. Fails while interfaces or zones still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete virtual wire"),
	}, netDeleteHandler(d, "panos_virtual_wire_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// VLAN object (network/vlan)
// ---------------------------------------------------------------------------

func newVlanService(d *Deps) nameFixAdapter[vlan.Location, vlan.Entry] {
	return nameFixAdapter[vlan.Location, vlan.Entry]{
		svc:    vlan.NewService(d.Client),
		client: d.Client,
		name:   func(e *vlan.Entry) string { return e.Name },
	}
}

func vlanParts() netScopeParts[vlan.Location] {
	return netScopeParts[vlan.Location]{
		ngfw: func() vlan.Location {
			return vlan.Location{Ngfw: &vlan.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) vlan.Location {
			return vlan.Location{Template: &vlan.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) vlan.Location {
			return vlan.Location{TemplateStack: &vlan.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// VlanInput is the input for the VLAN object create and update tools. The
// virtual-interface (the layer-3 SVI binding) is not modeled here and is
// preserved across updates.
type VlanInput struct {
	NetScopeInput
	Name       string   `json:"name" jsonschema:"VLAN object name"`
	Interfaces []string `json:"interfaces,omitzero" jsonschema:"Layer-2 member interfaces in the broadcast domain; replaces the whole list when provided"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyVlan(e *vlan.Entry, in VlanInput) {
	if in.Interfaces != nil {
		e.Interface = in.Interfaces
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildVlan(in VlanInput) (*vlan.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &vlan.Entry{Name: in.Name}
	applyVlan(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayVlan(e *vlan.Entry, in VlanInput) error {
	applyVlan(e, in)
	return nil
}

func vlanSummary(e *vlan.Entry) any {
	return map[string]any{
		tagNameKey:    e.Name,
		interfacesKey: strList(e.Interface),
	}
}

// RegisterVlanTools registers the VLAN object tools on both firewall and
// Panorama. These manage the layer-2 switching object `vlan`, distinct from the
// layer-3 VLAN interface managed by panos_vlan_interface_*.
func RegisterVlanTools(s *mcp.Server, d *Deps) {
	svc := newVlanService(d)
	parts := vlanParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_list",
		Description: "List VLAN objects (layer-2 broadcast domains; distinct from VLAN interfaces). Firewall: local scope; Panorama: a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("List VLAN objects"),
	}, netListHandler(d, "panos_vlan_list", svc, parts, svc.name, vlanSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_get",
		Description: "Get one VLAN object (its layer-2 member interfaces). This is the switching object `vlan`, not the layer-3 VLAN interface (panos_vlan_interface_get). The virtual-interface binding is not modeled and is preserved on update. Read-only.",
		Annotations: readOnlyTool("Get VLAN object"),
	}, netGetHandler(d, "panos_vlan_get", svc, parts, vlanSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_create",
		Description: "Create a VLAN object (layer-2 broadcast domain) in the candidate config. Distinct from a VLAN interface (panos_vlan_interface_create). Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create VLAN object"),
	}, netCreateHandler(d, "panos_vlan_create", svc, parts, buildVlan, vlanSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_update",
		Description: "Update a VLAN object: read-modify-write, only provided fields change. A provided interfaces list replaces the whole member set (an empty list clears it). The virtual-interface binding is preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update VLAN object"),
	}, netUpdateHandler(d, "panos_vlan_update", svc, parts,
		func(in VlanInput) string { return in.Name }, overlayVlan, vlanSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_delete",
		Description: "Delete a VLAN object from the candidate config. Fails while interfaces still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete VLAN object"),
	}, netDeleteHandler(d, "panos_vlan_delete", svc, parts))
}
