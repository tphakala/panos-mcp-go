package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/interface/loopback"
	"github.com/PaloAltoNetworks/pango/network/interface/tunnel"
	"github.com/PaloAltoNetworks/pango/network/interface/vlan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Summary map keys shared across the three interface summaries (goconst). The
// name key reuses the package-wide tagNameKey.
const (
	commentKey              = "comment"
	interfaceMgmtProfileKey = "interface_management_profile"
	ipsKey                  = "ips"
)

// This file registers CRUD tools for the loopback, VLAN, and tunnel logical
// interfaces. All three share the network scope pango models as
// {Ngfw | Template | TemplateStack} (the net-scope resolver): on a firewall
// they resolve to the device (Ngfw) scope; on Panorama exactly one of template
// or template_stack is required.
//
// For these three interface types pango places Ip, Ipv6, Mtu and
// InterfaceManagementProfile DIRECTLY on the top-level Entry (there is no
// Layer3 sub-struct, unlike ethernet and aggregate). This server manages only
// that common Layer3 surface plus the tunnel-only link_tag; every other field
// (DdnsConfig, DhcpClient, Arp, Bonjour, NdpProxy, AdjustTcpMss, the full
// Ipv6.Address list, and so on) is left untouched. Because the update path is a
// read-modify-write overlay that applies only the caller-provided fields, those
// unmanaged fields survive across an update. What preserves them is the
// read-modify-write itself, not Entry.Misc: pango declares them as typed fields
// on the Entry, and the overlay simply never writes them. For VLAN that covers
// every field named above; for loopback and tunnel it covers the subset each of
// them models.

// ---------------------------------------------------------------------------
// Loopback interface (network/interface/loopback)
// ---------------------------------------------------------------------------

func newLoopbackInterfaceService(d *Deps) nameFixAdapter[loopback.Location, loopback.Entry] {
	return nameFixAdapter[loopback.Location, loopback.Entry]{
		svc:    loopback.NewService(d.Client),
		client: d.Client,
		name:   func(e *loopback.Entry) string { return e.Name },
	}
}

func loopbackInterfaceParts() netScopeParts[loopback.Location] {
	return netScopeParts[loopback.Location]{
		ngfw: func() loopback.Location {
			return loopback.Location{Ngfw: &loopback.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) loopback.Location {
			return loopback.Location{Template: &loopback.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) loopback.Location {
			return loopback.Location{TemplateStack: &loopback.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// LogicalInterfaceCommonInput is the shared field block for the loopback, VLAN
// and tunnel logical interfaces. Unlike ethernet/aggregate (whose
// InterfaceCommonInput maps to the nested Entry.Layer3 block), these three carry
// their addressing on the Entry root, so this is a separate embed with its own
// field descriptions rather than a reuse of InterfaceCommonInput.
type LogicalInterfaceCommonInput struct {
	Comment                    *string  `json:"comment,omitzero" jsonschema:"Free-text interface comment"`
	Mtu                        *int64   `json:"mtu,omitzero" jsonschema:"Interface MTU in bytes"`
	Ips                        []string `json:"ips,omitzero" jsonschema:"IP addresses (CIDR or address-object names); replaces the full list on update"`
	InterfaceManagementProfile *string  `json:"interface_management_profile,omitzero" jsonschema:"Name of the interface management profile to attach"`
	Ipv6Enabled                *bool    `json:"ipv6_enabled,omitzero" jsonschema:"Enable IPv6 on the interface"`
}

// LoopbackInterfaceInput is the input for the loopback interface create and
// update tools.
type LoopbackInterfaceInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Interface unit name, e.g. loopback.1"`
	LogicalInterfaceCommonInput
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLoopbackInterface(in LoopbackInterfaceInput) (*loopback.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &loopback.Entry{Name: in.Name}
	overlayLoopbackFields(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLoopbackInterface(e *loopback.Entry, in LoopbackInterfaceInput) error {
	overlayLoopbackFields(e, in)
	return nil
}

//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract that calls this.
func overlayLoopbackFields(e *loopback.Entry, in LoopbackInterfaceInput) {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.InterfaceManagementProfile, in.InterfaceManagementProfile)
	if in.Mtu != nil {
		e.Mtu = in.Mtu
	}
	if in.Ips != nil {
		ips := make([]loopback.Ip, 0, len(in.Ips))
		for _, name := range in.Ips {
			ips = append(ips, loopback.Ip{Name: name})
		}
		e.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if e.Ipv6 == nil {
			e.Ipv6 = &loopback.Ipv6{}
		}
		e.Ipv6.Enabled = in.Ipv6Enabled
	}
}

func loopbackInterfaceSummary(e *loopback.Entry) any {
	m := map[string]any{
		tagNameKey:              e.Name,
		commentKey:              strVal(e.Comment),
		interfaceMgmtProfileKey: strVal(e.InterfaceManagementProfile),
		ipsKey:                  strList(names(e.Ip, func(ip loopback.Ip) string { return ip.Name })),
	}
	putInt(m, "mtu", e.Mtu)
	if e.Ipv6 != nil {
		putBool(m, "ipv6_enabled", e.Ipv6.Enabled)
	}
	return m
}

// RegisterLoopbackInterfaceTools registers the loopback interface tools. Mutating
// tools are skipped entirely in read-only mode.
func RegisterLoopbackInterfaceTools(s *mcp.Server, d *Deps) {
	svc := newLoopbackInterfaceService(d)
	parts := loopbackInterfaceParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_loopback_interface_list",
		Description: "List loopback interfaces. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List loopback interfaces"),
	}, netListHandler(d, "panos_loopback_interface_list", svc, parts, svc.name, loopbackInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_loopback_interface_get",
		Description: "Get one loopback interface (comment, mtu, ips, management profile, ipv6). Read-only.",
		Annotations: readOnlyTool("Get loopback interface"),
	}, netGetHandler(d, "panos_loopback_interface_get", svc, parts, loopbackInterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_loopback_interface_create",
		Description: "Create a loopback interface in the candidate config. Only name is required. Run panos_commit to apply.",
		Annotations: createTool("Create loopback interface"),
	}, netCreateHandler(d, "panos_loopback_interface_create", svc, parts, buildLoopbackInterface, loopbackInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_loopback_interface_update",
		Description: "Update a loopback interface: read-modify-write, only provided fields change; a provided ips list replaces fully. Run panos_commit to apply.",
		Annotations: updateTool("Update loopback interface"),
	}, netUpdateHandler(d, "panos_loopback_interface_update", svc, parts,
		func(in LoopbackInterfaceInput) string { return in.Name }, overlayLoopbackInterface, loopbackInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_loopback_interface_delete",
		Description: "Delete a loopback interface from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete loopback interface"),
	}, netDeleteHandler(d, "panos_loopback_interface_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// VLAN interface (network/interface/vlan)
// ---------------------------------------------------------------------------

func newVlanInterfaceService(d *Deps) nameFixAdapter[vlan.Location, vlan.Entry] {
	return nameFixAdapter[vlan.Location, vlan.Entry]{
		svc:    vlan.NewService(d.Client),
		client: d.Client,
		name:   func(e *vlan.Entry) string { return e.Name },
	}
}

func vlanInterfaceParts() netScopeParts[vlan.Location] {
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

// VlanInterfaceInput is the input for the VLAN interface create and update tools.
type VlanInterfaceInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Interface unit name, e.g. vlan.1"`
	LogicalInterfaceCommonInput
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildVlanInterface(in VlanInterfaceInput) (*vlan.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &vlan.Entry{Name: in.Name}
	overlayVlanFields(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayVlanInterface(e *vlan.Entry, in VlanInterfaceInput) error {
	overlayVlanFields(e, in)
	return nil
}

//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract that calls this.
func overlayVlanFields(e *vlan.Entry, in VlanInterfaceInput) {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.InterfaceManagementProfile, in.InterfaceManagementProfile)
	if in.Mtu != nil {
		e.Mtu = in.Mtu
	}
	if in.Ips != nil {
		ips := make([]vlan.Ip, 0, len(in.Ips))
		for _, name := range in.Ips {
			ips = append(ips, vlan.Ip{Name: name})
		}
		e.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if e.Ipv6 == nil {
			e.Ipv6 = &vlan.Ipv6{}
		}
		e.Ipv6.Enabled = in.Ipv6Enabled
	}
}

func vlanInterfaceSummary(e *vlan.Entry) any {
	m := map[string]any{
		tagNameKey:              e.Name,
		commentKey:              strVal(e.Comment),
		interfaceMgmtProfileKey: strVal(e.InterfaceManagementProfile),
		ipsKey:                  strList(names(e.Ip, func(ip vlan.Ip) string { return ip.Name })),
	}
	putInt(m, "mtu", e.Mtu)
	if e.Ipv6 != nil {
		putBool(m, "ipv6_enabled", e.Ipv6.Enabled)
	}
	return m
}

// RegisterVlanInterfaceTools registers the VLAN interface tools. Mutating tools
// are skipped entirely in read-only mode.
func RegisterVlanInterfaceTools(s *mcp.Server, d *Deps) {
	svc := newVlanInterfaceService(d)
	parts := vlanInterfaceParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_interface_list",
		Description: "List VLAN interfaces. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List VLAN interfaces"),
	}, netListHandler(d, "panos_vlan_interface_list", svc, parts, svc.name, vlanInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_interface_get",
		Description: "Get one VLAN interface (comment, mtu, ips, management profile, ipv6). Read-only.",
		Annotations: readOnlyTool("Get VLAN interface"),
	}, netGetHandler(d, "panos_vlan_interface_get", svc, parts, vlanInterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_interface_create",
		Description: "Create a VLAN interface in the candidate config. Only name is required. Run panos_commit to apply.",
		Annotations: createTool("Create VLAN interface"),
	}, netCreateHandler(d, "panos_vlan_interface_create", svc, parts, buildVlanInterface, vlanInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_interface_update",
		Description: "Update a VLAN interface: read-modify-write, only provided fields change; a provided ips list replaces fully. Run panos_commit to apply.",
		Annotations: updateTool("Update VLAN interface"),
	}, netUpdateHandler(d, "panos_vlan_interface_update", svc, parts,
		func(in VlanInterfaceInput) string { return in.Name }, overlayVlanInterface, vlanInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vlan_interface_delete",
		Description: "Delete a VLAN interface from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete VLAN interface"),
	}, netDeleteHandler(d, "panos_vlan_interface_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Tunnel interface (network/interface/tunnel)
// ---------------------------------------------------------------------------

func newTunnelInterfaceService(d *Deps) nameFixAdapter[tunnel.Location, tunnel.Entry] {
	return nameFixAdapter[tunnel.Location, tunnel.Entry]{
		svc:    tunnel.NewService(d.Client),
		client: d.Client,
		name:   func(e *tunnel.Entry) string { return e.Name },
	}
}

func tunnelInterfaceParts() netScopeParts[tunnel.Location] {
	return netScopeParts[tunnel.Location]{
		ngfw: func() tunnel.Location {
			return tunnel.Location{Ngfw: &tunnel.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) tunnel.Location {
			return tunnel.Location{Template: &tunnel.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) tunnel.Location {
			return tunnel.Location{TemplateStack: &tunnel.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// TunnelInterfaceInput is the input for the tunnel interface create and update
// tools. link_tag is tunnel-only (it is absent on loopback and VLAN).
type TunnelInterfaceInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Interface unit name, e.g. tunnel.1"`
	LogicalInterfaceCommonInput
	LinkTag *string `json:"link_tag,omitzero" jsonschema:"Link tag for the tunnel interface"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildTunnelInterface(in TunnelInterfaceInput) (*tunnel.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &tunnel.Entry{Name: in.Name}
	overlayTunnelFields(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayTunnelInterface(e *tunnel.Entry, in TunnelInterfaceInput) error {
	overlayTunnelFields(e, in)
	return nil
}

//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract that calls this.
func overlayTunnelFields(e *tunnel.Entry, in TunnelInterfaceInput) {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.InterfaceManagementProfile, in.InterfaceManagementProfile)
	setPtr(&e.LinkTag, in.LinkTag)
	if in.Mtu != nil {
		e.Mtu = in.Mtu
	}
	if in.Ips != nil {
		ips := make([]tunnel.Ip, 0, len(in.Ips))
		for _, name := range in.Ips {
			ips = append(ips, tunnel.Ip{Name: name})
		}
		e.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if e.Ipv6 == nil {
			e.Ipv6 = &tunnel.Ipv6{}
		}
		e.Ipv6.Enabled = in.Ipv6Enabled
	}
}

func tunnelInterfaceSummary(e *tunnel.Entry) any {
	m := map[string]any{
		tagNameKey:              e.Name,
		commentKey:              strVal(e.Comment),
		interfaceMgmtProfileKey: strVal(e.InterfaceManagementProfile),
		"link_tag":              strVal(e.LinkTag),
		ipsKey:                  strList(names(e.Ip, func(ip tunnel.Ip) string { return ip.Name })),
	}
	putInt(m, "mtu", e.Mtu)
	if e.Ipv6 != nil {
		putBool(m, "ipv6_enabled", e.Ipv6.Enabled)
	}
	return m
}

// RegisterTunnelInterfaceTools registers the tunnel interface tools. Mutating
// tools are skipped entirely in read-only mode.
func RegisterTunnelInterfaceTools(s *mcp.Server, d *Deps) {
	svc := newTunnelInterfaceService(d)
	parts := tunnelInterfaceParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tunnel_interface_list",
		Description: "List tunnel interfaces. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List tunnel interfaces"),
	}, netListHandler(d, "panos_tunnel_interface_list", svc, parts, svc.name, tunnelInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tunnel_interface_get",
		Description: "Get one tunnel interface (comment, mtu, ips, management profile, ipv6, link_tag). Read-only.",
		Annotations: readOnlyTool("Get tunnel interface"),
	}, netGetHandler(d, "panos_tunnel_interface_get", svc, parts, tunnelInterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tunnel_interface_create",
		Description: "Create a tunnel interface in the candidate config. Only name is required. Run panos_commit to apply.",
		Annotations: createTool("Create tunnel interface"),
	}, netCreateHandler(d, "panos_tunnel_interface_create", svc, parts, buildTunnelInterface, tunnelInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tunnel_interface_update",
		Description: "Update a tunnel interface: read-modify-write, only provided fields change; a provided ips list replaces fully. Run panos_commit to apply.",
		Annotations: updateTool("Update tunnel interface"),
	}, netUpdateHandler(d, "panos_tunnel_interface_update", svc, parts,
		func(in TunnelInterfaceInput) string { return in.Name }, overlayTunnelInterface, tunnelInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tunnel_interface_delete",
		Description: "Delete a tunnel interface from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete tunnel interface"),
	}, netDeleteHandler(d, "panos_tunnel_interface_delete", svc, parts))
}
