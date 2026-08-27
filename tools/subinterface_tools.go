package tools

import (
	"errors"

	aggsub "github.com/PaloAltoNetworks/pango/network/interface/aggregate/subinterface/layer3"
	ethsub "github.com/PaloAltoNetworks/pango/network/interface/ethernet/subinterface/layer3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Layer 3 subinterfaces (network/interface/{ethernet|aggregate-ethernet}/<parent>/layer3/units)
// ---------------------------------------------------------------------------
//
// A Layer 3 subinterface (a tagged logical unit, e.g. ethernet1/1.100 or
// ae1.100) lives under its parent physical or aggregate interface, addressed by
// a two-component xpath (the parent interface entry, then the unit entry). Both
// families are net-scoped (firewall-local, or on Panorama under a template or
// template-stack) and share the parent-scoped adapter in parent_scope.go, with
// the parent interface name carried in parentScopeLoc.parent.
//
// For these subinterfaces pango places Ip, Ipv6, Mtu and
// InterfaceManagementProfile DIRECTLY on the top-level Entry (like the
// loopback/VLAN/tunnel logical interfaces, not nested in a Layer3 sub-struct),
// plus the subinterface-only Tag (the 802.1q VLAN tag). This server manages
// that common Layer 3 surface plus Tag; every other field (Arp, DdnsConfig,
// DhcpClient, the full Ipv6.Address list, Pppoe on the ethernet family, and so
// on) is left untouched and survives an update through the read-modify-write
// round-trip and Entry.Misc.

// SubinterfaceInput is the create/update input, shared by the ethernet and
// aggregate Layer 3 subinterface families.
type SubinterfaceInput struct {
	NetScopeInput
	ParentInterface string `json:"parent_interface" jsonschema:"Parent physical/aggregate interface, e.g. ethernet1/1 or ae1"`
	Name            string `json:"name" jsonschema:"Subinterface unit name, e.g. ethernet1/1.100"`
	Tag             *int64 `json:"tag,omitzero" jsonschema:"802.1q VLAN tag"`
	LogicalInterfaceCommonInput
}

// SubinterfaceListInput is the list input for both subinterface families.
type SubinterfaceListInput struct {
	NetScopeInput
	ParentInterface string `json:"parent_interface" jsonschema:"Parent physical/aggregate interface, e.g. ethernet1/1 or ae1"`
	Limit           int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset          int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter          string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// SubinterfaceNameInput is the get/delete input for both subinterface families.
type SubinterfaceNameInput struct {
	NetScopeInput
	ParentInterface string `json:"parent_interface" jsonschema:"Parent physical/aggregate interface, e.g. ethernet1/1 or ae1"`
	Name            string `json:"name" jsonschema:"Subinterface unit name, e.g. ethernet1/1.100"`
}

// ---------------------------------------------------------------------------
// Family A3: ethernet Layer 3 subinterface
// ---------------------------------------------------------------------------

func newEthernetSubinterfaceService(d *Deps) parentFixAdapter[ethsub.Location, ethsub.Entry] {
	return parentFixAdapter[ethsub.Location, ethsub.Entry]{
		svc:    ethsub.NewService(d.Client),
		client: d.Client,
		name:   func(e *ethsub.Entry) string { return e.Name },
	}
}

func ethernetSubinterfaceParts() netScopeParts[ethsub.Location] {
	return netScopeParts[ethsub.Location]{
		ngfw: func() ethsub.Location {
			return ethsub.Location{Ngfw: &ethsub.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ethsub.Location {
			return ethsub.Location{Template: &ethsub.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ethsub.Location {
			return ethsub.Location{TemplateStack: &ethsub.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// applyEthernetSubinterface overlays the managed fields onto e, applying only
// what the caller provided. Shared by build and overlay; it never rebuilds e.
//
//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract.
func applyEthernetSubinterface(e *ethsub.Entry, in SubinterfaceInput) {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.InterfaceManagementProfile, in.InterfaceManagementProfile)
	setPtr(&e.Tag, in.Tag)
	setPtr(&e.Mtu, in.Mtu)
	if in.Ips != nil {
		ips := make([]ethsub.Ip, 0, len(in.Ips))
		for _, name := range in.Ips {
			ips = append(ips, ethsub.Ip{Name: name})
		}
		e.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if e.Ipv6 == nil {
			e.Ipv6 = &ethsub.Ipv6{}
		}
		e.Ipv6.Enabled = in.Ipv6Enabled
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildEthernetSubinterface(in SubinterfaceInput) (*ethsub.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ethsub.Entry{Name: in.Name}
	applyEthernetSubinterface(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayEthernetSubinterface(e *ethsub.Entry, in SubinterfaceInput) error {
	applyEthernetSubinterface(e, in)
	return nil
}

func ethernetSubinterfaceSummary(e *ethsub.Entry) any {
	m := map[string]any{
		tagNameKey:              e.Name,
		commentKey:              strVal(e.Comment),
		interfaceMgmtProfileKey: strVal(e.InterfaceManagementProfile),
		ipsKey:                  strList(names(e.Ip, func(ip ethsub.Ip) string { return ip.Name })),
	}
	putInt(m, "tag", e.Tag)
	putInt(m, "mtu", e.Mtu)
	if e.Ipv6 != nil {
		putBool(m, "ipv6_enabled", e.Ipv6.Enabled)
	}
	return m
}

// RegisterEthernetSubinterfaceTools registers the ethernet Layer 3 subinterface
// CRUD tools. They are net-scoped and parent-scoped (a parent_interface is
// required). Mutating tools are skipped entirely in read-only mode.
func RegisterEthernetSubinterfaceTools(s *mcp.Server, d *Deps) {
	svc := newEthernetSubinterfaceService(d)
	parts := ethernetSubinterfaceParts()
	listParent := func(in SubinterfaceListInput) string { return in.ParentInterface }
	nameParent := func(in SubinterfaceNameInput) string { return in.ParentInterface }
	parent := func(in SubinterfaceInput) string { return in.ParentInterface }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_subinterface_list",
		Description: "List Layer 3 ethernet subinterfaces under a parent interface. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List ethernet subinterfaces"),
	}, parentListHandler(d, "panos_ethernet_subinterface_list", svc, parts, listParent,
		func(in SubinterfaceListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		svc.name, ethernetSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_subinterface_get",
		Description: "Get one ethernet subinterface (tag, comment, mtu, ips, management profile, ipv6). Read-only.",
		Annotations: readOnlyTool("Get ethernet subinterface"),
	}, parentGetHandler(d, "panos_ethernet_subinterface_get", svc, parts, nameParent,
		func(in SubinterfaceNameInput) string { return in.Name }, ethernetSubinterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_subinterface_create",
		Description: "Create a Layer 3 ethernet subinterface under a parent interface. name and parent_interface are required. Run panos_commit to apply.",
		Annotations: createTool("Create ethernet subinterface"),
	}, parentCreateHandler(d, "panos_ethernet_subinterface_create", svc, parts, parent, buildEthernetSubinterface, ethernetSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_subinterface_update",
		Description: "Update an ethernet subinterface: read-modify-write, only provided fields change; a provided ips list replaces the addresses fully. Run panos_commit to apply.",
		Annotations: updateTool("Update ethernet subinterface"),
	}, parentUpdateHandler(d, "panos_ethernet_subinterface_update", svc, parts, parent,
		func(in SubinterfaceInput) string { return in.Name }, overlayEthernetSubinterface, ethernetSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_subinterface_delete",
		Description: "Delete an ethernet subinterface from the candidate config. name and parent_interface are required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete ethernet subinterface"),
	}, parentDeleteHandler(d, "panos_ethernet_subinterface_delete", svc, parts, nameParent,
		func(in SubinterfaceNameInput) string { return in.Name }))
}

// ---------------------------------------------------------------------------
// Family A4: aggregate Layer 3 subinterface
// ---------------------------------------------------------------------------

func newAggregateSubinterfaceService(d *Deps) parentFixAdapter[aggsub.Location, aggsub.Entry] {
	return parentFixAdapter[aggsub.Location, aggsub.Entry]{
		svc:    aggsub.NewService(d.Client),
		client: d.Client,
		name:   func(e *aggsub.Entry) string { return e.Name },
	}
}

func aggregateSubinterfaceParts() netScopeParts[aggsub.Location] {
	return netScopeParts[aggsub.Location]{
		ngfw: func() aggsub.Location {
			return aggsub.Location{Ngfw: &aggsub.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) aggsub.Location {
			return aggsub.Location{Template: &aggsub.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) aggsub.Location {
			return aggsub.Location{TemplateStack: &aggsub.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// applyAggregateSubinterface overlays the managed fields onto e; see
// applyEthernetSubinterface.
//
//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract.
func applyAggregateSubinterface(e *aggsub.Entry, in SubinterfaceInput) {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.InterfaceManagementProfile, in.InterfaceManagementProfile)
	setPtr(&e.Tag, in.Tag)
	setPtr(&e.Mtu, in.Mtu)
	if in.Ips != nil {
		ips := make([]aggsub.Ip, 0, len(in.Ips))
		for _, name := range in.Ips {
			ips = append(ips, aggsub.Ip{Name: name})
		}
		e.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if e.Ipv6 == nil {
			e.Ipv6 = &aggsub.Ipv6{}
		}
		e.Ipv6.Enabled = in.Ipv6Enabled
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildAggregateSubinterface(in SubinterfaceInput) (*aggsub.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &aggsub.Entry{Name: in.Name}
	applyAggregateSubinterface(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayAggregateSubinterface(e *aggsub.Entry, in SubinterfaceInput) error {
	applyAggregateSubinterface(e, in)
	return nil
}

func aggregateSubinterfaceSummary(e *aggsub.Entry) any {
	m := map[string]any{
		tagNameKey:              e.Name,
		commentKey:              strVal(e.Comment),
		interfaceMgmtProfileKey: strVal(e.InterfaceManagementProfile),
		ipsKey:                  strList(names(e.Ip, func(ip aggsub.Ip) string { return ip.Name })),
	}
	putInt(m, "tag", e.Tag)
	putInt(m, "mtu", e.Mtu)
	if e.Ipv6 != nil {
		putBool(m, "ipv6_enabled", e.Ipv6.Enabled)
	}
	return m
}

// RegisterAggregateSubinterfaceTools registers the aggregate Layer 3
// subinterface CRUD tools; see RegisterEthernetSubinterfaceTools.
func RegisterAggregateSubinterfaceTools(s *mcp.Server, d *Deps) {
	svc := newAggregateSubinterfaceService(d)
	parts := aggregateSubinterfaceParts()
	listParent := func(in SubinterfaceListInput) string { return in.ParentInterface }
	nameParent := func(in SubinterfaceNameInput) string { return in.ParentInterface }
	parent := func(in SubinterfaceInput) string { return in.ParentInterface }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_subinterface_list",
		Description: "List Layer 3 aggregate (ae) subinterfaces under a parent interface. Firewall: device scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("List aggregate subinterfaces"),
	}, parentListHandler(d, "panos_aggregate_subinterface_list", svc, parts, listParent,
		func(in SubinterfaceListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		svc.name, aggregateSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_subinterface_get",
		Description: "Get one aggregate subinterface (tag, comment, mtu, ips, management profile, ipv6). Read-only.",
		Annotations: readOnlyTool("Get aggregate subinterface"),
	}, parentGetHandler(d, "panos_aggregate_subinterface_get", svc, parts, nameParent,
		func(in SubinterfaceNameInput) string { return in.Name }, aggregateSubinterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_subinterface_create",
		Description: "Create a Layer 3 aggregate subinterface under a parent interface. name and parent_interface are required. Run panos_commit to apply.",
		Annotations: createTool("Create aggregate subinterface"),
	}, parentCreateHandler(d, "panos_aggregate_subinterface_create", svc, parts, parent, buildAggregateSubinterface, aggregateSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_subinterface_update",
		Description: "Update an aggregate subinterface: read-modify-write, only provided fields change; a provided ips list replaces the addresses fully. Run panos_commit to apply.",
		Annotations: updateTool("Update aggregate subinterface"),
	}, parentUpdateHandler(d, "panos_aggregate_subinterface_update", svc, parts, parent,
		func(in SubinterfaceInput) string { return in.Name }, overlayAggregateSubinterface, aggregateSubinterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_subinterface_delete",
		Description: "Delete an aggregate subinterface from the candidate config. name and parent_interface are required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete aggregate subinterface"),
	}, parentDeleteHandler(d, "panos_aggregate_subinterface_delete", svc, parts, nameParent,
		func(in SubinterfaceNameInput) string { return in.Name }))
}
