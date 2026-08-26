package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/interface/aggregate"
	"github.com/PaloAltoNetworks/pango/network/interface/ethernet"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file adds full CRUD for two Layer 3 interface families: physical
// ethernet ports and aggregate (aggregate-ethernet) interfaces. Both live at a
// network scope pango models as {Ngfw | Template | TemplateStack}, so they use
// the net-scope resolver (resolveNetScope) rather than the object
// shared/vsys/device_group model.
//
// Scope decision (conservative, by design): an interface Entry carries several
// mutually exclusive mode blocks (layer2, layer3, virtual-wire, tap, ha, and so
// on). This server models ONLY the Layer3 mode. On create it builds a Layer3
// interface; on update it applies the Layer3 fields into the existing (or a new)
// Layer3 block via read-modify-write and never clears a sibling mode block, so
// the SDK-only subtrees round-trip through Entry.Misc untouched. Converting an
// existing layer2 or virtual-wire port to layer3 is therefore out of scope: it
// would require wiping a sibling block, which these tools deliberately do not do.

// InterfaceCommonInput holds the Layer3 fields shared by the ethernet and
// aggregate interface tools. It is embedded (and so flattened into the tool
// schema) by both family inputs. Comment maps to Entry.Comment; the rest map to
// the Entry.Layer3 block.
type InterfaceCommonInput struct {
	Comment                    *string  `json:"comment,omitempty" jsonschema:"Free-text interface comment"`
	Mtu                        *int64   `json:"mtu,omitempty" jsonschema:"Layer3 MTU in bytes (e.g. 1500)"`
	Ips                        []string `json:"ips,omitempty" jsonschema:"Layer3 IP addresses (ip-netmask or an address-object name); on update this list replaces the current IPs fully, an empty list clears them"`
	InterfaceManagementProfile *string  `json:"interface_management_profile,omitempty" jsonschema:"Name of the interface management profile to attach"`
	Ipv6Enabled                *bool    `json:"ipv6_enabled,omitempty" jsonschema:"Enable or disable IPv6 on the Layer3 interface"`
}

// hasLayer3Fields reports whether any Layer3 field was provided, so an update
// that touches none leaves the Layer3 block (present or absent) exactly as read
// rather than fabricating an empty one (which would flip a non-layer3 port to
// layer3, outside this server's scope).
func (in InterfaceCommonInput) hasLayer3Fields() bool {
	return in.Mtu != nil || in.Ips != nil || in.InterfaceManagementProfile != nil || in.Ipv6Enabled != nil
}

// ---------------------------------------------------------------------------
// Ethernet interface (network/interface/ethernet)
// ---------------------------------------------------------------------------

func newEthernetInterfaceService(d *Deps) nameFixAdapter[ethernet.Location, ethernet.Entry] {
	return nameFixAdapter[ethernet.Location, ethernet.Entry]{
		svc:    ethernet.NewService(d.Client),
		client: d.Client,
		name:   func(e *ethernet.Entry) string { return e.Name },
	}
}

func ethernetInterfaceParts() netScopeParts[ethernet.Location] {
	return netScopeParts[ethernet.Location]{
		ngfw: func() ethernet.Location {
			return ethernet.Location{Ngfw: &ethernet.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ethernet.Location {
			return ethernet.Location{Template: &ethernet.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ethernet.Location {
			return ethernet.Location{TemplateStack: &ethernet.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// EthernetInterfaceInput is the input for the ethernet interface create and
// update tools. It models a Layer3 physical interface plus the physical link
// settings that live on the ethernet Entry itself.
type EthernetInterfaceInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Interface name, e.g. ethernet1/1"`
	InterfaceCommonInput
	LinkState      *string `json:"link_state,omitempty" jsonschema:"Administrative link state: up, down, or auto"`
	LinkSpeed      *string `json:"link_speed,omitempty" jsonschema:"Link speed: 10, 100, 1000, or auto"`
	LinkDuplex     *string `json:"link_duplex,omitempty" jsonschema:"Link duplex: full, half, or auto"`
	AggregateGroup *string `json:"aggregate_group,omitempty" jsonschema:"Name of the aggregate-ethernet group this port is a member of, e.g. ae1"`
}

// applyEthernetLayer3 writes the provided Layer3 fields into l3, leaving an
// omitted field untouched (read-modify-write). A provided ips list replaces the
// current addresses fully.
func applyEthernetLayer3(l3 *ethernet.Layer3, in InterfaceCommonInput) {
	setPtr(&l3.Mtu, in.Mtu)
	setPtr(&l3.InterfaceManagementProfile, in.InterfaceManagementProfile)
	if in.Ips != nil {
		ips := make([]ethernet.Layer3Ip, len(in.Ips))
		for i, name := range in.Ips {
			ips[i] = ethernet.Layer3Ip{Name: name}
		}
		l3.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if l3.Ipv6 == nil {
			l3.Ipv6 = &ethernet.Layer3Ipv6{}
		}
		l3.Ipv6.Enabled = in.Ipv6Enabled
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildEthernetInterface(in EthernetInterfaceInput) (*ethernet.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ethernet.Entry{Name: in.Name}
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.LinkState, in.LinkState)
	setPtr(&e.LinkSpeed, in.LinkSpeed)
	setPtr(&e.LinkDuplex, in.LinkDuplex)
	setPtr(&e.AggregateGroup, in.AggregateGroup)
	// Create always declares a Layer3 interface: this server models only the
	// layer3 mode, so a new interface is layer3 even when no L3 field is set.
	e.Layer3 = &ethernet.Layer3{}
	applyEthernetLayer3(e.Layer3, in.InterfaceCommonInput)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayEthernetInterface(e *ethernet.Entry, in EthernetInterfaceInput) error {
	setPtr(&e.Comment, in.Comment)
	setPtr(&e.LinkState, in.LinkState)
	setPtr(&e.LinkSpeed, in.LinkSpeed)
	setPtr(&e.LinkDuplex, in.LinkDuplex)
	setPtr(&e.AggregateGroup, in.AggregateGroup)
	// Only touch the Layer3 block when a Layer3 field was provided; otherwise
	// leave the interface's existing mode (layer3 or a sibling) exactly as read.
	// Sibling mode blocks are never cleared, so their SDK-only subtrees survive.
	if in.hasLayer3Fields() {
		if e.Layer3 == nil {
			e.Layer3 = &ethernet.Layer3{}
		}
		applyEthernetLayer3(e.Layer3, in.InterfaceCommonInput)
	}
	return nil
}

func ethernetInterfaceSummary(e *ethernet.Entry) any {
	m := map[string]any{tagNameKey: e.Name, "comment": strVal(e.Comment)}
	m["link_state"] = strVal(e.LinkState)
	m["link_speed"] = strVal(e.LinkSpeed)
	m["link_duplex"] = strVal(e.LinkDuplex)
	m["aggregate_group"] = strVal(e.AggregateGroup)
	if l3 := e.Layer3; l3 != nil {
		putInt(m, "mtu", l3.Mtu)
		m["interface_management_profile"] = strVal(l3.InterfaceManagementProfile)
		names := make([]string, 0, len(l3.Ip))
		for i := range l3.Ip {
			names = append(names, l3.Ip[i].Name)
		}
		m["ips"] = strList(names)
		if l3.Ipv6 != nil {
			putBool(m, "ipv6_enabled", l3.Ipv6.Enabled)
		}
	} else {
		m["ips"] = strList(nil)
		m["interface_management_profile"] = ""
	}
	return m
}

// RegisterEthernetInterfaceTools registers the ethernet interface tools.
// Mutating tools are skipped entirely in read-only mode.
func RegisterEthernetInterfaceTools(s *mcp.Server, d *Deps) {
	svc := newEthernetInterfaceService(d)
	parts := ethernetInterfaceParts()
	scope := func(in EthernetInterfaceInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_interface_list",
		Description: "List physical ethernet interfaces. Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List ethernet interfaces"),
	}, netListHandler(d, "panos_ethernet_interface_list", svc, parts, svc.name, ethernetInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_interface_get",
		Description: "Get one ethernet interface (Layer3 IPs, MTU, management profile, IPv6 toggle, and physical link settings). Read-only.",
		Annotations: readOnlyTool("Get ethernet interface"),
	}, netGetHandler(d, "panos_ethernet_interface_get", svc, parts, ethernetInterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_interface_create",
		Description: "Create a Layer3 ethernet interface in the candidate config. This server models only the layer3 mode: the new interface is layer3, and layer2, virtual-wire and tap modes are not offered here. Set ips (ip-netmask or address-object names), mtu, interface_management_profile and ipv6_enabled as needed. Run panos_commit to apply.",
		Annotations: createTool("Create ethernet interface"),
	}, netCreateHandler(d, "panos_ethernet_interface_create", svc, parts, scope, buildEthernetInterface, ethernetInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_interface_update",
		Description: "Update an ethernet interface: read-modify-write, only provided fields change; a provided ips list replaces the current addresses fully (an empty list clears them). Layer3 fields apply into the existing layer3 block. Converting an existing layer2, virtual-wire or tap port to layer3 is out of scope: sibling mode blocks are never cleared, and their SDK-only subtrees are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update ethernet interface"),
	}, netUpdateHandler(d, "panos_ethernet_interface_update", svc, parts, scope,
		func(in EthernetInterfaceInput) string { return in.Name }, overlayEthernetInterface, ethernetInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ethernet_interface_delete",
		Description: "Delete an ethernet interface from the candidate config. Fails while zones, virtual routers or other config still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete ethernet interface"),
	}, netDeleteHandler(d, "panos_ethernet_interface_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Aggregate interface (network/interface/aggregate, the aggregate-ethernet node)
// ---------------------------------------------------------------------------

func newAggregateInterfaceService(d *Deps) nameFixAdapter[aggregate.Location, aggregate.Entry] {
	return nameFixAdapter[aggregate.Location, aggregate.Entry]{
		svc:    aggregate.NewService(d.Client),
		client: d.Client,
		name:   func(e *aggregate.Entry) string { return e.Name },
	}
}

func aggregateInterfaceParts() netScopeParts[aggregate.Location] {
	return netScopeParts[aggregate.Location]{
		ngfw: func() aggregate.Location {
			return aggregate.Location{Ngfw: &aggregate.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) aggregate.Location {
			return aggregate.Location{Template: &aggregate.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) aggregate.Location {
			return aggregate.Location{TemplateStack: &aggregate.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// AggregateInterfaceInput is the input for the aggregate interface create and
// update tools. An aggregate (aggregate-ethernet) interface is the bundle
// itself, so it carries no physical link_* fields; member ports reference it
// through their aggregate_group.
type AggregateInterfaceInput struct {
	NetScopeInput
	Name string `json:"name" jsonschema:"Aggregate interface name, e.g. ae1"`
	InterfaceCommonInput
}

// applyAggregateLayer3 writes the provided Layer3 fields into l3, leaving an
// omitted field untouched (read-modify-write). A provided ips list replaces the
// current addresses fully. aggregate.Layer3 is a distinct type from
// ethernet.Layer3, so this mirrors applyEthernetLayer3 rather than sharing it.
func applyAggregateLayer3(l3 *aggregate.Layer3, in InterfaceCommonInput) {
	setPtr(&l3.Mtu, in.Mtu)
	setPtr(&l3.InterfaceManagementProfile, in.InterfaceManagementProfile)
	if in.Ips != nil {
		ips := make([]aggregate.Layer3Ip, len(in.Ips))
		for i, name := range in.Ips {
			ips[i] = aggregate.Layer3Ip{Name: name}
		}
		l3.Ip = ips
	}
	if in.Ipv6Enabled != nil {
		if l3.Ipv6 == nil {
			l3.Ipv6 = &aggregate.Layer3Ipv6{}
		}
		l3.Ipv6.Enabled = in.Ipv6Enabled
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildAggregateInterface(in AggregateInterfaceInput) (*aggregate.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &aggregate.Entry{Name: in.Name}
	setPtr(&e.Comment, in.Comment)
	e.Layer3 = &aggregate.Layer3{}
	applyAggregateLayer3(e.Layer3, in.InterfaceCommonInput)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayAggregateInterface(e *aggregate.Entry, in AggregateInterfaceInput) error {
	setPtr(&e.Comment, in.Comment)
	if in.hasLayer3Fields() {
		if e.Layer3 == nil {
			e.Layer3 = &aggregate.Layer3{}
		}
		applyAggregateLayer3(e.Layer3, in.InterfaceCommonInput)
	}
	return nil
}

func aggregateInterfaceSummary(e *aggregate.Entry) any {
	m := map[string]any{tagNameKey: e.Name, "comment": strVal(e.Comment)}
	if l3 := e.Layer3; l3 != nil {
		putInt(m, "mtu", l3.Mtu)
		m["interface_management_profile"] = strVal(l3.InterfaceManagementProfile)
		names := make([]string, 0, len(l3.Ip))
		for i := range l3.Ip {
			names = append(names, l3.Ip[i].Name)
		}
		m["ips"] = strList(names)
		if l3.Ipv6 != nil {
			putBool(m, "ipv6_enabled", l3.Ipv6.Enabled)
		}
	} else {
		m["ips"] = strList(nil)
		m["interface_management_profile"] = ""
	}
	return m
}

// RegisterAggregateInterfaceTools registers the aggregate interface tools.
// Mutating tools are skipped entirely in read-only mode.
func RegisterAggregateInterfaceTools(s *mcp.Server, d *Deps) {
	svc := newAggregateInterfaceService(d)
	parts := aggregateInterfaceParts()
	scope := func(in AggregateInterfaceInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_interface_list",
		Description: "List aggregate (aggregate-ethernet) interfaces. Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List aggregate interfaces"),
	}, netListHandler(d, "panos_aggregate_interface_list", svc, parts, svc.name, aggregateInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_interface_get",
		Description: "Get one aggregate interface (Layer3 IPs, MTU, management profile, IPv6 toggle). Read-only.",
		Annotations: readOnlyTool("Get aggregate interface"),
	}, netGetHandler(d, "panos_aggregate_interface_get", svc, parts, aggregateInterfaceSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_interface_create",
		Description: "Create a Layer3 aggregate (aggregate-ethernet) interface in the candidate config. This server models only the layer3 mode. Add member ports by setting aggregate_group on the ethernet interfaces. Run panos_commit to apply.",
		Annotations: createTool("Create aggregate interface"),
	}, netCreateHandler(d, "panos_aggregate_interface_create", svc, parts, scope, buildAggregateInterface, aggregateInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_interface_update",
		Description: "Update an aggregate interface: read-modify-write, only provided fields change; a provided ips list replaces the current addresses fully (an empty list clears them). Converting an existing layer2 or virtual-wire aggregate to layer3 is out of scope: sibling mode blocks are never cleared, and their SDK-only subtrees are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update aggregate interface"),
	}, netUpdateHandler(d, "panos_aggregate_interface_update", svc, parts, scope,
		func(in AggregateInterfaceInput) string { return in.Name }, overlayAggregateInterface, aggregateInterfaceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_aggregate_interface_delete",
		Description: "Delete an aggregate interface from the candidate config. Fails while member ports or other config still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete aggregate interface"),
	}, netDeleteHandler(d, "panos_aggregate_interface_delete", svc, parts))
}
