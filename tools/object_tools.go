package tools

import (
	"errors"
	"fmt"

	"github.com/PaloAltoNetworks/pango/objects/address"
	address_group "github.com/PaloAltoNetworks/pango/objects/address/group"
	"github.com/PaloAltoNetworks/pango/objects/admintag"
	"github.com/PaloAltoNetworks/pango/objects/service"
	service_group "github.com/PaloAltoNetworks/pango/objects/service/group"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addressParts supplies address locations for resolveLocation.
func addressParts() locParts[address.Location] {
	return locParts[address.Location]{
		shared: func(string) address.Location {
			return address.Location{Shared: &address.SharedLocation{}}
		},
		vsys: func(v string) address.Location {
			return address.Location{Vsys: &address.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) address.Location {
			return address.Location{DeviceGroup: &address.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// newAddressService adapts pango's address service to crudService; the shared
// nameFixAdapter routes around pango's raw-name Read/Update rejection.
func newAddressService(d *Deps) nameFixAdapter[address.Location, address.Entry] {
	return nameFixAdapter[address.Location, address.Entry]{
		svc:    address.NewService(d.Client),
		client: d.Client,
		name:   func(e *address.Entry) string { return e.Name },
	}
}

// newAddressGroupService adapts pango's address group service to crudService via
// the shared nameFixAdapter.
func newAddressGroupService(d *Deps) nameFixAdapter[address_group.Location, address_group.Entry] {
	return nameFixAdapter[address_group.Location, address_group.Entry]{
		svc:    address_group.NewService(d.Client),
		client: d.Client,
		name:   func(e *address_group.Entry) string { return e.Name },
	}
}

// AddressInput is the input for address create and update tools.
type AddressInput struct {
	Name        string        `json:"name" jsonschema:"Address object name"`
	Location    LocationInput `json:"location,omitempty"`
	IPNetmask   string        `json:"ip_netmask,omitempty" jsonschema:"IP or CIDR, e.g. 10.0.0.5 or 10.0.0.0/24"`
	IPRange     string        `json:"ip_range,omitempty" jsonschema:"Range, e.g. 10.0.0.10-10.0.0.20"`
	FQDN        string        `json:"fqdn,omitempty" jsonschema:"Fully qualified domain name"`
	Description string        `json:"description,omitempty"`
	Tags        []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided"`
}

// countValueTypes returns how many of the mutually-exclusive address value
// fields (ip_netmask, ip_range, fqdn) the input sets. A PAN-OS address object
// has exactly one value type, so create requires exactly one and update at most
// one; both callers share this count. Takes a pointer to avoid copying the
// large AddressInput (the by-value builder signatures carry it for the generic
// handler contract; this private helper is not bound by that).
func countValueTypes(in *AddressInput) int {
	n := 0
	if in.IPNetmask != "" {
		n++
	}
	if in.IPRange != "" {
		n++
	}
	if in.FQDN != "" {
		n++
	}
	return n
}

// buildAddressEntry validates an AddressInput and builds a create entry. Exactly
// one of ip_netmask, ip_range, fqdn must be set: a PAN-OS address object has
// exactly one value type.
//
// AddressInput is taken by value to match the generic handler builder contract
// (createHandler takes build as func(In); In is the go-sdk tool input, decoded by
// value). A pointer would ripple *AddressInput through every resource tool and its
// MCP input schema.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see doc comment.
func buildAddressEntry(in AddressInput) (*address.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if countValueTypes(&in) != 1 {
		return nil, errors.New("exactly one of ip_netmask, ip_range, fqdn is required")
	}
	e := &address.Entry{Name: in.Name, Tag: in.Tags}
	if in.IPNetmask != "" {
		e.IpNetmask = ptr(in.IPNetmask)
	}
	if in.IPRange != "" {
		e.IpRange = ptr(in.IPRange)
	}
	if in.FQDN != "" {
		e.Fqdn = ptr(in.FQDN)
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return e, nil
}

// overlayAddress applies provided fields onto the current entry. At most one
// value type (ip_netmask, ip_range, fqdn) may be provided; providing one clears
// every other value type, including a pre-existing ip_wildcard set outside this
// tool, since an address object has exactly one value. Providing more than one is
// rejected, matching buildAddressEntry. An omitted (empty) description leaves the
// existing description unchanged; a nil tags slice leaves tags unchanged, while a
// non-nil empty slice clears them.
//
// In is taken by value for the same reason as buildAddressEntry: updateHandler
// takes overlay as func(*E, In) and In is the go-sdk tool input, decoded by value.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayAddress(e *address.Entry, in AddressInput) error {
	if countValueTypes(&in) > 1 {
		return errors.New("at most one of ip_netmask, ip_range, fqdn may be set")
	}
	// Each branch rewrites all four value fields: it sets the chosen type and nils
	// the other three. IpWildcard is not a tool input but the read-modify-write
	// reads it back, so an object created elsewhere with ip-wildcard would
	// otherwise keep it and produce a dual-valued (invalid) entry.
	if in.IPNetmask != "" {
		e.IpNetmask, e.IpRange, e.Fqdn, e.IpWildcard = ptr(in.IPNetmask), nil, nil, nil
	}
	if in.IPRange != "" {
		e.IpNetmask, e.IpRange, e.Fqdn, e.IpWildcard = nil, ptr(in.IPRange), nil, nil
	}
	if in.FQDN != "" {
		e.IpNetmask, e.IpRange, e.Fqdn, e.IpWildcard = nil, nil, ptr(in.FQDN), nil
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	return nil
}

// summaryBase builds the fields every object summary shares: name, description
// and tags. Each resource summary adds its own type-specific keys onto the
// returned map. Centralising these keys also keeps the shared literals under
// goconst's occurrence threshold as more resources are added.
func summaryBase(name string, description *string, tags []string) map[string]any {
	return map[string]any{"name": name, descriptionKey: strVal(description), "tags": tags}
}

// addressSummary reduces an entry to the list view fields.
func addressSummary(e *address.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["ip_netmask"] = strVal(e.IpNetmask)
	m["ip_range"] = strVal(e.IpRange)
	m["fqdn"] = strVal(e.Fqdn)
	m["ip_wildcard"] = strVal(e.IpWildcard)
	return m
}

// RegisterAddressTools registers the address object tools. Mutating tools are
// skipped entirely in read-only mode.
func RegisterAddressTools(s *mcp.Server, d *Deps) {
	svc := newAddressService(d)
	parts := addressParts()
	resolve := func(in LocationInput) (address.Location, error) { return resolveLocation(d, in, parts) }
	name := func(e *address.Entry) string { return e.Name }
	loc := func(in AddressInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_list",
		Description: "List address objects (IP netmask, IP range, FQDN) at a location. Read-only.",
		Annotations: readOnlyTool("List addresses"),
	}, listHandler[address.Location, address.Entry](d, "panos_address_list", svc, resolve, name, addressSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_get",
		Description: "Get one address object by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get address"),
	}, getHandler[address.Location, address.Entry](d, "panos_address_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_create",
		Description: "Create an address object in the candidate config. Exactly one of ip_netmask, ip_range, fqdn. Run panos_commit to apply.",
		Annotations: createTool("Create address"),
	}, createHandler[address.Location, address.Entry, AddressInput](d, "panos_address_create", svc, resolve, loc, buildAddressEntry))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_update",
		Description: "Update an address object: read-modify-write, only provided fields change; provided arrays replace fully. Candidate config only.",
		Annotations: updateTool("Update address"),
	}, updateHandler[address.Location, address.Entry, AddressInput](d, "panos_address_update", svc, resolve, loc,
		func(in AddressInput) string { return in.Name }, overlayAddress))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_delete",
		Description: "Delete an address object from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete address"),
	}, deleteHandler[address.Location, address.Entry](d, "panos_address_delete", svc, resolve))
}

// addressGroupParts supplies address group locations for resolveLocation.
func addressGroupParts() locParts[address_group.Location] {
	return locParts[address_group.Location]{
		shared: func(string) address_group.Location {
			return address_group.Location{Shared: &address_group.SharedLocation{}}
		},
		vsys: func(v string) address_group.Location {
			return address_group.Location{Vsys: &address_group.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) address_group.Location {
			return address_group.Location{DeviceGroup: &address_group.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// AddressGroupInput is the input for address group create and update tools.
type AddressGroupInput struct {
	Name          string        `json:"name" jsonschema:"Address group name"`
	Location      LocationInput `json:"location,omitempty"`
	Static        []string      `json:"static,omitempty" jsonschema:"Static member names; a non-empty list replaces the members. An explicitly empty list is rejected on update, since a static group cannot be emptied in place (switch to dynamic_filter or delete the group)"`
	DynamicFilter string        `json:"dynamic_filter,omitempty" jsonschema:"Dynamic match expression over tags, e.g. 'prod' and 'web'"`
	Description   string        `json:"description,omitempty"`
	Tags          []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided"`
}

// buildAddressGroupEntry validates an AddressGroupInput and builds a create
// entry. Exactly one of static, dynamic_filter must be set: a PAN-OS address
// group is either a static member list or a dynamic tag-filter match, never
// both. An empty static list counts as absent; a group needs members.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildAddressGroupEntry(in AddressGroupInput) (*address_group.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	hasStatic := len(in.Static) > 0
	hasDynamic := in.DynamicFilter != ""
	if hasStatic == hasDynamic {
		return nil, errors.New("exactly one of static, dynamic_filter is required")
	}
	e := &address_group.Entry{Name: in.Name, Tag: in.Tags}
	if hasStatic {
		e.Static = in.Static
	} else {
		e.Dynamic = &address_group.Dynamic{Filter: ptr(in.DynamicFilter)}
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return e, nil
}

// overlayAddressGroup applies provided fields onto the current entry. At most one
// of static, dynamic_filter may be provided; each provided side rewrites both
// membership fields, so switching a group's type clears the other side and the
// read-modify-write cannot emit a dual-typed (invalid) entry. A non-empty static
// list replaces membership; an explicitly empty static list is rejected, since a
// static group cannot be emptied in place (switch to dynamic_filter or delete the
// group). An omitted (empty) description leaves the existing one unchanged; a nil
// tags slice leaves tags unchanged, while a non-nil empty slice clears them.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayAddressGroup(e *address_group.Entry, in AddressGroupInput) error {
	if in.Static != nil && len(in.Static) == 0 {
		return errors.New("static must have at least one member; a static group cannot be emptied in place (switch to dynamic_filter or delete the group)")
	}
	hasStatic := len(in.Static) > 0
	hasDynamic := in.DynamicFilter != ""
	if hasStatic && hasDynamic {
		return errors.New("at most one of static, dynamic_filter may be set")
	}
	if hasStatic {
		e.Static, e.Dynamic = in.Static, nil
	}
	if hasDynamic {
		e.Static, e.Dynamic = nil, &address_group.Dynamic{Filter: ptr(in.DynamicFilter)}
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	return nil
}

// addressGroupSummary reduces an entry to the list view fields.
func addressGroupSummary(e *address_group.Entry) any {
	filter := ""
	if e.Dynamic != nil {
		filter = strVal(e.Dynamic.Filter)
	}
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["static"] = e.Static
	m["dynamic_filter"] = filter
	return m
}

// RegisterAddressGroupTools registers the address group tools. Mutating tools
// are skipped entirely in read-only mode.
func RegisterAddressGroupTools(s *mcp.Server, d *Deps) {
	svc := newAddressGroupService(d)
	parts := addressGroupParts()
	resolve := func(in LocationInput) (address_group.Location, error) {
		return resolveLocation(d, in, parts)
	}
	name := func(e *address_group.Entry) string { return e.Name }
	loc := func(in AddressGroupInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_list",
		Description: "List address groups (static member list or dynamic tag filter) at a location. Read-only.",
		Annotations: readOnlyTool("List address groups"),
	}, listHandler[address_group.Location, address_group.Entry](d, "panos_address_group_list", svc, resolve, name, addressGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_get",
		Description: "Get one address group by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get address group"),
	}, getHandler[address_group.Location, address_group.Entry](d, "panos_address_group_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_create",
		Description: "Create an address group in the candidate config. Exactly one of static, dynamic_filter. Run panos_commit to apply.",
		Annotations: createTool("Create address group"),
	}, createHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_create", svc, resolve, loc, buildAddressGroupEntry))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_update",
		Description: "Update an address group: read-modify-write, only provided fields change. Tags replace fully (an empty list clears them); a non-empty static or dynamic_filter replaces membership and switches the group type. An explicitly empty static list is rejected: a static group cannot be emptied in place, so switch to dynamic_filter or delete the group. Candidate config only.",
		Annotations: updateTool("Update address group"),
	}, updateHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_update", svc, resolve, loc,
		func(in AddressGroupInput) string { return in.Name }, overlayAddressGroup))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_delete",
		Description: "Delete an address group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete address group"),
	}, deleteHandler[address_group.Location, address_group.Entry](d, "panos_address_group_delete", svc, resolve))
}

// serviceParts supplies service object locations for resolveLocation.
func serviceParts() locParts[service.Location] {
	return locParts[service.Location]{
		shared: func(string) service.Location {
			return service.Location{Shared: &service.SharedLocation{}}
		},
		vsys: func(v string) service.Location {
			return service.Location{Vsys: &service.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) service.Location {
			return service.Location{DeviceGroup: &service.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// newServiceService adapts pango's service object service to crudService via the
// shared nameFixAdapter; pango's raw-name Read/Update would otherwise be rejected
// client-side (see nameFixService).
func newServiceService(d *Deps) nameFixAdapter[service.Location, service.Entry] {
	return nameFixAdapter[service.Location, service.Entry]{
		svc:    service.NewService(d.Client),
		client: d.Client,
		name:   func(e *service.Entry) string { return e.Name },
	}
}

// ServiceInput is the input for service create and update tools.
type ServiceInput struct {
	Name        string        `json:"name" jsonschema:"Service object name"`
	Location    LocationInput `json:"location,omitempty"`
	Protocol    string        `json:"protocol,omitempty" jsonschema:"tcp or udp (required on create; on update required together with port when changing ports)"`
	Port        string        `json:"port,omitempty" jsonschema:"Destination port or range, e.g. 8080 or 8000-8080"`
	SourcePort  string        `json:"source_port,omitempty" jsonschema:"Source port or range; only meaningful together with protocol and port"`
	Description string        `json:"description,omitempty"`
	Tags        []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided"`
}

// buildServiceProtocol maps protocol, port, and source_port onto the pango
// protocol struct. A service object is exactly one of tcp or udp, and PAN-OS
// requires a destination port.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildServiceProtocol(in ServiceInput) (*service.Protocol, error) {
	if in.Port == "" {
		return nil, errors.New("port is required")
	}
	switch in.Protocol {
	case "tcp":
		p := &service.ProtocolTcp{Port: ptr(in.Port)}
		if in.SourcePort != "" {
			p.SourcePort = ptr(in.SourcePort)
		}
		return &service.Protocol{Tcp: p}, nil
	case "udp":
		p := &service.ProtocolUdp{Port: ptr(in.Port)}
		if in.SourcePort != "" {
			p.SourcePort = ptr(in.SourcePort)
		}
		return &service.Protocol{Udp: p}, nil
	default:
		return nil, fmt.Errorf("protocol must be \"tcp\" or \"udp\", got %q", in.Protocol)
	}
}

// buildServiceEntry validates a ServiceInput and builds a create entry.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildServiceEntry(in ServiceInput) (*service.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	proto, err := buildServiceProtocol(in)
	if err != nil {
		return nil, err
	}
	e := &service.Entry{Name: in.Name, Tag: in.Tags, Protocol: proto}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return e, nil
}

// overlayService applies provided fields onto the current entry. Touching the
// protocol side (protocol, port, or source_port) requires protocol and port
// together and rebuilds that side's port and source_port from the input, so an
// omitted source_port clears a pre-existing one. A timeout override, which this
// tool does not expose, is carried across a same-protocol change so a plain port
// edit cannot silently destroy it; switching tcp to udp (or back) drops the old
// side entirely, including its override, since the override belongs to the other
// protocol. An omitted (empty) description leaves the existing description
// unchanged; a nil tags slice leaves tags unchanged, while a non-nil empty slice
// clears them.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayService(e *service.Entry, in ServiceInput) error {
	if in.Protocol != "" || in.Port != "" || in.SourcePort != "" {
		if in.Protocol == "" || in.Port == "" {
			return errors.New("changing the protocol or ports requires both protocol and port")
		}
		proto, err := buildServiceProtocol(in)
		if err != nil {
			return err
		}
		carryServiceOverride(proto, e.Protocol)
		e.Protocol = proto
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	return nil
}

// carryServiceOverride copies a timeout override from the current protocol block
// (src) onto the freshly built one (dst) when the protocol type is unchanged.
// Override is not a tool input, so a read-modify-write that rebuilds the block
// from input would otherwise silently drop it on a plain port change. A
// protocol-type switch (tcp <-> udp) carries nothing: the override belongs to
// the side being removed.
func carryServiceOverride(dst, src *service.Protocol) {
	if src == nil {
		return
	}
	if dst.Tcp != nil && src.Tcp != nil {
		dst.Tcp.Override = src.Tcp.Override
	}
	if dst.Udp != nil && src.Udp != nil {
		dst.Udp.Override = src.Udp.Override
	}
}

// serviceSummary reduces an entry to the list view fields.
func serviceSummary(e *service.Entry) any {
	proto, port, srcPort := "", "", ""
	if e.Protocol != nil {
		switch {
		case e.Protocol.Tcp != nil:
			proto, port, srcPort = "tcp", strVal(e.Protocol.Tcp.Port), strVal(e.Protocol.Tcp.SourcePort)
		case e.Protocol.Udp != nil:
			proto, port, srcPort = "udp", strVal(e.Protocol.Udp.Port), strVal(e.Protocol.Udp.SourcePort)
		}
	}
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["protocol"] = proto
	m["port"] = port
	m["source_port"] = srcPort
	return m
}

// RegisterServiceTools registers the service object tools. Mutating tools are
// skipped entirely in read-only mode.
func RegisterServiceTools(s *mcp.Server, d *Deps) {
	svc := newServiceService(d)
	parts := serviceParts()
	resolve := func(in LocationInput) (service.Location, error) { return resolveLocation(d, in, parts) }
	name := func(e *service.Entry) string { return e.Name }
	loc := func(in ServiceInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_list",
		Description: "List service objects (TCP/UDP port definitions) at a location. Read-only.",
		Annotations: readOnlyTool("List services"),
	}, listHandler[service.Location, service.Entry](d, "panos_service_list", svc, resolve, name, serviceSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_get",
		Description: "Get one service object by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get service"),
	}, getHandler[service.Location, service.Entry](d, "panos_service_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_create",
		Description: "Create a service object in the candidate config. protocol (tcp|udp) and port are required. Run panos_commit to apply.",
		Annotations: createTool("Create service"),
	}, createHandler[service.Location, service.Entry, ServiceInput](d, "panos_service_create", svc, resolve, loc, buildServiceEntry))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_update",
		Description: "Update a service object: read-modify-write, only provided fields change; changing ports requires protocol and port together and replaces the whole protocol block. Candidate config only.",
		Annotations: updateTool("Update service"),
	}, updateHandler[service.Location, service.Entry, ServiceInput](d, "panos_service_update", svc, resolve, loc,
		func(in ServiceInput) string { return in.Name }, overlayService))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_delete",
		Description: "Delete a service object from the candidate config. Fails while rules reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete service"),
	}, deleteHandler[service.Location, service.Entry](d, "panos_service_delete", svc, resolve))
}

// serviceGroupParts supplies service group locations for resolveLocation.
func serviceGroupParts() locParts[service_group.Location] {
	return locParts[service_group.Location]{
		shared: func(string) service_group.Location {
			return service_group.Location{Shared: &service_group.SharedLocation{}}
		},
		vsys: func(v string) service_group.Location {
			return service_group.Location{Vsys: &service_group.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) service_group.Location {
			return service_group.Location{DeviceGroup: &service_group.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// newServiceGroupService adapts pango's service group service to crudService
// via the shared nameFixAdapter; pango's raw-name Read/Update would otherwise
// be rejected client-side (see nameFixService).
func newServiceGroupService(d *Deps) nameFixAdapter[service_group.Location, service_group.Entry] {
	return nameFixAdapter[service_group.Location, service_group.Entry]{
		svc:    service_group.NewService(d.Client),
		client: d.Client,
		name:   func(e *service_group.Entry) string { return e.Name },
	}
}

// ServiceGroupInput is the input for service group create and update tools.
// PAN-OS service groups have no description field (pango
// objects/service/group Entry), so none is exposed.
type ServiceGroupInput struct {
	Name     string        `json:"name" jsonschema:"Service group name"`
	Location LocationInput `json:"location,omitempty"`
	Members  []string      `json:"members,omitempty" jsonschema:"Member service or service group names; at least one is required on create, and a non-empty list replaces the full membership on update (an explicitly empty list is rejected)"`
	Tags     []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided"`
}

// buildServiceGroupEntry validates a ServiceGroupInput and builds a create
// entry; a name and at least one member are required.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildServiceGroupEntry(in ServiceGroupInput) (*service_group.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if len(in.Members) == 0 {
		return nil, errors.New("at least one member is required")
	}
	return &service_group.Entry{Name: in.Name, Members: in.Members, Tag: in.Tags}, nil
}

// overlayServiceGroup applies provided fields onto the current entry. A
// non-empty members list replaces the membership; an explicitly empty one is
// rejected, because a group cannot be emptied in place (delete it instead). A
// nil tags slice leaves tags unchanged, while a non-nil empty slice clears them.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayServiceGroup(e *service_group.Entry, in ServiceGroupInput) error {
	if in.Members != nil && len(in.Members) == 0 {
		return errors.New("members must have at least one entry; a group cannot be emptied in place (delete the group instead)")
	}
	if len(in.Members) > 0 {
		e.Members = in.Members
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	return nil
}

// serviceGroupSummary reduces an entry to the list view fields. Service groups
// have no description field (pango objects/service/group Entry), so this does
// not build on summaryBase: hand-rolling the map avoids emitting a bogus empty
// description.
func serviceGroupSummary(e *service_group.Entry) any {
	return map[string]any{"name": e.Name, "members": e.Members, "tags": e.Tag}
}

// RegisterServiceGroupTools registers the service group tools. Mutating tools
// are skipped entirely in read-only mode.
func RegisterServiceGroupTools(s *mcp.Server, d *Deps) {
	svc := newServiceGroupService(d)
	parts := serviceGroupParts()
	resolve := func(in LocationInput) (service_group.Location, error) {
		return resolveLocation(d, in, parts)
	}
	name := func(e *service_group.Entry) string { return e.Name }
	loc := func(in ServiceGroupInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_group_list",
		Description: "List service groups (named sets of services and service groups) at a location. Read-only.",
		Annotations: readOnlyTool("List service groups"),
	}, listHandler[service_group.Location, service_group.Entry](d, "panos_service_group_list", svc, resolve, name, serviceGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_group_get",
		Description: "Get one service group by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get service group"),
	}, getHandler[service_group.Location, service_group.Entry](d, "panos_service_group_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_group_create",
		Description: "Create a service group in the candidate config. At least one member is required. Run panos_commit to apply.",
		Annotations: createTool("Create service group"),
	}, createHandler[service_group.Location, service_group.Entry, ServiceGroupInput](d, "panos_service_group_create", svc, resolve, loc, buildServiceGroupEntry))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_group_update",
		Description: "Update a service group: read-modify-write, only provided fields change. A non-empty members list replaces the full membership; an explicitly empty members list is rejected (a group cannot be emptied in place; delete it instead); tags replace fully (an empty list clears them). Candidate config only.",
		Annotations: updateTool("Update service group"),
	}, updateHandler[service_group.Location, service_group.Entry, ServiceGroupInput](d, "panos_service_group_update", svc, resolve, loc,
		func(in ServiceGroupInput) string { return in.Name }, overlayServiceGroup))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_service_group_delete",
		Description: "Delete a service group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete service group"),
	}, deleteHandler[service_group.Location, service_group.Entry](d, "panos_service_group_delete", svc, resolve))
}

// TagInput is the input for tag create and update tools. DisableOverride is
// not exposed, matching how the sibling inputs omit their override fields; it
// rides through the read-modify-write untouched.
type TagInput struct {
	Name     string        `json:"name" jsonschema:"Tag name"`
	Location LocationInput `json:"location,omitempty"`
	Color    string        `json:"color,omitempty" jsonschema:"PAN-OS named color code, color1 to color42, excluding the unused color11 and color18"`
	Comments string        `json:"comments,omitempty"`
}

// buildTagEntry validates a TagInput and builds a create entry; only the name
// is required. Color and comments map to pointer fields and are set only when
// non-empty, so a bare create omits them from the XML.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildTagEntry(in TagInput) (*admintag.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &admintag.Entry{Name: in.Name}
	if in.Color != "" {
		e.Color = ptr(in.Color)
	}
	if in.Comments != "" {
		e.Comments = ptr(in.Comments)
	}
	return e, nil
}

// overlayTag applies provided fields onto the current entry. An omitted
// (empty) color or comments leaves the current value unchanged, matching how
// the sibling overlays treat their description fields; consequently neither
// field can be cleared in place, only overwritten. DisableOverride is not a
// tool input and passes through the read-modify-write untouched.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayTag(e *admintag.Entry, in TagInput) error {
	if in.Color != "" {
		e.Color = ptr(in.Color)
	}
	if in.Comments != "" {
		e.Comments = ptr(in.Comments)
	}
	return nil
}

// tagParts supplies tag locations for resolveLocation. The pango package is
// objects/admintag: it targets the same .../tag config node as objects/tag,
// but exposes the XpathWithComponents and *WithXpath surface nameFixAdapter
// needs, which objects/tag does not.
func tagParts() locParts[admintag.Location] {
	return locParts[admintag.Location]{
		shared: func(string) admintag.Location {
			return admintag.Location{Shared: &admintag.SharedLocation{}}
		},
		vsys: func(v string) admintag.Location {
			return admintag.Location{Vsys: &admintag.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) admintag.Location {
			return admintag.Location{DeviceGroup: &admintag.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// newTagService adapts pango's admin tag service to crudService via the
// shared nameFixAdapter; pango's raw-name Read/Update would otherwise be
// rejected client-side (see nameFixService).
func newTagService(d *Deps) nameFixAdapter[admintag.Location, admintag.Entry] {
	return nameFixAdapter[admintag.Location, admintag.Entry]{
		svc:    admintag.NewService(d.Client),
		client: d.Client,
		name:   func(e *admintag.Entry) string { return e.Name },
	}
}

// descriptionKey is the "description" map key shared by the summary helpers.
// goconst counts map composite-literal keys, and three production summaries
// (summaryBase here plus deviceGroupSummary and templateSummary in
// device_tools.go) emit it, which trips min-occurrences=3 (measured with
// golangci-lint 2.12.2 and this repo's config). The const collapses those to a
// single literal.
const descriptionKey = "description"

// tagNameKey is the "name" map key shared by tagSummary and the device
// summaries (deviceGroupSummary, templateSummary in device_tools.go). goconst
// counts map composite-literal keys: summaryBase and serviceGroupSummary
// already hold two production "name" literals, so any further literal would
// trip min-occurrences=3 against this existing const (measured with
// golangci-lint 2.12.2 and this repo's config). Routing the other summaries
// through the const keeps the literal count at two without touching those two
// siblings.
const tagNameKey = "name"

// tagSummary reduces an entry to the list view fields. Tags have no
// description and no tag list of their own (pango objects/admintag Entry), so
// this does not build on summaryBase: hand-rolling the map avoids emitting
// bogus empty fields.
func tagSummary(e *admintag.Entry) any {
	return map[string]any{tagNameKey: e.Name, "color": strVal(e.Color), "comments": strVal(e.Comments)}
}

// RegisterTagTools registers the tag tools. Mutating tools are skipped
// entirely in read-only mode.
func RegisterTagTools(s *mcp.Server, d *Deps) {
	svc := newTagService(d)
	parts := tagParts()
	resolve := func(in LocationInput) (admintag.Location, error) { return resolveLocation(d, in, parts) }
	name := func(e *admintag.Entry) string { return e.Name }
	loc := func(in TagInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tag_list",
		Description: "List tags (labels attachable to objects and rules, each with an optional color) at a location. Read-only.",
		Annotations: readOnlyTool("List tags"),
	}, listHandler[admintag.Location, admintag.Entry](d, "panos_tag_list", svc, resolve, name, tagSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tag_get",
		Description: "Get one tag by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get tag"),
	}, getHandler[admintag.Location, admintag.Entry](d, "panos_tag_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tag_create",
		Description: "Create a tag in the candidate config. Only the name is required; color (color1 to color42, excluding color11 and color18) and comments are optional. Run panos_commit to apply.",
		Annotations: createTool("Create tag"),
	}, createHandler[admintag.Location, admintag.Entry, TagInput](d, "panos_tag_create", svc, resolve, loc, buildTagEntry))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tag_update",
		Description: "Update a tag: read-modify-write, only provided fields change; an omitted color or comments keeps the current value, so neither can be cleared in place. Candidate config only.",
		Annotations: updateTool("Update tag"),
	}, updateHandler[admintag.Location, admintag.Entry, TagInput](d, "panos_tag_update", svc, resolve, loc,
		func(in TagInput) string { return in.Name }, overlayTag))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tag_delete",
		Description: "Delete a tag from the candidate config. Fails while objects or rules still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete tag"),
	}, deleteHandler[admintag.Location, admintag.Entry](d, "panos_tag_delete", svc, resolve))
}
