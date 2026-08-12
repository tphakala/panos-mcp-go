package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/objects/address"
	address_group "github.com/PaloAltoNetworks/pango/objects/address/group"
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
	e := &address.Entry{Name: in.Name, Tag: in.Tags}
	set := 0
	if in.IPNetmask != "" {
		set++
		e.IpNetmask = ptr(in.IPNetmask)
	}
	if in.IPRange != "" {
		set++
		e.IpRange = ptr(in.IPRange)
	}
	if in.FQDN != "" {
		set++
		e.Fqdn = ptr(in.FQDN)
	}
	if set != 1 {
		return nil, errors.New("exactly one of ip_netmask, ip_range, fqdn is required")
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
	set := 0
	if in.IPNetmask != "" {
		set++
	}
	if in.IPRange != "" {
		set++
	}
	if in.FQDN != "" {
		set++
	}
	if set > 1 {
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

// addressSummary reduces an entry to the list view fields.
func addressSummary(e *address.Entry) any {
	return map[string]any{
		"name": e.Name, "ip_netmask": strVal(e.IpNetmask), "ip_range": strVal(e.IpRange),
		"fqdn": strVal(e.Fqdn), "ip_wildcard": strVal(e.IpWildcard),
		"description": strVal(e.Description), "tags": e.Tag,
	}
}

// RegisterAddressTools registers the address object tools. Mutating tools are
// skipped entirely in read-only mode.
func RegisterAddressTools(s *mcp.Server, d *Deps) {
	svc := newAddressService(d)
	resolve := func(in LocationInput) (address.Location, error) { return resolveLocation(d, in, addressParts()) }
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
	Static        []string      `json:"static,omitempty" jsonschema:"Static member names; a non-empty list replaces the members. An empty list is ignored, since a static group cannot be emptied in place (switch to dynamic_filter or delete the group)"`
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
// read-modify-write cannot emit a dual-typed (invalid) entry. A static list counts
// as provided only when it has members; an empty static list is ignored, since a
// static group cannot be emptied in place (switch to dynamic_filter or delete the
// group). An omitted (empty) description leaves the existing one unchanged; a nil
// tags slice leaves tags unchanged, while a non-nil empty slice clears them.
//
//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayAddressGroup(e *address_group.Entry, in AddressGroupInput) error {
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
	return map[string]any{
		"name": e.Name, "static": e.Static, "dynamic_filter": filter,
		"description": strVal(e.Description), "tags": e.Tag,
	}
}

// RegisterAddressGroupTools registers the address group tools. Mutating tools
// are skipped entirely in read-only mode.
func RegisterAddressGroupTools(s *mcp.Server, d *Deps) {
	svc := newAddressGroupService(d)
	resolve := func(in LocationInput) (address_group.Location, error) {
		return resolveLocation(d, in, addressGroupParts())
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
		Description: "Update an address group: read-modify-write, only provided fields change. Tags replace fully (an empty list clears them); a non-empty static or dynamic_filter replaces membership and switches the group type. An empty static list is ignored: a static group cannot be emptied in place, so switch to dynamic_filter or delete the group. Candidate config only.",
		Annotations: updateTool("Update address group"),
	}, updateHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_update", svc, resolve, loc,
		func(in AddressGroupInput) string { return in.Name }, overlayAddressGroup))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_address_group_delete",
		Description: "Delete an address group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete address group"),
	}, deleteHandler[address_group.Location, address_group.Entry](d, "panos_address_group_delete", svc, resolve))
}
