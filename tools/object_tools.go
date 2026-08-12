package tools

import (
	"context"
	"errors"

	"github.com/PaloAltoNetworks/pango/objects/address"
	"github.com/PaloAltoNetworks/pango/util"
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

// addressService adapts pango's address.Service to crudService. pango's
// name-based Read and Update pass the raw object name to
// Location.XpathWithComponents (objects/address/service.go read/Update), which
// rejects any component not shaped like "entry[...]"
// (objects/address/location.go XpathWithComponents), so both fail client-side
// on any real name. The adapter pre-wraps the name with util.AsEntryXpath and
// drives Update through the xpath-based SDK methods. Create, Delete, and List
// wrap the name themselves in the SDK and pass through unchanged.
//
// Revisit on any pango upgrade: if the SDK starts wrapping names internally,
// this adapter would double-wrap. TestAddressAPIErrorSurfaces pins that the get
// reaches the API with an entry xpath, which flags a regression here.
type addressService struct {
	*address.Service
	client util.PangoClient
}

func newAddressService(d *Deps) addressService {
	return addressService{Service: address.NewService(d.Client), client: d.Client}
}

// Read fetches one entry by name using the given action ("get" or "show").
func (s addressService) Read(ctx context.Context, loc address.Location, name, action string) (*address.Entry, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	// Call the embedded Service.Read, not s.Read: s.Read is this override, so
	// s.Read here would recurse infinitely.
	return s.Service.Read(ctx, loc, util.AsEntryXpath(name), action)
}

// Update edits the entry in place, mirroring the SDK's Update
// (objects/address/service.go Update) with the xpath built from a properly
// wrapped entry name. The update tool never renames (overlayAddress never
// touches Name), so the SDK rename path is unreachable here.
func (s addressService) Update(ctx context.Context, loc address.Location, entry *address.Entry, name string) (*address.Entry, error) {
	if entry.Name == "" {
		return nil, errors.New("name is required")
	}
	path, err := loc.XpathWithComponents(s.client.Versioning(), util.AsEntryXpath(entry.Name))
	if err != nil {
		return nil, err
	}
	xpath := util.AsXpath(path)
	if err := s.UpdateWithXpath(ctx, xpath, entry, name); err != nil {
		return nil, err
	}
	return s.ReadWithXpath(ctx, xpath, "get")
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
