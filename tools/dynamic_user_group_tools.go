package tools

import (
	"errors"

	dug "github.com/PaloAltoNetworks/pango/device/dynamicusergroups"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Dynamic user group (device/dynamicusergroups)
// ---------------------------------------------------------------------------
// A dynamic user group selects its members at match time from a tag-based
// filter expression, rather than from a static member list. It lives at the
// object scope (shared, vsys or device_group), the same location model as the
// address and service objects.

func newDynamicUserGroupService(d *Deps) nameFixAdapter[dug.Location, dug.Entry] {
	return nameFixAdapter[dug.Location, dug.Entry]{
		svc:    dug.NewService(d.Client),
		client: d.Client,
		name:   func(e *dug.Entry) string { return e.Name },
	}
}

func dynamicUserGroupParts() locParts[dug.Location] {
	return locParts[dug.Location]{
		shared: func(string) dug.Location {
			return dug.Location{Shared: &dug.SharedLocation{}}
		},
		vsys: func(v string) dug.Location {
			return dug.Location{Vsys: &dug.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dgName, _ string) dug.Location {
			return dug.Location{DeviceGroup: &dug.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dgName}}
		},
	}
}

// DynamicUserGroupInput is the input for the dynamic user group create and
// update tools. filter is the tag-match expression that selects members; tags
// are the administrative tags on the group itself. disable-override is not
// exposed, matching how the sibling object inputs omit their override fields; it
// rides through the read-modify-write untouched.
type DynamicUserGroupInput struct {
	Name        string        `json:"name" jsonschema:"Dynamic user group name"`
	Location    LocationInput `json:"location,omitzero"`
	Description string        `json:"description,omitempty"`
	Filter      string        `json:"filter,omitempty" jsonschema:"Tag-based match expression selecting the group members, e.g. 'contractor' and 'emea'"`
	Tags        []string      `json:"tags,omitempty" jsonschema:"Administrative tags on the group itself; a provided list replaces the current tags fully"`
}

// buildDynamicUserGroup validates a DynamicUserGroupInput and builds a create
// entry; only the name is required. description and filter map to pointer fields
// and are set only when non-empty, so a bare create omits them from the XML.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildDynamicUserGroup(in DynamicUserGroupInput) (*dug.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &dug.Entry{Name: in.Name, Tag: in.Tags}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if in.Filter != "" {
		e.Filter = new(in.Filter)
	}
	return e, nil
}

// overlayDynamicUserGroup applies provided fields onto the current entry. An
// omitted (empty) description or filter leaves the current value unchanged, so
// neither can be cleared in place; a provided tags list replaces the current
// tags fully.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayDynamicUserGroup(e *dug.Entry, in DynamicUserGroupInput) error {
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if in.Filter != "" {
		e.Filter = new(in.Filter)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	return nil
}

func dynamicUserGroupSummary(e *dug.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["filter"] = strVal(e.Filter)
	m["tags"] = strList(e.Tag)
	return m
}

// RegisterDynamicUserGroupTools registers the dynamic user group CRUD tools.
// Mutating tools are skipped entirely in read-only mode.
func RegisterDynamicUserGroupTools(s *mcp.Server, d *Deps) {
	svc := newDynamicUserGroupService(d)
	parts := dynamicUserGroupParts()
	resolve := func(in LocationInput) (dug.Location, error) { return resolveLocation(d, in, parts) }
	name := svc.name
	loc := func(in DynamicUserGroupInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_user_group_list",
		Description: "List dynamic user groups (tag-based member selection) at a location. Read-only.",
		Annotations: readOnlyTool("List dynamic user groups"),
	}, listHandler[dug.Location, dug.Entry](d, "panos_dynamic_user_group_list", svc, resolve, name, dynamicUserGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_user_group_get",
		Description: "Get one dynamic user group by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get dynamic user group"),
	}, getHandler[dug.Location, dug.Entry](d, "panos_dynamic_user_group_get", svc, resolve, dynamicUserGroupSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_user_group_create",
		Description: "Create a dynamic user group in the candidate config. Only the name is required; filter is the tag-match expression that selects members. Run panos_commit to apply.",
		Annotations: createTool("Create dynamic user group"),
	}, createHandler[dug.Location, dug.Entry, DynamicUserGroupInput](d, "panos_dynamic_user_group_create", svc, resolve, loc, buildDynamicUserGroup, dynamicUserGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_user_group_update",
		Description: "Update a dynamic user group: read-modify-write, only provided fields change. An omitted description or filter keeps the current value; a provided tags list replaces the tags fully. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update dynamic user group"),
	}, updateHandler[dug.Location, dug.Entry, DynamicUserGroupInput](d, "panos_dynamic_user_group_update", svc, resolve, loc,
		func(in DynamicUserGroupInput) string { return in.Name }, overlayDynamicUserGroup, dynamicUserGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_user_group_delete",
		Description: "Delete a dynamic user group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete dynamic user group"),
	}, deleteHandler[dug.Location, dug.Entry](d, "panos_dynamic_user_group_delete", svc, resolve))
}
