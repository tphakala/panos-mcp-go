package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PaloAltoNetworks/pango/panorama/devicegroup"
	"github.com/PaloAltoNetworks/pango/panorama/template"
	"github.com/PaloAltoNetworks/pango/panorama/template_stack"
	"github.com/PaloAltoNetworks/pango/panorama/template_variable"
)

// The four Panorama container resources (device group, template, template
// stack, template variable) are Panorama-only: every tool here gates on
// d.IsPanorama. Device groups, templates and template stacks live at a single
// fixed Panorama location, so they resolve through panoramaFixedResolve and the
// public single-object tools take PanoramaNameInput (no location parameter),
// mirroring the existing panos_device_group_list / panos_template_list wrappers.
// The template variable is scoped to a template or template stack, so it uses
// the net-scope resolver with the Ngfw branch disabled.

// PanoramaNameInput is the single-object input for a fixed Panorama-level
// resource. It carries only a name: the location is fixed, so advertising a
// location parameter that would always be rejected is avoided.
type PanoramaNameInput struct {
	Name string `json:"name" jsonschema:"Object name"`
}

// panoramaNameAdapter wraps a NameInput handler so it can be registered against
// PanoramaNameInput, which carries only a name at a fixed Panorama location.
// Every fixed Panorama-level get and delete tool routes through it, copying the
// name through and leaving the location empty.
func panoramaNameAdapter(inner func(context.Context, *mcp.CallToolRequest, NameInput) (*mcp.CallToolResult, any, error)) func(context.Context, *mcp.CallToolRequest, PanoramaNameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in PanoramaNameInput) (*mcp.CallToolResult, any, error) {
		return inner(ctx, req, NameInput{Name: in.Name})
	}
}

// ---------------------------------------------------------------------------
// Device group (panorama/devicegroup)
// ---------------------------------------------------------------------------

func newDeviceGroupService(d *Deps) nameFixAdapter[devicegroup.Location, devicegroup.Entry] {
	return nameFixAdapter[devicegroup.Location, devicegroup.Entry]{
		svc:    devicegroup.NewService(d.Client),
		client: d.Client,
		name:   func(e *devicegroup.Entry) string { return e.Name },
	}
}

func deviceGroupResolve(tool string) func(LocationInput) (devicegroup.Location, error) {
	return panoramaFixedResolve(tool,
		devicegroup.Location{Panorama: &devicegroup.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}})
}

// DeviceGroupInput is the input for the device group create and update tools.
// Panorama device-group hierarchy (the parent device group) is not exposed by
// pango's devicegroup package and is not managed here. Firewall (device)
// membership is left to the device onboarding workflow and preserved verbatim
// across an update.
type DeviceGroupInput struct {
	Name              string   `json:"name" jsonschema:"Device group name"`
	Description       *string  `json:"description,omitempty" jsonschema:"Free-text description"`
	Templates         []string `json:"templates,omitempty" jsonschema:"Template names bound to the device group; replaces the bound templates fully on update"`
	AuthorizationCode *string  `json:"authorization_code,omitempty" jsonschema:"Device-group authorization code; write-only, never returned"`
}

func applyDeviceGroup(e *devicegroup.Entry, in *DeviceGroupInput) {
	setPtr(&e.Description, in.Description)
	if in.Templates != nil {
		e.Templates = in.Templates
	}
	setPtr(&e.AuthorizationCode, in.AuthorizationCode)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildDeviceGroup(in DeviceGroupInput) (*devicegroup.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &devicegroup.Entry{Name: in.Name}
	applyDeviceGroup(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayDeviceGroup(e *devicegroup.Entry, in DeviceGroupInput) error {
	applyDeviceGroup(e, &in)
	return nil
}

func deviceGroupDeviceNames(devs []devicegroup.Devices) []string {
	return names(devs, func(dv devicegroup.Devices) string { return dv.Name })
}

// deviceGroupDetail is the get/create/update projection. It is deliberately
// separate from deviceGroupSummary (the list view) so the pinned list output is
// not perturbed: the detail view adds device membership and an authorization
// code presence flag.
func deviceGroupDetail(e *devicegroup.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["templates"] = strList(e.Templates)
	m["devices"] = deviceGroupDeviceNames(e.Devices)
	m["has_authorization_code"] = e.AuthorizationCode != nil
	return m
}

// RegisterDeviceGroupWriteTools registers the Panorama device group get and
// write tools (the list tool is registered by RegisterDeviceTools).
func RegisterDeviceGroupWriteTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	svc := newDeviceGroupService(d)
	loc := func(DeviceGroupInput) LocationInput { return LocationInput{} }

	getInner := getHandler[devicegroup.Location, devicegroup.Entry](
		d, "panos_device_group_get", svc, deviceGroupResolve("panos_device_group_get"), deviceGroupDetail)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_device_group_get",
		Description: "Get one Panorama device group (description, bound templates, member devices). Read-only.",
		Annotations: readOnlyTool("Get device group"),
	}, panoramaNameAdapter(getInner))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_device_group_create",
		Description: "Create a Panorama device group in the candidate config. Parent device-group hierarchy is not managed. Run panos_commit to apply, then panos_push to its firewalls.",
		Annotations: createTool("Create device group"),
	}, createHandler[devicegroup.Location, devicegroup.Entry, DeviceGroupInput](
		d, "panos_device_group_create", svc, deviceGroupResolve("panos_device_group_create"), loc, buildDeviceGroup, deviceGroupDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_device_group_update",
		Description: "Update a Panorama device group: read-modify-write, only provided fields change; a provided templates list replaces the bound templates fully, and firewall membership is preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update device group"),
	}, updateHandler[devicegroup.Location, devicegroup.Entry, DeviceGroupInput](
		d, "panos_device_group_update", svc, deviceGroupResolve("panos_device_group_update"), loc,
		func(in DeviceGroupInput) string { return in.Name }, overlayDeviceGroup, deviceGroupDetail))

	delInner := deleteHandler[devicegroup.Location, devicegroup.Entry](
		d, "panos_device_group_delete", svc, deviceGroupResolve("panos_device_group_delete"))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_device_group_delete",
		Description: "Delete a Panorama device group from the candidate config. Fails while it still contains policy or references. Run panos_commit to apply.",
		Annotations: deleteTool("Delete device group"),
	}, panoramaNameAdapter(delInner))
}

// ---------------------------------------------------------------------------
// Template (panorama/template)
// ---------------------------------------------------------------------------

func newTemplateService(d *Deps) nameFixAdapter[template.Location, template.Entry] {
	return nameFixAdapter[template.Location, template.Entry]{
		svc:    template.NewService(d.Client),
		client: d.Client,
		name:   func(e *template.Entry) string { return e.Name },
	}
}

func templateResolve(tool string) func(LocationInput) (template.Location, error) {
	return panoramaFixedResolve(tool,
		template.Location{Panorama: &template.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}})
}

// TemplateInput is the input for the template create and update tools. The
// template's device/vsys config subtree is populated by the network and device
// tools scoped to the template and is preserved verbatim across an update.
type TemplateInput struct {
	Name        string  `json:"name" jsonschema:"Template name"`
	Description *string `json:"description,omitempty" jsonschema:"Free-text description"`
	DefaultVsys *string `json:"default_vsys,omitempty" jsonschema:"Default vsys for single-vsys firewalls the template targets, e.g. vsys1"`
}

func applyTemplate(e *template.Entry, in *TemplateInput) {
	setPtr(&e.Description, in.Description)
	setPtr(&e.DefaultVsys, in.DefaultVsys)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildTemplate(in TemplateInput) (*template.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &template.Entry{Name: in.Name}
	applyTemplate(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayTemplate(e *template.Entry, in TemplateInput) error {
	applyTemplate(e, &in)
	return nil
}

// templateDetail is the get/create/update projection. It is separate from
// templateSummary (the list view) so the pinned list output is not perturbed:
// the detail view adds default_vsys.
func templateDetail(e *template.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["default_vsys"] = strVal(e.DefaultVsys)
	return m
}

// RegisterTemplateWriteTools registers the Panorama template get and write tools
// (the list tool is registered by RegisterDeviceTools).
func RegisterTemplateWriteTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	svc := newTemplateService(d)
	loc := func(TemplateInput) LocationInput { return LocationInput{} }

	getInner := getHandler[template.Location, template.Entry](
		d, "panos_template_get", svc, templateResolve("panos_template_get"), templateDetail)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_get",
		Description: "Get one Panorama template (description, default_vsys). Read-only.",
		Annotations: readOnlyTool("Get template"),
	}, panoramaNameAdapter(getInner))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_create",
		Description: "Create a Panorama template in the candidate config. Bind it to a template stack and populate its network/device config with the template-scoped tools. Run panos_commit to apply.",
		Annotations: createTool("Create template"),
	}, createHandler[template.Location, template.Entry, TemplateInput](
		d, "panos_template_create", svc, templateResolve("panos_template_create"), loc, buildTemplate, templateDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_update",
		Description: "Update a Panorama template: read-modify-write, only provided fields change; the template's device/vsys config subtree is preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update template"),
	}, updateHandler[template.Location, template.Entry, TemplateInput](
		d, "panos_template_update", svc, templateResolve("panos_template_update"), loc,
		func(in TemplateInput) string { return in.Name }, overlayTemplate, templateDetail))

	delInner := deleteHandler[template.Location, template.Entry](
		d, "panos_template_delete", svc, templateResolve("panos_template_delete"))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_delete",
		Description: "Delete a Panorama template from the candidate config. Fails while a template stack still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete template"),
	}, panoramaNameAdapter(delInner))
}

// ---------------------------------------------------------------------------
// Template stack (panorama/template_stack)
// ---------------------------------------------------------------------------

func newTemplateStackService(d *Deps) nameFixAdapter[template_stack.Location, template_stack.Entry] {
	return nameFixAdapter[template_stack.Location, template_stack.Entry]{
		svc:    template_stack.NewService(d.Client),
		client: d.Client,
		name:   func(e *template_stack.Entry) string { return e.Name },
	}
}

func templateStackResolve(tool string) func(LocationInput) (template_stack.Location, error) {
	return panoramaFixedResolve(tool,
		template_stack.Location{Panorama: &template_stack.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}})
}

// TemplateStackInput is the input for the template stack create and update
// tools. The templates list is ordered by priority, highest first: PAN-OS gives
// precedence to members higher in the list, so the first member is the top of
// the stack and wins any setting configured in more than one member. The order
// is preserved as given.
type TemplateStackInput struct {
	Name         string   `json:"name" jsonschema:"Template stack name"`
	Description  *string  `json:"description,omitempty" jsonschema:"Free-text description"`
	Templates    []string `json:"templates,omitempty" jsonschema:"Member template names in priority order, highest first; the first member is the top of the stack and wins any setting configured in more than one member; replaces the members fully on update"`
	DefaultVsys  *string  `json:"default_vsys,omitempty" jsonschema:"Default vsys for single-vsys firewalls the stack targets, e.g. vsys1"`
	Devices      []string `json:"devices,omitempty" jsonschema:"Firewall serial numbers assigned to the stack; replaces the assigned devices fully on update"`
	MasterDevice *string  `json:"master_device,omitempty" jsonschema:"Serial number of the master device that sources user-group and HIP information"`
}

func applyTemplateStack(e *template_stack.Entry, in *TemplateStackInput) {
	setPtr(&e.Description, in.Description)
	if in.Templates != nil {
		e.Templates = in.Templates
	}
	setPtr(&e.DefaultVsys, in.DefaultVsys)
	if in.Devices != nil {
		devs := make([]template_stack.Devices, 0, len(in.Devices))
		for _, dv := range in.Devices {
			devs = append(devs, template_stack.Devices{Name: dv})
		}
		e.Devices = devs
	}
	if in.MasterDevice != nil {
		if e.UserGroupSource == nil {
			e.UserGroupSource = &template_stack.UserGroupSource{}
		}
		e.UserGroupSource.MasterDevice = in.MasterDevice
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildTemplateStack(in TemplateStackInput) (*template_stack.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &template_stack.Entry{Name: in.Name}
	applyTemplateStack(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayTemplateStack(e *template_stack.Entry, in TemplateStackInput) error {
	applyTemplateStack(e, &in)
	return nil
}

func templateStackDeviceNames(devs []template_stack.Devices) []string {
	return names(devs, func(dv template_stack.Devices) string { return dv.Name })
}

func templateStackSummary(e *template_stack.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["templates"] = strList(e.Templates)
	m["default_vsys"] = strVal(e.DefaultVsys)
	m["devices"] = templateStackDeviceNames(e.Devices)
	master := ""
	if e.UserGroupSource != nil {
		master = strVal(e.UserGroupSource.MasterDevice)
	}
	m["master_device"] = master
	return m
}

// RegisterTemplateStackTools registers the Panorama template stack tools.
func RegisterTemplateStackTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	svc := newTemplateStackService(d)
	loc := func(TemplateStackInput) LocationInput { return LocationInput{} }

	listInner := listHandler[template_stack.Location, template_stack.Entry](
		d, "panos_template_stack_list", svc, templateStackResolve("panos_template_stack_list"), svc.name, templateStackSummary)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_stack_list",
		Description: "List Panorama template stacks (member templates, assigned devices). Read-only.",
		Annotations: readOnlyTool("List template stacks"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in PanoramaListInput) (*mcp.CallToolResult, any, error) {
		return listInner(ctx, req, ListInput{Limit: in.Limit, Offset: in.Offset, Filter: in.Filter})
	})

	getInner := getHandler[template_stack.Location, template_stack.Entry](
		d, "panos_template_stack_get", svc, templateStackResolve("panos_template_stack_get"), templateStackSummary)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_stack_get",
		Description: "Get one Panorama template stack (ordered member templates, default_vsys, assigned devices, master_device). Read-only.",
		Annotations: readOnlyTool("Get template stack"),
	}, panoramaNameAdapter(getInner))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_stack_create",
		Description: "Create a Panorama template stack in the candidate config. List its member templates in priority order, highest first (the first member is the top of the stack and wins any duplicated setting), and assign firewalls by serial. Run panos_commit to apply.",
		Annotations: createTool("Create template stack"),
	}, createHandler[template_stack.Location, template_stack.Entry, TemplateStackInput](
		d, "panos_template_stack_create", svc, templateStackResolve("panos_template_stack_create"), loc, buildTemplateStack, templateStackSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_stack_update",
		Description: "Update a Panorama template stack: read-modify-write, only provided fields change; a provided templates or devices list replaces that member list fully in the given order. Run panos_commit to apply.",
		Annotations: updateTool("Update template stack"),
	}, updateHandler[template_stack.Location, template_stack.Entry, TemplateStackInput](
		d, "panos_template_stack_update", svc, templateStackResolve("panos_template_stack_update"), loc,
		func(in TemplateStackInput) string { return in.Name }, overlayTemplateStack, templateStackSummary))
	delInner := deleteHandler[template_stack.Location, template_stack.Entry](
		d, "panos_template_stack_delete", svc, templateStackResolve("panos_template_stack_delete"))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_stack_delete",
		Description: "Delete a Panorama template stack from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete template stack"),
	}, panoramaNameAdapter(delInner))
}

// ---------------------------------------------------------------------------
// Template variable (panorama/template_variable)
// ---------------------------------------------------------------------------

func newTemplateVariableService(d *Deps) nameFixAdapter[template_variable.Location, template_variable.Entry] {
	return nameFixAdapter[template_variable.Location, template_variable.Entry]{
		svc:    template_variable.NewService(d.Client),
		client: d.Client,
		name:   func(e *template_variable.Entry) string { return e.Name },
	}
}

func templateVariableParts() netScopeParts[template_variable.Location] {
	return netScopeParts[template_variable.Location]{
		// ngfw is nil: a template variable exists only inside a template or a
		// template stack, so a bare firewall scope has no meaning.
		template: func(tmpl string) template_variable.Location {
			return template_variable.Location{Template: &template_variable.TemplateLocation{
				PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) template_variable.Location {
			return template_variable.Location{TemplateStack: &template_variable.TemplateStackLocation{
				PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// templateVariableKind names one template-variable value type and the pango
// Type pointer field it maps to. Keeping the name, getter and setter in one row
// makes the var_type set a single source of truth for building, reading and
// validating a variable.
type templateVariableKind struct {
	name string
	get  func(*template_variable.Type) *string
	set  func(*template_variable.Type, *string)
}

var templateVariableKinds = []templateVariableKind{
	{"ip-netmask", func(t *template_variable.Type) *string { return t.IpNetmask }, func(t *template_variable.Type, v *string) { t.IpNetmask = v }},
	{"ip-range", func(t *template_variable.Type) *string { return t.IpRange }, func(t *template_variable.Type, v *string) { t.IpRange = v }},
	{"fqdn", func(t *template_variable.Type) *string { return t.Fqdn }, func(t *template_variable.Type, v *string) { t.Fqdn = v }},
	{"group-id", func(t *template_variable.Type) *string { return t.GroupId }, func(t *template_variable.Type, v *string) { t.GroupId = v }},
	{"device-priority", func(t *template_variable.Type) *string { return t.DevicePriority }, func(t *template_variable.Type, v *string) { t.DevicePriority = v }},
	{"device-id", func(t *template_variable.Type) *string { return t.DeviceId }, func(t *template_variable.Type, v *string) { t.DeviceId = v }},
	{"interface", func(t *template_variable.Type) *string { return t.Interface }, func(t *template_variable.Type, v *string) { t.Interface = v }},
	{"as-number", func(t *template_variable.Type) *string { return t.AsNumber }, func(t *template_variable.Type, v *string) { t.AsNumber = v }},
	{"qos-profile", func(t *template_variable.Type) *string { return t.QosProfile }, func(t *template_variable.Type, v *string) { t.QosProfile = v }},
	{"egress-max", func(t *template_variable.Type) *string { return t.EgressMax }, func(t *template_variable.Type, v *string) { t.EgressMax = v }},
	{"link-tag", func(t *template_variable.Type) *string { return t.LinkTag }, func(t *template_variable.Type, v *string) { t.LinkTag = v }},
}

func templateVariableTypeNames() []string {
	out := make([]string, 0, len(templateVariableKinds))
	for _, k := range templateVariableKinds {
		out = append(out, k.name)
	}
	return out
}

// setTemplateVariableType clears every type branch and sets the one named by
// varType to value. Switching var_type on update therefore replaces the active
// branch, matching the zone network_type replace semantics.
func setTemplateVariableType(t *template_variable.Type, varType, value string) error {
	for _, k := range templateVariableKinds {
		if k.name == varType {
			*t = template_variable.Type{Misc: t.Misc, MiscAttributes: t.MiscAttributes}
			k.set(t, new(value))
			return nil
		}
	}
	return fmt.Errorf("var_type must be one of %v, got %q", templateVariableTypeNames(), varType)
}

func templateVariableTypeAndValue(t *template_variable.Type) (varType, value string) {
	if t == nil {
		return "", ""
	}
	for _, k := range templateVariableKinds {
		if v := k.get(t); v != nil {
			return k.name, *v
		}
	}
	return "", ""
}

// TemplateVariableInput is the input for the template variable create and update
// tools. A variable holds one typed value: create requires var_type and value
// together; update changes the value only when var_type and value are provided
// together, which replaces the active type branch.
type TemplateVariableInput struct {
	NetScopeInput
	Name        string  `json:"name" jsonschema:"Variable name; PAN-OS requires it to start with a dollar sign, e.g. $wan-ip"`
	Description *string `json:"description,omitempty" jsonschema:"Free-text description"`
	VarType     string  `json:"var_type,omitempty" jsonschema:"Value type: ip-netmask, ip-range, fqdn, group-id, device-priority, device-id, interface, as-number, qos-profile, egress-max, or link-tag"`
	Value       string  `json:"value,omitempty" jsonschema:"The variable value, interpreted per var_type"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildTemplateVariable(in TemplateVariableInput) (*template_variable.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if !strings.HasPrefix(in.Name, "$") {
		return nil, errors.New("name must start with a dollar sign, e.g. $wan-ip")
	}
	if in.VarType == "" || in.Value == "" {
		return nil, errors.New("var_type and value are required")
	}
	e := &template_variable.Entry{Name: in.Name}
	setPtr(&e.Description, in.Description)
	e.Type = &template_variable.Type{}
	if err := setTemplateVariableType(e.Type, in.VarType, in.Value); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayTemplateVariable(e *template_variable.Entry, in TemplateVariableInput) error {
	setPtr(&e.Description, in.Description)
	switch {
	case in.VarType != "" && in.Value != "":
		if e.Type == nil {
			e.Type = &template_variable.Type{}
		}
		return setTemplateVariableType(e.Type, in.VarType, in.Value)
	case in.VarType != "" || in.Value != "":
		return errors.New("var_type and value must be provided together to change the value")
	default:
		return nil
	}
}

func templateVariableSummary(e *template_variable.Entry) any {
	varType, value := templateVariableTypeAndValue(e.Type)
	m := nameDescription(e.Name, e.Description)
	m["type"] = varType
	m["value"] = value
	return m
}

// RegisterTemplateVariableTools registers the Panorama template variable tools.
func RegisterTemplateVariableTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	svc := newTemplateVariableService(d)
	parts := templateVariableParts()
	scope := func(in TemplateVariableInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_variable_list",
		Description: "List Panorama template variables in a template or template_stack (one is required). Read-only.",
		Annotations: readOnlyTool("List template variables"),
	}, netListHandler(d, "panos_template_variable_list", svc, parts, svc.name, templateVariableSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_variable_get",
		Description: "Get one Panorama template variable (type and value) in a template or template_stack. Read-only.",
		Annotations: readOnlyTool("Get template variable"),
	}, netGetHandler(d, "panos_template_variable_get", svc, parts, templateVariableSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_variable_create",
		Description: "Create a Panorama template variable in a template or template_stack. var_type and value are required. Run panos_commit to apply.",
		Annotations: createTool("Create template variable"),
	}, netCreateHandler(d, "panos_template_variable_create", svc, parts, scope, buildTemplateVariable, templateVariableSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_variable_update",
		Description: "Update a Panorama template variable: read-modify-write. Provide var_type and value together to change the value (this replaces the active type). Run panos_commit to apply.",
		Annotations: updateTool("Update template variable"),
	}, netUpdateHandler(d, "panos_template_variable_update", svc, parts, scope,
		func(in TemplateVariableInput) string { return in.Name }, overlayTemplateVariable, templateVariableSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_template_variable_delete",
		Description: "Delete a Panorama template variable from a template or template_stack. Run panos_commit to apply.",
		Annotations: deleteTool("Delete template variable"),
	}, netDeleteHandler(d, "panos_template_variable_delete", svc, parts))
}
