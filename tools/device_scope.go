package tools

import (
	"cmp"
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// noSharedScopeProfiles lists the device-scoped profile families whose pango
// location has no shared scope (deviceScopeParts.shared is nil for them), so a
// shared request is rejected. It is the single source of truth for that list.
// The DeviceScopeInput.Shared jsonschema tag and the doc comments in this file
// repeat these names because a Go struct tag cannot reference a const; keep them
// in sync with this value when a new no-shared family is added.
const noSharedScopeProfiles = "syslog, snmp-trap, email and authentication profiles"

// DeviceScopeInput selects where a device server profile lives. The
// device/profiles/* packages (LDAP, RADIUS, TACACS+, syslog, SNMP-trap, email)
// model their location more richly than either LocationInput (the object
// shared/vsys/device_group model) or NetScopeInput (the {Ngfw|Template|
// TemplateStack} model): a firewall vsys or shared scope, a Panorama template or
// template-stack (optionally down to a specific vsys within it), or the Panorama
// shared scope. This gets its own resolver, resolveDeviceScope.
//
// Not every profile type supports every scope: the log-settings profiles
// (syslog, SNMP-trap, email) and the authentication profile have no shared
// scope, so requesting shared for one of them is rejected rather than silently
// retargeted.
type DeviceScopeInput struct {
	Shared        bool   `json:"shared,omitzero" jsonschema:"Use the shared scope (firewall shared, or Panorama shared pushed to all device groups). Not available for syslog, snmp-trap, email and authentication profiles."`
	Vsys          string `json:"vsys,omitzero" jsonschema:"Firewall vsys name (firewall only; default vsys1)"`
	Template      string `json:"template,omitzero" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitzero" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
	TemplateVsys  string `json:"template_vsys,omitzero" jsonschema:"vsys within the chosen template or template-stack (Panorama only); omit for the template's shared scope"`
}

// deviceScope returns the scope itself, so every input that embeds
// DeviceScopeInput satisfies deviceScoped through promotion and the handlers can take
// the scope off the input rather than being handed a closure that does it.
func (in DeviceScopeInput) deviceScope() DeviceScopeInput { return in }

// deviceScopeParts supplies the per-resource pango location constructors for
// resolveDeviceScope. shared may be nil for a resource pango does not model at a
// shared scope (the log-settings profiles syslog, SNMP-trap and email, and the
// authentication profile), which makes a shared request an error rather than a
// silently invalid location.
type deviceScopeParts[L any] struct {
	shared func() L
	vsys   func(ngfw, vsys string) L
	templateScopeParts[L]
}

// resolveDeviceScope maps a DeviceScopeInput onto a pango location for the
// connected device type. A firewall resolves to its vsys scope by default (or the
// shared scope when shared is set and the resource supports it); Panorama requires
// an explicit template, template_stack, or shared selection.
func resolveDeviceScope[L any](d *Deps, in DeviceScopeInput, p deviceScopeParts[L]) (L, error) {
	var zero L
	if err := validateTemplateExclusivity(in.Template, in.TemplateStack, in.TemplateVsys); err != nil {
		return zero, err
	}
	if d.IsPanorama {
		return resolvePanoramaDeviceScope(in, p)
	}

	if in.Template != "" || in.TemplateStack != "" {
		return zero, errors.New("template and template_stack require a Panorama connection")
	}
	if in.Shared {
		if p.shared == nil {
			return zero, errors.New("the shared scope is not available for this profile type; on a firewall it is stored per-vsys")
		}
		return p.shared(), nil
	}
	return p.vsys(defaultNgfwDevice, cmp.Or(in.Vsys, defaultVsys)), nil
}

// resolvePanoramaDeviceScope handles the Panorama branch of resolveDeviceScope:
// an explicit template, template_stack (optionally down to a vsys), or the shared
// scope is required.
func resolvePanoramaDeviceScope[L any](in DeviceScopeInput, p deviceScopeParts[L]) (L, error) {
	var zero L
	if loc, ok := resolveTemplateTier(in.Template, in.TemplateStack, in.TemplateVsys, p.templateScopeParts); ok {
		return loc, nil
	}
	switch {
	case in.Shared:
		if p.shared == nil {
			return zero, errors.New("the shared scope is not available for this profile type; use a template or template_stack")
		}
		return p.shared(), nil
	default:
		return zero, errors.New("on Panorama set template, template_stack, or shared (shared is unavailable for " + noSharedScopeProfiles + "); list templates with panos_template_list")
	}
}

// DeviceNameInput is the common input for single-object device-scoped tools.
type DeviceNameInput struct {
	Name string `json:"name" jsonschema:"Profile name"`
	DeviceScopeInput
}

// DeviceListInput is the common input for device-scoped list tools.
type DeviceListInput struct {
	DeviceScopeInput
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// page exposes the paging triplet to the shared list handler. The value
// receiver is required: the constraint is satisfied by the input value the
// handler is given, not by a pointer to it.
//
//nolint:gocritic // hugeParam: the receiver is by value to satisfy the listInput constraint.
func (in DeviceListInput) page() (limit, offset int, filter string) {
	return in.Limit, in.Offset, in.Filter
}

// entryName exposes the entry name to the shared get and delete handlers. The
// value receiver is required for the same reason as page.
//
//nolint:gocritic // hugeParam: the receiver is by value to satisfy the nameInput constraint.
func (in DeviceNameInput) entryName() string { return in.Name }

// deviceListHandler mirrors netListHandler for the device-scope resolver.
func deviceListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, DeviceListInput) (*mcp.CallToolResult, any, error) {
	return scopedListHandler(d, tool, svc,
		func(in DeviceListInput) (L, error) { return resolveDeviceScope(d, in.deviceScope(), p) },
		name, summarize)
}

// deviceGetHandler mirrors netGetHandler for the device-scope resolver.
func deviceGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, DeviceNameInput) (*mcp.CallToolResult, any, error) {
	return scopedGetHandler(d, tool, svc,
		func(in DeviceNameInput) (L, error) { return resolveDeviceScope(d, in.deviceScope(), p) },
		summarize)
}

// deviceDeleteHandler mirrors netDeleteHandler for the device-scope resolver.
func deviceDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, DeviceNameInput) (*mcp.CallToolResult, any, error) {
	return scopedDeleteHandler(d, tool, svc,
		func(in DeviceNameInput) (L, error) { return resolveDeviceScope(d, in.deviceScope(), p) })
}

// deviceCreateHandler mirrors netCreateHandler for the device-scope resolver.
func deviceCreateHandler[L, E any, In deviceScoped](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	build func(In) (*E, error),
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (L, error) { return resolveDeviceScope(d, in.deviceScope(), p) },
		build, summarize, opts...)
}

// deviceUpdateHandler mirrors netUpdateHandler for the device-scope resolver: a
// read-modify-write overlay applying only the caller-provided fields.
func deviceUpdateHandler[L, E any, In deviceScoped](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (L, error) { return resolveDeviceScope(d, in.deviceScope(), p) },
		name, overlay, summarize, opts...)
}
