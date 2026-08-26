package tools

import (
	"cmp"
	"context"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DeviceScopeInput selects where a device server profile lives. The
// device/profiles/* packages (LDAP, RADIUS, TACACS+, syslog, SNMP-trap, email)
// model their location more richly than either LocationInput (the object
// shared/vsys/device_group model) or NetScopeInput (the {Ngfw|Template|
// TemplateStack} model): a firewall vsys or shared scope, a Panorama template or
// template-stack (optionally down to a specific vsys within it), or the Panorama
// shared scope. This gets its own resolver, resolveDeviceScope.
//
// Not every profile type supports every scope: the log-settings profiles
// (syslog, SNMP-trap, email) have no shared scope, so requesting shared for one
// of them is rejected rather than silently retargeted.
type DeviceScopeInput struct {
	Shared        bool   `json:"shared,omitzero" jsonschema:"Use the shared scope (firewall shared, or Panorama shared pushed to all device groups). Not available for syslog, snmp-trap and email profiles."`
	Vsys          string `json:"vsys,omitzero" jsonschema:"Firewall vsys name (firewall only; default vsys1)"`
	Template      string `json:"template,omitzero" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitzero" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
	TemplateVsys  string `json:"template_vsys,omitzero" jsonschema:"vsys within the chosen template or template-stack (Panorama only); omit for the template's shared scope"`
}

// deviceScopeParts supplies the per-resource pango location constructors for
// resolveDeviceScope. shared may be nil for a resource pango does not model at a
// shared scope (the log-settings profiles: syslog, SNMP-trap, email), which makes
// a shared request an error rather than a silently invalid location.
type deviceScopeParts[L any] struct {
	shared            func() L
	vsys              func(ngfw, vsys string) L
	template          func(panorama, template string) L
	templateVsys      func(panorama, template, ngfw, vsys string) L
	templateStack     func(panorama, stack string) L
	templateStackVsys func(panorama, stack, ngfw, vsys string) L
}

// resolveDeviceScope maps a DeviceScopeInput onto a pango location for the
// connected device type. A firewall resolves to its vsys scope by default (or the
// shared scope when shared is set and the resource supports it); Panorama requires
// an explicit template, template_stack, or shared selection.
func resolveDeviceScope[L any](d *Deps, in DeviceScopeInput, p deviceScopeParts[L]) (L, error) {
	var zero L
	if in.Template != "" && in.TemplateStack != "" {
		return zero, errors.New("set only one of template or template_stack, not both")
	}
	if in.TemplateVsys != "" && in.Template == "" && in.TemplateStack == "" {
		return zero, errors.New("template_vsys requires a template or template_stack")
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
	switch {
	case in.Template != "":
		if in.TemplateVsys != "" {
			return p.templateVsys(defaultPanoramaDevice, in.Template, defaultNgfwDevice, in.TemplateVsys), nil
		}
		return p.template(defaultPanoramaDevice, in.Template), nil
	case in.TemplateStack != "":
		if in.TemplateVsys != "" {
			return p.templateStackVsys(defaultPanoramaDevice, in.TemplateStack, defaultNgfwDevice, in.TemplateVsys), nil
		}
		return p.templateStack(defaultPanoramaDevice, in.TemplateStack), nil
	case in.Shared:
		if p.shared == nil {
			return zero, errors.New("the shared scope is not available for this profile type; use a template or template_stack")
		}
		return p.shared(), nil
	default:
		return zero, errors.New("on Panorama set template, template_stack, or shared (shared is unavailable for syslog, snmp-trap and email); list templates with panos_template_list")
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

// deviceListHandler mirrors netListHandler for the device-scope resolver.
func deviceListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, DeviceListInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeviceListInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		d.Logger.Debug(tool, "limit", in.Limit, "offset", in.Offset, "filter", in.Filter)
		loc, err := resolveDeviceScope(d, in.DeviceScopeInput, p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entries, err := svc.List(ctx, loc, "get", "", "")
		if err != nil {
			if !isObjectNotFound(err) {
				d.Logger.Error("failed: "+tool, "error", err)
				res, v := errorResult("failed: %s: %v", tool, err)
				return res, v, nil
			}
			entries = nil
		}
		if in.Filter != "" {
			needle := strings.ToLower(in.Filter)
			kept := entries[:0:0]
			for _, e := range entries {
				if strings.Contains(strings.ToLower(name(e)), needle) {
					kept = append(kept, e)
				}
			}
			entries = kept
		}
		total := len(entries)
		lo, hi := clampList(in.Limit, in.Offset, total)
		out := make([]any, 0, hi-lo)
		for _, e := range entries[lo:hi] {
			out = append(out, summarize(e))
		}
		res, v := jsonResult(map[string]any{totalKey: total, offsetKey: lo, countKey: len(out), entriesKey: out})
		return res, v, nil
	}
}

// deviceGetHandler mirrors netGetHandler for the device-scope resolver.
func deviceGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, DeviceNameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeviceNameInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolveDeviceScope(d, in.DeviceScopeInput, p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entry, err := svc.Read(ctx, loc, in.Name, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := jsonResult(summarize(entry))
		return res, v, nil
	}
}

// deviceDeleteHandler mirrors netDeleteHandler for the device-scope resolver.
func deviceDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, DeviceNameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeviceNameInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolveDeviceScope(d, in.DeviceScopeInput, p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		if err := svc.Delete(ctx, loc, in.Name); err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := successResult(d.Logger, tool, "deleted %q from candidate config; run panos_commit to apply", in.Name)
		return res, v, nil
	}
}

// deviceCreateHandler mirrors netCreateHandler for the device-scope resolver.
func deviceCreateHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	scope func(In) DeviceScopeInput,
	build func(In) (*E, error),
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		entry, err := build(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		loc, err := resolveDeviceScope(d, scope(in), p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		created, err := svc.Create(ctx, loc, entry)
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		d.Logger.Info(tool + " succeeded")
		res, v := jsonResult(summarize(created))
		return res, v, nil
	}
}

// deviceUpdateHandler mirrors netUpdateHandler for the device-scope resolver: a
// read-modify-write overlay applying only the caller-provided fields.
func deviceUpdateHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E], p deviceScopeParts[L],
	scope func(In) DeviceScopeInput,
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		n := name(in)
		if n == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolveDeviceScope(d, scope(in), p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		entry, err := svc.Read(ctx, loc, n, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: read %q: %v", tool, n, err)
			return res, v, nil
		}
		if err := overlay(entry, in); err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		updated, err := svc.Update(ctx, loc, entry, n)
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		d.Logger.Info(tool+" succeeded", "name", n)
		res, v := jsonResult(summarize(updated))
		return res, v, nil
	}
}
