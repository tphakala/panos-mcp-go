package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NetScopeInput selects where a network-scoped config object lives. Several
// pango packages (the VPN crypto profiles, IKE gateway, IPSec and GRE tunnels,
// and the Panorama template variable) model their location as
// {Ngfw | Template | TemplateStack}: a whole-device Ngfw scope on a firewall
// (no vsys, no shared, no device_group), or a Panorama template / template-stack
// scope. This differs from LocationInput (the object shared/vsys/device_group
// model), so it gets its own resolver.
//
// On a firewall both fields stay empty and the object resolves to the Ngfw
// scope. On Panorama exactly one of template or template_stack is required.
type NetScopeInput struct {
	Template      string `json:"template,omitempty" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitempty" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
}

// netScope returns the scope itself, so every input that embeds
// NetScopeInput satisfies netScoped through promotion and the handlers can take
// the scope off the input rather than being handed a closure that does it.
func (in NetScopeInput) netScope() NetScopeInput { return in }

// netScopeParts supplies the per-resource pango location constructors for
// resolveNetScope. ngfw may be nil for a resource that pango models only under a
// template or template-stack (the template variable): a nil ngfw makes a bare
// firewall request an error rather than silently building an invalid location.
type netScopeParts[L any] struct {
	ngfw          func() L
	template      func(tmpl string) L
	templateStack func(stack string) L
}

// resolveNetScope maps a NetScopeInput onto a pango location for the connected
// device type. Firewall with neither field set resolves to the Ngfw scope (when
// the resource supports it); Panorama requires exactly one of template or
// template_stack.
func resolveNetScope[L any](d *Deps, in NetScopeInput, p netScopeParts[L]) (L, error) {
	var zero L
	switch {
	case in.Template != "" && in.TemplateStack != "":
		return zero, errors.New("set only one of template or template_stack, not both")
	case in.TemplateStack != "":
		if !d.IsPanorama {
			return zero, errors.New("template_stack requires a Panorama connection")
		}
		return p.templateStack(in.TemplateStack), nil
	case in.Template != "":
		if !d.IsPanorama {
			return zero, errors.New("template requires a Panorama connection")
		}
		return p.template(in.Template), nil
	case d.IsPanorama:
		return zero, errors.New("template or template_stack is required on Panorama; list templates with panos_template_list")
	case p.ngfw == nil:
		// A resource pango models only under a template or template-stack (the
		// template variable): it has no firewall-local scope, so a bare firewall
		// request cannot be satisfied.
		return zero, errors.New("template or template_stack is required")
	default:
		return p.ngfw(), nil
	}
}

// NetNameInput is the common input for single-object network-scoped tools.
type NetNameInput struct {
	Name string `json:"name" jsonschema:"Object name"`
	NetScopeInput
}

// NetListInput is the common input for network-scoped list tools.
type NetListInput struct {
	NetScopeInput
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// page exposes the paging triplet to the shared list handler. The value
// receiver is required: the constraint is satisfied by the input value the
// handler is given, not by a pointer to it.
func (in NetListInput) page() (limit, offset int, filter string) {
	return in.Limit, in.Offset, in.Filter
}

// entryName exposes the entry name to the shared get and delete handlers. The
// value receiver is required for the same reason as page.
func (in NetNameInput) entryName() string { return in.Name }

// netListHandler mirrors listHandler for the net-scope resolver: fetch all
// entries at the resolved location, filter by name substring, clamp, summarize.
func netListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NetListInput) (*mcp.CallToolResult, any, error) {
	return scopedListHandler(d, tool, svc,
		func(in NetListInput) (L, error) { return resolveNetScope(d, in.netScope(), p) },
		name, summarize)
}

// netGetHandler mirrors getHandler for the net-scope resolver.
func netGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NetNameInput) (*mcp.CallToolResult, any, error) {
	return scopedGetHandler(d, tool, svc,
		func(in NetNameInput) (L, error) { return resolveNetScope(d, in.netScope(), p) },
		summarize)
}

// netDeleteHandler mirrors deleteHandler for the net-scope resolver.
func netDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, NetNameInput) (*mcp.CallToolResult, any, error) {
	return scopedDeleteHandler(d, tool, svc,
		func(in NetNameInput) (L, error) { return resolveNetScope(d, in.netScope(), p) })
}

// netCreateHandler mirrors createHandler for the net-scope resolver.
func netCreateHandler[L, E any, In netScoped](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	build func(In) (*E, error),
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (L, error) { return resolveNetScope(d, in.netScope(), p) },
		build, summarize, opts...)
}

// netUpdateHandler mirrors updateHandler for the net-scope resolver: a
// read-modify-write overlay applying only the caller-provided fields.
func netUpdateHandler[L, E any, In netScoped](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (L, error) { return resolveNetScope(d, in.netScope(), p) },
		name, overlay, summarize, opts...)
}
