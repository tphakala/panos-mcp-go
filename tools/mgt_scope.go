package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Management-plane scope (mgt-config)
// ---------------------------------------------------------------------------
//
// Administrators and password profiles live under /config/mgt-config, which is
// device-wide rather than per-vsys. pango models the tree with four locations:
// the firewall's own mgt-config, Panorama's own, and a Panorama template or
// template-stack pushing one to managed firewalls. There is no vsys tier (an
// administrator is not scoped to a vsys the way a server profile is) and no
// shared tier, so neither DeviceScopeInput nor ProfileScopeInput fits.

// MgtScopeInput selects a management-plane location. On a firewall every field
// is left unset: the device's own mgt-config is the only reachable scope. On
// Panorama exactly one of panorama, template or template_stack is required.
type MgtScopeInput struct {
	Panorama      bool   `json:"panorama,omitzero" jsonschema:"Use the Panorama management-plane scope (Panorama only)"`
	Template      string `json:"template,omitzero" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitzero" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
}

// mgtScope returns the scope itself, so every input embedding MgtScopeInput
// satisfies mgtScoped through promotion.
func (in MgtScopeInput) mgtScope() MgtScopeInput { return in }

// mgtScopeParts supplies the four pango location constructors resolveMgtScope
// selects among. It embeds the shared template tier, whose vsys-narrowed
// constructors stay nil: this tree has no vsys level, and MgtScopeInput exposes
// no template_vsys field, so they are never reached.
type mgtScopeParts[L any] struct {
	ngfw     func() L
	panorama func() L
	templateScopeParts[L]
}

// resolveMgtScope maps an MgtScopeInput onto a pango location for the connected
// device type. A firewall always resolves to its own mgt-config; panorama,
// template and template_stack all require a Panorama connection. Panorama
// requires an explicit choice rather than defaulting, matching the other scope
// families.
func resolveMgtScope[L any](d *Deps, in MgtScopeInput, p mgtScopeParts[L]) (L, error) {
	var zero L
	if err := validateTemplateExclusivity(in.Template, in.TemplateStack, ""); err != nil {
		return zero, err
	}
	// panorama and a template tier are different destinations; the shared helper
	// rejects the pairing with the same message the device scope uses (see
	// validateTemplatePanoramaExclusivity for why silently resolving it is unsafe).
	if err := validateTemplatePanoramaExclusivity(in.Template, in.TemplateStack, in.Panorama); err != nil {
		return zero, err
	}
	if !d.IsPanorama {
		if in.Panorama || in.Template != "" || in.TemplateStack != "" {
			return zero, errors.New("panorama, template and template_stack require a Panorama connection; on a firewall these live in the device's own mgt-config")
		}
		return p.ngfw(), nil
	}
	loc, ok, err := resolveTemplateTier(in.Template, in.TemplateStack, "", p.templateScopeParts)
	if err != nil {
		return zero, err
	}
	if ok {
		return loc, nil
	}
	if in.Panorama {
		return p.panorama(), nil
	}
	return zero, errors.New("on Panorama set panorama, template, or template_stack; list templates with panos_template_list")
}

// MgtNameInput is the common input for single-entry management-plane tools.
type MgtNameInput struct {
	Name string `json:"name" jsonschema:"Entry name"`
	MgtScopeInput
}

// MgtListInput is the common input for management-plane list tools.
type MgtListInput struct {
	MgtScopeInput
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// page exposes the paging triplet to the shared list handler. The value receiver
// is required: the constraint is satisfied by the input value the handler is
// given, not by a pointer to it.
func (in MgtListInput) page() (limit, offset int, filter string) {
	return in.Limit, in.Offset, in.Filter
}

// entryName exposes the entry name to the shared get and delete handlers. The
// value receiver is required for the same reason as page.
func (in MgtNameInput) entryName() string { return in.Name }

// mgtListHandler mirrors deviceListHandler for the management-plane resolver.
func mgtListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p mgtScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, MgtListInput) (*mcp.CallToolResult, any, error) {
	return scopedListHandler(d, tool, svc,
		func(in MgtListInput) (L, error) { return resolveMgtScope(d, in.mgtScope(), p) },
		name, summarize)
}

// mgtGetHandler mirrors deviceGetHandler for the management-plane resolver.
func mgtGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p mgtScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, MgtNameInput) (*mcp.CallToolResult, any, error) {
	return scopedGetHandler(d, tool, svc,
		func(in MgtNameInput) (L, error) { return resolveMgtScope(d, in.mgtScope(), p) },
		summarize)
}

// mgtDeleteHandler mirrors deviceDeleteHandler for the management-plane resolver.
func mgtDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p mgtScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, MgtNameInput) (*mcp.CallToolResult, any, error) {
	return scopedDeleteHandler(d, tool, svc,
		func(in MgtNameInput) (L, error) { return resolveMgtScope(d, in.mgtScope(), p) })
}

// mgtCreateHandler mirrors deviceCreateHandler for the management-plane resolver.
func mgtCreateHandler[L, E any, In mgtScoped](
	d *Deps, tool string, svc crudService[L, E], p mgtScopeParts[L],
	build func(In) (*E, error),
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (L, error) { return resolveMgtScope(d, in.mgtScope(), p) },
		build, summarize, opts...)
}

// mgtUpdateHandler mirrors deviceUpdateHandler for the management-plane
// resolver: a read-modify-write overlay applying only the caller-provided
// fields.
func mgtUpdateHandler[L, E any, In mgtScoped](
	d *Deps, tool string, svc crudService[L, E], p mgtScopeParts[L],
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (L, error) { return resolveMgtScope(d, in.mgtScope(), p) },
		name, overlay, summarize, opts...)
}
