package tools

import (
	"context"
	"errors"
	"strings"

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

// netListHandler mirrors listHandler for the net-scope resolver: fetch all
// entries at the resolved location, filter by name substring, clamp, summarize.
func netListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NetListInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NetListInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		d.Logger.Debug(tool, "limit", in.Limit, "offset", in.Offset, "filter", in.Filter)
		loc, err := resolveNetScope(d, in.NetScopeInput, p)
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

// netGetHandler mirrors getHandler for the net-scope resolver.
func netGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NetNameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NetNameInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolveNetScope(d, in.NetScopeInput, p)
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

// netDeleteHandler mirrors deleteHandler for the net-scope resolver.
func netDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, NetNameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NetNameInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolveNetScope(d, in.NetScopeInput, p)
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

// netCreateHandler mirrors createHandler for the net-scope resolver.
func netCreateHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	scope func(In) NetScopeInput,
	build func(In) (*E, error),
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		entry, err := build(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		loc, err := resolveNetScope(d, scope(in), p)
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

// netUpdateHandler mirrors updateHandler for the net-scope resolver: a
// read-modify-write overlay applying only the caller-provided fields.
func netUpdateHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E], p netScopeParts[L],
	scope func(In) NetScopeInput,
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
		loc, err := resolveNetScope(d, scope(in), p)
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
