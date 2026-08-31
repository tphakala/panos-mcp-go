package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Shared scope machinery
// ---------------------------------------------------------------------------
//
// Several families answer the same question in different location trees: which
// pango location does this request name? Each owns an input struct (its public
// MCP schema), a resolver, and thin handler wrappers over the generic *Core
// functions in tools.go.
//
// The resolvers stay separate on purpose. They are not copies of one function:
// the input structs expose different tiers (only the device scope has a vsys,
// the net scope has neither a vsys nor a panorama scope), the firewall
// rejection messages are per-field in the net scope but combined in the device
// scope, and the cross-tier rules differ. On that last point the device scope is
// the outlier: given a template combined with shared it resolves to the
// template, where the profile and management scopes reject the combination.
// That divergence is pinned by a test rather than settled; see issue #98.
// Merging the resolvers would either change tool input schemas, which are this
// server's public API, or change behaviour no test pins.
//
// What IS shared lives here: the scope accessors that let a handler pull a scope
// off any input that embeds one, and the Panorama template tier that several of
// the scopes implement the same way.

// The scope accessor constraints. Every family input embeds its scope struct, so
// the single method defined on each scope struct is promoted to all of them and
// every input satisfies the matching constraint for free. That is what lets a
// handler take the scope off the input directly, instead of every registration
// passing a closure that does the same thing.
type (
	netScoped     interface{ netScope() NetScopeInput }
	deviceScoped  interface{ deviceScope() DeviceScopeInput }
	profileScoped interface{ profileScope() ProfileScopeInput }
	mgtScoped     interface{ mgtScope() MgtScopeInput }
)

// The paging and single-entry accessors. A list input carries the same
// limit/offset/filter triplet whichever family it belongs to, and a name input
// the same entry name, so the three read handlers below are written once against
// these rather than once per family. The object family implements them too, so
// these constraints are not limited to the scope families above.
type (
	listInput interface {
		page() (limit, offset int, filter string)
	}
	nameInput interface{ entryName() string }
)

// scopedListHandler builds a list tool handler for any scope family. The family
// supplies only the difference between them: how its input resolves to a pango
// location.
func scopedListHandler[LI listInput, L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LI) (L, error),
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, LI) (*mcp.CallToolResult, any, error) {
	return listCore(d, tool, svc, resolve,
		func(in LI) (int, int, string) { return in.page() },
		name, summarize)
}

// scopedGetHandler builds a get tool handler for any scope family.
func scopedGetHandler[NI nameInput, L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(NI) (L, error), summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NI) (*mcp.CallToolResult, any, error) {
	return getCore(d, tool, svc, resolve,
		func(in NI) string { return in.entryName() },
		summarize)
}

// scopedDeleteHandler builds a delete tool handler for any scope family.
func scopedDeleteHandler[NI nameInput, L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(NI) (L, error),
) func(context.Context, *mcp.CallToolRequest, NI) (*mcp.CallToolResult, any, error) {
	return deleteCore(d, tool, svc, resolve,
		func(in NI) string { return in.entryName() })
}

// templateScopeParts is the Panorama template and template-stack half of a
// scope, optionally narrowed to a vsys within the template. Every scope whose
// pango locations take a (panorama, template) pair embeds this rather than
// redeclaring the constructors; a scope with no vsys level leaves the two
// vsys-narrowed constructors nil. The net scope deliberately does not embed it:
// pango gives it a single-argument template constructor, a different shape.
type templateScopeParts[L any] struct {
	template          func(panorama, template string) L
	templateVsys      func(panorama, template, ngfw, vsys string) L
	templateStack     func(panorama, stack string) L
	templateStackVsys func(panorama, stack, ngfw, vsys string) L
}

// validateTemplateExclusivity enforces the two template-tier input rules its
// callers share verbatim. The device and profile scopes spelled these out
// separately before; the messages are unchanged. A family with further
// cross-tier rules checks those itself.
func validateTemplateExclusivity(template, stack, vsys string) error {
	switch {
	case template != "" && stack != "":
		return errors.New("set only one of template or template_stack, not both")
	case vsys != "" && template == "" && stack == "":
		return errors.New("template_vsys requires a template or template_stack")
	}
	return nil
}

// validateSharedPanoramaExclusivity rejects naming both the shared and the
// Panorama management-plane scope. The device and profile scopes forbid this
// pairing with the same message; extracting it stops each from carrying its own
// inline copy. The template tier is checked separately because its rule differs
// between those two scopes.
func validateSharedPanoramaExclusivity(shared, panorama bool) error {
	if shared && panorama {
		return errors.New("set only one of shared or panorama, not both")
	}
	return nil
}

// validateTemplatePanoramaExclusivity rejects combining a template tier with the
// Panorama management-plane scope: they name different destinations, so naming
// both is a client error rather than a precedence question, and resolving it
// silently would create the entry inside the template, which pushes it to every
// managed firewall using that template while the caller believes it landed on
// Panorama. The device and management scopes share this exact rule and message;
// the profile scope's variant also folds in the shared scope, so it keeps its
// own combined check.
func validateTemplatePanoramaExclusivity(template, stack string, panorama bool) error {
	if (template != "" || stack != "") && panorama {
		return errors.New("set exactly one scope: template or template_stack cannot be combined with panorama")
	}
	return nil
}

// resolveTemplateTier returns the location a template or template-stack request
// names, narrowed to a vsys when one is given. ok is false when the request
// names neither tier, which leaves the caller to handle its own remaining
// scopes. Callers must have validated exclusivity first, so a request naming
// both tiers cannot reach here.
//
// A scope with no vsys level leaves the two vsys-narrowed constructors nil (see
// templateScopeParts). No current family both leaves them nil and exposes a
// template_vsys field, so today the nil branch is unreachable; guarding it turns
// that latent trap for the next family into a clear error rather than a nil-call
// panic. err is non-nil only in that guarded case.
func resolveTemplateTier[L any](template, stack, vsys string, p templateScopeParts[L]) (loc L, ok bool, err error) {
	switch {
	case template != "":
		if vsys != "" {
			if p.templateVsys == nil {
				return loc, false, errors.New("template_vsys is not supported for this family")
			}
			return p.templateVsys(defaultPanoramaDevice, template, defaultNgfwDevice, vsys), true, nil
		}
		return p.template(defaultPanoramaDevice, template), true, nil
	case stack != "":
		if vsys != "" {
			if p.templateStackVsys == nil {
				return loc, false, errors.New("template_vsys is not supported for this family")
			}
			return p.templateStackVsys(defaultPanoramaDevice, stack, defaultNgfwDevice, vsys), true, nil
		}
		return p.templateStack(defaultPanoramaDevice, stack), true, nil
	}
	return loc, false, nil
}
