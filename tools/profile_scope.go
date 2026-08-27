package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ProfileScopeInput selects where an ssltls / certificate profile lives. The
// device/profile/{ssltls,certificate} packages model a firewall shared scope, a
// Panorama shared or management-plane (panorama) scope, or a Panorama template /
// template-stack (optionally down to a specific vsys within it). Unlike the
// device server profiles (DeviceScopeInput), these packages expose NO firewall
// vsys scope: on a firewall the only reachable location is the shared scope, so
// this gets its own resolver, resolveProfileScope.
type ProfileScopeInput struct {
	Shared        bool   `json:"shared,omitzero" jsonschema:"Use the shared scope (the only scope on a firewall; on Panorama pushed to all device groups)"`
	Panorama      bool   `json:"panorama,omitzero" jsonschema:"Use the Panorama management-plane scope (Panorama only)"`
	Template      string `json:"template,omitzero" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitzero" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
	TemplateVsys  string `json:"template_vsys,omitzero" jsonschema:"vsys within the chosen template or template_stack (Panorama only); omit for the template shared scope"`
}

// profileScope returns the scope itself, so every input that embeds
// ProfileScopeInput satisfies profileScoped through promotion and the handlers can take
// the scope off the input rather than being handed a closure that does it.
func (in ProfileScopeInput) profileScope() ProfileScopeInput { return in }

// profileScopeParts supplies the six pango location constructors resolveProfileScope
// selects among.
type profileScopeParts[L any] struct {
	shared            func() L
	panorama          func() L
	template          func(panorama, template string) L
	templateVsys      func(panorama, template, ngfw, vsys string) L
	templateStack     func(panorama, stack string) L
	templateStackVsys func(panorama, stack, ngfw, vsys string) L
}

// resolveProfileScope maps a ProfileScopeInput onto a pango location for the
// connected device type. A firewall ALWAYS resolves to the shared scope (these
// packages model no firewall vsys); template, template_stack and panorama on a
// firewall are errors. Panorama requires exactly one of shared, panorama,
// template, or template_stack, optionally narrowed to a template vsys.
func resolveProfileScope[L any](d *Deps, in ProfileScopeInput, p profileScopeParts[L]) (L, error) {
	var zero L
	if err := validateProfileScopeExclusivity(in); err != nil {
		return zero, err
	}
	if d.IsPanorama {
		return resolvePanoramaProfileScope(in, p)
	}
	if in.Template != "" || in.TemplateStack != "" || in.Panorama {
		return zero, errors.New("template, template_stack and panorama require a Panorama connection; on a firewall these profiles live in the shared scope")
	}
	return p.shared(), nil
}

// validateProfileScopeExclusivity enforces the "exactly one scope" contract for
// both the firewall and Panorama branches: template and template_stack are
// mutually exclusive, a template_vsys requires one of them, shared and panorama
// are mutually exclusive, and a template tier cannot be combined with shared or
// panorama.
func validateProfileScopeExclusivity(in ProfileScopeInput) error {
	switch {
	case in.Template != "" && in.TemplateStack != "":
		return errors.New("set only one of template or template_stack, not both")
	case in.TemplateVsys != "" && in.Template == "" && in.TemplateStack == "":
		return errors.New("template_vsys requires a template or template_stack")
	case in.Shared && in.Panorama:
		return errors.New("set only one of shared or panorama, not both")
	case (in.Template != "" || in.TemplateStack != "") && (in.Shared || in.Panorama):
		return errors.New("set exactly one scope: template or template_stack cannot be combined with shared or panorama")
	}
	return nil
}

// resolvePanoramaProfileScope handles the Panorama branch of resolveProfileScope:
// an explicit template, template_stack (optionally down to a vsys), the panorama
// management-plane scope, or the shared scope is required.
func resolvePanoramaProfileScope[L any](in ProfileScopeInput, p profileScopeParts[L]) (L, error) {
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
	case in.Panorama:
		return p.panorama(), nil
	case in.Shared:
		return p.shared(), nil
	default:
		return zero, errors.New("on Panorama set shared, panorama, template, or template_stack; list templates with panos_template_list")
	}
}

// ProfileNameInput is the common input for single-object profile-scoped tools.
type ProfileNameInput struct {
	Name string `json:"name" jsonschema:"Profile name"`
	ProfileScopeInput
}

// ProfileListInput is the common input for profile-scoped list tools.
type ProfileListInput struct {
	ProfileScopeInput
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// profileListHandler mirrors deviceListHandler for the profile-scope resolver.
func profileListHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p profileScopeParts[L],
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, ProfileListInput) (*mcp.CallToolResult, any, error) {
	return listCore(d, tool, svc,
		func(in ProfileListInput) (L, error) { return resolveProfileScope(d, in.ProfileScopeInput, p) },
		func(in ProfileListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		name, summarize)
}

// profileGetHandler mirrors deviceGetHandler for the profile-scope resolver.
func profileGetHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p profileScopeParts[L],
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, ProfileNameInput) (*mcp.CallToolResult, any, error) {
	return getCore(d, tool, svc,
		func(in ProfileNameInput) (L, error) { return resolveProfileScope(d, in.ProfileScopeInput, p) },
		func(in ProfileNameInput) string { return in.Name },
		summarize)
}

// profileDeleteHandler mirrors deviceDeleteHandler for the profile-scope resolver.
func profileDeleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], p profileScopeParts[L],
) func(context.Context, *mcp.CallToolRequest, ProfileNameInput) (*mcp.CallToolResult, any, error) {
	return deleteCore(d, tool, svc,
		func(in ProfileNameInput) (L, error) { return resolveProfileScope(d, in.ProfileScopeInput, p) },
		func(in ProfileNameInput) string { return in.Name })
}

// profileCreateHandler mirrors deviceCreateHandler for the profile-scope resolver.
func profileCreateHandler[L, E any, In profileScoped](
	d *Deps, tool string, svc crudService[L, E], p profileScopeParts[L],
	build func(In) (*E, error),
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (L, error) { return resolveProfileScope(d, in.profileScope(), p) },
		build, summarize, opts...)
}

// profileUpdateHandler mirrors deviceUpdateHandler for the profile-scope resolver:
// a read-modify-write overlay applying only the caller-provided fields.
func profileUpdateHandler[L, E any, In profileScoped](
	d *Deps, tool string, svc crudService[L, E], p profileScopeParts[L],
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (L, error) { return resolveProfileScope(d, in.profileScope(), p) },
		name, overlay, summarize, opts...)
}
