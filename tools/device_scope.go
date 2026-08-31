package tools

import (
	"cmp"
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// noSharedScopeProfiles lists the device-scoped profile families this server
// does not expose a shared scope for (deviceScopeParts.shared is nil for them),
// so a shared request is rejected. It is the single source of truth for that list.
//
// The reason is the same for all three: pango models no shared location at all.
// In pango v0.10.3-0.20260731153743, device/profiles/snmptrap/location.go,
// device/profiles/email/location.go and device/authprofile/location.go declare no
// Shared field and carry no SharedLocation type to build one from.
//
// syslog was on this list until it was measured. pango DOES model a shared
// location for it (device/profiles/syslog/location.go:14, and the Shared arm of
// XpathPrefix at :187 emitting config/shared, entry suffix
// log-settings/syslog/$name), and on one
// PA-VM running PAN-OS 11.2.6 an XML API get of /config/shared/log-settings/syslog
// returned status="success" code="19" total-count="1" holding a pre-existing,
// operator-created profile. That box stores and serves syslog profiles at exactly
// the xpath pango's Shared location builds, so the tier is now exposed rather than
// withheld. Scope of that evidence: one firewall, one PAN-OS version. Panorama's
// own shared scope and other PAN-OS releases are NOT MEASURED; the tier is exposed
// on both device types because pango addresses both the same way, not because both
// were tested.
//
// A Go struct tag cannot reference a const, so this list is restated in the
// DeviceScopeInput.Shared jsonschema tag, in the doc comments in this file, in
// each affected family's _list tool description, and in README.md. Grep this
// const's contents before changing it; the sweep is wider than this file.
const noSharedScopeProfiles = "snmp-trap, email and authentication profiles"

// noPanoramaScopeFamilies lists the device-scoped families this server does not
// expose the Panorama management-plane scope for (deviceScopeParts.panorama is
// nil for them), so a panorama request is rejected. It is the single source of
// truth for that list.
//
// The reason is the same for both: pango models no Panorama location at all. In
// pango v0.10.3-0.20260731153743, device/localdb/user/location.go and
// device/profiles/mfa/location.go declare no Panorama field and carry no
// PanoramaLocation type to build one from, while the other eight device-scoped
// packages do. That is an upstream gap, not a decision taken here.
//
// Named families rather than profiles because a local database user is not a
// profile. As with noSharedScopeProfiles, a Go struct tag cannot reference a
// const, so this list is restated in the DeviceScopeInput.Panorama jsonschema
// tag, in each affected family's _list tool description, and in README.md. Grep
// this const's contents before changing it.
const noPanoramaScopeFamilies = "local database users and MFA server profiles"

// DeviceScopeInput selects where a device-scoped object lives. The ten families
// that embed it (LDAP, RADIUS, TACACS+, syslog, SNMP-trap, email, SAML IdP, MFA,
// local database users and authentication profiles)
// model their location more richly than either LocationInput (the object
// shared/vsys/device_group model) or NetScopeInput (the {Ngfw|Template|
// TemplateStack} model): a firewall vsys or shared scope, a Panorama template or
// template-stack (optionally down to a specific vsys within it), the Panorama
// shared scope, or the Panorama management-plane (panorama) scope, which is where
// Panorama's own appliance-level configuration lives. This gets its own resolver,
// resolveDeviceScope.
//
// Not every profile type is offered every scope here: two of the three
// log-settings profiles (SNMP-trap and email) and the authentication profile have
// no shared scope on this server, so requesting shared for one of them is rejected
// rather than silently retargeted. syslog is not among them; see
// noSharedScopeProfiles. Two families have no panorama scope for the same kind of
// reason; see noPanoramaScopeFamilies.
type DeviceScopeInput struct {
	Shared        bool   `json:"shared,omitzero" jsonschema:"Use the shared scope (firewall shared, or Panorama shared pushed to all device groups). Not available for snmp-trap, email and authentication profiles."`
	Panorama      bool   `json:"panorama,omitzero" jsonschema:"Use the Panorama management-plane scope (Panorama only). Not available for local database users and MFA server profiles."`
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
// resolveDeviceScope. Two of the constructors may be nil, which makes a request
// for that tier an error rather than a silently invalid location: shared for the
// SNMP-trap and email log-settings profiles and the authentication profile (see
// noSharedScopeProfiles), and panorama for local database users and MFA server
// profiles (see noPanoramaScopeFamilies). pango models no location at all for
// those combinations, so there is nothing to construct.
type deviceScopeParts[L any] struct {
	shared   func() L
	panorama func() L
	vsys     func(ngfw, vsys string) L
	templateScopeParts[L]
}

// validateDeviceScopeExclusivity enforces the "exactly one scope" contract for
// both device types: the two template-tier rules, plus shared and panorama being
// mutually exclusive and neither template tier combining with panorama.
//
// It deliberately does NOT reject template combined with shared, which resolves
// to the template. That is the device scope's documented divergence from the
// profile and management scopes, pinned by TestResolveDeviceScopePanoramaTemplate
// and tracked by issue #98; the asymmetry is preserved rather than widened.
// panorama is rejected with a template tier because the failure modes differ in
// blast radius: silently resolving panorama+template writes into a template,
// which pushes to every managed firewall using that template while the caller
// believes the write landed on the Panorama appliance itself.
func validateDeviceScopeExclusivity(in DeviceScopeInput) error {
	if err := validateTemplateExclusivity(in.Template, in.TemplateStack, in.TemplateVsys); err != nil {
		return err
	}
	if err := validateSharedPanoramaExclusivity(in.Shared, in.Panorama); err != nil {
		return err
	}
	return validateTemplatePanoramaExclusivity(in.Template, in.TemplateStack, in.Panorama)
}

// resolveDeviceScope maps a DeviceScopeInput onto a pango location for the
// connected device type. A firewall resolves to its vsys scope by default (or the
// shared scope when shared is set and the resource supports it); Panorama requires
// an explicit template, template_stack, shared, or panorama selection.
//
// vsys is ignored on a Panorama connection rather than rejected. That is
// pre-existing behaviour no test pins; tightening it would change the error
// surface of every device-scoped tool and belongs in its own change.
func resolveDeviceScope[L any](d *Deps, in DeviceScopeInput, p deviceScopeParts[L]) (L, error) {
	var zero L
	if err := validateDeviceScopeExclusivity(in); err != nil {
		return zero, err
	}
	if d.IsPanorama {
		return resolvePanoramaDeviceScope(in, p)
	}

	if in.Panorama || in.Template != "" || in.TemplateStack != "" {
		return zero, errors.New("panorama, template and template_stack require a Panorama connection; " +
			"on a firewall these live in the vsys scope (set vsys, or omit for vsys1)")
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
// an explicit template, template_stack (optionally down to a vsys), the shared
// scope, or the panorama management-plane scope is required. The template tier is
// tried first, so the template+shared divergence noted on
// validateDeviceScopeExclusivity keeps resolving to the template.
func resolvePanoramaDeviceScope[L any](in DeviceScopeInput, p deviceScopeParts[L]) (L, error) {
	var zero L
	loc, ok, err := resolveTemplateTier(in.Template, in.TemplateStack, in.TemplateVsys, p.templateScopeParts)
	if err != nil {
		return zero, err
	}
	if ok {
		return loc, nil
	}
	switch {
	case in.Panorama:
		if p.panorama == nil {
			return zero, errors.New("the panorama scope is not available for this object type; use a template, template_stack, or shared")
		}
		return p.panorama(), nil
	case in.Shared:
		if p.shared == nil {
			return zero, errors.New("the shared scope is not available for this profile type; use a template, template_stack, or panorama")
		}
		return p.shared(), nil
	default:
		return zero, errors.New("on Panorama set template, template_stack, shared, or panorama (shared is unavailable for " +
			noSharedScopeProfiles + "; panorama is unavailable for " + noPanoramaScopeFamilies +
			"); list templates with panos_template_list")
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
