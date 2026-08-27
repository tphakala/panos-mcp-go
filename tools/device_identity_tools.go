package tools

import (
	"errors"

	localdb "github.com/PaloAltoNetworks/pango/device/localdb/user"
	"github.com/PaloAltoNetworks/pango/device/profiles/mfa"
	"github.com/PaloAltoNetworks/pango/device/profiles/samlidp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Local database user (device/localdb/user)
// ---------------------------------------------------------------------------

func newLocalUserService(d *Deps) nameFixAdapter[localdb.Location, localdb.Entry] {
	return nameFixAdapter[localdb.Location, localdb.Entry]{
		svc:    localdb.NewService(d.Client),
		client: d.Client,
		name:   func(e *localdb.Entry) string { return e.Name },
	}
}

func localUserParts() deviceScopeParts[localdb.Location] {
	return deviceScopeParts[localdb.Location]{
		shared: func() localdb.Location { return localdb.Location{Shared: &localdb.SharedLocation{}} },
		vsys: func(ngfw, vsys string) localdb.Location {
			return localdb.Location{Vsys: &localdb.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) localdb.Location {
			return localdb.Location{Template: &localdb.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) localdb.Location {
			return localdb.Location{TemplateVsys: &localdb.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) localdb.Location {
			return localdb.Location{TemplateStack: &localdb.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) localdb.Location {
			return localdb.Location{TemplateStackVsys: &localdb.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// LocalUserInput is the input for the local database user create and update
// tools. password_hash is a write-only pre-hashed password (PHASH) and is never
// returned; has_password_hash in the summary reports only whether one is set.
type LocalUserInput struct {
	DeviceScopeInput
	Name         string  `json:"name" jsonschema:"Local database user name"`
	Disabled     *bool   `json:"disabled,omitzero" jsonschema:"Disable this user"`
	PasswordHash *string `json:"password_hash,omitzero" jsonschema:"Pre-hashed password (PHASH string, e.g. the output of the request-password-hash operation). Required on create (PAN-OS rejects a local user with no phash); optional on update, where omitting it keeps the stored value. Write-only: never returned."`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyLocalUser(e *localdb.Entry, in LocalUserInput) {
	setPtr(&e.Disabled, in.Disabled)
	setPtr(&e.Phash, in.PasswordHash)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLocalUser(in LocalUserInput) (*localdb.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	// PAN-OS requires a password hash for every local database user. A create
	// without one fails commit-time validation with "... local-user-database ->
	// user -> <name> is missing 'phash'" (verified live against PAN-OS
	// 11.1.16-h1 via validate full). Reject it up front with a clear message
	// instead of surfacing the device error at commit. Update stays lenient: an
	// omitted password_hash keeps the stored value (see overlayLocalUser), so the
	// guard lives here on the create path only, not on the shared applyLocalUser.
	if in.PasswordHash == nil || *in.PasswordHash == "" {
		return nil, errors.New("password_hash is required to create a local database user")
	}
	e := &localdb.Entry{Name: in.Name}
	applyLocalUser(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLocalUser(e *localdb.Entry, in LocalUserInput) error {
	applyLocalUser(e, in)
	return nil
}

func localUserSummary(e *localdb.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putBool(m, "disabled", e.Disabled)
	// has_password_hash reports presence only; the phash itself is a write-only
	// secret and never appears in the summary.
	m["has_password_hash"] = e.Phash != nil && *e.Phash != ""
	return m
}

// RegisterLocalUserTools registers the local database user tools on both
// firewall and Panorama.
func RegisterLocalUserTools(s *mcp.Server, d *Deps) {
	svc := newLocalUserService(d)
	parts := localUserParts()
	scope := func(in LocalUserInput) DeviceScopeInput { return in.DeviceScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_local_user_list",
		Description: "List local database users. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List local database users"),
	}, deviceListHandler(d, "panos_local_user_list", svc, parts, svc.name, localUserSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_local_user_get",
		Description: "Get one local database user. The password hash is never returned; has_password_hash reports whether one is set. Read-only.",
		Annotations: readOnlyTool("Get local database user"),
	}, deviceGetHandler(d, "panos_local_user_get", svc, parts, localUserSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_local_user_create",
		Description: "Create a local database user in the candidate config. password_hash is required (PAN-OS rejects a local user with no phash) and is a write-only pre-hashed password. Run panos_commit to apply.",
		Annotations: createTool("Create local database user"),
	}, deviceCreateHandler(d, "panos_local_user_create", svc, parts, scope, buildLocalUser, localUserSummary, withSecrets(localUserSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_local_user_update",
		Description: "Update a local database user: read-modify-write, only provided fields change. An omitted password_hash keeps the stored value. Run panos_commit to apply.",
		Annotations: updateTool("Update local database user"),
	}, deviceUpdateHandler(d, "panos_local_user_update", svc, parts, scope,
		func(in LocalUserInput) string { return in.Name }, overlayLocalUser, localUserSummary, withSecrets(localUserSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_local_user_delete",
		Description: "Delete a local database user from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete local database user"),
	}, deviceDeleteHandler(d, "panos_local_user_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// SAML IdP profile (device/profiles/samlidp)
// ---------------------------------------------------------------------------

func newSamlIdpProfileService(d *Deps) nameFixAdapter[samlidp.Location, samlidp.Entry] {
	return nameFixAdapter[samlidp.Location, samlidp.Entry]{
		svc:    samlidp.NewService(d.Client),
		client: d.Client,
		name:   func(e *samlidp.Entry) string { return e.Name },
	}
}

func samlIdpProfileParts() deviceScopeParts[samlidp.Location] {
	return deviceScopeParts[samlidp.Location]{
		shared: func() samlidp.Location { return samlidp.Location{Shared: &samlidp.SharedLocation{}} },
		vsys: func(ngfw, vsys string) samlidp.Location {
			return samlidp.Location{Vsys: &samlidp.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) samlidp.Location {
			return samlidp.Location{Template: &samlidp.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) samlidp.Location {
			return samlidp.Location{TemplateVsys: &samlidp.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) samlidp.Location {
			return samlidp.Location{TemplateStack: &samlidp.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) samlidp.Location {
			return samlidp.Location{TemplateStackVsys: &samlidp.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// SamlIdpProfileInput is the input for the SAML IdP profile create and update
// tools. certificate names an existing device certificate (a reference), not a
// secret blob. The remaining SAML attribute-mapping fields (access-domain and
// admin-role import) are not modeled here; a read-modify-write update preserves
// them untouched.
type SamlIdpProfileInput struct {
	DeviceScopeInput
	Name                   string  `json:"name" jsonschema:"SAML IdP server profile name"`
	EntityId               *string `json:"entity_id,omitzero" jsonschema:"SAML entity ID of the identity provider"`
	SsoUrl                 *string `json:"sso_url,omitzero" jsonschema:"Identity provider single sign-on URL"`
	SsoBindings            *string `json:"sso_bindings,omitzero" jsonschema:"SSO request binding: post or redirect"`
	SloUrl                 *string `json:"slo_url,omitzero" jsonschema:"Identity provider single logout URL"`
	SloBindings            *string `json:"slo_bindings,omitzero" jsonschema:"SLO request binding: post or redirect"`
	Certificate            *string `json:"certificate,omitzero" jsonschema:"Name of the identity provider certificate (a reference to a device certificate, not a certificate blob)"`
	ValidateIdpCertificate *bool   `json:"validate_idp_certificate,omitzero" jsonschema:"Validate the identity provider certificate"`
	WantAuthRequestsSigned *bool   `json:"want_auth_requests_signed,omitzero" jsonschema:"Sign SAML authentication requests"`
	MaxClockSkew           *int64  `json:"max_clock_skew,omitzero" jsonschema:"Maximum allowed clock skew in seconds"`
	AdminUseOnly           *bool   `json:"admin_use_only,omitzero" jsonschema:"Restrict this profile to administrator authentication"`
	AttributeUsername      *string `json:"attribute_username,omitzero" jsonschema:"SAML attribute name carrying the username"`
	AttributeUsergroup     *string `json:"attribute_usergroup,omitzero" jsonschema:"SAML attribute name carrying the user group"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applySamlIdpProfile(e *samlidp.Entry, in SamlIdpProfileInput) {
	setPtr(&e.EntityId, in.EntityId)
	setPtr(&e.SsoUrl, in.SsoUrl)
	setPtr(&e.SsoBindings, in.SsoBindings)
	setPtr(&e.SloUrl, in.SloUrl)
	setPtr(&e.SloBindings, in.SloBindings)
	setPtr(&e.Certificate, in.Certificate)
	setPtr(&e.ValidateIdpCertificate, in.ValidateIdpCertificate)
	setPtr(&e.WantAuthRequestsSigned, in.WantAuthRequestsSigned)
	setPtr(&e.MaxClockSkew, in.MaxClockSkew)
	setPtr(&e.AdminUseOnly, in.AdminUseOnly)
	setPtr(&e.AttributeNameUsernameImport, in.AttributeUsername)
	setPtr(&e.AttributeNameUsergroupImport, in.AttributeUsergroup)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildSamlIdpProfile(in SamlIdpProfileInput) (*samlidp.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &samlidp.Entry{Name: in.Name}
	applySamlIdpProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlaySamlIdpProfile(e *samlidp.Entry, in SamlIdpProfileInput) error {
	applySamlIdpProfile(e, in)
	return nil
}

func samlIdpProfileSummary(e *samlidp.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["entity_id"] = strVal(e.EntityId)
	m["sso_url"] = strVal(e.SsoUrl)
	m["sso_bindings"] = strVal(e.SsoBindings)
	m["slo_url"] = strVal(e.SloUrl)
	m["slo_bindings"] = strVal(e.SloBindings)
	m["certificate"] = strVal(e.Certificate)
	putBool(m, "validate_idp_certificate", e.ValidateIdpCertificate)
	putBool(m, "want_auth_requests_signed", e.WantAuthRequestsSigned)
	putInt(m, "max_clock_skew", e.MaxClockSkew)
	putBool(m, "admin_use_only", e.AdminUseOnly)
	m["attribute_username"] = strVal(e.AttributeNameUsernameImport)
	m["attribute_usergroup"] = strVal(e.AttributeNameUsergroupImport)
	return m
}

// RegisterSamlIdpProfileTools registers the SAML IdP server profile tools on
// both firewall and Panorama.
func RegisterSamlIdpProfileTools(s *mcp.Server, d *Deps) {
	svc := newSamlIdpProfileService(d)
	parts := samlIdpProfileParts()
	scope := func(in SamlIdpProfileInput) DeviceScopeInput { return in.DeviceScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_saml_idp_profile_list",
		Description: "List SAML IdP server profiles. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List SAML IdP server profiles"),
	}, deviceListHandler(d, "panos_saml_idp_profile_list", svc, parts, svc.name, samlIdpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_saml_idp_profile_get",
		Description: "Get one SAML IdP server profile. Read-only.",
		Annotations: readOnlyTool("Get SAML IdP server profile"),
	}, deviceGetHandler(d, "panos_saml_idp_profile_get", svc, parts, samlIdpProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_saml_idp_profile_create",
		Description: "Create a SAML IdP server profile in the candidate config. certificate names an existing device certificate. Run panos_commit to apply.",
		Annotations: createTool("Create SAML IdP server profile"),
	}, deviceCreateHandler(d, "panos_saml_idp_profile_create", svc, parts, scope, buildSamlIdpProfile, samlIdpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_saml_idp_profile_update",
		Description: "Update a SAML IdP server profile: read-modify-write, only provided fields change. Run panos_commit to apply.",
		Annotations: updateTool("Update SAML IdP server profile"),
	}, deviceUpdateHandler(d, "panos_saml_idp_profile_update", svc, parts, scope,
		func(in SamlIdpProfileInput) string { return in.Name }, overlaySamlIdpProfile, samlIdpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_saml_idp_profile_delete",
		Description: "Delete a SAML IdP server profile from the candidate config. Fails while authentication profiles still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete SAML IdP server profile"),
	}, deviceDeleteHandler(d, "panos_saml_idp_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// MFA server profile (device/profiles/mfa)
// ---------------------------------------------------------------------------

func newMfaProfileService(d *Deps) nameFixAdapter[mfa.Location, mfa.Entry] {
	return nameFixAdapter[mfa.Location, mfa.Entry]{
		svc:    mfa.NewService(d.Client),
		client: d.Client,
		name:   func(e *mfa.Entry) string { return e.Name },
	}
}

func mfaProfileParts() deviceScopeParts[mfa.Location] {
	return deviceScopeParts[mfa.Location]{
		shared: func() mfa.Location { return mfa.Location{Shared: &mfa.SharedLocation{}} },
		vsys: func(ngfw, vsys string) mfa.Location {
			return mfa.Location{Vsys: &mfa.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) mfa.Location {
			return mfa.Location{Template: &mfa.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) mfa.Location {
			return mfa.Location{TemplateVsys: &mfa.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) mfa.Location {
			return mfa.Location{TemplateStack: &mfa.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) mfa.Location {
			return mfa.Location{TemplateStackVsys: &mfa.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// MfaVendorConfigInput is one MFA vendor configuration item: a name and its
// single value. pango models MfaConfig as a flat name/value pair (Value is a
// single *string), so it is modeled here as a simple list rather than a nested
// structure. A vendor config value can be a vendor secret (for example an API
// secret key), so it is treated as write-only: it is accepted on create and
// update, redacted from a failed-write error, and never returned. A get reports
// only has_value.
type MfaVendorConfigInput struct {
	Name  string  `json:"name" jsonschema:"Vendor configuration attribute name"`
	Value *string `json:"value,omitzero" jsonschema:"Vendor configuration attribute value. Write-only: it may hold a vendor secret, so it is never returned; a get reports has_value."`
}

// MfaProfileInput is the input for the MFA server profile create and update
// tools. Vendor config values are treated as write-only (see MfaVendorConfigInput).
type MfaProfileInput struct {
	DeviceScopeInput
	Name               string                 `json:"name" jsonschema:"MFA server profile name"`
	CertificateProfile *string                `json:"certificate_profile,omitzero" jsonschema:"Name of the certificate profile used to validate the MFA server certificate"`
	VendorType         *string                `json:"vendor_type,omitzero" jsonschema:"MFA vendor type (e.g. PingID, Okta Adaptive, Duo v2, RSA SecurID Access)"`
	Config             []MfaVendorConfigInput `json:"config,omitzero" jsonschema:"Vendor configuration name/value items; replaces the whole list when provided"`
}

func mfaVendorConfig(in []MfaVendorConfigInput) []mfa.MfaConfig {
	out := make([]mfa.MfaConfig, 0, len(in))
	for _, c := range in {
		mc := mfa.MfaConfig{Name: c.Name}
		setPtr(&mc.Value, c.Value)
		out = append(out, mc)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyMfaProfile(e *mfa.Entry, in MfaProfileInput) {
	setPtr(&e.MfaCertProfile, in.CertificateProfile)
	setPtr(&e.MfaVendorType, in.VendorType)
	if in.Config != nil {
		e.MfaConfig = mfaVendorConfig(in.Config)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildMfaProfile(in MfaProfileInput) (*mfa.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &mfa.Entry{Name: in.Name}
	applyMfaProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayMfaProfile(e *mfa.Entry, in MfaProfileInput) error {
	applyMfaProfile(e, in)
	return nil
}

func mfaVendorConfigSummaries(items []mfa.MfaConfig) []any {
	out := make([]any, 0, len(items))
	for i := range items {
		c := &items[i]
		out = append(out, map[string]any{tagNameKey: c.Name, "has_value": c.Value != nil && *c.Value != ""})
	}
	return out
}

func mfaProfileSummary(e *mfa.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["certificate_profile"] = strVal(e.MfaCertProfile)
	m["vendor_type"] = strVal(e.MfaVendorType)
	m["config"] = mfaVendorConfigSummaries(e.MfaConfig)
	return m
}

// RegisterMfaProfileTools registers the MFA server profile tools on both
// firewall and Panorama.
func RegisterMfaProfileTools(s *mcp.Server, d *Deps) {
	svc := newMfaProfileService(d)
	parts := mfaProfileParts()
	scope := func(in MfaProfileInput) DeviceScopeInput { return in.DeviceScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_mfa_profile_list",
		Description: "List MFA server profiles. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List MFA server profiles"),
	}, deviceListHandler(d, "panos_mfa_profile_list", svc, parts, svc.name, mfaProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_mfa_profile_get",
		Description: "Get one MFA server profile. Read-only.",
		Annotations: readOnlyTool("Get MFA server profile"),
	}, deviceGetHandler(d, "panos_mfa_profile_get", svc, parts, mfaProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_mfa_profile_create",
		Description: "Create an MFA server profile in the candidate config. Vendor config values are write-only. Run panos_commit to apply.",
		Annotations: createTool("Create MFA server profile"),
	}, deviceCreateHandler(d, "panos_mfa_profile_create", svc, parts, scope, buildMfaProfile, mfaProfileSummary, withSecrets(mfaProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_mfa_profile_update",
		Description: "Update an MFA server profile: read-modify-write, only provided fields change; a provided config list replaces the whole list. Vendor config values are write-only. Run panos_commit to apply.",
		Annotations: updateTool("Update MFA server profile"),
	}, deviceUpdateHandler(d, "panos_mfa_profile_update", svc, parts, scope,
		func(in MfaProfileInput) string { return in.Name }, overlayMfaProfile, mfaProfileSummary, withSecrets(mfaProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_mfa_profile_delete",
		Description: "Delete an MFA server profile from the candidate config. Fails while authentication profiles still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete MFA server profile"),
	}, deviceDeleteHandler(d, "panos_mfa_profile_delete", svc, parts))
}
