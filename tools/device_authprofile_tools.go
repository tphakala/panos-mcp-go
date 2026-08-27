package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/authprofile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Authentication profiles (device/authprofile) name the method PAN-OS uses to
// authenticate a user or administrator, plus the lockout, MFA and Kerberos
// single-sign-on settings that wrap it. The method is a choice: exactly one of
// the branches under it may be set, which this server enforces client-side
// because pango does not (see applyAuthProfileMethod).
//
// Scope: pango models the authentication profile at a firewall vsys, a Panorama
// template or template-stack (optionally down to a vsys within it), and
// Panorama's own configuration. There is no shared scope, so this family joins
// the no-shared group alongside the log-settings profiles and leaves
// deviceScopeParts.shared nil; see noSharedScopeProfiles.
//
// Panorama's own authentication profiles (authprofile.Location.Panorama) are not
// reachable here. deviceScopeParts has no panorama constructor, so every
// device-scoped family reaches Panorama only through a template or
// template-stack. That is a limitation of the shared device scope rather than of
// this family, and it matches every other device-scoped family in this server.

func newAuthProfileService(d *Deps) nameFixAdapter[authprofile.Location, authprofile.Entry] {
	return nameFixAdapter[authprofile.Location, authprofile.Entry]{
		svc:    authprofile.NewService(d.Client),
		client: d.Client,
		name:   func(e *authprofile.Entry) string { return e.Name },
	}
}

// authProfileParts leaves shared nil: authprofile.Location has no shared scope,
// so resolveDeviceScope rejects a shared request rather than building an invalid
// location.
func authProfileParts() deviceScopeParts[authprofile.Location] {
	return deviceScopeParts[authprofile.Location]{
		vsys: func(ngfw, vsys string) authprofile.Location {
			return authprofile.Location{Vsys: &authprofile.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) authprofile.Location {
			return authprofile.Location{Template: &authprofile.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) authprofile.Location {
			return authprofile.Location{TemplateVsys: &authprofile.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) authprofile.Location {
			return authprofile.Location{TemplateStack: &authprofile.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) authprofile.Location {
			return authprofile.Location{TemplateStackVsys: &authprofile.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// Method branch inputs. Each branch is a pointer so that selection is driven by
// PRESENCE, not by a non-empty string: local-database and none carry no fields
// at all, so a string discriminator could never select them, and an empty string
// would be indistinguishable from "not provided" for the others. Send an empty
// object to select a field-free branch, for example {"method_none": {}}.

// AuthMethodKerberosInput selects Kerberos authentication.
type AuthMethodKerberosInput struct {
	Realm         *string `json:"realm,omitzero" jsonschema:"Kerberos realm"`
	ServerProfile *string `json:"server_profile,omitzero" jsonschema:"Kerberos server profile name"`
}

// AuthMethodLdapInput selects LDAP authentication.
type AuthMethodLdapInput struct {
	LoginAttribute *string `json:"login_attribute,omitzero" jsonschema:"LDAP attribute holding the login name (for example sAMAccountName)"`
	PasswdExpDays  *int64  `json:"passwd_exp_days,omitzero" jsonschema:"Warn this many days before the LDAP password expires"`
	ServerProfile  *string `json:"server_profile,omitzero" jsonschema:"LDAP server profile name (create one with panos_ldap_profile_create)"`
}

// AuthMethodLocalDatabaseInput selects the local user database. It carries no
// fields; send an empty object to select it.
type AuthMethodLocalDatabaseInput struct{}

// AuthMethodNoneInput selects no authentication. It carries no fields; send an
// empty object to select it.
type AuthMethodNoneInput struct{}

// AuthMethodRadiusInput selects RADIUS authentication.
type AuthMethodRadiusInput struct {
	Checkgroup    *bool   `json:"checkgroup,omitzero" jsonschema:"Retrieve the user group from the RADIUS Vendor-Specific Attribute"`
	ServerProfile *string `json:"server_profile,omitzero" jsonschema:"RADIUS server profile name (create one with panos_radius_profile_create)"`
}

// AuthMethodSamlIdpInput selects SAML single-sign-on authentication.
type AuthMethodSamlIdpInput struct {
	AttributeNameAccessDomain *string `json:"attribute_name_access_domain,omitzero" jsonschema:"SAML attribute carrying the access domain"`
	AttributeNameAdminRole    *string `json:"attribute_name_admin_role,omitzero" jsonschema:"SAML attribute carrying the admin role"`
	AttributeNameUsergroup    *string `json:"attribute_name_usergroup,omitzero" jsonschema:"SAML attribute carrying the user group"`
	AttributeNameUsername     *string `json:"attribute_name_username,omitzero" jsonschema:"SAML attribute carrying the username"`
	CertificateProfile        *string `json:"certificate_profile,omitzero" jsonschema:"Certificate profile validating the IdP signature (create one with panos_certificate_profile_create)"`
	EnableSingleLogout        *bool   `json:"enable_single_logout,omitzero" jsonschema:"Enable SAML single logout"`
	RequestSigningCertificate *string `json:"request_signing_certificate,omitzero" jsonschema:"Name of the certificate signing SAML requests"`
	ServerProfile             *string `json:"server_profile,omitzero" jsonschema:"SAML IdP server profile name (create one with panos_saml_idp_profile_create)"`
}

// AuthMethodTacplusInput selects TACACS+ authentication.
type AuthMethodTacplusInput struct {
	Checkgroup    *bool   `json:"checkgroup,omitzero" jsonschema:"Retrieve the user group from the TACACS+ server"`
	ServerProfile *string `json:"server_profile,omitzero" jsonschema:"TACACS+ server profile name (create one with panos_tacacs_profile_create)"`
}

// AuthProfileInput is the input for the authentication profile create and update
// tools. At most one method_* branch may be set; providing none leaves the
// stored method untouched.
//
// sso_kerberos_keytab is write-only and is never returned: a keytab holds the
// long-term key of its principal, so has_kerberos_keytab in the summary reports
// only whether one is set.
type AuthProfileInput struct {
	DeviceScopeInput
	Name             string   `json:"name" jsonschema:"Authentication profile name"`
	AllowList        []string `json:"allow_list,omitempty" jsonschema:"Users and groups permitted to authenticate; replaces the stored list"`
	UserDomain       *string  `json:"user_domain,omitzero" jsonschema:"Domain appended to the username before authenticating"`
	UsernameModifier *string  `json:"username_modifier,omitzero" jsonschema:"Username transformation, for example %USERINPUT% or %USERDOMAIN%\\\\%USERINPUT%"`

	LockoutFailedAttempts *int64 `json:"lockout_failed_attempts,omitzero" jsonschema:"Failed attempts before lockout (0 disables lockout)"`
	LockoutTime           *int64 `json:"lockout_time,omitzero" jsonschema:"Lockout duration in minutes"`

	MfaEnable  *bool    `json:"mfa_enable,omitzero" jsonschema:"Enable multi-factor authentication"`
	MfaFactors []string `json:"mfa_factors,omitempty" jsonschema:"MFA server profile names, in challenge order; replaces the stored list"`

	SsoRealm            *string `json:"sso_realm,omitzero" jsonschema:"Kerberos single-sign-on realm"`
	SsoServicePrincipal *string `json:"sso_service_principal,omitzero" jsonschema:"Kerberos single-sign-on service principal name"`
	SsoKerberosKeytab   *string `json:"sso_kerberos_keytab,omitzero" jsonschema:"Base64-encoded Kerberos keytab (write-only; never returned)"`

	MethodKerberos      *AuthMethodKerberosInput      `json:"method_kerberos,omitzero" jsonschema:"Authenticate against Kerberos"`
	MethodLdap          *AuthMethodLdapInput          `json:"method_ldap,omitzero" jsonschema:"Authenticate against LDAP"`
	MethodLocalDatabase *AuthMethodLocalDatabaseInput `json:"method_local_database,omitzero" jsonschema:"Authenticate against the local user database; send an empty object to select"`
	MethodNone          *AuthMethodNoneInput          `json:"method_none,omitzero" jsonschema:"No authentication; send an empty object to select"`
	MethodRadius        *AuthMethodRadiusInput        `json:"method_radius,omitzero" jsonschema:"Authenticate against RADIUS"`
	MethodSamlIdp       *AuthMethodSamlIdpInput       `json:"method_saml_idp,omitzero" jsonschema:"Authenticate against a SAML identity provider"`
	MethodTacplus       *AuthMethodTacplusInput       `json:"method_tacplus,omitzero" jsonschema:"Authenticate against TACACS+"`
}

// authMethodBranchNames lists the method_* input fields in the order the
// too-many-branches error reports them. It is the single source of truth for
// that message.
const authMethodBranchNames = "method_kerberos, method_ldap, method_local_database, method_none, method_radius, method_saml_idp, method_tacplus"

// applyAuthProfileMethod sets the authentication method. PAN-OS treats the eight
// children of <method> as a choice, but pango does not enforce it: methodXml's
// marshaller writes every non-nil branch independently, so setting one without
// clearing the others leaves the device a document it rejects. Selection is by
// field PRESENCE rather than by a non-empty value, because two of the branches
// (local-database and none) carry no fields at all.
//
// Providing no branch leaves the stored method untouched, which is what makes an
// update that only changes, say, user_domain safe for a profile whose method this
// server does not model (cloud).
//
// The clear covers all eight pango branches including cloud, which this server
// cannot set but a stored profile may carry: omitting it from the clear would
// leave two children under <method> after a switch away from cloud. The chosen
// branch is seeded from the value captured BEFORE the clear so a same-branch
// rebuild keeps that branch's unmodeled Misc, and the Method container itself is
// reused rather than replaced so the container's own Misc survives.
func applyAuthProfileMethod(e *authprofile.Entry, in *AuthProfileInput) error {
	n := 0
	for _, set := range []bool{
		in.MethodKerberos != nil, in.MethodLdap != nil, in.MethodLocalDatabase != nil,
		in.MethodNone != nil, in.MethodRadius != nil, in.MethodSamlIdp != nil, in.MethodTacplus != nil,
	} {
		if set {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if n > 1 {
		return errors.New("at most one of " + authMethodBranchNames + " may be set")
	}

	if e.Method == nil {
		e.Method = &authprofile.Method{}
	}
	m := e.Method

	// Capture before the clear: a same-branch rebuild seeds from these so the
	// branch keeps any XML this server does not model.
	oldKerberos, oldLdap, oldLocalDatabase := m.Kerberos, m.Ldap, m.LocalDatabase
	oldNone, oldRadius, oldSamlIdp, oldTacplus := m.None, m.Radius, m.SamlIdp, m.Tacplus

	m.Cloud, m.Kerberos, m.Ldap, m.LocalDatabase = nil, nil, nil, nil
	m.None, m.Radius, m.SamlIdp, m.Tacplus = nil, nil, nil, nil

	switch {
	case in.MethodKerberos != nil:
		b := seedBranch(oldKerberos)
		setPtr(&b.Realm, in.MethodKerberos.Realm)
		setPtr(&b.ServerProfile, in.MethodKerberos.ServerProfile)
		m.Kerberos = b
	case in.MethodLdap != nil:
		b := seedBranch(oldLdap)
		setPtr(&b.LoginAttribute, in.MethodLdap.LoginAttribute)
		setPtr(&b.PasswdExpDays, in.MethodLdap.PasswdExpDays)
		setPtr(&b.ServerProfile, in.MethodLdap.ServerProfile)
		m.Ldap = b
	case in.MethodLocalDatabase != nil:
		m.LocalDatabase = seedBranch(oldLocalDatabase)
	case in.MethodNone != nil:
		m.None = seedBranch(oldNone)
	case in.MethodRadius != nil:
		b := seedBranch(oldRadius)
		setPtr(&b.Checkgroup, in.MethodRadius.Checkgroup)
		setPtr(&b.ServerProfile, in.MethodRadius.ServerProfile)
		m.Radius = b
	case in.MethodSamlIdp != nil:
		b := seedBranch(oldSamlIdp)
		setPtr(&b.AttributeNameAccessDomain, in.MethodSamlIdp.AttributeNameAccessDomain)
		setPtr(&b.AttributeNameAdminRole, in.MethodSamlIdp.AttributeNameAdminRole)
		setPtr(&b.AttributeNameUsergroup, in.MethodSamlIdp.AttributeNameUsergroup)
		setPtr(&b.AttributeNameUsername, in.MethodSamlIdp.AttributeNameUsername)
		setPtr(&b.CertificateProfile, in.MethodSamlIdp.CertificateProfile)
		setPtr(&b.EnableSingleLogout, in.MethodSamlIdp.EnableSingleLogout)
		setPtr(&b.RequestSigningCertificate, in.MethodSamlIdp.RequestSigningCertificate)
		setPtr(&b.ServerProfile, in.MethodSamlIdp.ServerProfile)
		m.SamlIdp = b
	default: // in.MethodTacplus != nil
		b := seedBranch(oldTacplus)
		setPtr(&b.Checkgroup, in.MethodTacplus.Checkgroup)
		setPtr(&b.ServerProfile, in.MethodTacplus.ServerProfile)
		m.Tacplus = b
	}
	return nil
}

// seedBranch returns the stored method branch so a same-branch rebuild keeps its
// unmodeled Misc, or a fresh one when the profile previously used a different
// branch. Taking the stored pointer rather than copying is safe because the
// caller has already cleared every branch off the container, so the returned
// value has exactly one owner.
func seedBranch[T any](old *T) *T {
	if old != nil {
		return old
	}
	return new(T)
}

// applyAuthProfileLockout sets the lockout sub-block, allocating it only when the
// caller provides a value so an untouched profile keeps a nil Lockout rather than
// gaining an empty node.
func applyAuthProfileLockout(e *authprofile.Entry, in *AuthProfileInput) {
	if in.LockoutFailedAttempts == nil && in.LockoutTime == nil {
		return
	}
	if e.Lockout == nil {
		e.Lockout = &authprofile.Lockout{}
	}
	setPtr(&e.Lockout.FailedAttempts, in.LockoutFailedAttempts)
	setPtr(&e.Lockout.LockoutTime, in.LockoutTime)
}

// applyAuthProfileMfa sets the multi-factor sub-block. Factors replaces the
// stored list when provided; a nil list leaves it alone.
func applyAuthProfileMfa(e *authprofile.Entry, in *AuthProfileInput) {
	if in.MfaEnable == nil && in.MfaFactors == nil {
		return
	}
	if e.MultiFactorAuth == nil {
		e.MultiFactorAuth = &authprofile.MultiFactorAuth{}
	}
	setPtr(&e.MultiFactorAuth.MfaEnable, in.MfaEnable)
	if in.MfaFactors != nil {
		e.MultiFactorAuth.Factors = in.MfaFactors
	}
}

// applyAuthProfileSso sets the Kerberos single-sign-on sub-block. The keytab is
// write-only: it is set when provided and otherwise left as stored, so an update
// that omits it keeps the device's copy.
func applyAuthProfileSso(e *authprofile.Entry, in *AuthProfileInput) {
	if in.SsoRealm == nil && in.SsoServicePrincipal == nil && in.SsoKerberosKeytab == nil {
		return
	}
	if e.SingleSignOn == nil {
		e.SingleSignOn = &authprofile.SingleSignOn{}
	}
	setPtr(&e.SingleSignOn.Realm, in.SsoRealm)
	setPtr(&e.SingleSignOn.ServicePrincipal, in.SsoServicePrincipal)
	setPtr(&e.SingleSignOn.KerberosKeytab, in.SsoKerberosKeytab)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyAuthProfile(e *authprofile.Entry, in AuthProfileInput) error {
	if in.AllowList != nil {
		e.AllowList = in.AllowList
	}
	setPtr(&e.UserDomain, in.UserDomain)
	setPtr(&e.UsernameModifier, in.UsernameModifier)
	applyAuthProfileLockout(e, &in)
	applyAuthProfileMfa(e, &in)
	applyAuthProfileSso(e, &in)
	return applyAuthProfileMethod(e, &in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildAuthProfile(in AuthProfileInput) (*authprofile.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &authprofile.Entry{Name: in.Name}
	if err := applyAuthProfile(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayAuthProfile(e *authprofile.Entry, in AuthProfileInput) error {
	return applyAuthProfile(e, in)
}

// authProfileMethodString names the active method branch, including cloud, which
// this server can report but not set. An empty string means no method is
// configured.
func authProfileMethodString(m *authprofile.Method) string {
	if m == nil {
		return ""
	}
	switch {
	case m.Cloud != nil:
		return "cloud"
	case m.Kerberos != nil:
		return "kerberos"
	case m.Ldap != nil:
		return "ldap"
	case m.LocalDatabase != nil:
		return "local-database"
	case m.None != nil:
		return "none"
	case m.Radius != nil:
		return "radius"
	case m.SamlIdp != nil:
		return "saml-idp"
	case m.Tacplus != nil:
		return "tacplus"
	default:
		return ""
	}
}

// authProfileMethodDetail projects the active branch's modeled fields. The cloud
// branch reports its name only: this server does not model its five-level
// subtree, which the read-modify-write update preserves untouched.
func authProfileMethodDetail(m *authprofile.Method) map[string]any {
	detail := map[string]any{}
	if m == nil {
		return detail
	}
	switch {
	case m.Kerberos != nil:
		detail["realm"] = strVal(m.Kerberos.Realm)
		detail["server_profile"] = strVal(m.Kerberos.ServerProfile)
	case m.Ldap != nil:
		detail["login_attribute"] = strVal(m.Ldap.LoginAttribute)
		detail["server_profile"] = strVal(m.Ldap.ServerProfile)
		putInt(detail, "passwd_exp_days", m.Ldap.PasswdExpDays)
	case m.Radius != nil:
		detail["server_profile"] = strVal(m.Radius.ServerProfile)
		putBool(detail, "checkgroup", m.Radius.Checkgroup)
	case m.Tacplus != nil:
		detail["server_profile"] = strVal(m.Tacplus.ServerProfile)
		putBool(detail, "checkgroup", m.Tacplus.Checkgroup)
	case m.SamlIdp != nil:
		detail["server_profile"] = strVal(m.SamlIdp.ServerProfile)
		detail["certificate_profile"] = strVal(m.SamlIdp.CertificateProfile)
		detail["request_signing_certificate"] = strVal(m.SamlIdp.RequestSigningCertificate)
		detail["attribute_name_username"] = strVal(m.SamlIdp.AttributeNameUsername)
		detail["attribute_name_usergroup"] = strVal(m.SamlIdp.AttributeNameUsergroup)
		detail["attribute_name_admin_role"] = strVal(m.SamlIdp.AttributeNameAdminRole)
		detail["attribute_name_access_domain"] = strVal(m.SamlIdp.AttributeNameAccessDomain)
		putBool(detail, "enable_single_logout", m.SamlIdp.EnableSingleLogout)
	}
	return detail
}

// authProfileSummary projects an authentication profile. The Kerberos keytab is
// key material and is never echoed; has_kerberos_keytab reports presence only.
func authProfileSummary(e *authprofile.Entry) any {
	m := map[string]any{
		tagNameKey: e.Name,
		"method":   authProfileMethodString(e.Method),
	}
	if detail := authProfileMethodDetail(e.Method); len(detail) > 0 {
		m["method_detail"] = detail
	}
	if len(e.AllowList) > 0 {
		m["allow_list"] = e.AllowList
	}
	m["user_domain"] = strVal(e.UserDomain)
	m["username_modifier"] = strVal(e.UsernameModifier)
	if e.Lockout != nil {
		putInt(m, "lockout_failed_attempts", e.Lockout.FailedAttempts)
		putInt(m, "lockout_time", e.Lockout.LockoutTime)
	}
	if e.MultiFactorAuth != nil {
		putBool(m, "mfa_enable", e.MultiFactorAuth.MfaEnable)
		if len(e.MultiFactorAuth.Factors) > 0 {
			m["mfa_factors"] = e.MultiFactorAuth.Factors
		}
	}
	// The keytab is write-only; report presence only, never the value.
	hasKeytab := false
	if e.SingleSignOn != nil {
		m["sso_realm"] = strVal(e.SingleSignOn.Realm)
		m["sso_service_principal"] = strVal(e.SingleSignOn.ServicePrincipal)
		hasKeytab = e.SingleSignOn.KerberosKeytab != nil && *e.SingleSignOn.KerberosKeytab != ""
	}
	m["has_kerberos_keytab"] = hasKeytab
	return m
}

// RegisterAuthProfileTools registers the authentication profile tools on both
// firewall and Panorama.
func RegisterAuthProfileTools(s *mcp.Server, d *Deps) {
	svc := newAuthProfileService(d)
	parts := authProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_auth_profile_list",
		Description: "List authentication profiles. Firewall: vsys; Panorama: a template or template_stack is required. There is no shared scope for authentication profiles. Read-only.",
		Annotations: readOnlyTool("List authentication profiles"),
	}, deviceListHandler(d, "panos_auth_profile_list", svc, parts, svc.name, authProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_auth_profile_get",
		Description: "Get one authentication profile: the active method and its settings, lockout, MFA and Kerberos single sign-on. The Kerberos keytab is never returned; has_kerberos_keytab reports whether one is set. Read-only.",
		Annotations: readOnlyTool("Get authentication profile"),
	}, deviceGetHandler(d, "panos_auth_profile_get", svc, parts, authProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "panos_auth_profile_create",
		Description: "Create an authentication profile in the candidate config. Set at most one method_* branch; each names a server profile created by its own tool. " +
			"sso_kerberos_keytab is write-only and is never returned. Run panos_commit to apply.",
		Annotations: createTool("Create authentication profile"),
	}, deviceCreateHandler(d, "panos_auth_profile_create", svc, parts,
		buildAuthProfile, authProfileSummary, withSecrets(authProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name: "panos_auth_profile_update",
		Description: "Update an authentication profile: read-modify-write, only provided fields change. Setting one method_* branch clears the others, because PAN-OS allows exactly one; " +
			"that includes clearing a cloud method this server cannot set. Providing no method_* branch leaves the stored method untouched. " +
			"allow_list and mfa_factors replace the stored lists. Omitting sso_kerberos_keytab keeps the stored keytab. Run panos_commit to apply.",
		Annotations: updateTool("Update authentication profile"),
	}, deviceUpdateHandler(d, "panos_auth_profile_update", svc, parts,
		func(in AuthProfileInput) string { return in.Name }, overlayAuthProfile, authProfileSummary,
		withSecrets(authProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_auth_profile_delete",
		Description: "Delete an authentication profile from the candidate config. Fails while an authentication rule or administrator still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete authentication profile"),
	}, deviceDeleteHandler(d, "panos_auth_profile_delete", svc, parts))
}
