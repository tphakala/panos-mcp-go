package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/administrator"
	"github.com/PaloAltoNetworks/pango/device/profiles/password"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Password profile (device/profiles/password)
// ---------------------------------------------------------------------------

func newPasswordProfileService(d *Deps) nameFixAdapter[password.Location, password.Entry] {
	return nameFixAdapter[password.Location, password.Entry]{
		svc:    password.NewService(d.Client),
		client: d.Client,
		name:   func(e *password.Entry) string { return e.Name },
	}
}

func passwordProfileParts() mgtScopeParts[password.Location] {
	return mgtScopeParts[password.Location]{
		ngfw:     func() password.Location { return password.Location{Ngfw: &password.NgfwLocation{}} },
		panorama: func() password.Location { return password.Location{Panorama: &password.PanoramaLocation{}} },
		templateScopeParts: templateScopeParts[password.Location]{
			template: func(pano, tmpl string) password.Location {
				return password.Location{Template: &password.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
			},
			templateStack: func(pano, stack string) password.Location {
				return password.Location{TemplateStack: &password.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
			},
		},
	}
}

// PasswordProfileInput is the input for the password profile create and update
// tools. Every setting lives under pango's password-change block, which is
// allocated only when the caller provides one of them.
type PasswordProfileInput struct {
	MgtScopeInput
	Name                          string `json:"name" jsonschema:"Password profile name"`
	ExpirationPeriod              *int64 `json:"expiration_period,omitzero" jsonschema:"Days before a password expires (0 disables expiry)"`
	ExpirationWarningPeriod       *int64 `json:"expiration_warning_period,omitzero" jsonschema:"Days before expiry to start warning the administrator"`
	PostExpirationAdminLoginCount *int64 `json:"post_expiration_admin_login_count,omitzero" jsonschema:"Number of logins allowed after the password expires"`
	PostExpirationGracePeriod     *int64 `json:"post_expiration_grace_period,omitzero" jsonschema:"Days of grace allowed after the password expires"`
}

// passwordProfileHasChangeSettings reports whether the caller provided any
// password-change setting. A name-only create must not emit an empty
// password-change block.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func passwordProfileHasChangeSettings(in PasswordProfileInput) bool {
	return in.ExpirationPeriod != nil || in.ExpirationWarningPeriod != nil ||
		in.PostExpirationAdminLoginCount != nil || in.PostExpirationGracePeriod != nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyPasswordProfile(e *password.Entry, in PasswordProfileInput) {
	if !passwordProfileHasChangeSettings(in) {
		return
	}
	if e.PasswordChange == nil {
		e.PasswordChange = &password.PasswordChange{}
	}
	setPtr(&e.PasswordChange.ExpirationPeriod, in.ExpirationPeriod)
	setPtr(&e.PasswordChange.ExpirationWarningPeriod, in.ExpirationWarningPeriod)
	setPtr(&e.PasswordChange.PostExpirationAdminLoginCount, in.PostExpirationAdminLoginCount)
	setPtr(&e.PasswordChange.PostExpirationGracePeriod, in.PostExpirationGracePeriod)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildPasswordProfile(in PasswordProfileInput) (*password.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &password.Entry{Name: in.Name}
	applyPasswordProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayPasswordProfile(e *password.Entry, in PasswordProfileInput) error {
	applyPasswordProfile(e, in)
	return nil
}

func passwordProfileSummary(e *password.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	if e.PasswordChange != nil {
		putInt(m, "expiration_period", e.PasswordChange.ExpirationPeriod)
		putInt(m, "expiration_warning_period", e.PasswordChange.ExpirationWarningPeriod)
		putInt(m, "post_expiration_admin_login_count", e.PasswordChange.PostExpirationAdminLoginCount)
		putInt(m, "post_expiration_grace_period", e.PasswordChange.PostExpirationGracePeriod)
	}
	return m
}

// RegisterPasswordProfileTools registers the password profile tools on both
// firewall and Panorama.
func RegisterPasswordProfileTools(s *mcp.Server, d *Deps) {
	svc := newPasswordProfileService(d)
	parts := passwordProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_password_profile_list",
		Description: "List password profiles (mgt-config). Firewall: the device's own scope; Panorama: panorama, template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List password profiles"),
	}, mgtListHandler(d, "panos_password_profile_list", svc, parts, svc.name, passwordProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_password_profile_get",
		Description: "Get one password profile (expiry period, warning period, post-expiry logins and grace period). Read-only.",
		Annotations: readOnlyTool("Get password profile"),
	}, mgtGetHandler(d, "panos_password_profile_get", svc, parts, passwordProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_password_profile_create",
		Description: "Create a password profile in the candidate config. Administrators reference it by name through password_profile. Run panos_commit to apply.",
		Annotations: createTool("Create password profile"),
	}, mgtCreateHandler(d, "panos_password_profile_create", svc, parts, buildPasswordProfile, passwordProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_password_profile_update",
		Description: "Update a password profile: read-modify-write, only provided fields change. Run panos_commit to apply.",
		Annotations: updateTool("Update password profile"),
	}, mgtUpdateHandler(d, "panos_password_profile_update", svc, parts,
		func(in PasswordProfileInput) string { return in.Name }, overlayPasswordProfile, passwordProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_password_profile_delete",
		Description: "Delete a password profile from the candidate config. An administrator still referencing it will fail validation. Run panos_commit to apply.",
		Annotations: deleteTool("Delete password profile"),
	}, mgtDeleteHandler(d, "panos_password_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Administrator (device/administrator)
// ---------------------------------------------------------------------------

func newAdministratorService(d *Deps) nameFixAdapter[administrator.Location, administrator.Entry] {
	return nameFixAdapter[administrator.Location, administrator.Entry]{
		svc:    administrator.NewService(d.Client),
		client: d.Client,
		name:   func(e *administrator.Entry) string { return e.Name },
	}
}

func administratorParts() mgtScopeParts[administrator.Location] {
	return mgtScopeParts[administrator.Location]{
		ngfw: func() administrator.Location { return administrator.Location{Ngfw: &administrator.NgfwLocation{}} },
		panorama: func() administrator.Location {
			return administrator.Location{Panorama: &administrator.PanoramaLocation{}}
		},
		templateScopeParts: templateScopeParts[administrator.Location]{
			template: func(pano, tmpl string) administrator.Location {
				return administrator.Location{Template: &administrator.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
			},
			templateStack: func(pano, stack string) administrator.Location {
				return administrator.Location{TemplateStack: &administrator.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
			},
		},
	}
}

// The built-in role names PAN-OS accepts for role, each a dedicated node under
// the role-based permissions rather than a value of one field.
const (
	adminRoleSuperuser     = "superuser"
	adminRoleSuperreader   = "superreader"
	adminRolePanoramaAdmin = "panorama-admin"
	adminRoleDeviceAdmin   = "deviceadmin"
	adminRoleDeviceReader  = "devicereader"
	// Reported by a get, never accepted as input: pango models each of these as
	// a list of per-device entries carrying their own vsys list, a shape
	// AdministratorInput does not express.
	adminRoleVsysAdmin  = "vsysadmin"
	adminRoleVsysReader = "vsysreader"
)

// AdministratorInput is the input for the administrator create and update tools.
//
// password_hash is a write-only pre-hashed password and is never returned;
// has_password_hash in the summary reports only whether one is set.
//
// public_key and the administrator's UI preferences are deliberately not
// modeled. Both round-trip untouched through the read-modify-write overlay, so
// this server neither reads nor overwrites them; has_public_key reports only
// whether a key is set.
type AdministratorInput struct {
	MgtScopeInput
	Name                  string   `json:"name" jsonschema:"Administrator user name"`
	PasswordHash          *string  `json:"password_hash,omitzero" jsonschema:"Pre-hashed password (PHASH string, e.g. the output of the request-password-hash operation). Omitting it on update keeps the stored value. Write-only: never returned."`
	AuthenticationProfile *string  `json:"authentication_profile,omitzero" jsonschema:"Authentication profile name used to authenticate this administrator"`
	PasswordProfile       *string  `json:"password_profile,omitzero" jsonschema:"Password profile name applied to this administrator (see panos_password_profile_list)"`
	ClientCertificateOnly *bool    `json:"client_certificate_only,omitzero" jsonschema:"Authenticate with a client certificate only, without a password"`
	Role                  *string  `json:"role,omitzero" jsonschema:"Built-in role: superuser, superreader, panorama-admin, deviceadmin or devicereader. Mutually exclusive with role_profile: setting this clears a custom role, and it also clears a per-vsys vsysadmin or vsysreader grant, which a get can report but these tools cannot set."`
	RoleProfile           *string  `json:"role_profile,omitzero" jsonschema:"Custom admin-role profile name. Mutually exclusive with role: setting this clears a built-in role."`
	RoleVsys              []string `json:"role_vsys,omitzero" jsonschema:"vsys the custom role profile applies to. Only meaningful with role_profile."`
}

// builtinAdminRoles is the set of role names accepted as input, used only to
// reject an unknown one.
var builtinAdminRoles = map[string]struct{}{
	adminRoleSuperuser:     {},
	adminRoleSuperreader:   {},
	adminRolePanoramaAdmin: {},
	adminRoleDeviceAdmin:   {},
	adminRoleDeviceReader:  {},
}

// clearRoleBased blanks every role branch pango models under role-based
// permissions. PAN-OS role permissions are exactly-one, so the caller sets the
// branch it wants immediately after. Vsysadmin and Vsysreader are branches this
// server does not offer as inputs, but they are siblings of the rest under the
// same role-based node, so switching a per-vsys administrator to another role
// clears them too. NOT MEASURED against a device: pango models all eight
// branches as independent optional fields, so the exactly-one rule is PAN-OS's,
// not the SDK's. Clearing is the conservative reading, and it means a role
// switch discards the per-vsys grants, which these tools cannot recreate.
func clearRoleBased(rb *administrator.PermissionsRoleBased) {
	rb.Superuser = nil
	rb.Superreader = nil
	rb.PanoramaAdmin = nil
	rb.Deviceadmin = nil
	rb.Devicereader = nil
	rb.Vsysadmin = nil
	rb.Vsysreader = nil
	rb.Custom = nil
}

// setBuiltinRole writes the pango field expressing one built-in role. The first
// three branches are presence flags carrying "yes"; the last two are member
// lists. The caller has already cleared every branch.
func setBuiltinRole(rb *administrator.PermissionsRoleBased, role string) {
	const yes = "yes"
	switch role {
	case adminRoleSuperuser:
		rb.Superuser = new(yes)
	case adminRoleSuperreader:
		rb.Superreader = new(yes)
	case adminRolePanoramaAdmin:
		rb.PanoramaAdmin = new(yes)
	case adminRoleDeviceAdmin:
		rb.Deviceadmin = []string{yes}
	case adminRoleDeviceReader:
		rb.Devicereader = []string{yes}
	}
}

// administratorRoleRequest reports what role change the caller asked for:
// whether it names the custom branch, and whether it names a role change at all.
// A transition is detected by field PRESENCE, not by a non-empty value, so
// role: "" is a rejected value rather than a silently ignored one, and it is
// detected in BOTH directions: role names the built-in branch, while either
// role_profile or role_vsys names the custom one.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func administratorRoleRequest(in AdministratorInput) (custom, requested bool, err error) {
	custom = in.RoleProfile != nil || in.RoleVsys != nil
	requested = in.Role != nil || custom
	switch {
	case !requested:
		return false, false, nil
	case in.Role != nil && custom:
		return false, true, errors.New("set only one of role or role_profile, not both")
	}
	if in.Role != nil {
		if _, ok := builtinAdminRoles[*in.Role]; !ok {
			return false, true, errors.New("role must be one of superuser, superreader, panorama-admin, deviceadmin or devicereader")
		}
	}
	return custom, true, nil
}

// applyAdministratorRole writes the requested role branch, clearing the others.
//
// This is a deliberate exception to the read-modify-write rule that an overlay
// touches only what the caller provided: the branches are mutually exclusive in
// PAN-OS, so leaving a stale sibling set produces a config the device rejects.
//
// Providing neither role, role_profile nor role_vsys leaves Permissions
// untouched, including any unmodeled XML it carries.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyAdministratorRole(e *administrator.Entry, in AdministratorInput) error {
	custom, requested, err := administratorRoleRequest(in)
	if err != nil || !requested {
		return err
	}

	if e.Permissions == nil {
		e.Permissions = &administrator.Permissions{}
	}
	if e.Permissions.RoleBased == nil {
		e.Permissions.RoleBased = &administrator.PermissionsRoleBased{}
	}
	rb := e.Permissions.RoleBased
	// Capture the stored custom branch before clearing, so a caller who names
	// only one of its two fields keeps the other and keeps the branch's own
	// unmodeled XML. clearRoleBased nils it, so reading it afterwards is too
	// late.
	stored := rb.Custom

	// The profile name IS the custom role, so the branch is meaningless without
	// one. Reject on the EFFECTIVE name rather than on whether role_profile was
	// provided: an explicit empty string is non-nil and would otherwise slip
	// past, clearing the stored role and writing a custom branch naming no
	// profile, which PAN-OS rejects at commit. Checked before anything is
	// cleared, so a refused request leaves the entry untouched.
	profile := strVal(in.RoleProfile)
	if in.RoleProfile == nil && stored != nil {
		profile = strVal(stored.Profile)
	}
	if custom && profile == "" {
		return errors.New("a custom role needs a non-empty role_profile")
	}

	clearRoleBased(rb)

	if custom {
		if stored == nil {
			stored = &administrator.PermissionsRoleBasedCustom{}
		}
		rb.Custom = stored
		setPtr(&rb.Custom.Profile, in.RoleProfile)
		if in.RoleVsys != nil {
			rb.Custom.Vsys = in.RoleVsys
		}
		return nil
	}
	setBuiltinRole(rb, *in.Role)
	return nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyAdministrator(e *administrator.Entry, in AdministratorInput) error {
	setPtr(&e.Phash, in.PasswordHash)
	setPtr(&e.AuthenticationProfile, in.AuthenticationProfile)
	setPtr(&e.PasswordProfile, in.PasswordProfile)
	setPtr(&e.ClientCertificateOnly, in.ClientCertificateOnly)
	return applyAdministratorRole(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildAdministrator(in AdministratorInput) (*administrator.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &administrator.Entry{Name: in.Name}
	if err := applyAdministrator(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayAdministrator(e *administrator.Entry, in AdministratorInput) error {
	return applyAdministrator(e, in)
}

// administratorRole reports the built-in role an entry carries, or "" when it
// carries a custom profile or no role at all. It reports the two per-vsys roles
// as well: those cannot be SET through these tools, but an administrator
// configured with one elsewhere must not read back as having no role.
func administratorRole(rb *administrator.PermissionsRoleBased) string {
	switch {
	case rb == nil:
		return ""
	case rb.Superuser != nil:
		return adminRoleSuperuser
	case rb.Superreader != nil:
		return adminRoleSuperreader
	case rb.PanoramaAdmin != nil:
		return adminRolePanoramaAdmin
	case len(rb.Deviceadmin) > 0:
		return adminRoleDeviceAdmin
	case len(rb.Devicereader) > 0:
		return adminRoleDeviceReader
	case len(rb.Vsysadmin) > 0:
		return adminRoleVsysAdmin
	case len(rb.Vsysreader) > 0:
		return adminRoleVsysReader
	}
	return ""
}

func administratorSummary(e *administrator.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["authentication_profile"] = strVal(e.AuthenticationProfile)
	m["password_profile"] = strVal(e.PasswordProfile)
	putBool(m, "client_certificate_only", e.ClientCertificateOnly)
	// The phash and the public key are never echoed: the first is a write-only
	// secret, the second an unmodeled blob. Both are reported as presence only.
	m["has_password_hash"] = e.Phash != nil && *e.Phash != ""
	m["has_public_key"] = e.PublicKey != nil && *e.PublicKey != ""

	var rb *administrator.PermissionsRoleBased
	if e.Permissions != nil {
		rb = e.Permissions.RoleBased
	}
	if role := administratorRole(rb); role != "" {
		m["role"] = role
	}
	if rb != nil && rb.Custom != nil {
		m["role_profile"] = strVal(rb.Custom.Profile)
		m["role_vsys"] = strList(rb.Custom.Vsys)
	}
	return m
}

// RegisterAdministratorTools registers the administrator tools on both firewall
// and Panorama.
func RegisterAdministratorTools(s *mcp.Server, d *Deps) {
	svc := newAdministratorService(d)
	parts := administratorParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_administrator_list",
		Description: "List administrators (mgt-config users). Firewall: the device's own scope; Panorama: panorama, template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List administrators"),
	}, mgtListHandler(d, "panos_administrator_list", svc, parts, svc.name, administratorSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_administrator_get",
		Description: "Get one administrator (role, authentication and password profiles). The password hash and public key are never returned; has_password_hash and has_public_key report whether they are set. Read-only.",
		Annotations: readOnlyTool("Get administrator"),
	}, mgtGetHandler(d, "panos_administrator_get", svc, parts, administratorSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_administrator_create",
		Description: "Create an administrator in the candidate config. password_hash is a write-only pre-hashed password. Set either role (a built-in role) or role_profile (a custom admin-role profile), never both. Run panos_commit to apply.",
		Annotations: createTool("Create administrator"),
	}, mgtCreateHandler(d, "panos_administrator_create", svc, parts, buildAdministrator, administratorSummary, withSecrets(administratorSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_administrator_update",
		Description: "Update an administrator: read-modify-write, only provided fields change, and an omitted password_hash keeps the stored value. Roles are mutually exclusive, so providing role clears a custom role and providing role_profile or role_vsys clears a built-in one. If the administrator holds a per-vsys role (vsysadmin or vsysreader), switching it discards those per-vsys grants, which these tools cannot recreate. Run panos_commit to apply.",
		Annotations: updateTool("Update administrator"),
	}, mgtUpdateHandler(d, "panos_administrator_update", svc, parts,
		func(in AdministratorInput) string { return in.Name }, overlayAdministrator, administratorSummary, withSecrets(administratorSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_administrator_delete",
		Description: "Delete an administrator from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete administrator"),
	}, mgtDeleteHandler(d, "panos_administrator_delete", svc, parts))
}
