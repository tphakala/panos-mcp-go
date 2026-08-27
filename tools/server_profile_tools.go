package tools

import (
	"errors"
	"fmt"

	"github.com/PaloAltoNetworks/pango/device/profiles/email"
	"github.com/PaloAltoNetworks/pango/device/profiles/ldap"
	"github.com/PaloAltoNetworks/pango/device/profiles/radius"
	"github.com/PaloAltoNetworks/pango/device/profiles/snmptrap"
	"github.com/PaloAltoNetworks/pango/device/profiles/syslog"
	"github.com/PaloAltoNetworks/pango/device/profiles/tacacsplus"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// protocolKey is the shared summary key for a protocol field (goconst).
const protocolKey = "protocol"

// This file registers CRUD tools for the device server profiles pango models
// under device/profiles/*: LDAP, TACACS+ and RADIUS (authentication server
// profiles), and syslog, SNMP-trap and email (log-forwarding server profiles).
// They are referenced by authentication profiles, log-forwarding profiles and
// log settings.
//
// All six are device-scoped, resolved by resolveDeviceScope: a firewall vsys or
// (for the three authentication SERVER profiles) shared scope, or a Panorama
// template, template-stack or shared scope. The three log-forwarding profiles
// (syslog, snmptrap, email) have no shared scope; resolveDeviceScope rejects a
// shared request for them. Do not read that as the complete no-shared set:
// device/authprofile, the authentication PROFILE that references these server
// profiles, also has none. noSharedScopeProfiles in device_scope.go is the
// single source of truth.
//
// Secrets (LDAP bind password, TACACS+/RADIUS shared secrets, SNMP community and
// v3 passwords, email SMTP password) are write-only: they are accepted on create
// and update but never returned in a get or list. The device stores them
// encrypted, so echoing them back would leak ciphertext; summaries report only a
// has_<secret> boolean. On update, an omitted scalar secret is preserved
// (read-modify-write); a provided server list is merged by name, so a server
// omitted from the list is removed while an untouched server keeps its stored
// secret and any unmodeled per-server XML the device round-trips. A per-server
// secret omitted on an existing server is likewise kept; supply it only to
// change it. (#89)

// ---------------------------------------------------------------------------
// LDAP server profile (device/profiles/ldap)
// ---------------------------------------------------------------------------

func newLdapProfileService(d *Deps) nameFixAdapter[ldap.Location, ldap.Entry] {
	return nameFixAdapter[ldap.Location, ldap.Entry]{
		svc:    ldap.NewService(d.Client),
		client: d.Client,
		name:   func(e *ldap.Entry) string { return e.Name },
	}
}

func ldapProfileParts() deviceScopeParts[ldap.Location] {
	return deviceScopeParts[ldap.Location]{
		shared: func() ldap.Location { return ldap.Location{Shared: &ldap.SharedLocation{}} },
		vsys: func(ngfw, vsys string) ldap.Location {
			return ldap.Location{Vsys: &ldap.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) ldap.Location {
			return ldap.Location{Template: &ldap.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) ldap.Location {
			return ldap.Location{TemplateVsys: &ldap.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) ldap.Location {
			return ldap.Location{TemplateStack: &ldap.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) ldap.Location {
			return ldap.Location{TemplateStackVsys: &ldap.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// LdapServerInput is one LDAP server entry. LDAP servers carry no per-server
// secret; the bind password lives on the profile.
type LdapServerInput struct {
	Name    string  `json:"name" jsonschema:"Server entry name"`
	Address *string `json:"address,omitzero" jsonschema:"Server hostname or IP address"`
	Port    *int64  `json:"port,omitzero" jsonschema:"Server port (default 389, or 636 for SSL)"`
}

// LdapProfileInput is the input for the LDAP server profile create and update
// tools. bind_password is write-only.
type LdapProfileInput struct {
	DeviceScopeInput
	Name                    string            `json:"name" jsonschema:"LDAP server profile name"`
	Base                    *string           `json:"base,omitzero" jsonschema:"Distinguished name of the search base"`
	BindDn                  *string           `json:"bind_dn,omitzero" jsonschema:"Bind DN used to authenticate to the directory"`
	BindPassword            *string           `json:"bind_password,omitzero" jsonschema:"Bind password (write-only; never returned). Omit on update to keep the stored value."`
	BindTimelimit           *int64            `json:"bind_timelimit,omitzero" jsonschema:"Bind timeout in seconds"`
	RetryInterval           *int64            `json:"retry_interval,omitzero" jsonschema:"Retry interval in seconds"`
	Timelimit               *int64            `json:"timelimit,omitzero" jsonschema:"Search timeout in seconds"`
	LdapType                *string           `json:"ldap_type,omitzero" jsonschema:"Directory type: active-directory, e-directory, sun, or other"`
	Ssl                     *bool             `json:"ssl,omitzero" jsonschema:"Require SSL/TLS to the directory"`
	Disabled                *bool             `json:"disabled,omitzero" jsonschema:"Disable this profile"`
	VerifyServerCertificate *bool             `json:"verify_server_certificate,omitzero" jsonschema:"Verify the server certificate for SSL/TLS"`
	Servers                 []LdapServerInput `json:"servers,omitzero" jsonschema:"LDAP servers, merged by name; a server absent from the list is removed, an untouched server keeps its stored values"`
}

// ldapServers merges the provided server inputs onto the existing list by name:
// each output server is seeded from the same-named existing server, so any
// unmodeled per-server XML (Misc/MiscAttributes) and, for the families that have
// one, the stored write-only secret survive when the input omits it; the
// provided fields are then overlaid. A server whose name is absent from in is
// dropped, so the provided set still fully replaces the list. On create existing
// is nil, so every server is built fresh. The other *Servers builders below
// follow the same shape. (#89)
func ldapServers(in []LdapServerInput, existing []ldap.Server) []ldap.Server {
	prev := indexByName(existing, func(s ldap.Server) string { return s.Name })
	out := make([]ldap.Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.Address, s.Address)
		setPtr(&srv.Port, s.Port)
		out = append(out, srv)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyLdapProfile(e *ldap.Entry, in LdapProfileInput) {
	setPtr(&e.Base, in.Base)
	setPtr(&e.BindDn, in.BindDn)
	setPtr(&e.BindPassword, in.BindPassword)
	setPtr(&e.BindTimelimit, in.BindTimelimit)
	setPtr(&e.RetryInterval, in.RetryInterval)
	setPtr(&e.Timelimit, in.Timelimit)
	setPtr(&e.LdapType, in.LdapType)
	setPtr(&e.Ssl, in.Ssl)
	setPtr(&e.Disabled, in.Disabled)
	setPtr(&e.VerifyServerCertificate, in.VerifyServerCertificate)
	if in.Servers != nil {
		e.Server = ldapServers(in.Servers, e.Server)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLdapProfile(in LdapProfileInput) (*ldap.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ldap.Entry{Name: in.Name}
	applyLdapProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLdapProfile(e *ldap.Entry, in LdapProfileInput) error {
	applyLdapProfile(e, in)
	return nil
}

func ldapServerSummaries(servers []ldap.Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		sm := map[string]any{tagNameKey: s.Name, "address": strVal(s.Address)}
		putInt(sm, "port", s.Port)
		out = append(out, sm)
	}
	return out
}

func ldapProfileSummary(e *ldap.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["base"] = strVal(e.Base)
	m["bind_dn"] = strVal(e.BindDn)
	m["has_bind_password"] = e.BindPassword != nil
	putInt(m, "bind_timelimit", e.BindTimelimit)
	putInt(m, "retry_interval", e.RetryInterval)
	putInt(m, "timelimit", e.Timelimit)
	m["ldap_type"] = strVal(e.LdapType)
	putBool(m, "ssl", e.Ssl)
	putBool(m, "disabled", e.Disabled)
	putBool(m, "verify_server_certificate", e.VerifyServerCertificate)
	m["servers"] = ldapServerSummaries(e.Server)
	return m
}

// RegisterLdapProfileTools registers the LDAP server profile tools on both
// firewall and Panorama.
func RegisterLdapProfileTools(s *mcp.Server, d *Deps) {
	svc := newLdapProfileService(d)
	parts := ldapProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ldap_profile_list",
		Description: "List LDAP server profiles. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List LDAP server profiles"),
	}, deviceListHandler(d, "panos_ldap_profile_list", svc, parts, svc.name, ldapProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ldap_profile_get",
		Description: "Get one LDAP server profile. The bind password is never returned; has_bind_password reports whether one is set. Read-only.",
		Annotations: readOnlyTool("Get LDAP server profile"),
	}, deviceGetHandler(d, "panos_ldap_profile_get", svc, parts, ldapProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ldap_profile_create",
		Description: "Create an LDAP server profile in the candidate config. bind_password is write-only. Run panos_commit to apply.",
		Annotations: createTool("Create LDAP server profile"),
	}, deviceCreateHandler(d, "panos_ldap_profile_create", svc, parts, buildLdapProfile, ldapProfileSummary, withSecrets(ldapProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ldap_profile_update",
		Description: "Update an LDAP server profile: read-modify-write, only provided fields change. An omitted bind_password keeps the stored value; a provided servers list is merged by name, so a server absent from the list is removed and an untouched server keeps its stored values. Run panos_commit to apply.",
		Annotations: updateTool("Update LDAP server profile"),
	}, deviceUpdateHandler(d, "panos_ldap_profile_update", svc, parts,
		func(in LdapProfileInput) string { return in.Name }, overlayLdapProfile, ldapProfileSummary, withSecrets(ldapProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ldap_profile_delete",
		Description: "Delete an LDAP server profile from the candidate config. Fails while authentication profiles still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete LDAP server profile"),
	}, deviceDeleteHandler(d, "panos_ldap_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// TACACS+ server profile (device/profiles/tacacsplus)
// ---------------------------------------------------------------------------

func newTacacsProfileService(d *Deps) nameFixAdapter[tacacsplus.Location, tacacsplus.Entry] {
	return nameFixAdapter[tacacsplus.Location, tacacsplus.Entry]{
		svc:    tacacsplus.NewService(d.Client),
		client: d.Client,
		name:   func(e *tacacsplus.Entry) string { return e.Name },
	}
}

func tacacsProfileParts() deviceScopeParts[tacacsplus.Location] {
	return deviceScopeParts[tacacsplus.Location]{
		shared: func() tacacsplus.Location { return tacacsplus.Location{Shared: &tacacsplus.SharedLocation{}} },
		vsys: func(ngfw, vsys string) tacacsplus.Location {
			return tacacsplus.Location{Vsys: &tacacsplus.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) tacacsplus.Location {
			return tacacsplus.Location{Template: &tacacsplus.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) tacacsplus.Location {
			return tacacsplus.Location{TemplateVsys: &tacacsplus.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) tacacsplus.Location {
			return tacacsplus.Location{TemplateStack: &tacacsplus.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) tacacsplus.Location {
			return tacacsplus.Location{TemplateStackVsys: &tacacsplus.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// TacacsServerInput is one TACACS+ server entry. secret is write-only.
type TacacsServerInput struct {
	Name    string  `json:"name" jsonschema:"Server entry name"`
	Address *string `json:"address,omitzero" jsonschema:"Server hostname or IP address"`
	Secret  *string `json:"secret,omitzero" jsonschema:"Shared secret (write-only; never returned)"`
	Port    *int64  `json:"port,omitzero" jsonschema:"Server port (default 49)"`
}

// TacacsProfileInput is the input for the TACACS+ server profile create and
// update tools.
type TacacsProfileInput struct {
	DeviceScopeInput
	Name                string              `json:"name" jsonschema:"TACACS+ server profile name"`
	Protocol            *string             `json:"protocol,omitzero" jsonschema:"Authentication protocol: CHAP or PAP"`
	Timeout             *int64              `json:"timeout,omitzero" jsonschema:"Timeout in seconds"`
	UseSingleConnection *bool               `json:"use_single_connection,omitzero" jsonschema:"Use a single TCP connection for all authentication"`
	Servers             []TacacsServerInput `json:"servers,omitzero" jsonschema:"TACACS+ servers, merged by name; a server absent from the list is removed, and an omitted per-server secret keeps the stored value"`
}

func tacacsServers(in []TacacsServerInput, existing []tacacsplus.Server) []tacacsplus.Server {
	prev := indexByName(existing, func(s tacacsplus.Server) string { return s.Name })
	out := make([]tacacsplus.Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.Address, s.Address)
		setPtr(&srv.Secret, s.Secret)
		setPtr(&srv.Port, s.Port)
		out = append(out, srv)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyTacacsProfile(e *tacacsplus.Entry, in TacacsProfileInput) {
	setPtr(&e.Protocol, in.Protocol)
	setPtr(&e.Timeout, in.Timeout)
	setPtr(&e.UseSingleConnection, in.UseSingleConnection)
	if in.Servers != nil {
		e.Server = tacacsServers(in.Servers, e.Server)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildTacacsProfile(in TacacsProfileInput) (*tacacsplus.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &tacacsplus.Entry{Name: in.Name}
	applyTacacsProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayTacacsProfile(e *tacacsplus.Entry, in TacacsProfileInput) error {
	applyTacacsProfile(e, in)
	return nil
}

func tacacsServerSummaries(servers []tacacsplus.Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		sm := map[string]any{tagNameKey: s.Name, "address": strVal(s.Address), "has_secret": s.Secret != nil}
		putInt(sm, "port", s.Port)
		out = append(out, sm)
	}
	return out
}

func tacacsProfileSummary(e *tacacsplus.Entry) any {
	m := map[string]any{tagNameKey: e.Name, protocolKey: strVal(e.Protocol)}
	putInt(m, "timeout", e.Timeout)
	putBool(m, "use_single_connection", e.UseSingleConnection)
	m["servers"] = tacacsServerSummaries(e.Server)
	return m
}

// RegisterTacacsProfileTools registers the TACACS+ server profile tools on both
// firewall and Panorama.
func RegisterTacacsProfileTools(s *mcp.Server, d *Deps) {
	svc := newTacacsProfileService(d)
	parts := tacacsProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tacacs_profile_list",
		Description: "List TACACS+ server profiles. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List TACACS+ server profiles"),
	}, deviceListHandler(d, "panos_tacacs_profile_list", svc, parts, svc.name, tacacsProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tacacs_profile_get",
		Description: "Get one TACACS+ server profile. Per-server shared secrets are never returned; has_secret reports whether each is set. Read-only.",
		Annotations: readOnlyTool("Get TACACS+ server profile"),
	}, deviceGetHandler(d, "panos_tacacs_profile_get", svc, parts, tacacsProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tacacs_profile_create",
		Description: "Create a TACACS+ server profile in the candidate config. Each server secret is write-only. Run panos_commit to apply.",
		Annotations: createTool("Create TACACS+ server profile"),
	}, deviceCreateHandler(d, "panos_tacacs_profile_create", svc, parts, buildTacacsProfile, tacacsProfileSummary, withSecrets(tacacsProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tacacs_profile_update",
		Description: "Update a TACACS+ server profile: read-modify-write, only provided fields change. A provided servers list is merged by name: a server absent from the list is removed, and an omitted per-server secret keeps the stored value. Run panos_commit to apply.",
		Annotations: updateTool("Update TACACS+ server profile"),
	}, deviceUpdateHandler(d, "panos_tacacs_profile_update", svc, parts,
		func(in TacacsProfileInput) string { return in.Name }, overlayTacacsProfile, tacacsProfileSummary, withSecrets(tacacsProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_tacacs_profile_delete",
		Description: "Delete a TACACS+ server profile from the candidate config. Fails while authentication profiles still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete TACACS+ server profile"),
	}, deviceDeleteHandler(d, "panos_tacacs_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// RADIUS server profile (device/profiles/radius)
// ---------------------------------------------------------------------------

func newRadiusProfileService(d *Deps) nameFixAdapter[radius.Location, radius.Entry] {
	return nameFixAdapter[radius.Location, radius.Entry]{
		svc:    radius.NewService(d.Client),
		client: d.Client,
		name:   func(e *radius.Entry) string { return e.Name },
	}
}

func radiusProfileParts() deviceScopeParts[radius.Location] {
	return deviceScopeParts[radius.Location]{
		shared: func() radius.Location { return radius.Location{Shared: &radius.SharedLocation{}} },
		vsys: func(ngfw, vsys string) radius.Location {
			return radius.Location{Vsys: &radius.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) radius.Location {
			return radius.Location{Template: &radius.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) radius.Location {
			return radius.Location{TemplateVsys: &radius.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) radius.Location {
			return radius.Location{TemplateStack: &radius.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) radius.Location {
			return radius.Location{TemplateStackVsys: &radius.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// RadiusServerInput is one RADIUS server entry. secret is write-only.
type RadiusServerInput struct {
	Name      string  `json:"name" jsonschema:"Server entry name"`
	IpAddress *string `json:"ip_address,omitzero" jsonschema:"Server hostname or IP address"`
	Secret    *string `json:"secret,omitzero" jsonschema:"Shared secret (write-only; never returned)"`
	Port      *int64  `json:"port,omitzero" jsonschema:"Server port (default 1812)"`
}

// RadiusProfileInput is the input for the RADIUS server profile create and update
// tools. The authentication protocol subtree (CHAP/PAP/EAP-TTLS/PEAP) is not
// modeled here and is preserved across updates.
type RadiusProfileInput struct {
	DeviceScopeInput
	Name    string              `json:"name" jsonschema:"RADIUS server profile name"`
	Retries *int64              `json:"retries,omitzero" jsonschema:"Number of retries before failover"`
	Timeout *int64              `json:"timeout,omitzero" jsonschema:"Timeout in seconds"`
	Servers []RadiusServerInput `json:"servers,omitzero" jsonschema:"RADIUS servers, merged by name; a server absent from the list is removed, and an omitted per-server secret keeps the stored value"`
}

func radiusServers(in []RadiusServerInput, existing []radius.Server) []radius.Server {
	prev := indexByName(existing, func(s radius.Server) string { return s.Name })
	out := make([]radius.Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.IpAddress, s.IpAddress)
		setPtr(&srv.Secret, s.Secret)
		setPtr(&srv.Port, s.Port)
		out = append(out, srv)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyRadiusProfile(e *radius.Entry, in RadiusProfileInput) {
	setPtr(&e.Retries, in.Retries)
	setPtr(&e.Timeout, in.Timeout)
	if in.Servers != nil {
		e.Server = radiusServers(in.Servers, e.Server)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildRadiusProfile(in RadiusProfileInput) (*radius.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &radius.Entry{Name: in.Name}
	applyRadiusProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayRadiusProfile(e *radius.Entry, in RadiusProfileInput) error {
	applyRadiusProfile(e, in)
	return nil
}

func radiusServerSummaries(servers []radius.Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		sm := map[string]any{tagNameKey: s.Name, "ip_address": strVal(s.IpAddress), "has_secret": s.Secret != nil}
		putInt(sm, "port", s.Port)
		out = append(out, sm)
	}
	return out
}

func radiusProfileSummary(e *radius.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "retries", e.Retries)
	putInt(m, "timeout", e.Timeout)
	m["has_protocol"] = e.Protocol != nil
	m["servers"] = radiusServerSummaries(e.Server)
	return m
}

// RegisterRadiusProfileTools registers the RADIUS server profile tools on both
// firewall and Panorama.
func RegisterRadiusProfileTools(s *mcp.Server, d *Deps) {
	svc := newRadiusProfileService(d)
	parts := radiusProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_radius_profile_list",
		Description: "List RADIUS server profiles. Firewall: vsys or shared; Panorama: template, template_stack or shared. Read-only.",
		Annotations: readOnlyTool("List RADIUS server profiles"),
	}, deviceListHandler(d, "panos_radius_profile_list", svc, parts, svc.name, radiusProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_radius_profile_get",
		Description: "Get one RADIUS server profile. Per-server shared secrets are never returned; has_secret reports whether each is set. The authentication protocol subtree is not modeled; has_protocol reports whether one is set. Read-only.",
		Annotations: readOnlyTool("Get RADIUS server profile"),
	}, deviceGetHandler(d, "panos_radius_profile_get", svc, parts, radiusProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_radius_profile_create",
		Description: "Create a RADIUS server profile in the candidate config. Each server secret is write-only. The authentication protocol subtree is not settable here. Run panos_commit to apply.",
		Annotations: createTool("Create RADIUS server profile"),
	}, deviceCreateHandler(d, "panos_radius_profile_create", svc, parts, buildRadiusProfile, radiusProfileSummary, withSecrets(radiusProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_radius_profile_update",
		Description: "Update a RADIUS server profile: read-modify-write, only provided fields change. A provided servers list is merged by name: a server absent from the list is removed, and an omitted per-server secret keeps the stored value. The authentication protocol subtree is preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update RADIUS server profile"),
	}, deviceUpdateHandler(d, "panos_radius_profile_update", svc, parts,
		func(in RadiusProfileInput) string { return in.Name }, overlayRadiusProfile, radiusProfileSummary, withSecrets(radiusProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_radius_profile_delete",
		Description: "Delete a RADIUS server profile from the candidate config. Fails while authentication profiles still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete RADIUS server profile"),
	}, deviceDeleteHandler(d, "panos_radius_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Syslog server profile (device/profiles/syslog) - log-settings, no shared scope
// ---------------------------------------------------------------------------

func newSyslogProfileService(d *Deps) nameFixAdapter[syslog.Location, syslog.Entry] {
	return nameFixAdapter[syslog.Location, syslog.Entry]{
		svc:    syslog.NewService(d.Client),
		client: d.Client,
		name:   func(e *syslog.Entry) string { return e.Name },
	}
}

func syslogProfileParts() deviceScopeParts[syslog.Location] {
	return deviceScopeParts[syslog.Location]{
		vsys: func(ngfw, vsys string) syslog.Location {
			return syslog.Location{Vsys: &syslog.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) syslog.Location {
			return syslog.Location{Template: &syslog.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) syslog.Location {
			return syslog.Location{TemplateVsys: &syslog.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) syslog.Location {
			return syslog.Location{TemplateStack: &syslog.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) syslog.Location {
			return syslog.Location{TemplateStackVsys: &syslog.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// SyslogServerInput is one syslog server entry. Syslog servers carry no secret.
type SyslogServerInput struct {
	Name      string  `json:"name" jsonschema:"Server entry name"`
	Server    *string `json:"server,omitzero" jsonschema:"Server hostname or IP address"`
	Transport *string `json:"transport,omitzero" jsonschema:"Transport: UDP, TCP, or SSL"`
	Port      *int64  `json:"port,omitzero" jsonschema:"Server port (default 514)"`
	Format    *string `json:"format,omitzero" jsonschema:"Syslog format: BSD or IETF"`
	Facility  *string `json:"facility,omitzero" jsonschema:"Syslog facility, e.g. LOG_USER"`
}

// SyslogProfileInput is the input for the syslog server profile create and update
// tools. The per-log-type format subtree is not modeled here and is preserved
// across updates.
type SyslogProfileInput struct {
	DeviceScopeInput
	Name    string              `json:"name" jsonschema:"Syslog server profile name"`
	Servers []SyslogServerInput `json:"servers,omitzero" jsonschema:"Syslog servers, merged by name; a server absent from the list is removed, an untouched server keeps its stored values"`
}

func syslogServers(in []SyslogServerInput, existing []syslog.Server) []syslog.Server {
	prev := indexByName(existing, func(s syslog.Server) string { return s.Name })
	out := make([]syslog.Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.Server, s.Server)
		setPtr(&srv.Transport, s.Transport)
		setPtr(&srv.Port, s.Port)
		setPtr(&srv.Format, s.Format)
		setPtr(&srv.Facility, s.Facility)
		out = append(out, srv)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applySyslogProfile(e *syslog.Entry, in SyslogProfileInput) {
	if in.Servers != nil {
		e.Server = syslogServers(in.Servers, e.Server)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildSyslogProfile(in SyslogProfileInput) (*syslog.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &syslog.Entry{Name: in.Name}
	applySyslogProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlaySyslogProfile(e *syslog.Entry, in SyslogProfileInput) error {
	applySyslogProfile(e, in)
	return nil
}

func syslogServerSummaries(servers []syslog.Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		sm := map[string]any{
			tagNameKey:  s.Name,
			"server":    strVal(s.Server),
			"transport": strVal(s.Transport),
			"format":    strVal(s.Format),
			"facility":  strVal(s.Facility),
		}
		putInt(sm, "port", s.Port)
		out = append(out, sm)
	}
	return out
}

func syslogProfileSummary(e *syslog.Entry) any {
	return map[string]any{tagNameKey: e.Name, "servers": syslogServerSummaries(e.Server)}
}

// RegisterSyslogProfileTools registers the syslog server profile tools on both
// firewall and Panorama.
func RegisterSyslogProfileTools(s *mcp.Server, d *Deps) {
	svc := newSyslogProfileService(d)
	parts := syslogProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_syslog_profile_list",
		Description: "List syslog server profiles. Firewall: vsys; Panorama: template or template_stack (no shared scope). Read-only.",
		Annotations: readOnlyTool("List syslog server profiles"),
	}, deviceListHandler(d, "panos_syslog_profile_list", svc, parts, svc.name, syslogProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_syslog_profile_get",
		Description: "Get one syslog server profile (its servers). The per-log-type format subtree is not modeled and is preserved on update. Read-only.",
		Annotations: readOnlyTool("Get syslog server profile"),
	}, deviceGetHandler(d, "panos_syslog_profile_get", svc, parts, syslogProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_syslog_profile_create",
		Description: "Create a syslog server profile in the candidate config. Run panos_commit to apply.",
		Annotations: createTool("Create syslog server profile"),
	}, deviceCreateHandler(d, "panos_syslog_profile_create", svc, parts, buildSyslogProfile, syslogProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_syslog_profile_update",
		Description: "Update a syslog server profile: read-modify-write, only provided fields change. A provided servers list is merged by name: a server absent from the list is removed, an untouched server keeps its stored values. The per-log-type format subtree is preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update syslog server profile"),
	}, deviceUpdateHandler(d, "panos_syslog_profile_update", svc, parts,
		func(in SyslogProfileInput) string { return in.Name }, overlaySyslogProfile, syslogProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_syslog_profile_delete",
		Description: "Delete a syslog server profile from the candidate config. Fails while log-forwarding profiles or log settings still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete syslog server profile"),
	}, deviceDeleteHandler(d, "panos_syslog_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// SNMP-trap server profile (device/profiles/snmptrap) - log-settings, no shared
// ---------------------------------------------------------------------------

func newSnmpTrapProfileService(d *Deps) nameFixAdapter[snmptrap.Location, snmptrap.Entry] {
	return nameFixAdapter[snmptrap.Location, snmptrap.Entry]{
		svc:    snmptrap.NewService(d.Client),
		client: d.Client,
		name:   func(e *snmptrap.Entry) string { return e.Name },
	}
}

func snmpTrapProfileParts() deviceScopeParts[snmptrap.Location] {
	return deviceScopeParts[snmptrap.Location]{
		vsys: func(ngfw, vsys string) snmptrap.Location {
			return snmptrap.Location{Vsys: &snmptrap.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) snmptrap.Location {
			return snmptrap.Location{Template: &snmptrap.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) snmptrap.Location {
			return snmptrap.Location{TemplateVsys: &snmptrap.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) snmptrap.Location {
			return snmptrap.Location{TemplateStack: &snmptrap.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) snmptrap.Location {
			return snmptrap.Location{TemplateStackVsys: &snmptrap.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// SnmpV2cServerInput is one SNMPv2c trap receiver. community is write-only.
type SnmpV2cServerInput struct {
	Name      string  `json:"name" jsonschema:"Server entry name"`
	Manager   *string `json:"manager,omitzero" jsonschema:"Trap receiver hostname or IP address"`
	Community *string `json:"community,omitzero" jsonschema:"SNMP community string (write-only; never returned)"`
}

// SnmpV3ServerInput is one SNMPv3 trap receiver. auth_password and priv_password
// are write-only.
type SnmpV3ServerInput struct {
	Name         string  `json:"name" jsonschema:"Server entry name"`
	Manager      *string `json:"manager,omitzero" jsonschema:"Trap receiver hostname or IP address"`
	User         *string `json:"user,omitzero" jsonschema:"SNMPv3 user name"`
	EngineId     *string `json:"engine_id,omitzero" jsonschema:"SNMPv3 engine ID"`
	AuthPassword *string `json:"auth_password,omitzero" jsonschema:"Authentication password (write-only; never returned)"`
	PrivPassword *string `json:"priv_password,omitzero" jsonschema:"Privacy password (write-only; never returned)"`
	AuthProtocol *string `json:"auth_protocol,omitzero" jsonschema:"Authentication protocol, e.g. sha, md5"`
	PrivProtocol *string `json:"priv_protocol,omitzero" jsonschema:"Privacy protocol, e.g. aes-128-cfb, des"`
}

// SnmpTrapProfileInput is the input for the SNMP-trap server profile create and
// update tools. version selects the receiver list that applies; v2c and v3 are
// mutually exclusive.
type SnmpTrapProfileInput struct {
	DeviceScopeInput
	Name       string               `json:"name" jsonschema:"SNMP-trap server profile name"`
	Version    string               `json:"version,omitzero" jsonschema:"SNMP version: v2c or v3. Required on create; on update, switching version clears the other version's receivers."`
	V2cServers []SnmpV2cServerInput `json:"v2c_servers,omitzero" jsonschema:"SNMPv2c trap receivers (version v2c), merged by name; a receiver absent from the list is removed, and an omitted community keeps the stored value"`
	V3Servers  []SnmpV3ServerInput  `json:"v3_servers,omitzero" jsonschema:"SNMPv3 trap receivers (version v3), merged by name; a receiver absent from the list is removed, and an omitted password keeps the stored value"`
}

func snmpV2cServers(in []SnmpV2cServerInput, existing []snmptrap.VersionV2cServer) []snmptrap.VersionV2cServer {
	prev := indexByName(existing, func(s snmptrap.VersionV2cServer) string { return s.Name })
	out := make([]snmptrap.VersionV2cServer, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.Manager, s.Manager)
		setPtr(&srv.Community, s.Community)
		out = append(out, srv)
	}
	return out
}

func snmpV3Servers(in []SnmpV3ServerInput, existing []snmptrap.VersionV3Server) []snmptrap.VersionV3Server {
	prev := indexByName(existing, func(s snmptrap.VersionV3Server) string { return s.Name })
	out := make([]snmptrap.VersionV3Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.Manager, s.Manager)
		setPtr(&srv.User, s.User)
		setPtr(&srv.Engineid, s.EngineId)
		setPtr(&srv.Authpwd, s.AuthPassword)
		setPtr(&srv.Privpwd, s.PrivPassword)
		setPtr(&srv.Authproto, s.AuthProtocol)
		setPtr(&srv.Privproto, s.PrivProtocol)
		out = append(out, srv)
	}
	return out
}

// applySnmpTrapProfile writes the version selection and receiver lists onto e.
// Switching version nils the other branch so the entry never carries both a
// <v2c> and a <v3> subtree, which PAN-OS rejects. A receiver list can only be set
// for the active version.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applySnmpTrapProfile(e *snmptrap.Entry, in SnmpTrapProfileInput) error {
	switch in.Version {
	case "v2c":
		if e.Version == nil {
			e.Version = &snmptrap.Version{}
		}
		e.Version.V3 = nil
		if e.Version.V2c == nil {
			e.Version.V2c = &snmptrap.VersionV2c{}
		}
	case "v3":
		if e.Version == nil {
			e.Version = &snmptrap.Version{}
		}
		e.Version.V2c = nil
		if e.Version.V3 == nil {
			e.Version.V3 = &snmptrap.VersionV3{}
		}
	case "":
		// Keep the existing version branch.
	default:
		return fmt.Errorf("invalid version %q: must be v2c or v3", in.Version)
	}

	if in.V2cServers != nil {
		if e.Version == nil || e.Version.V2c == nil {
			return errors.New("v2c_servers requires the profile version to be v2c")
		}
		e.Version.V2c.Server = snmpV2cServers(in.V2cServers, e.Version.V2c.Server)
	}
	if in.V3Servers != nil {
		if e.Version == nil || e.Version.V3 == nil {
			return errors.New("v3_servers requires the profile version to be v3")
		}
		e.Version.V3.Server = snmpV3Servers(in.V3Servers, e.Version.V3.Server)
	}
	return nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildSnmpTrapProfile(in SnmpTrapProfileInput) (*snmptrap.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Version == "" {
		return nil, errors.New("version is required on create (v2c or v3)")
	}
	e := &snmptrap.Entry{Name: in.Name}
	if err := applySnmpTrapProfile(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlaySnmpTrapProfile(e *snmptrap.Entry, in SnmpTrapProfileInput) error {
	return applySnmpTrapProfile(e, in)
}

func snmpV2cServerSummaries(servers []snmptrap.VersionV2cServer) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		out = append(out, map[string]any{tagNameKey: s.Name, "manager": strVal(s.Manager), "has_community": s.Community != nil})
	}
	return out
}

func snmpV3ServerSummaries(servers []snmptrap.VersionV3Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		out = append(out, map[string]any{
			tagNameKey:          s.Name,
			"manager":           strVal(s.Manager),
			"user":              strVal(s.User),
			"engine_id":         strVal(s.Engineid),
			"auth_protocol":     strVal(s.Authproto),
			"priv_protocol":     strVal(s.Privproto),
			"has_auth_password": s.Authpwd != nil,
			"has_priv_password": s.Privpwd != nil,
		})
	}
	return out
}

func snmpTrapProfileSummary(e *snmptrap.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	switch {
	case e.Version != nil && e.Version.V2c != nil:
		m["version"] = "v2c"
		m["v2c_servers"] = snmpV2cServerSummaries(e.Version.V2c.Server)
	case e.Version != nil && e.Version.V3 != nil:
		m["version"] = "v3"
		m["v3_servers"] = snmpV3ServerSummaries(e.Version.V3.Server)
	default:
		m["version"] = ""
	}
	return m
}

// RegisterSnmpTrapProfileTools registers the SNMP-trap server profile tools on
// both firewall and Panorama.
func RegisterSnmpTrapProfileTools(s *mcp.Server, d *Deps) {
	svc := newSnmpTrapProfileService(d)
	parts := snmpTrapProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_snmptrap_profile_list",
		Description: "List SNMP-trap server profiles. Firewall: vsys; Panorama: template or template_stack (no shared scope). Read-only.",
		Annotations: readOnlyTool("List SNMP-trap server profiles"),
	}, deviceListHandler(d, "panos_snmptrap_profile_list", svc, parts, svc.name, snmpTrapProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_snmptrap_profile_get",
		Description: "Get one SNMP-trap server profile. Communities and v3 passwords are never returned; has_community / has_auth_password / has_priv_password report whether each is set. Read-only.",
		Annotations: readOnlyTool("Get SNMP-trap server profile"),
	}, deviceGetHandler(d, "panos_snmptrap_profile_get", svc, parts, snmpTrapProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_snmptrap_profile_create",
		Description: "Create an SNMP-trap server profile in the candidate config. version (v2c or v3) is required. Communities and v3 passwords are write-only. Run panos_commit to apply.",
		Annotations: createTool("Create SNMP-trap server profile"),
	}, deviceCreateHandler(d, "panos_snmptrap_profile_create", svc, parts, buildSnmpTrapProfile, snmpTrapProfileSummary, withSecrets(snmpTrapProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_snmptrap_profile_update",
		Description: "Update an SNMP-trap server profile: read-modify-write, only provided fields change. Setting version switches branch and clears the other version's receivers. Within a version a provided receiver list is merged by name: a receiver absent from the list is removed, and an omitted community or password keeps the stored value. Run panos_commit to apply.",
		Annotations: updateTool("Update SNMP-trap server profile"),
	}, deviceUpdateHandler(d, "panos_snmptrap_profile_update", svc, parts,
		func(in SnmpTrapProfileInput) string { return in.Name }, overlaySnmpTrapProfile, snmpTrapProfileSummary, withSecrets(snmpTrapProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_snmptrap_profile_delete",
		Description: "Delete an SNMP-trap server profile from the candidate config. Fails while log-forwarding profiles or log settings still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete SNMP-trap server profile"),
	}, deviceDeleteHandler(d, "panos_snmptrap_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Email server profile (device/profiles/email) - log-settings, no shared scope
// ---------------------------------------------------------------------------

func newEmailProfileService(d *Deps) nameFixAdapter[email.Location, email.Entry] {
	return nameFixAdapter[email.Location, email.Entry]{
		svc:    email.NewService(d.Client),
		client: d.Client,
		name:   func(e *email.Entry) string { return e.Name },
	}
}

func emailProfileParts() deviceScopeParts[email.Location] {
	return deviceScopeParts[email.Location]{
		vsys: func(ngfw, vsys string) email.Location {
			return email.Location{Vsys: &email.VsysLocation{NgfwDevice: ngfw, Vsys: vsys}}
		},
		template: func(pano, tmpl string) email.Location {
			return email.Location{Template: &email.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) email.Location {
			return email.Location{TemplateVsys: &email.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) email.Location {
			return email.Location{TemplateStack: &email.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) email.Location {
			return email.Location{TemplateStackVsys: &email.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// EmailServerInput is one email (SMTP) server entry. password is write-only.
type EmailServerInput struct {
	Name               string  `json:"name" jsonschema:"Server entry name"`
	DisplayName        *string `json:"display_name,omitzero" jsonschema:"Display name shown in the email"`
	From               *string `json:"from,omitzero" jsonschema:"From address"`
	To                 *string `json:"to,omitzero" jsonschema:"Primary recipient address"`
	AndAlsoTo          *string `json:"and_also_to,omitzero" jsonschema:"Additional recipient address"`
	Gateway            *string `json:"gateway,omitzero" jsonschema:"SMTP gateway hostname or IP address"`
	Protocol           *string `json:"protocol,omitzero" jsonschema:"SMTP protocol: SMTP or TLS"`
	Port               *int64  `json:"port,omitzero" jsonschema:"SMTP port (default 25, or 587 for TLS)"`
	TlsVersion         *string `json:"tls_version,omitzero" jsonschema:"Minimum TLS version, e.g. 1.2"`
	Auth               *string `json:"auth,omitzero" jsonschema:"SMTP authentication method, e.g. Auto, Login, Plain"`
	CertificateProfile *string `json:"certificate_profile,omitzero" jsonschema:"Certificate profile for server verification"`
	Username           *string `json:"username,omitzero" jsonschema:"SMTP auth username"`
	Password           *string `json:"password,omitzero" jsonschema:"SMTP auth password (write-only; never returned)"`
}

// EmailProfileInput is the input for the email server profile create and update
// tools. The per-log-type format subtree is not modeled here and is preserved
// across updates.
type EmailProfileInput struct {
	DeviceScopeInput
	Name    string             `json:"name" jsonschema:"Email server profile name"`
	Servers []EmailServerInput `json:"servers,omitzero" jsonschema:"SMTP servers, merged by name; a server absent from the list is removed, and an omitted password keeps the stored value"`
}

func emailServers(in []EmailServerInput, existing []email.Server) []email.Server {
	prev := indexByName(existing, func(s email.Server) string { return s.Name })
	out := make([]email.Server, 0, len(in))
	for _, s := range in {
		srv := prev[s.Name]
		srv.Name = s.Name
		setPtr(&srv.DisplayName, s.DisplayName)
		setPtr(&srv.From, s.From)
		setPtr(&srv.To, s.To)
		setPtr(&srv.AndAlsoTo, s.AndAlsoTo)
		setPtr(&srv.Gateway, s.Gateway)
		setPtr(&srv.Protocol, s.Protocol)
		setPtr(&srv.Port, s.Port)
		setPtr(&srv.TlsVersion, s.TlsVersion)
		setPtr(&srv.Auth, s.Auth)
		setPtr(&srv.CertificateProfile, s.CertificateProfile)
		setPtr(&srv.Username, s.Username)
		setPtr(&srv.Password, s.Password)
		out = append(out, srv)
	}
	return out
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyEmailProfile(e *email.Entry, in EmailProfileInput) {
	if in.Servers != nil {
		e.Server = emailServers(in.Servers, e.Server)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildEmailProfile(in EmailProfileInput) (*email.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &email.Entry{Name: in.Name}
	applyEmailProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayEmailProfile(e *email.Entry, in EmailProfileInput) error {
	applyEmailProfile(e, in)
	return nil
}

func emailServerSummaries(servers []email.Server) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		sm := map[string]any{
			tagNameKey:            s.Name,
			"display_name":        strVal(s.DisplayName),
			"from":                strVal(s.From),
			"to":                  strVal(s.To),
			"and_also_to":         strVal(s.AndAlsoTo),
			"gateway":             strVal(s.Gateway),
			protocolKey:           strVal(s.Protocol),
			"tls_version":         strVal(s.TlsVersion),
			"auth":                strVal(s.Auth),
			"certificate_profile": strVal(s.CertificateProfile),
			"username":            strVal(s.Username),
			"has_password":        s.Password != nil,
		}
		putInt(sm, "port", s.Port)
		out = append(out, sm)
	}
	return out
}

func emailProfileSummary(e *email.Entry) any {
	return map[string]any{tagNameKey: e.Name, "servers": emailServerSummaries(e.Server)}
}

// RegisterEmailProfileTools registers the email server profile tools on both
// firewall and Panorama.
func RegisterEmailProfileTools(s *mcp.Server, d *Deps) {
	svc := newEmailProfileService(d)
	parts := emailProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_email_profile_list",
		Description: "List email server profiles. Firewall: vsys; Panorama: template or template_stack (no shared scope). Read-only.",
		Annotations: readOnlyTool("List email server profiles"),
	}, deviceListHandler(d, "panos_email_profile_list", svc, parts, svc.name, emailProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_email_profile_get",
		Description: "Get one email server profile. SMTP passwords are never returned; has_password reports whether each is set. The per-log-type format subtree is not modeled and is preserved on update. Read-only.",
		Annotations: readOnlyTool("Get email server profile"),
	}, deviceGetHandler(d, "panos_email_profile_get", svc, parts, emailProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_email_profile_create",
		Description: "Create an email server profile in the candidate config. Each SMTP password is write-only. Run panos_commit to apply.",
		Annotations: createTool("Create email server profile"),
	}, deviceCreateHandler(d, "panos_email_profile_create", svc, parts, buildEmailProfile, emailProfileSummary, withSecrets(emailProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_email_profile_update",
		Description: "Update an email server profile: read-modify-write, only provided fields change. A provided servers list is merged by name: a server absent from the list is removed, and an omitted password keeps the stored value. The per-log-type format subtree is preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update email server profile"),
	}, deviceUpdateHandler(d, "panos_email_profile_update", svc, parts,
		func(in EmailProfileInput) string { return in.Name }, overlayEmailProfile, emailProfileSummary, withSecrets(emailProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_email_profile_delete",
		Description: "Delete an email server profile from the candidate config. Fails while log-forwarding profiles or log settings still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete email server profile"),
	}, deviceDeleteHandler(d, "panos_email_profile_delete", svc, parts))
}
