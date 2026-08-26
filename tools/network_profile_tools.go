package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/profiles/interface_management"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Interface management profile (network/profiles/interface-management-profile)
// ---------------------------------------------------------------------------
//
// The interface management profile controls which management services (http,
// https, ssh, ping, snmp, and so on) an interface answers, plus an optional
// permitted-ip allow list. pango models it at the same network scope as the
// site-to-site VPN resources: {Ngfw | Template | TemplateStack}, resolved by
// resolveNetScope. It is registered on both firewall and Panorama.

func newInterfaceManagementProfileService(d *Deps) nameFixAdapter[interface_management.Location, interface_management.Entry] {
	return nameFixAdapter[interface_management.Location, interface_management.Entry]{
		svc:    interface_management.NewService(d.Client),
		client: d.Client,
		name:   func(e *interface_management.Entry) string { return e.Name },
	}
}

func interfaceManagementProfileParts() netScopeParts[interface_management.Location] {
	return netScopeParts[interface_management.Location]{
		ngfw: func() interface_management.Location {
			return interface_management.Location{Ngfw: &interface_management.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) interface_management.Location {
			return interface_management.Location{Template: &interface_management.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) interface_management.Location {
			return interface_management.Location{TemplateStack: &interface_management.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// InterfaceManagementProfileInput is the input for the interface management
// profile create and update tools. Each service toggle is a tri-state *bool
// (present-true / present-false / absent-inherits-default); an omitted toggle
// leaves the current value untouched on update. permitted_ip is an allow list
// replaced fully whenever provided.
type InterfaceManagementProfileInput struct {
	NetScopeInput
	Name                    string   `json:"name" jsonschema:"Interface management profile name"`
	Http                    *bool    `json:"http,omitzero" jsonschema:"Allow HTTP management"`
	Https                   *bool    `json:"https,omitzero" jsonschema:"Allow HTTPS management"`
	HttpOcsp                *bool    `json:"http_ocsp,omitzero" jsonschema:"Allow HTTP OCSP responder"`
	Ping                    *bool    `json:"ping,omitzero" jsonschema:"Allow ICMP ping"`
	Snmp                    *bool    `json:"snmp,omitzero" jsonschema:"Allow SNMP"`
	Ssh                     *bool    `json:"ssh,omitzero" jsonschema:"Allow SSH management"`
	Telnet                  *bool    `json:"telnet,omitzero" jsonschema:"Allow Telnet management"`
	ResponsePages           *bool    `json:"response_pages,omitzero" jsonschema:"Allow response pages (captive portal, URL admin override)"`
	UseridService           *bool    `json:"userid_service,omitzero" jsonschema:"Allow the User-ID service"`
	UseridSyslogListenerSsl *bool    `json:"userid_syslog_listener_ssl,omitzero" jsonschema:"Allow the User-ID syslog listener over SSL"`
	UseridSyslogListenerUdp *bool    `json:"userid_syslog_listener_udp,omitzero" jsonschema:"Allow the User-ID syslog listener over UDP"`
	PermittedIp             []string `json:"permitted_ip,omitzero" jsonschema:"Source IPs/subnets permitted to reach the enabled services; replaces the whole list when provided"`
}

// applyInterfaceManagementProfile writes the provided input fields onto e. Each
// *bool toggle is applied only when non-nil, so an omitted toggle keeps the
// existing value (read-modify-write); permitted_ip replaces the whole list only
// when the caller provides it. Shared by the build (create) and overlay
// (update) paths so both map fields identically.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyInterfaceManagementProfile(e *interface_management.Entry, in InterfaceManagementProfileInput) {
	setPtr(&e.Http, in.Http)
	setPtr(&e.Https, in.Https)
	setPtr(&e.HttpOcsp, in.HttpOcsp)
	setPtr(&e.Ping, in.Ping)
	setPtr(&e.Snmp, in.Snmp)
	setPtr(&e.Ssh, in.Ssh)
	setPtr(&e.Telnet, in.Telnet)
	setPtr(&e.ResponsePages, in.ResponsePages)
	setPtr(&e.UseridService, in.UseridService)
	setPtr(&e.UseridSyslogListenerSsl, in.UseridSyslogListenerSsl)
	setPtr(&e.UseridSyslogListenerUdp, in.UseridSyslogListenerUdp)
	if in.PermittedIp != nil {
		e.PermittedIp = permittedIpEntries(in.PermittedIp)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildInterfaceManagementProfile(in InterfaceManagementProfileInput) (*interface_management.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &interface_management.Entry{Name: in.Name}
	applyInterfaceManagementProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayInterfaceManagementProfile(e *interface_management.Entry, in InterfaceManagementProfileInput) error {
	applyInterfaceManagementProfile(e, in)
	return nil
}

// permittedIpEntries maps the flat allow list onto pango's entry-named list.
func permittedIpEntries(ips []string) []interface_management.PermittedIp {
	out := make([]interface_management.PermittedIp, 0, len(ips))
	for _, ip := range ips {
		out = append(out, interface_management.PermittedIp{Name: ip})
	}
	return out
}

// permittedIpNames pulls the entry names back out of pango's allow list for the
// summary.
func permittedIpNames(ips []interface_management.PermittedIp) []string {
	out := make([]string, 0, len(ips))
	for i := range ips {
		out = append(out, ips[i].Name)
	}
	return out
}

func interfaceManagementProfileSummary(e *interface_management.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putBool(m, "http", e.Http)
	putBool(m, "https", e.Https)
	putBool(m, "http_ocsp", e.HttpOcsp)
	putBool(m, "ping", e.Ping)
	putBool(m, "snmp", e.Snmp)
	putBool(m, "ssh", e.Ssh)
	putBool(m, "telnet", e.Telnet)
	putBool(m, "response_pages", e.ResponsePages)
	putBool(m, "userid_service", e.UseridService)
	putBool(m, "userid_syslog_listener_ssl", e.UseridSyslogListenerSsl)
	putBool(m, "userid_syslog_listener_udp", e.UseridSyslogListenerUdp)
	m["permitted_ip"] = strList(permittedIpNames(e.PermittedIp))
	return m
}

// RegisterInterfaceManagementProfileTools registers the interface management
// profile tools on both firewall and Panorama.
func RegisterInterfaceManagementProfileTools(s *mcp.Server, d *Deps) {
	svc := newInterfaceManagementProfileService(d)
	parts := interfaceManagementProfileParts()
	scope := func(in InterfaceManagementProfileInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_list",
		Description: "List interface management profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List interface management profiles"),
	}, netListHandler(d, "panos_interface_mgmt_profile_list", svc, parts, svc.name, interfaceManagementProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_get",
		Description: "Get one interface management profile (service toggles and the permitted-ip allow list). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get interface management profile"),
	}, netGetHandler(d, "panos_interface_mgmt_profile_get", svc, parts, interfaceManagementProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_create",
		Description: "Create an interface management profile in the candidate config. Only name is required; each service toggle defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create interface management profile"),
	}, netCreateHandler(d, "panos_interface_mgmt_profile_create", svc, parts, scope, buildInterfaceManagementProfile, interfaceManagementProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_update",
		Description: "Update an interface management profile: read-modify-write, only provided fields change. A provided permitted_ip replaces the whole allow list. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update interface management profile"),
	}, netUpdateHandler(d, "panos_interface_mgmt_profile_update", svc, parts, scope,
		func(in InterfaceManagementProfileInput) string { return in.Name }, overlayInterfaceManagementProfile, interfaceManagementProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_delete",
		Description: "Delete an interface management profile from the candidate config. Fails while interfaces still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete interface management profile"),
	}, netDeleteHandler(d, "panos_interface_mgmt_profile_delete", svc, parts))
}
