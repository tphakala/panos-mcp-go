package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/profiles/bfd"
	"github.com/PaloAltoNetworks/pango/network/profiles/interface_management"
	"github.com/PaloAltoNetworks/pango/network/profiles/lldp"
	"github.com/PaloAltoNetworks/pango/network/profiles/monitor"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Summary keys shared across the network profile summaries (goconst).
const (
	modeKey   = "mode"
	actionKey = "action"
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
	m["permitted_ip"] = strList(names(e.PermittedIp, func(p interface_management.PermittedIp) string { return p.Name }))
	return m
}

// RegisterInterfaceManagementProfileTools registers the interface management
// profile tools on both firewall and Panorama.
func RegisterInterfaceManagementProfileTools(s *mcp.Server, d *Deps) {
	svc := newInterfaceManagementProfileService(d)
	parts := interfaceManagementProfileParts()

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
	}, netCreateHandler(d, "panos_interface_mgmt_profile_create", svc, parts, buildInterfaceManagementProfile, interfaceManagementProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_update",
		Description: "Update an interface management profile: read-modify-write, only provided fields change. A provided permitted_ip replaces the whole allow list. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update interface management profile"),
	}, netUpdateHandler(d, "panos_interface_mgmt_profile_update", svc, parts,
		func(in InterfaceManagementProfileInput) string { return in.Name }, overlayInterfaceManagementProfile, interfaceManagementProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_mgmt_profile_delete",
		Description: "Delete an interface management profile from the candidate config. Fails while interfaces still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete interface management profile"),
	}, netDeleteHandler(d, "panos_interface_mgmt_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// LLDP profile (network/profiles/lldp)
// ---------------------------------------------------------------------------
//
// An LLDP profile controls Link Layer Discovery Protocol behaviour on an
// interface (transmit/receive mode and SNMP/syslog notification on MIB change).
// The optional TLV set is not modeled here and is preserved across updates.
// Net-scoped like the interface management profile: {Ngfw | Template |
// TemplateStack}.

func newLldpProfileService(d *Deps) nameFixAdapter[lldp.Location, lldp.Entry] {
	return nameFixAdapter[lldp.Location, lldp.Entry]{
		svc:    lldp.NewService(d.Client),
		client: d.Client,
		name:   func(e *lldp.Entry) string { return e.Name },
	}
}

func lldpProfileParts() netScopeParts[lldp.Location] {
	return netScopeParts[lldp.Location]{
		ngfw: func() lldp.Location {
			return lldp.Location{Ngfw: &lldp.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) lldp.Location {
			return lldp.Location{Template: &lldp.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) lldp.Location {
			return lldp.Location{TemplateStack: &lldp.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// LldpProfileInput is the input for the LLDP profile create and update tools.
type LldpProfileInput struct {
	NetScopeInput
	Name                   string  `json:"name" jsonschema:"LLDP profile name"`
	Mode                   *string `json:"mode,omitzero" jsonschema:"LLDP mode: transmit-receive, transmit-only, or receive-only"`
	SnmpSyslogNotification *bool   `json:"snmp_syslog_notification,omitzero" jsonschema:"Send an SNMP trap and syslog notification on an LLDP MIB change"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyLldpProfile(e *lldp.Entry, in LldpProfileInput) {
	setPtr(&e.Mode, in.Mode)
	setPtr(&e.SnmpSyslogNotification, in.SnmpSyslogNotification)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLldpProfile(in LldpProfileInput) (*lldp.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &lldp.Entry{Name: in.Name}
	applyLldpProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLldpProfile(e *lldp.Entry, in LldpProfileInput) error {
	applyLldpProfile(e, in)
	return nil
}

func lldpProfileSummary(e *lldp.Entry) any {
	m := map[string]any{tagNameKey: e.Name, modeKey: strVal(e.Mode)}
	putBool(m, "snmp_syslog_notification", e.SnmpSyslogNotification)
	return m
}

// RegisterLldpProfileTools registers the LLDP profile tools on both firewall and
// Panorama.
func RegisterLldpProfileTools(s *mcp.Server, d *Deps) {
	svc := newLldpProfileService(d)
	parts := lldpProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_lldp_profile_list",
		Description: "List LLDP profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List LLDP profiles"),
	}, netListHandler(d, "panos_lldp_profile_list", svc, parts, svc.name, lldpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_lldp_profile_get",
		Description: "Get one LLDP profile (mode and the notification toggle). The optional TLV set is not modeled and is preserved on update. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get LLDP profile"),
	}, netGetHandler(d, "panos_lldp_profile_get", svc, parts, lldpProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_lldp_profile_create",
		Description: "Create an LLDP profile in the candidate config. Only name is required. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create LLDP profile"),
	}, netCreateHandler(d, "panos_lldp_profile_create", svc, parts, buildLldpProfile, lldpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_lldp_profile_update",
		Description: "Update an LLDP profile: read-modify-write, only provided fields change. The optional TLV set is preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update LLDP profile"),
	}, netUpdateHandler(d, "panos_lldp_profile_update", svc, parts,
		func(in LldpProfileInput) string { return in.Name }, overlayLldpProfile, lldpProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_lldp_profile_delete",
		Description: "Delete an LLDP profile from the candidate config. Fails while interfaces still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete LLDP profile"),
	}, netDeleteHandler(d, "panos_lldp_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// BFD profile (network/profiles/bfd)
// ---------------------------------------------------------------------------
//
// A BFD (Bidirectional Forwarding Detection) profile tunes the failure-detection
// timers a routing protocol or static route uses to declare a neighbor down. The
// optional multihop settings are not modeled here and are preserved across
// updates. Net-scoped: {Ngfw | Template | TemplateStack}.

// Note for anyone adding the advanced routing engine's own BFD profile:
// network/routing-profile/bfd is a DIFFERENT pango package from the
// network/profiles/bfd wrapped here. The two carry an identical Entry but sit at
// different xpaths (network/routing-profile/bfd versus
// network/profiles/bfd-profile), so the advanced-routing one is a genuine
// addition rather than a duplicate. It needs an import alias and a distinct tool
// name. The rest of network/routing-profile (BGP, OSPF, OSPFv3 and the route
// filters) shares the net scope used here, so nothing about this scope
// machinery blocks it; it waits on the logical-router VRF configuration that
// would reference those profiles.
func newBfdProfileService(d *Deps) nameFixAdapter[bfd.Location, bfd.Entry] {
	return nameFixAdapter[bfd.Location, bfd.Entry]{
		svc:    bfd.NewService(d.Client),
		client: d.Client,
		name:   func(e *bfd.Entry) string { return e.Name },
	}
}

func bfdProfileParts() netScopeParts[bfd.Location] {
	return netScopeParts[bfd.Location]{
		ngfw: func() bfd.Location {
			return bfd.Location{Ngfw: &bfd.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) bfd.Location {
			return bfd.Location{Template: &bfd.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) bfd.Location {
			return bfd.Location{TemplateStack: &bfd.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// BfdProfileInput is the input for the BFD profile create and update tools.
type BfdProfileInput struct {
	NetScopeInput
	Name                string  `json:"name" jsonschema:"BFD profile name"`
	Mode                *string `json:"mode,omitzero" jsonschema:"BFD mode: active or passive"`
	MinTxInterval       *int64  `json:"min_tx_interval,omitzero" jsonschema:"Desired minimum transmit interval in ms"`
	MinRxInterval       *int64  `json:"min_rx_interval,omitzero" jsonschema:"Required minimum receive interval in ms"`
	DetectionMultiplier *int64  `json:"detection_multiplier,omitzero" jsonschema:"Detection time multiplier"`
	HoldTime            *int64  `json:"hold_time,omitzero" jsonschema:"Delay in ms before transmitting BFD control packets after the link comes up"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyBfdProfile(e *bfd.Entry, in BfdProfileInput) {
	setPtr(&e.Mode, in.Mode)
	setPtr(&e.MinTxInterval, in.MinTxInterval)
	setPtr(&e.MinRxInterval, in.MinRxInterval)
	setPtr(&e.DetectionMultiplier, in.DetectionMultiplier)
	setPtr(&e.HoldTime, in.HoldTime)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildBfdProfile(in BfdProfileInput) (*bfd.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &bfd.Entry{Name: in.Name}
	applyBfdProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayBfdProfile(e *bfd.Entry, in BfdProfileInput) error {
	applyBfdProfile(e, in)
	return nil
}

func bfdProfileSummary(e *bfd.Entry) any {
	m := map[string]any{tagNameKey: e.Name, modeKey: strVal(e.Mode)}
	putInt(m, "min_tx_interval", e.MinTxInterval)
	putInt(m, "min_rx_interval", e.MinRxInterval)
	putInt(m, "detection_multiplier", e.DetectionMultiplier)
	putInt(m, "hold_time", e.HoldTime)
	return m
}

// RegisterBfdProfileTools registers the BFD profile tools on both firewall and
// Panorama.
func RegisterBfdProfileTools(s *mcp.Server, d *Deps) {
	svc := newBfdProfileService(d)
	parts := bfdProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bfd_profile_list",
		Description: "List BFD profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List BFD profiles"),
	}, netListHandler(d, "panos_bfd_profile_list", svc, parts, svc.name, bfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bfd_profile_get",
		Description: "Get one BFD profile (mode and detection timers). The optional multihop settings are not modeled and are preserved on update. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get BFD profile"),
	}, netGetHandler(d, "panos_bfd_profile_get", svc, parts, bfdProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bfd_profile_create",
		Description: "Create a BFD profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create BFD profile"),
	}, netCreateHandler(d, "panos_bfd_profile_create", svc, parts, buildBfdProfile, bfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bfd_profile_update",
		Description: "Update a BFD profile: read-modify-write, only provided fields change. The optional multihop settings are preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update BFD profile"),
	}, netUpdateHandler(d, "panos_bfd_profile_update", svc, parts,
		func(in BfdProfileInput) string { return in.Name }, overlayBfdProfile, bfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bfd_profile_delete",
		Description: "Delete a BFD profile from the candidate config. Fails while routing protocols or static routes still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete BFD profile"),
	}, netDeleteHandler(d, "panos_bfd_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Monitor profile (network/profiles/monitor)
// ---------------------------------------------------------------------------
//
// A monitor profile defines the action (wait-recover or fail-over) and timers a
// tunnel or path monitor applies when a monitored destination stops responding.
// Net-scoped: {Ngfw | Template | TemplateStack}.

func newMonitorProfileService(d *Deps) nameFixAdapter[monitor.Location, monitor.Entry] {
	return nameFixAdapter[monitor.Location, monitor.Entry]{
		svc:    monitor.NewService(d.Client),
		client: d.Client,
		name:   func(e *monitor.Entry) string { return e.Name },
	}
}

func monitorProfileParts() netScopeParts[monitor.Location] {
	return netScopeParts[monitor.Location]{
		ngfw: func() monitor.Location {
			return monitor.Location{Ngfw: &monitor.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) monitor.Location {
			return monitor.Location{Template: &monitor.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) monitor.Location {
			return monitor.Location{TemplateStack: &monitor.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// MonitorProfileInput is the input for the monitor profile create and update
// tools.
type MonitorProfileInput struct {
	NetScopeInput
	Name      string  `json:"name" jsonschema:"Monitor profile name"`
	Action    *string `json:"action,omitzero" jsonschema:"Action on failure: wait-recover or fail-over"`
	Interval  *int64  `json:"interval,omitzero" jsonschema:"Probe interval in seconds"`
	Threshold *int64  `json:"threshold,omitzero" jsonschema:"Number of failed probes before the action is taken"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyMonitorProfile(e *monitor.Entry, in MonitorProfileInput) {
	setPtr(&e.Action, in.Action)
	setPtr(&e.Interval, in.Interval)
	setPtr(&e.Threshold, in.Threshold)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildMonitorProfile(in MonitorProfileInput) (*monitor.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &monitor.Entry{Name: in.Name}
	applyMonitorProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayMonitorProfile(e *monitor.Entry, in MonitorProfileInput) error {
	applyMonitorProfile(e, in)
	return nil
}

func monitorProfileSummary(e *monitor.Entry) any {
	m := map[string]any{tagNameKey: e.Name, actionKey: strVal(e.Action)}
	putInt(m, "interval", e.Interval)
	putInt(m, "threshold", e.Threshold)
	return m
}

// RegisterMonitorProfileTools registers the monitor profile tools on both
// firewall and Panorama.
func RegisterMonitorProfileTools(s *mcp.Server, d *Deps) {
	svc := newMonitorProfileService(d)
	parts := monitorProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_monitor_profile_list",
		Description: "List monitor profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List monitor profiles"),
	}, netListHandler(d, "panos_monitor_profile_list", svc, parts, svc.name, monitorProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_monitor_profile_get",
		Description: "Get one monitor profile (action, interval and threshold). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get monitor profile"),
	}, netGetHandler(d, "panos_monitor_profile_get", svc, parts, monitorProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_monitor_profile_create",
		Description: "Create a monitor profile in the candidate config. Only name is required. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create monitor profile"),
	}, netCreateHandler(d, "panos_monitor_profile_create", svc, parts, buildMonitorProfile, monitorProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_monitor_profile_update",
		Description: "Update a monitor profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update monitor profile"),
	}, netUpdateHandler(d, "panos_monitor_profile_update", svc, parts,
		func(in MonitorProfileInput) string { return in.Name }, overlayMonitorProfile, monitorProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_monitor_profile_delete",
		Description: "Delete a monitor profile from the candidate config. Fails while tunnels or path monitors still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete monitor profile"),
	}, netDeleteHandler(d, "panos_monitor_profile_delete", svc, parts))
}
