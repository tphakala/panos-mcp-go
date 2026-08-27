package tools

import (
	"errors"

	zoneprotection "github.com/PaloAltoNetworks/pango/network/profiles/zoneprotection"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Zone protection profile (network/profiles/zoneprotection)
// ---------------------------------------------------------------------------
// A zone protection profile attached to a security zone. This server models the
// scalar packet-based-attack toggles (the boolean drops and the three string
// options below). The typed sub-blocks (flood protection, IPv6, reconnaissance
// / net-inspection, non-IP protocol, L2 SGT protection, and scan white-lists)
// are NOT modeled and are preserved unchanged across an update via the
// read-modify-write cycle. It is net-scoped: firewall-local or, on Panorama,
// under a template or template-stack.

func newZoneProtectionService(d *Deps) nameFixAdapter[zoneprotection.Location, zoneprotection.Entry] {
	return nameFixAdapter[zoneprotection.Location, zoneprotection.Entry]{
		svc:    zoneprotection.NewService(d.Client),
		client: d.Client,
		name:   func(e *zoneprotection.Entry) string { return e.Name },
	}
}

func zoneProtectionParts() netScopeParts[zoneprotection.Location] {
	return netScopeParts[zoneprotection.Location]{
		ngfw: func() zoneprotection.Location {
			return zoneprotection.Location{Ngfw: &zoneprotection.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) zoneprotection.Location {
			return zoneprotection.Location{Template: &zoneprotection.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) zoneprotection.Location {
			return zoneprotection.Location{TemplateStack: &zoneprotection.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// ZoneProtectionInput is the input for the zone protection profile create and
// update tools. Every field below is a scalar packet-based-attack toggle; the
// flood, IPv6, reconnaissance, non-IP-protocol and scan sub-blocks are not
// modeled and are preserved across updates.
type ZoneProtectionInput struct {
	NetScopeInput
	Name             string  `json:"name" jsonschema:"Zone protection profile name"`
	Description      string  `json:"description,omitempty"`
	AsymmetricPath   *string `json:"asymmetric_path,omitzero" jsonschema:"Action on asymmetric-path packets: global, drop or bypass"`
	StripMptcpOption *string `json:"strip_mptcp_option,omitzero" jsonschema:"MPTCP option handling: global, no or yes (strip)"`
	TcpRejectNonSyn  *string `json:"tcp_reject_non_syn,omitzero" jsonschema:"Reject non-SYN TCP: global, no or yes"`

	DiscardIcmpError                     *bool `json:"discard_icmp_error,omitzero" jsonschema:"Discard packets with an ICMP error"`
	DiscardIcmpFrag                      *bool `json:"discard_icmp_frag,omitzero" jsonschema:"Discard fragmented ICMP packets"`
	DiscardIcmpLargePacket               *bool `json:"discard_icmp_large_packet,omitzero" jsonschema:"Discard large (>1024 byte) ICMP packets"`
	DiscardIcmpPingZeroId                *bool `json:"discard_icmp_ping_zero_id,omitzero" jsonschema:"Discard ICMP ping packets with a zero identifier"`
	DiscardIpFrag                        *bool `json:"discard_ip_frag,omitzero" jsonschema:"Discard fragmented IP packets"`
	DiscardIpSpoof                       *bool `json:"discard_ip_spoof,omitzero" jsonschema:"Discard spoofed IP packets"`
	DiscardLooseSourceRouting            *bool `json:"discard_loose_source_routing,omitzero" jsonschema:"Discard packets with the loose source routing IP option"`
	DiscardMalformedOption               *bool `json:"discard_malformed_option,omitzero" jsonschema:"Discard packets with a malformed IP option"`
	DiscardOverlappingTcpSegmentMismatch *bool `json:"discard_overlapping_tcp_segment_mismatch,omitzero" jsonschema:"Discard packets with a mismatched overlapping TCP segment"`
	DiscardRecordRoute                   *bool `json:"discard_record_route,omitzero" jsonschema:"Discard packets with the record-route IP option"`
	DiscardSecurity                      *bool `json:"discard_security,omitzero" jsonschema:"Discard packets with the security IP option"`
	DiscardStreamId                      *bool `json:"discard_stream_id,omitzero" jsonschema:"Discard packets with the stream-ID IP option"`
	DiscardStrictSourceRouting           *bool `json:"discard_strict_source_routing,omitzero" jsonschema:"Discard packets with the strict source routing IP option"`
	DiscardTcpSplitHandshake             *bool `json:"discard_tcp_split_handshake,omitzero" jsonschema:"Discard TCP split-handshake sessions"`
	DiscardTcpSynWithData                *bool `json:"discard_tcp_syn_with_data,omitzero" jsonschema:"Discard TCP SYN packets carrying data"`
	DiscardTcpSynackWithData             *bool `json:"discard_tcp_synack_with_data,omitzero" jsonschema:"Discard TCP SYN-ACK packets carrying data"`
	DiscardTimestamp                     *bool `json:"discard_timestamp,omitzero" jsonschema:"Discard packets with the timestamp IP option"`
	DiscardUnknownOption                 *bool `json:"discard_unknown_option,omitzero" jsonschema:"Discard packets with an unknown IP option"`
	RemoveTcpTimestamp                   *bool `json:"remove_tcp_timestamp,omitzero" jsonschema:"Strip the TCP timestamp option"`
	StrictIpCheck                        *bool `json:"strict_ip_check,omitzero" jsonschema:"Enable strict IP address checking"`
	StripTcpFastOpenAndData              *bool `json:"strip_tcp_fast_open_and_data,omitzero" jsonschema:"Strip the TCP Fast Open option and any data it carries"`
	SuppressIcmpNeedfrag                 *bool `json:"suppress_icmp_needfrag,omitzero" jsonschema:"Suppress ICMP fragmentation-needed responses"`
	SuppressIcmpTimeexceeded             *bool `json:"suppress_icmp_timeexceeded,omitzero" jsonschema:"Suppress ICMP time-exceeded responses"`
}

// zpToggle maps one boolean packet-based-attack field across the input, the
// summary key, and the pango entry. Defining each field once here (rather than
// as three parallel lists in apply, summary and back) is what keeps the mapping
// from drifting as toggles are added.
type zpToggle struct {
	key   string
	in    func(*ZoneProtectionInput) *bool
	entry func(*zoneprotection.Entry) **bool
}

var zpToggles = []zpToggle{
	{"discard_icmp_error", func(i *ZoneProtectionInput) *bool { return i.DiscardIcmpError }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIcmpError }},
	{"discard_icmp_frag", func(i *ZoneProtectionInput) *bool { return i.DiscardIcmpFrag }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIcmpFrag }},
	{"discard_icmp_large_packet", func(i *ZoneProtectionInput) *bool { return i.DiscardIcmpLargePacket }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIcmpLargePacket }},
	{"discard_icmp_ping_zero_id", func(i *ZoneProtectionInput) *bool { return i.DiscardIcmpPingZeroId }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIcmpPingZeroId }},
	{"discard_ip_frag", func(i *ZoneProtectionInput) *bool { return i.DiscardIpFrag }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIpFrag }},
	{"discard_ip_spoof", func(i *ZoneProtectionInput) *bool { return i.DiscardIpSpoof }, func(e *zoneprotection.Entry) **bool { return &e.DiscardIpSpoof }},
	{"discard_loose_source_routing", func(i *ZoneProtectionInput) *bool { return i.DiscardLooseSourceRouting }, func(e *zoneprotection.Entry) **bool { return &e.DiscardLooseSourceRouting }},
	{"discard_malformed_option", func(i *ZoneProtectionInput) *bool { return i.DiscardMalformedOption }, func(e *zoneprotection.Entry) **bool { return &e.DiscardMalformedOption }},
	{"discard_overlapping_tcp_segment_mismatch", func(i *ZoneProtectionInput) *bool { return i.DiscardOverlappingTcpSegmentMismatch }, func(e *zoneprotection.Entry) **bool { return &e.DiscardOverlappingTcpSegmentMismatch }},
	{"discard_record_route", func(i *ZoneProtectionInput) *bool { return i.DiscardRecordRoute }, func(e *zoneprotection.Entry) **bool { return &e.DiscardRecordRoute }},
	{"discard_security", func(i *ZoneProtectionInput) *bool { return i.DiscardSecurity }, func(e *zoneprotection.Entry) **bool { return &e.DiscardSecurity }},
	{"discard_stream_id", func(i *ZoneProtectionInput) *bool { return i.DiscardStreamId }, func(e *zoneprotection.Entry) **bool { return &e.DiscardStreamId }},
	{"discard_strict_source_routing", func(i *ZoneProtectionInput) *bool { return i.DiscardStrictSourceRouting }, func(e *zoneprotection.Entry) **bool { return &e.DiscardStrictSourceRouting }},
	{"discard_tcp_split_handshake", func(i *ZoneProtectionInput) *bool { return i.DiscardTcpSplitHandshake }, func(e *zoneprotection.Entry) **bool { return &e.DiscardTcpSplitHandshake }},
	{"discard_tcp_syn_with_data", func(i *ZoneProtectionInput) *bool { return i.DiscardTcpSynWithData }, func(e *zoneprotection.Entry) **bool { return &e.DiscardTcpSynWithData }},
	{"discard_tcp_synack_with_data", func(i *ZoneProtectionInput) *bool { return i.DiscardTcpSynackWithData }, func(e *zoneprotection.Entry) **bool { return &e.DiscardTcpSynackWithData }},
	{"discard_timestamp", func(i *ZoneProtectionInput) *bool { return i.DiscardTimestamp }, func(e *zoneprotection.Entry) **bool { return &e.DiscardTimestamp }},
	{"discard_unknown_option", func(i *ZoneProtectionInput) *bool { return i.DiscardUnknownOption }, func(e *zoneprotection.Entry) **bool { return &e.DiscardUnknownOption }},
	{"remove_tcp_timestamp", func(i *ZoneProtectionInput) *bool { return i.RemoveTcpTimestamp }, func(e *zoneprotection.Entry) **bool { return &e.RemoveTcpTimestamp }},
	{"strict_ip_check", func(i *ZoneProtectionInput) *bool { return i.StrictIpCheck }, func(e *zoneprotection.Entry) **bool { return &e.StrictIpCheck }},
	{"strip_tcp_fast_open_and_data", func(i *ZoneProtectionInput) *bool { return i.StripTcpFastOpenAndData }, func(e *zoneprotection.Entry) **bool { return &e.StripTcpFastOpenAndData }},
	{"suppress_icmp_needfrag", func(i *ZoneProtectionInput) *bool { return i.SuppressIcmpNeedfrag }, func(e *zoneprotection.Entry) **bool { return &e.SuppressIcmpNeedfrag }},
	{"suppress_icmp_timeexceeded", func(i *ZoneProtectionInput) *bool { return i.SuppressIcmpTimeexceeded }, func(e *zoneprotection.Entry) **bool { return &e.SuppressIcmpTimeexceeded }},
}

// applyZoneProtection overlays the provided scalar fields onto e with setPtr,
// applying only what the caller provided. It is shared by build and overlay so
// create and update agree on the mapping, and it never rebuilds e, so the
// unmanaged flood/IPv6/reconnaissance/non-IP/scan sub-blocks survive an update.
func applyZoneProtection(e *zoneprotection.Entry, in *ZoneProtectionInput) {
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	setPtr(&e.AsymmetricPath, in.AsymmetricPath)
	setPtr(&e.StripMptcpOption, in.StripMptcpOption)
	setPtr(&e.TcpRejectNonSyn, in.TcpRejectNonSyn)
	for _, t := range zpToggles {
		setPtr(t.entry(e), t.in(in))
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildZoneProtection(in ZoneProtectionInput) (*zoneprotection.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &zoneprotection.Entry{Name: in.Name}
	applyZoneProtection(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayZoneProtection(e *zoneprotection.Entry, in ZoneProtectionInput) error {
	applyZoneProtection(e, &in)
	return nil
}

func zoneProtectionSummary(e *zoneprotection.Entry) any {
	m := nameDescription(e.Name, e.Description)
	if e.AsymmetricPath != nil {
		m["asymmetric_path"] = *e.AsymmetricPath
	}
	if e.StripMptcpOption != nil {
		m["strip_mptcp_option"] = *e.StripMptcpOption
	}
	if e.TcpRejectNonSyn != nil {
		m["tcp_reject_non_syn"] = *e.TcpRejectNonSyn
	}
	for _, t := range zpToggles {
		putBool(m, t.key, *t.entry(e))
	}
	return m
}

// RegisterZoneProtectionTools registers the zone protection profile CRUD tools.
// They are net-scoped: firewall-local or, on Panorama, under a template or
// template-stack. Mutating tools are skipped in read-only mode.
func RegisterZoneProtectionTools(s *mcp.Server, d *Deps) {
	svc := newZoneProtectionService(d)
	parts := zoneProtectionParts()
	scope := func(in ZoneProtectionInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_protection_list",
		Description: "List zone protection profiles at a network scope. Firewall: the firewall-local scope; Panorama: a template or template_stack is required (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("List zone protection profiles"),
	}, netListHandler(d, "panos_zone_protection_list", svc, parts, svc.name, zoneProtectionSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_protection_get",
		Description: "Get one zone protection profile (packet-based-attack toggles). The flood, IPv6, reconnaissance, non-IP-protocol and scan sub-blocks are not returned. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get zone protection profile"),
	}, netGetHandler(d, "panos_zone_protection_get", svc, parts, zoneProtectionSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_protection_create",
		Description: "Create a zone protection profile in the candidate config. Only the name is required; the packet-based-attack toggles are optional. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create zone protection profile"),
	}, netCreateHandler(d, "panos_zone_protection_create", svc, parts, scope, buildZoneProtection, zoneProtectionSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_protection_update",
		Description: "Update a zone protection profile: read-modify-write, only provided fields change. The flood, IPv6, reconnaissance, non-IP-protocol and scan sub-blocks are preserved and not managed here. Run panos_commit to apply.",
		Annotations: updateTool("Update zone protection profile"),
	}, netUpdateHandler(d, "panos_zone_protection_update", svc, parts, scope,
		func(in ZoneProtectionInput) string { return in.Name }, overlayZoneProtection, zoneProtectionSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_protection_delete",
		Description: "Delete a zone protection profile from the candidate config. On Panorama a template or template_stack is required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete zone protection profile"),
	}, netDeleteHandler(d, "panos_zone_protection_delete", svc, parts))
}
