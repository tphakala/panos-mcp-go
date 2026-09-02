package tools

// Advanced-routing protocol profiles (network/routing-profile/*)
// ---------------------------------------------------------------------------
//
// PAN-OS's advanced routing engine keeps its BGP, OSPF, OSPFv3, BFD and PIM
// tuning as named, reusable profiles under network/routing-profile. A logical
// router's per-VRF protocol configuration references them by name. The profiles
// are standalone objects: they are created, listed and deleted independently of
// any VRF that uses them, so they wrap cleanly onto the same net scope
// ({Ngfw | Template | TemplateStack}) the interface and virtual-router tools
// already use, resolved by resolveNetScope.
//
// Only the shallow, scalar-tuning and auth profiles are wrapped here. The deep
// nested profiles (bgp/addressfamily, bgp/filtering, the redistribution and
// route-map filters, and the OSPFv3 auth profile) carry large match/set trees
// that do not fit the flat build/overlay contract and are left for dedicated
// handlers.
//
// Naming: the advanced-routing BFD profile below is a DIFFERENT pango package
// (network/routing-profile/bfd) from the legacy network/profiles/bfd wrapped as
// panos_bfd_profile_* in network_profile_tools.go. The two sit at different
// xpaths, so this one is registered as panos_routing_bfd_profile_* to keep the
// names distinct.

import (
	"errors"

	routingbfd "github.com/PaloAltoNetworks/pango/network/routing-profile/bfd"
	bgpauth "github.com/PaloAltoNetworks/pango/network/routing-profile/bgp/authprofile"
	"github.com/PaloAltoNetworks/pango/network/routing-profile/bgp/dampening"
	bgptimer "github.com/PaloAltoNetworks/pango/network/routing-profile/bgp/timer"
	pimtimer "github.com/PaloAltoNetworks/pango/network/routing-profile/multicast/ipv4/piminterfacetimer"
	ospfauth "github.com/PaloAltoNetworks/pango/network/routing-profile/ospf/authprofile"
	ospfiftimer "github.com/PaloAltoNetworks/pango/network/routing-profile/ospf/interfacetimer"
	ospfspftimer "github.com/PaloAltoNetworks/pango/network/routing-profile/ospf/spf/timer"
	ospfv3iftimer "github.com/PaloAltoNetworks/pango/network/routing-profile/ospfv3/iftimer"
	ospfv3spftimer "github.com/PaloAltoNetworks/pango/network/routing-profile/ospfv3/spf/timer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// netProfileParts builds the {Ngfw | Template | TemplateStack} location
// constructors for a routing profile package. Every routing-profile package
// shares the identical NgfwLocation/TemplateLocation/TemplateStackLocation
// shape, so each family below binds this once through a small adapter rather
// than repeating the three closures.

// --- BGP authentication profile (routing-profile/bgp/authprofile) -----------

func newBgpAuthProfileService(d *Deps) nameFixAdapter[bgpauth.Location, bgpauth.Entry] {
	return nameFixAdapter[bgpauth.Location, bgpauth.Entry]{
		svc:    bgpauth.NewService(d.Client),
		client: d.Client,
		name:   func(e *bgpauth.Entry) string { return e.Name },
	}
}

func bgpAuthProfileParts() netScopeParts[bgpauth.Location] {
	return netScopeParts[bgpauth.Location]{
		ngfw: func() bgpauth.Location {
			return bgpauth.Location{Ngfw: &bgpauth.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) bgpauth.Location {
			return bgpauth.Location{Template: &bgpauth.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) bgpauth.Location {
			return bgpauth.Location{TemplateStack: &bgpauth.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// BgpAuthProfileInput is the input for the BGP authentication profile create and
// update tools. Secret is the write-only MD5 authentication key.
type BgpAuthProfileInput struct {
	NetScopeInput
	Name   string  `json:"name" jsonschema:"BGP authentication profile name"`
	Secret *string `json:"secret,omitzero" jsonschema:"MD5 authentication key (write-only; never returned on read)"`
}

// bgpAuthProfileSecrets is the withSecrets extractor: the submitted key is
// redacted from any write-error message. Defined in redact.go alongside the
// other family extractors.

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyBgpAuthProfile(e *bgpauth.Entry, in BgpAuthProfileInput) {
	setPtr(&e.Secret, in.Secret)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildBgpAuthProfile(in BgpAuthProfileInput) (*bgpauth.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &bgpauth.Entry{Name: in.Name}
	applyBgpAuthProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayBgpAuthProfile(e *bgpauth.Entry, in BgpAuthProfileInput) error {
	applyBgpAuthProfile(e, in)
	return nil
}

// bgpAuthProfileSummary never returns the secret: PAN-OS masks it on read and
// it is write-only, so the summary reports only whether one is configured.
func bgpAuthProfileSummary(e *bgpauth.Entry) any {
	return map[string]any{tagNameKey: e.Name, hasSecretKey: e.Secret != nil}
}

// RegisterBgpAuthProfileTools registers the BGP authentication profile tools on
// both firewall and Panorama.
func RegisterBgpAuthProfileTools(s *mcp.Server, d *Deps) {
	svc := newBgpAuthProfileService(d)
	parts := bgpAuthProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_auth_profile_list",
		Description: "List advanced-routing BGP authentication profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). The MD5 key is never returned. Read-only.",
		Annotations: readOnlyTool("List BGP auth profiles"),
	}, netListHandler(d, "panos_bgp_auth_profile_list", svc, parts, svc.name, bgpAuthProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_auth_profile_get",
		Description: "Get one advanced-routing BGP authentication profile. The MD5 key is write-only and never returned; the result reports only whether a key is configured. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get BGP auth profile"),
	}, netGetHandler(d, "panos_bgp_auth_profile_get", svc, parts, bgpAuthProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_auth_profile_create",
		Description: "Create an advanced-routing BGP authentication profile in the candidate config. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create BGP auth profile"),
	}, netCreateHandler(d, "panos_bgp_auth_profile_create", svc, parts, buildBgpAuthProfile, bgpAuthProfileSummary,
		withSecrets(bgpAuthProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_auth_profile_update",
		Description: "Update an advanced-routing BGP authentication profile: read-modify-write, only provided fields change. Provide secret to replace the MD5 key. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update BGP auth profile"),
	}, netUpdateHandler(d, "panos_bgp_auth_profile_update", svc, parts,
		func(in BgpAuthProfileInput) string { return in.Name }, overlayBgpAuthProfile, bgpAuthProfileSummary,
		withSecrets(bgpAuthProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_auth_profile_delete",
		Description: "Delete an advanced-routing BGP authentication profile from the candidate config. Fails while a BGP peer group or peer still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete BGP auth profile"),
	}, netDeleteHandler(d, "panos_bgp_auth_profile_delete", svc, parts))
}

// --- BGP route-flap dampening profile (routing-profile/bgp/dampening) --------

func newBgpDampeningProfileService(d *Deps) nameFixAdapter[dampening.Location, dampening.Entry] {
	return nameFixAdapter[dampening.Location, dampening.Entry]{
		svc:    dampening.NewService(d.Client),
		client: d.Client,
		name:   func(e *dampening.Entry) string { return e.Name },
	}
}

func bgpDampeningProfileParts() netScopeParts[dampening.Location] {
	return netScopeParts[dampening.Location]{
		ngfw: func() dampening.Location {
			return dampening.Location{Ngfw: &dampening.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) dampening.Location {
			return dampening.Location{Template: &dampening.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) dampening.Location {
			return dampening.Location{TemplateStack: &dampening.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// BgpDampeningProfileInput is the input for the BGP dampening profile create and
// update tools.
type BgpDampeningProfileInput struct {
	NetScopeInput
	Name             string  `json:"name" jsonschema:"BGP dampening profile name"`
	Description      *string `json:"description,omitzero" jsonschema:"Free-text description"`
	HalfLife         *int64  `json:"half_life,omitzero" jsonschema:"Half-life in minutes for the penalty to decay by half"`
	MaxSuppressLimit *int64  `json:"max_suppress_limit,omitzero" jsonschema:"Maximum time in minutes a route can stay suppressed"`
	ReuseLimit       *int64  `json:"reuse_limit,omitzero" jsonschema:"Penalty below which a suppressed route is reused"`
	SuppressLimit    *int64  `json:"suppress_limit,omitzero" jsonschema:"Penalty above which a route is suppressed"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyBgpDampeningProfile(e *dampening.Entry, in BgpDampeningProfileInput) {
	setPtr(&e.Description, in.Description)
	setPtr(&e.HalfLife, in.HalfLife)
	setPtr(&e.MaxSuppressLimit, in.MaxSuppressLimit)
	setPtr(&e.ReuseLimit, in.ReuseLimit)
	setPtr(&e.SuppressLimit, in.SuppressLimit)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildBgpDampeningProfile(in BgpDampeningProfileInput) (*dampening.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &dampening.Entry{Name: in.Name}
	applyBgpDampeningProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayBgpDampeningProfile(e *dampening.Entry, in BgpDampeningProfileInput) error {
	applyBgpDampeningProfile(e, in)
	return nil
}

func bgpDampeningProfileSummary(e *dampening.Entry) any {
	m := map[string]any{tagNameKey: e.Name, "description": strVal(e.Description)}
	putInt(m, "half_life", e.HalfLife)
	putInt(m, "max_suppress_limit", e.MaxSuppressLimit)
	putInt(m, "reuse_limit", e.ReuseLimit)
	putInt(m, "suppress_limit", e.SuppressLimit)
	return m
}

// RegisterBgpDampeningProfileTools registers the BGP dampening profile tools on
// both firewall and Panorama.
func RegisterBgpDampeningProfileTools(s *mcp.Server, d *Deps) {
	svc := newBgpDampeningProfileService(d)
	parts := bgpDampeningProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_dampening_profile_list",
		Description: "List advanced-routing BGP route-flap dampening profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List BGP dampening profiles"),
	}, netListHandler(d, "panos_bgp_dampening_profile_list", svc, parts, svc.name, bgpDampeningProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_dampening_profile_get",
		Description: "Get one advanced-routing BGP dampening profile (half-life and the suppress/reuse limits). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get BGP dampening profile"),
	}, netGetHandler(d, "panos_bgp_dampening_profile_get", svc, parts, bgpDampeningProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_dampening_profile_create",
		Description: "Create an advanced-routing BGP dampening profile in the candidate config. Only name is required; each limit defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create BGP dampening profile"),
	}, netCreateHandler(d, "panos_bgp_dampening_profile_create", svc, parts, buildBgpDampeningProfile, bgpDampeningProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_dampening_profile_update",
		Description: "Update an advanced-routing BGP dampening profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update BGP dampening profile"),
	}, netUpdateHandler(d, "panos_bgp_dampening_profile_update", svc, parts,
		func(in BgpDampeningProfileInput) string { return in.Name }, overlayBgpDampeningProfile, bgpDampeningProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_dampening_profile_delete",
		Description: "Delete an advanced-routing BGP dampening profile from the candidate config. Fails while a BGP peer group still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete BGP dampening profile"),
	}, netDeleteHandler(d, "panos_bgp_dampening_profile_delete", svc, parts))
}

// --- BGP timer profile (routing-profile/bgp/timer) --------------------------

func newBgpTimerProfileService(d *Deps) nameFixAdapter[bgptimer.Location, bgptimer.Entry] {
	return nameFixAdapter[bgptimer.Location, bgptimer.Entry]{
		svc:    bgptimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *bgptimer.Entry) string { return e.Name },
	}
}

func bgpTimerProfileParts() netScopeParts[bgptimer.Location] {
	return netScopeParts[bgptimer.Location]{
		ngfw: func() bgptimer.Location {
			return bgptimer.Location{Ngfw: &bgptimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) bgptimer.Location {
			return bgptimer.Location{Template: &bgptimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) bgptimer.Location {
			return bgptimer.Location{TemplateStack: &bgptimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// BgpTimerProfileInput is the input for the BGP timer profile create and update
// tools. HoldTime and KeepAliveInterval are seconds carried as strings by
// pango, matching the device model.
type BgpTimerProfileInput struct {
	NetScopeInput
	Name                   string  `json:"name" jsonschema:"BGP timer profile name"`
	HoldTime               *string `json:"hold_time,omitzero" jsonschema:"Hold time in seconds"`
	KeepAliveInterval      *string `json:"keep_alive_interval,omitzero" jsonschema:"Keep-alive interval in seconds"`
	MinRouteAdvInterval    *int64  `json:"min_route_adv_interval,omitzero" jsonschema:"Minimum route advertisement interval in seconds"`
	OpenDelayTime          *int64  `json:"open_delay_time,omitzero" jsonschema:"Open delay time in seconds"`
	ReconnectRetryInterval *int64  `json:"reconnect_retry_interval,omitzero" jsonschema:"Reconnect retry interval in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyBgpTimerProfile(e *bgptimer.Entry, in BgpTimerProfileInput) {
	setPtr(&e.HoldTime, in.HoldTime)
	setPtr(&e.KeepAliveInterval, in.KeepAliveInterval)
	setPtr(&e.MinRouteAdvInterval, in.MinRouteAdvInterval)
	setPtr(&e.OpenDelayTime, in.OpenDelayTime)
	setPtr(&e.ReconnectRetryInterval, in.ReconnectRetryInterval)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildBgpTimerProfile(in BgpTimerProfileInput) (*bgptimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &bgptimer.Entry{Name: in.Name}
	applyBgpTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayBgpTimerProfile(e *bgptimer.Entry, in BgpTimerProfileInput) error {
	applyBgpTimerProfile(e, in)
	return nil
}

func bgpTimerProfileSummary(e *bgptimer.Entry) any {
	m := map[string]any{
		tagNameKey:            e.Name,
		"hold_time":           strVal(e.HoldTime),
		"keep_alive_interval": strVal(e.KeepAliveInterval),
	}
	putInt(m, "min_route_adv_interval", e.MinRouteAdvInterval)
	putInt(m, "open_delay_time", e.OpenDelayTime)
	putInt(m, "reconnect_retry_interval", e.ReconnectRetryInterval)
	return m
}

// RegisterBgpTimerProfileTools registers the BGP timer profile tools on both
// firewall and Panorama.
func RegisterBgpTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newBgpTimerProfileService(d)
	parts := bgpTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_timer_profile_list",
		Description: "List advanced-routing BGP timer profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List BGP timer profiles"),
	}, netListHandler(d, "panos_bgp_timer_profile_list", svc, parts, svc.name, bgpTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_timer_profile_get",
		Description: "Get one advanced-routing BGP timer profile (hold, keep-alive and the advertisement/retry intervals). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get BGP timer profile"),
	}, netGetHandler(d, "panos_bgp_timer_profile_get", svc, parts, bgpTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_timer_profile_create",
		Description: "Create an advanced-routing BGP timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create BGP timer profile"),
	}, netCreateHandler(d, "panos_bgp_timer_profile_create", svc, parts, buildBgpTimerProfile, bgpTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_timer_profile_update",
		Description: "Update an advanced-routing BGP timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update BGP timer profile"),
	}, netUpdateHandler(d, "panos_bgp_timer_profile_update", svc, parts,
		func(in BgpTimerProfileInput) string { return in.Name }, overlayBgpTimerProfile, bgpTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_bgp_timer_profile_delete",
		Description: "Delete an advanced-routing BGP timer profile from the candidate config. Fails while a BGP peer group still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete BGP timer profile"),
	}, netDeleteHandler(d, "panos_bgp_timer_profile_delete", svc, parts))
}

// --- OSPF authentication profile (routing-profile/ospf/authprofile) ---------

func newOspfAuthProfileService(d *Deps) nameFixAdapter[ospfauth.Location, ospfauth.Entry] {
	return nameFixAdapter[ospfauth.Location, ospfauth.Entry]{
		svc:    ospfauth.NewService(d.Client),
		client: d.Client,
		name:   func(e *ospfauth.Entry) string { return e.Name },
	}
}

func ospfAuthProfileParts() netScopeParts[ospfauth.Location] {
	return netScopeParts[ospfauth.Location]{
		ngfw: func() ospfauth.Location {
			return ospfauth.Location{Ngfw: &ospfauth.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ospfauth.Location {
			return ospfauth.Location{Template: &ospfauth.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ospfauth.Location {
			return ospfauth.Location{TemplateStack: &ospfauth.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// OspfMd5KeyInput is one MD5 key of an OSPF authentication profile. Key is the
// write-only key material; preferred marks the key used to sign outgoing
// packets.
type OspfMd5KeyInput struct {
	KeyID     string  `json:"key_id" jsonschema:"MD5 key ID (1-255)"`
	Key       *string `json:"key,omitzero" jsonschema:"MD5 key material (write-only; never returned on read)"`
	Preferred *bool   `json:"preferred,omitzero" jsonschema:"Use this key to sign outgoing packets"`
}

// OspfAuthProfileInput is the input for the OSPF authentication profile create
// and update tools. An OSPF profile uses either a simple password or a set of
// MD5 keys; provide whichever the neighbors expect. Both password and every MD5
// key are write-only.
type OspfAuthProfileInput struct {
	NetScopeInput
	Name     string            `json:"name" jsonschema:"OSPF authentication profile name"`
	Password *string           `json:"password,omitzero" jsonschema:"Simple text password (write-only; never returned on read)"`
	Md5Keys  []OspfMd5KeyInput `json:"md5_keys,omitempty" jsonschema:"MD5 keys; when provided, replaces the full key set"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyOspfAuthProfile(e *ospfauth.Entry, in OspfAuthProfileInput) error {
	setPtr(&e.Password, in.Password)
	// A provided md5_keys list replaces the key set entirely, matching how the
	// generic update contract treats provided arrays. An omitted list leaves the
	// existing keys untouched.
	if in.Md5Keys == nil {
		return nil
	}
	keys := make([]ospfauth.Md5, 0, len(in.Md5Keys))
	for _, k := range in.Md5Keys {
		if k.KeyID == "" {
			return errors.New("each md5_keys entry requires key_id")
		}
		m := ospfauth.Md5{Name: k.KeyID}
		setPtr(&m.Key, k.Key)
		setPtr(&m.Preferred, k.Preferred)
		keys = append(keys, m)
	}
	e.Md5 = keys
	return nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildOspfAuthProfile(in OspfAuthProfileInput) (*ospfauth.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ospfauth.Entry{Name: in.Name}
	if err := applyOspfAuthProfile(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayOspfAuthProfile(e *ospfauth.Entry, in OspfAuthProfileInput) error {
	return applyOspfAuthProfile(e, in)
}

// ospfAuthProfileSummary reports the key IDs and which is preferred but never
// the key material or password: both are write-only and masked on read.
func ospfAuthProfileSummary(e *ospfauth.Entry) any {
	keys := make([]any, 0, len(e.Md5))
	for i := range e.Md5 {
		km := map[string]any{"key_id": e.Md5[i].Name}
		putBool(km, "preferred", e.Md5[i].Preferred)
		keys = append(keys, km)
	}
	return map[string]any{
		tagNameKey:     e.Name,
		hasPasswordKey: e.Password != nil,
		"md5_keys":     keys,
	}
}

// RegisterOspfAuthProfileTools registers the OSPF authentication profile tools
// on both firewall and Panorama.
func RegisterOspfAuthProfileTools(s *mcp.Server, d *Deps) {
	svc := newOspfAuthProfileService(d)
	parts := ospfAuthProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_auth_profile_list",
		Description: "List advanced-routing OSPF authentication profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Passwords and MD5 keys are never returned. Read-only.",
		Annotations: readOnlyTool("List OSPF auth profiles"),
	}, netListHandler(d, "panos_ospf_auth_profile_list", svc, parts, svc.name, ospfAuthProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_auth_profile_get",
		Description: "Get one advanced-routing OSPF authentication profile. Passwords and MD5 key material are write-only and never returned; the result lists the MD5 key IDs and reports whether a password is set. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get OSPF auth profile"),
	}, netGetHandler(d, "panos_ospf_auth_profile_get", svc, parts, ospfAuthProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_auth_profile_create",
		Description: "Create an advanced-routing OSPF authentication profile in the candidate config. Use either password or md5_keys, matching the neighbors. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create OSPF auth profile"),
	}, netCreateHandler(d, "panos_ospf_auth_profile_create", svc, parts, buildOspfAuthProfile, ospfAuthProfileSummary,
		withSecrets(ospfAuthProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_auth_profile_update",
		Description: "Update an advanced-routing OSPF authentication profile: read-modify-write, only provided fields change. A provided md5_keys list replaces the whole key set. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update OSPF auth profile"),
	}, netUpdateHandler(d, "panos_ospf_auth_profile_update", svc, parts,
		func(in OspfAuthProfileInput) string { return in.Name }, overlayOspfAuthProfile, ospfAuthProfileSummary,
		withSecrets(ospfAuthProfileSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_auth_profile_delete",
		Description: "Delete an advanced-routing OSPF authentication profile from the candidate config. Fails while an OSPF area or interface still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete OSPF auth profile"),
	}, netDeleteHandler(d, "panos_ospf_auth_profile_delete", svc, parts))
}

// --- OSPF interface timer profile (routing-profile/ospf/interfacetimer) ------

func newOspfInterfaceTimerProfileService(d *Deps) nameFixAdapter[ospfiftimer.Location, ospfiftimer.Entry] {
	return nameFixAdapter[ospfiftimer.Location, ospfiftimer.Entry]{
		svc:    ospfiftimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *ospfiftimer.Entry) string { return e.Name },
	}
}

func ospfInterfaceTimerProfileParts() netScopeParts[ospfiftimer.Location] {
	return netScopeParts[ospfiftimer.Location]{
		ngfw: func() ospfiftimer.Location {
			return ospfiftimer.Location{Ngfw: &ospfiftimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ospfiftimer.Location {
			return ospfiftimer.Location{Template: &ospfiftimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ospfiftimer.Location {
			return ospfiftimer.Location{TemplateStack: &ospfiftimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// OspfInterfaceTimerProfileInput is the input for the OSPF interface timer
// profile create and update tools.
type OspfInterfaceTimerProfileInput struct {
	NetScopeInput
	Name               string `json:"name" jsonschema:"OSPF interface timer profile name"`
	HelloInterval      *int64 `json:"hello_interval,omitzero" jsonschema:"Hello interval in seconds"`
	DeadCounts         *int64 `json:"dead_counts,omitzero" jsonschema:"Dead-interval as a multiple of the hello interval"`
	RetransmitInterval *int64 `json:"retransmit_interval,omitzero" jsonschema:"LSA retransmit interval in seconds"`
	TransitDelay       *int64 `json:"transit_delay,omitzero" jsonschema:"Estimated LSA transit delay in seconds"`
	GrDelay            *int64 `json:"gr_delay,omitzero" jsonschema:"Graceful-restart hello delay in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyOspfInterfaceTimerProfile(e *ospfiftimer.Entry, in OspfInterfaceTimerProfileInput) {
	setPtr(&e.HelloInterval, in.HelloInterval)
	setPtr(&e.DeadCounts, in.DeadCounts)
	setPtr(&e.RetransmitInterval, in.RetransmitInterval)
	setPtr(&e.TransitDelay, in.TransitDelay)
	setPtr(&e.GrDelay, in.GrDelay)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildOspfInterfaceTimerProfile(in OspfInterfaceTimerProfileInput) (*ospfiftimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ospfiftimer.Entry{Name: in.Name}
	applyOspfInterfaceTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayOspfInterfaceTimerProfile(e *ospfiftimer.Entry, in OspfInterfaceTimerProfileInput) error {
	applyOspfInterfaceTimerProfile(e, in)
	return nil
}

func ospfInterfaceTimerProfileSummary(e *ospfiftimer.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "hello_interval", e.HelloInterval)
	putInt(m, "dead_counts", e.DeadCounts)
	putInt(m, "retransmit_interval", e.RetransmitInterval)
	putInt(m, "transit_delay", e.TransitDelay)
	putInt(m, "gr_delay", e.GrDelay)
	return m
}

// RegisterOspfInterfaceTimerProfileTools registers the OSPF interface timer
// profile tools on both firewall and Panorama.
func RegisterOspfInterfaceTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newOspfInterfaceTimerProfileService(d)
	parts := ospfInterfaceTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_interface_timer_profile_list",
		Description: "List advanced-routing OSPF interface timer profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List OSPF interface timer profiles"),
	}, netListHandler(d, "panos_ospf_interface_timer_profile_list", svc, parts, svc.name, ospfInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_interface_timer_profile_get",
		Description: "Get one advanced-routing OSPF interface timer profile (hello, dead, retransmit and transit timers). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get OSPF interface timer profile"),
	}, netGetHandler(d, "panos_ospf_interface_timer_profile_get", svc, parts, ospfInterfaceTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_interface_timer_profile_create",
		Description: "Create an advanced-routing OSPF interface timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create OSPF interface timer profile"),
	}, netCreateHandler(d, "panos_ospf_interface_timer_profile_create", svc, parts, buildOspfInterfaceTimerProfile, ospfInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_interface_timer_profile_update",
		Description: "Update an advanced-routing OSPF interface timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update OSPF interface timer profile"),
	}, netUpdateHandler(d, "panos_ospf_interface_timer_profile_update", svc, parts,
		func(in OspfInterfaceTimerProfileInput) string { return in.Name }, overlayOspfInterfaceTimerProfile, ospfInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_interface_timer_profile_delete",
		Description: "Delete an advanced-routing OSPF interface timer profile from the candidate config. Fails while an OSPF interface still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete OSPF interface timer profile"),
	}, netDeleteHandler(d, "panos_ospf_interface_timer_profile_delete", svc, parts))
}

// --- OSPF SPF timer profile (routing-profile/ospf/spf/timer) ----------------

func newOspfSpfTimerProfileService(d *Deps) nameFixAdapter[ospfspftimer.Location, ospfspftimer.Entry] {
	return nameFixAdapter[ospfspftimer.Location, ospfspftimer.Entry]{
		svc:    ospfspftimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *ospfspftimer.Entry) string { return e.Name },
	}
}

func ospfSpfTimerProfileParts() netScopeParts[ospfspftimer.Location] {
	return netScopeParts[ospfspftimer.Location]{
		ngfw: func() ospfspftimer.Location {
			return ospfspftimer.Location{Ngfw: &ospfspftimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ospfspftimer.Location {
			return ospfspftimer.Location{Template: &ospfspftimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ospfspftimer.Location {
			return ospfspftimer.Location{TemplateStack: &ospfspftimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// OspfSpfTimerProfileInput is the input for the OSPF SPF timer profile create
// and update tools.
type OspfSpfTimerProfileInput struct {
	NetScopeInput
	Name                string `json:"name" jsonschema:"OSPF SPF timer profile name"`
	SpfCalculationDelay *int64 `json:"spf_calculation_delay,omitzero" jsonschema:"Delay in seconds before an SPF recalculation"`
	LsaInterval         *int64 `json:"lsa_interval,omitzero" jsonschema:"Minimum interval in seconds between originating an LSA"`
	InitialHoldTime     *int64 `json:"initial_hold_time,omitzero" jsonschema:"Initial SPF hold time in seconds"`
	MaxHoldTime         *int64 `json:"max_hold_time,omitzero" jsonschema:"Maximum SPF hold time in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyOspfSpfTimerProfile(e *ospfspftimer.Entry, in OspfSpfTimerProfileInput) {
	setPtr(&e.SpfCalculationDelay, in.SpfCalculationDelay)
	setPtr(&e.LsaInterval, in.LsaInterval)
	setPtr(&e.InitialHoldTime, in.InitialHoldTime)
	setPtr(&e.MaxHoldTime, in.MaxHoldTime)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildOspfSpfTimerProfile(in OspfSpfTimerProfileInput) (*ospfspftimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ospfspftimer.Entry{Name: in.Name}
	applyOspfSpfTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayOspfSpfTimerProfile(e *ospfspftimer.Entry, in OspfSpfTimerProfileInput) error {
	applyOspfSpfTimerProfile(e, in)
	return nil
}

func ospfSpfTimerProfileSummary(e *ospfspftimer.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "spf_calculation_delay", e.SpfCalculationDelay)
	putInt(m, "lsa_interval", e.LsaInterval)
	putInt(m, "initial_hold_time", e.InitialHoldTime)
	putInt(m, "max_hold_time", e.MaxHoldTime)
	return m
}

// RegisterOspfSpfTimerProfileTools registers the OSPF SPF timer profile tools on
// both firewall and Panorama.
func RegisterOspfSpfTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newOspfSpfTimerProfileService(d)
	parts := ospfSpfTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_spf_timer_profile_list",
		Description: "List advanced-routing OSPF SPF timer profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List OSPF SPF timer profiles"),
	}, netListHandler(d, "panos_ospf_spf_timer_profile_list", svc, parts, svc.name, ospfSpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_spf_timer_profile_get",
		Description: "Get one advanced-routing OSPF SPF timer profile (SPF calculation delay, LSA interval and hold times). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get OSPF SPF timer profile"),
	}, netGetHandler(d, "panos_ospf_spf_timer_profile_get", svc, parts, ospfSpfTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_spf_timer_profile_create",
		Description: "Create an advanced-routing OSPF SPF timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create OSPF SPF timer profile"),
	}, netCreateHandler(d, "panos_ospf_spf_timer_profile_create", svc, parts, buildOspfSpfTimerProfile, ospfSpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_spf_timer_profile_update",
		Description: "Update an advanced-routing OSPF SPF timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update OSPF SPF timer profile"),
	}, netUpdateHandler(d, "panos_ospf_spf_timer_profile_update", svc, parts,
		func(in OspfSpfTimerProfileInput) string { return in.Name }, overlayOspfSpfTimerProfile, ospfSpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospf_spf_timer_profile_delete",
		Description: "Delete an advanced-routing OSPF SPF timer profile from the candidate config. Fails while an OSPF instance still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete OSPF SPF timer profile"),
	}, netDeleteHandler(d, "panos_ospf_spf_timer_profile_delete", svc, parts))
}

// --- OSPFv3 interface timer profile (routing-profile/ospfv3/iftimer) --------

func newOspfv3InterfaceTimerProfileService(d *Deps) nameFixAdapter[ospfv3iftimer.Location, ospfv3iftimer.Entry] {
	return nameFixAdapter[ospfv3iftimer.Location, ospfv3iftimer.Entry]{
		svc:    ospfv3iftimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *ospfv3iftimer.Entry) string { return e.Name },
	}
}

func ospfv3InterfaceTimerProfileParts() netScopeParts[ospfv3iftimer.Location] {
	return netScopeParts[ospfv3iftimer.Location]{
		ngfw: func() ospfv3iftimer.Location {
			return ospfv3iftimer.Location{Ngfw: &ospfv3iftimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ospfv3iftimer.Location {
			return ospfv3iftimer.Location{Template: &ospfv3iftimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ospfv3iftimer.Location {
			return ospfv3iftimer.Location{TemplateStack: &ospfv3iftimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// Ospfv3InterfaceTimerProfileInput is the input for the OSPFv3 interface timer
// profile create and update tools.
type Ospfv3InterfaceTimerProfileInput struct {
	NetScopeInput
	Name               string `json:"name" jsonschema:"OSPFv3 interface timer profile name"`
	HelloInterval      *int64 `json:"hello_interval,omitzero" jsonschema:"Hello interval in seconds"`
	DeadCounts         *int64 `json:"dead_counts,omitzero" jsonschema:"Dead-interval as a multiple of the hello interval"`
	RetransmitInterval *int64 `json:"retransmit_interval,omitzero" jsonschema:"LSA retransmit interval in seconds"`
	TransitDelay       *int64 `json:"transit_delay,omitzero" jsonschema:"Estimated LSA transit delay in seconds"`
	GrDelay            *int64 `json:"gr_delay,omitzero" jsonschema:"Graceful-restart hello delay in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyOspfv3InterfaceTimerProfile(e *ospfv3iftimer.Entry, in Ospfv3InterfaceTimerProfileInput) {
	setPtr(&e.HelloInterval, in.HelloInterval)
	setPtr(&e.DeadCounts, in.DeadCounts)
	setPtr(&e.RetransmitInterval, in.RetransmitInterval)
	setPtr(&e.TransitDelay, in.TransitDelay)
	setPtr(&e.GrDelay, in.GrDelay)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildOspfv3InterfaceTimerProfile(in Ospfv3InterfaceTimerProfileInput) (*ospfv3iftimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ospfv3iftimer.Entry{Name: in.Name}
	applyOspfv3InterfaceTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayOspfv3InterfaceTimerProfile(e *ospfv3iftimer.Entry, in Ospfv3InterfaceTimerProfileInput) error {
	applyOspfv3InterfaceTimerProfile(e, in)
	return nil
}

func ospfv3InterfaceTimerProfileSummary(e *ospfv3iftimer.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "hello_interval", e.HelloInterval)
	putInt(m, "dead_counts", e.DeadCounts)
	putInt(m, "retransmit_interval", e.RetransmitInterval)
	putInt(m, "transit_delay", e.TransitDelay)
	putInt(m, "gr_delay", e.GrDelay)
	return m
}

// RegisterOspfv3InterfaceTimerProfileTools registers the OSPFv3 interface timer
// profile tools on both firewall and Panorama.
func RegisterOspfv3InterfaceTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newOspfv3InterfaceTimerProfileService(d)
	parts := ospfv3InterfaceTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_interface_timer_profile_list",
		Description: "List advanced-routing OSPFv3 interface timer profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List OSPFv3 interface timer profiles"),
	}, netListHandler(d, "panos_ospfv3_interface_timer_profile_list", svc, parts, svc.name, ospfv3InterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_interface_timer_profile_get",
		Description: "Get one advanced-routing OSPFv3 interface timer profile (hello, dead, retransmit and transit timers). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get OSPFv3 interface timer profile"),
	}, netGetHandler(d, "panos_ospfv3_interface_timer_profile_get", svc, parts, ospfv3InterfaceTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_interface_timer_profile_create",
		Description: "Create an advanced-routing OSPFv3 interface timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create OSPFv3 interface timer profile"),
	}, netCreateHandler(d, "panos_ospfv3_interface_timer_profile_create", svc, parts, buildOspfv3InterfaceTimerProfile, ospfv3InterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_interface_timer_profile_update",
		Description: "Update an advanced-routing OSPFv3 interface timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update OSPFv3 interface timer profile"),
	}, netUpdateHandler(d, "panos_ospfv3_interface_timer_profile_update", svc, parts,
		func(in Ospfv3InterfaceTimerProfileInput) string { return in.Name }, overlayOspfv3InterfaceTimerProfile, ospfv3InterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_interface_timer_profile_delete",
		Description: "Delete an advanced-routing OSPFv3 interface timer profile from the candidate config. Fails while an OSPFv3 interface still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete OSPFv3 interface timer profile"),
	}, netDeleteHandler(d, "panos_ospfv3_interface_timer_profile_delete", svc, parts))
}

// --- OSPFv3 SPF timer profile (routing-profile/ospfv3/spf/timer) ------------

func newOspfv3SpfTimerProfileService(d *Deps) nameFixAdapter[ospfv3spftimer.Location, ospfv3spftimer.Entry] {
	return nameFixAdapter[ospfv3spftimer.Location, ospfv3spftimer.Entry]{
		svc:    ospfv3spftimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *ospfv3spftimer.Entry) string { return e.Name },
	}
}

func ospfv3SpfTimerProfileParts() netScopeParts[ospfv3spftimer.Location] {
	return netScopeParts[ospfv3spftimer.Location]{
		ngfw: func() ospfv3spftimer.Location {
			return ospfv3spftimer.Location{Ngfw: &ospfv3spftimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ospfv3spftimer.Location {
			return ospfv3spftimer.Location{Template: &ospfv3spftimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ospfv3spftimer.Location {
			return ospfv3spftimer.Location{TemplateStack: &ospfv3spftimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// Ospfv3SpfTimerProfileInput is the input for the OSPFv3 SPF timer profile
// create and update tools.
type Ospfv3SpfTimerProfileInput struct {
	NetScopeInput
	Name                string `json:"name" jsonschema:"OSPFv3 SPF timer profile name"`
	SpfCalculationDelay *int64 `json:"spf_calculation_delay,omitzero" jsonschema:"Delay in seconds before an SPF recalculation"`
	LsaInterval         *int64 `json:"lsa_interval,omitzero" jsonschema:"Minimum interval in seconds between originating an LSA"`
	InitialHoldTime     *int64 `json:"initial_hold_time,omitzero" jsonschema:"Initial SPF hold time in seconds"`
	MaxHoldTime         *int64 `json:"max_hold_time,omitzero" jsonschema:"Maximum SPF hold time in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyOspfv3SpfTimerProfile(e *ospfv3spftimer.Entry, in Ospfv3SpfTimerProfileInput) {
	setPtr(&e.SpfCalculationDelay, in.SpfCalculationDelay)
	setPtr(&e.LsaInterval, in.LsaInterval)
	setPtr(&e.InitialHoldTime, in.InitialHoldTime)
	setPtr(&e.MaxHoldTime, in.MaxHoldTime)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildOspfv3SpfTimerProfile(in Ospfv3SpfTimerProfileInput) (*ospfv3spftimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ospfv3spftimer.Entry{Name: in.Name}
	applyOspfv3SpfTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayOspfv3SpfTimerProfile(e *ospfv3spftimer.Entry, in Ospfv3SpfTimerProfileInput) error {
	applyOspfv3SpfTimerProfile(e, in)
	return nil
}

func ospfv3SpfTimerProfileSummary(e *ospfv3spftimer.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "spf_calculation_delay", e.SpfCalculationDelay)
	putInt(m, "lsa_interval", e.LsaInterval)
	putInt(m, "initial_hold_time", e.InitialHoldTime)
	putInt(m, "max_hold_time", e.MaxHoldTime)
	return m
}

// RegisterOspfv3SpfTimerProfileTools registers the OSPFv3 SPF timer profile
// tools on both firewall and Panorama.
func RegisterOspfv3SpfTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newOspfv3SpfTimerProfileService(d)
	parts := ospfv3SpfTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_spf_timer_profile_list",
		Description: "List advanced-routing OSPFv3 SPF timer profiles. Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List OSPFv3 SPF timer profiles"),
	}, netListHandler(d, "panos_ospfv3_spf_timer_profile_list", svc, parts, svc.name, ospfv3SpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_spf_timer_profile_get",
		Description: "Get one advanced-routing OSPFv3 SPF timer profile (SPF calculation delay, LSA interval and hold times). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get OSPFv3 SPF timer profile"),
	}, netGetHandler(d, "panos_ospfv3_spf_timer_profile_get", svc, parts, ospfv3SpfTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_spf_timer_profile_create",
		Description: "Create an advanced-routing OSPFv3 SPF timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create OSPFv3 SPF timer profile"),
	}, netCreateHandler(d, "panos_ospfv3_spf_timer_profile_create", svc, parts, buildOspfv3SpfTimerProfile, ospfv3SpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_spf_timer_profile_update",
		Description: "Update an advanced-routing OSPFv3 SPF timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update OSPFv3 SPF timer profile"),
	}, netUpdateHandler(d, "panos_ospfv3_spf_timer_profile_update", svc, parts,
		func(in Ospfv3SpfTimerProfileInput) string { return in.Name }, overlayOspfv3SpfTimerProfile, ospfv3SpfTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ospfv3_spf_timer_profile_delete",
		Description: "Delete an advanced-routing OSPFv3 SPF timer profile from the candidate config. Fails while an OSPFv3 instance still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete OSPFv3 SPF timer profile"),
	}, netDeleteHandler(d, "panos_ospfv3_spf_timer_profile_delete", svc, parts))
}

// --- Advanced-routing BFD profile (routing-profile/bfd) ---------------------

func newRoutingBfdProfileService(d *Deps) nameFixAdapter[routingbfd.Location, routingbfd.Entry] {
	return nameFixAdapter[routingbfd.Location, routingbfd.Entry]{
		svc:    routingbfd.NewService(d.Client),
		client: d.Client,
		name:   func(e *routingbfd.Entry) string { return e.Name },
	}
}

func routingBfdProfileParts() netScopeParts[routingbfd.Location] {
	return netScopeParts[routingbfd.Location]{
		ngfw: func() routingbfd.Location {
			return routingbfd.Location{Ngfw: &routingbfd.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) routingbfd.Location {
			return routingbfd.Location{Template: &routingbfd.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) routingbfd.Location {
			return routingbfd.Location{TemplateStack: &routingbfd.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// RoutingBfdProfileInput is the input for the advanced-routing BFD profile
// create and update tools. The multihop settings are not modeled and are
// preserved across updates.
type RoutingBfdProfileInput struct {
	NetScopeInput
	Name                string  `json:"name" jsonschema:"BFD profile name"`
	Mode                *string `json:"mode,omitzero" jsonschema:"BFD mode: active or passive"`
	MinTxInterval       *int64  `json:"min_tx_interval,omitzero" jsonschema:"Desired minimum transmit interval in ms"`
	MinRxInterval       *int64  `json:"min_rx_interval,omitzero" jsonschema:"Required minimum receive interval in ms"`
	DetectionMultiplier *int64  `json:"detection_multiplier,omitzero" jsonschema:"Detection time multiplier"`
	HoldTime            *int64  `json:"hold_time,omitzero" jsonschema:"Delay in ms before transmitting BFD control packets after the link comes up"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyRoutingBfdProfile(e *routingbfd.Entry, in RoutingBfdProfileInput) {
	setPtr(&e.Mode, in.Mode)
	setPtr(&e.MinTxInterval, in.MinTxInterval)
	setPtr(&e.MinRxInterval, in.MinRxInterval)
	setPtr(&e.DetectionMultiplier, in.DetectionMultiplier)
	setPtr(&e.HoldTime, in.HoldTime)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildRoutingBfdProfile(in RoutingBfdProfileInput) (*routingbfd.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &routingbfd.Entry{Name: in.Name}
	applyRoutingBfdProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayRoutingBfdProfile(e *routingbfd.Entry, in RoutingBfdProfileInput) error {
	applyRoutingBfdProfile(e, in)
	return nil
}

func routingBfdProfileSummary(e *routingbfd.Entry) any {
	m := map[string]any{tagNameKey: e.Name, modeKey: strVal(e.Mode)}
	putInt(m, "min_tx_interval", e.MinTxInterval)
	putInt(m, "min_rx_interval", e.MinRxInterval)
	putInt(m, "detection_multiplier", e.DetectionMultiplier)
	putInt(m, "hold_time", e.HoldTime)
	return m
}

// RegisterRoutingBfdProfileTools registers the advanced-routing BFD profile
// tools on both firewall and Panorama. These are distinct from the legacy
// network/profiles/bfd tools registered as panos_bfd_profile_*.
func RegisterRoutingBfdProfileTools(s *mcp.Server, d *Deps) {
	svc := newRoutingBfdProfileService(d)
	parts := routingBfdProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_routing_bfd_profile_list",
		Description: "List advanced-routing BFD profiles (the advanced routing engine's own BFD, distinct from the legacy BFD profiles listed by panos_bfd_profile_list). Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List routing BFD profiles"),
	}, netListHandler(d, "panos_routing_bfd_profile_list", svc, parts, svc.name, routingBfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_routing_bfd_profile_get",
		Description: "Get one advanced-routing BFD profile (mode and detection timers). The optional multihop settings are not modeled and are preserved on update. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get routing BFD profile"),
	}, netGetHandler(d, "panos_routing_bfd_profile_get", svc, parts, routingBfdProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_routing_bfd_profile_create",
		Description: "Create an advanced-routing BFD profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create routing BFD profile"),
	}, netCreateHandler(d, "panos_routing_bfd_profile_create", svc, parts, buildRoutingBfdProfile, routingBfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_routing_bfd_profile_update",
		Description: "Update an advanced-routing BFD profile: read-modify-write, only provided fields change. The optional multihop settings are preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update routing BFD profile"),
	}, netUpdateHandler(d, "panos_routing_bfd_profile_update", svc, parts,
		func(in RoutingBfdProfileInput) string { return in.Name }, overlayRoutingBfdProfile, routingBfdProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_routing_bfd_profile_delete",
		Description: "Delete an advanced-routing BFD profile from the candidate config. Fails while a routing protocol or interface still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete routing BFD profile"),
	}, netDeleteHandler(d, "panos_routing_bfd_profile_delete", svc, parts))
}

// --- PIM interface timer profile (routing-profile/multicast/ipv4/piminterfacetimer) ---

func newPimInterfaceTimerProfileService(d *Deps) nameFixAdapter[pimtimer.Location, pimtimer.Entry] {
	return nameFixAdapter[pimtimer.Location, pimtimer.Entry]{
		svc:    pimtimer.NewService(d.Client),
		client: d.Client,
		name:   func(e *pimtimer.Entry) string { return e.Name },
	}
}

func pimInterfaceTimerProfileParts() netScopeParts[pimtimer.Location] {
	return netScopeParts[pimtimer.Location]{
		ngfw: func() pimtimer.Location {
			return pimtimer.Location{Ngfw: &pimtimer.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) pimtimer.Location {
			return pimtimer.Location{Template: &pimtimer.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) pimtimer.Location {
			return pimtimer.Location{TemplateStack: &pimtimer.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// PimInterfaceTimerProfileInput is the input for the PIM interface timer profile
// create and update tools (IPv4 multicast).
type PimInterfaceTimerProfileInput struct {
	NetScopeInput
	Name              string `json:"name" jsonschema:"PIM interface timer profile name"`
	HelloInterval     *int64 `json:"hello_interval,omitzero" jsonschema:"PIM hello interval in seconds"`
	AssertInterval    *int64 `json:"assert_interval,omitzero" jsonschema:"PIM assert interval in seconds"`
	JoinPruneInterval *int64 `json:"join_prune_interval,omitzero" jsonschema:"PIM join/prune interval in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder/overlay contract.
func applyPimInterfaceTimerProfile(e *pimtimer.Entry, in PimInterfaceTimerProfileInput) {
	setPtr(&e.HelloInterval, in.HelloInterval)
	setPtr(&e.AssertInterval, in.AssertInterval)
	setPtr(&e.JoinPruneInterval, in.JoinPruneInterval)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildPimInterfaceTimerProfile(in PimInterfaceTimerProfileInput) (*pimtimer.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &pimtimer.Entry{Name: in.Name}
	applyPimInterfaceTimerProfile(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayPimInterfaceTimerProfile(e *pimtimer.Entry, in PimInterfaceTimerProfileInput) error {
	applyPimInterfaceTimerProfile(e, in)
	return nil
}

func pimInterfaceTimerProfileSummary(e *pimtimer.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putInt(m, "hello_interval", e.HelloInterval)
	putInt(m, "assert_interval", e.AssertInterval)
	putInt(m, "join_prune_interval", e.JoinPruneInterval)
	return m
}

// RegisterPimInterfaceTimerProfileTools registers the PIM interface timer
// profile tools on both firewall and Panorama.
func RegisterPimInterfaceTimerProfileTools(s *mcp.Server, d *Deps) {
	svc := newPimInterfaceTimerProfileService(d)
	parts := pimInterfaceTimerProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pim_interface_timer_profile_list",
		Description: "List advanced-routing PIM interface timer profiles (IPv4 multicast). Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List PIM interface timer profiles"),
	}, netListHandler(d, "panos_pim_interface_timer_profile_list", svc, parts, svc.name, pimInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pim_interface_timer_profile_get",
		Description: "Get one advanced-routing PIM interface timer profile (hello, assert and join/prune intervals). On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get PIM interface timer profile"),
	}, netGetHandler(d, "panos_pim_interface_timer_profile_get", svc, parts, pimInterfaceTimerProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pim_interface_timer_profile_create",
		Description: "Create an advanced-routing PIM interface timer profile in the candidate config. Only name is required; each timer defaults to the device default when omitted. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create PIM interface timer profile"),
	}, netCreateHandler(d, "panos_pim_interface_timer_profile_create", svc, parts, buildPimInterfaceTimerProfile, pimInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pim_interface_timer_profile_update",
		Description: "Update an advanced-routing PIM interface timer profile: read-modify-write, only provided fields change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update PIM interface timer profile"),
	}, netUpdateHandler(d, "panos_pim_interface_timer_profile_update", svc, parts,
		func(in PimInterfaceTimerProfileInput) string { return in.Name }, overlayPimInterfaceTimerProfile, pimInterfaceTimerProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pim_interface_timer_profile_delete",
		Description: "Delete an advanced-routing PIM interface timer profile from the candidate config. Fails while a multicast interface still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete PIM interface timer profile"),
	}, netDeleteHandler(d, "panos_pim_interface_timer_profile_delete", svc, parts))
}
