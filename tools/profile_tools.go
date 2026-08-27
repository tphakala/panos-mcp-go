package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/objects/profiles/antivirus"
	"github.com/PaloAltoNetworks/pango/objects/profiles/decryption"
	"github.com/PaloAltoNetworks/pango/objects/profiles/fileblocking"
	"github.com/PaloAltoNetworks/pango/objects/profiles/logforwarding"
	"github.com/PaloAltoNetworks/pango/objects/profiles/secgroup"
	"github.com/PaloAltoNetworks/pango/objects/profiles/urlfiltering"
	"github.com/PaloAltoNetworks/pango/objects/profiles/vulnerability"
	"github.com/PaloAltoNetworks/pango/objects/profiles/wildfireanalysis"
	"github.com/PaloAltoNetworks/pango/security/profiles/spyware"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file adds CRUD tools for the security profile types and the security
// profile group. Every resource follows the object_tools.go quintet
// (parts/service/input/build/overlay/summary + Register) over the shared
// generic handlers; profiles carry no Tag field, so their summaries build on
// nameDescription rather than summaryBase.
//
// Scope note (issue #52): create/update model the practical flat field subset.
// The deeply nested per-signature subtrees that use a pango oneof action are
// deferred as SDK-only and documented per resource: vulnerability/anti-spyware
// per-threat Rules, anti-spyware BotnetDomains (DNS security), url-filtering
// credential-enforcement and http-header-insertion. list, get, create and
// update return the full managed view for every type; delete returns a
// confirmation. Enum-valued rule fields (decoder/rule
// action, direction, analysis) are passed through to PAN-OS unchanged; the
// device validates them (the exact value sets are NOT MEASURED here).

// boolVal dereferences b, mapping nil to false. Profile summaries surface the
// optional PAN-OS toggles as plain booleans.
func boolVal(b *bool) bool { return b != nil && *b }

// putBool emits key only when v is non-nil. A PAN-OS *bool is tri-state
// (present-true / present-false / absent-inherits-default); coercing absent to
// false would misreport the device default, so a summary omits the key entirely
// when the toggle is unset (issue #67).
func putBool(m map[string]any, key string, v *bool) {
	if v != nil {
		m[key] = *v
	}
}

// putInt emits key only when v is non-nil, same tri-state reasoning as putBool.
func putInt(m map[string]any, key string, v *int64) {
	if v != nil {
		m[key] = *v
	}
}

// firstMember returns the first element of a single-member list, or "". pango
// models several single-value references (a profile group's per-type profile, a
// security rule's profile group) as slices; the tools hide that quirk behind a
// scalar.
func firstMember(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// setMember sets dst to a single-member list when v is non-empty, and leaves it
// untouched otherwise (read-modify-write preserves an existing member). Clearing
// a member in place is not supported, matching the other single-value fields.
func setMember(dst *[]string, v string) {
	if v != "" {
		*dst = []string{v}
	}
}

// --- Antivirus ---------------------------------------------------------------

// antivirusParts supplies antivirus profile locations for resolveLocation.
func antivirusParts() locParts[antivirus.Location] {
	return locParts[antivirus.Location]{
		shared: func(string) antivirus.Location {
			return antivirus.Location{Shared: &antivirus.SharedLocation{}}
		},
		vsys: func(v string) antivirus.Location {
			return antivirus.Location{Vsys: &antivirus.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) antivirus.Location {
			return antivirus.Location{DeviceGroup: &antivirus.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

// newAntivirusService adapts pango's antivirus profile service to crudService
// via the shared nameFixAdapter.
func newAntivirusService(d *Deps) nameFixAdapter[antivirus.Location, antivirus.Entry] {
	return nameFixAdapter[antivirus.Location, antivirus.Entry]{
		svc:    antivirus.NewService(d.Client),
		client: d.Client,
		name:   func(e *antivirus.Entry) string { return e.Name },
	}
}

// AntivirusDecoderInput is one protocol decoder's actions in an antivirus
// profile. action values (default, allow, alert, drop, reset-*) pass through to
// PAN-OS unchanged.
type AntivirusDecoderInput struct {
	Name           string `json:"name" jsonschema:"Decoder/protocol name, e.g. http, smtp, ftp, imap, pop3"`
	Action         string `json:"action,omitempty" jsonschema:"Action on a virus verdict"`
	WildfireAction string `json:"wildfire_action,omitempty" jsonschema:"Action on a WildFire-signature verdict"`
	MlavAction     string `json:"mlav_action,omitempty" jsonschema:"Action on the inline ML antivirus engine verdict"`
}

// AntivirusProfileInput is the input for antivirus profile create and update.
// The per-decoder actions are modelled; the ML-engine, application, and
// exception subtrees are SDK-only for now.
type AntivirusProfileInput struct {
	Name          string                  `json:"name" jsonschema:"Antivirus profile name"`
	Location      LocationInput           `json:"location,omitzero"`
	Description   string                  `json:"description,omitempty"`
	PacketCapture *bool                   `json:"packet_capture,omitempty" jsonschema:"Capture packets when a threat is detected"`
	Decoders      []AntivirusDecoderInput `json:"decoders,omitempty" jsonschema:"Per-protocol decoder actions; replaces the whole decoder set when provided, an explicit empty list clears it"`
}

// buildAntivirusDecoders maps the decoder inputs onto pango decoders, requiring
// a name on each. It returns nil for an empty input so the caller can leave the
// entry's decoders untouched.
func buildAntivirusDecoders(in []AntivirusDecoderInput) ([]antivirus.Decoder, error) {
	// nil (omitted) preserves; an explicit empty list yields an empty non-nil
	// slice the overlay assigns, clearing the set on update (issue #61).
	if in == nil {
		return nil, nil
	}
	out := make([]antivirus.Decoder, 0, len(in))
	for _, dec := range in {
		if dec.Name == "" {
			return nil, errors.New("each decoder requires a name")
		}
		d := antivirus.Decoder{Name: dec.Name}
		setStrPtr(&d.Action, dec.Action)
		setStrPtr(&d.WildfireAction, dec.WildfireAction)
		setStrPtr(&d.MlavAction, dec.MlavAction)
		out = append(out, d)
	}
	return out, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildAntivirusEntry(in AntivirusProfileInput) (*antivirus.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	decoders, err := buildAntivirusDecoders(in.Decoders)
	if err != nil {
		return nil, err
	}
	e := &antivirus.Entry{Name: in.Name, PacketCapture: in.PacketCapture, Decoder: decoders}
	setStrPtr(&e.Description, in.Description)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayAntivirus(e *antivirus.Entry, in AntivirusProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	if in.PacketCapture != nil {
		e.PacketCapture = in.PacketCapture
	}
	decoders, err := buildAntivirusDecoders(in.Decoders)
	if err != nil {
		return err
	}
	if decoders != nil {
		e.Decoder = decoders
	}
	return nil
}

// antivirusDecoderSummaries reduces the pango decoders to the clean tool view.
func antivirusDecoderSummaries(decoders []antivirus.Decoder) []any {
	out := make([]any, 0, len(decoders))
	for i := range decoders {
		d := &decoders[i]
		out = append(out, map[string]any{
			tagNameKey:        d.Name,
			"action":          strVal(d.Action),
			"wildfire_action": strVal(d.WildfireAction),
			"mlav_action":     strVal(d.MlavAction),
		})
	}
	return out
}

func antivirusSummary(e *antivirus.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["packet_capture"] = boolVal(e.PacketCapture)
	m["decoders"] = antivirusDecoderSummaries(e.Decoder)
	return m
}

// RegisterAntivirusProfileTools registers the antivirus profile tools. Mutating
// tools are skipped in read-only mode.
func RegisterAntivirusProfileTools(s *mcp.Server, d *Deps) {
	svc := newAntivirusService(d)
	resolve := func(in LocationInput) (antivirus.Location, error) { return resolveLocation(d, in, antivirusParts()) }
	name := svc.name
	loc := func(in AntivirusProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_antivirus_profile_list",
		Description: "List antivirus profiles at a location. Read-only.",
		Annotations: readOnlyTool("List antivirus profiles"),
	}, listHandler[antivirus.Location, antivirus.Entry](d, "panos_antivirus_profile_list", svc, resolve, name, antivirusSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_antivirus_profile_get",
		Description: "Get one antivirus profile by name with its managed fields (description, packet_capture, decoders). Read-only.",
		Annotations: readOnlyTool("Get antivirus profile"),
	}, getHandler[antivirus.Location, antivirus.Entry](d, "panos_antivirus_profile_get", svc, resolve, antivirusSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_antivirus_profile_create",
		Description: "Create an antivirus profile in the candidate config. Run panos_commit to apply.",
		Annotations: createTool("Create antivirus profile"),
	}, createHandler[antivirus.Location, antivirus.Entry, AntivirusProfileInput](d, "panos_antivirus_profile_create", svc, resolve, loc, buildAntivirusEntry, antivirusSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_antivirus_profile_update",
		Description: "Update an antivirus profile: read-modify-write, only provided fields change; a provided decoders list replaces the whole set, and an explicit empty list clears it. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update antivirus profile"),
	}, updateHandler[antivirus.Location, antivirus.Entry, AntivirusProfileInput](d, "panos_antivirus_profile_update", svc, resolve, loc,
		func(in AntivirusProfileInput) string { return in.Name }, overlayAntivirus, antivirusSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_antivirus_profile_delete",
		Description: "Delete an antivirus profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete antivirus profile"),
	}, deleteHandler[antivirus.Location, antivirus.Entry](d, "panos_antivirus_profile_delete", svc, resolve))
}

// --- Vulnerability protection ------------------------------------------------

// vulnerabilityParts supplies vulnerability profile locations. pango generates
// no vsys location for this type; on a firewall it is managed at shared (see
// resolveLocation's nil-vsys fallback).
func vulnerabilityParts() locParts[vulnerability.Location] {
	return locParts[vulnerability.Location]{
		shared: func(string) vulnerability.Location {
			return vulnerability.Location{Shared: &vulnerability.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) vulnerability.Location {
			return vulnerability.Location{DeviceGroup: &vulnerability.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newVulnerabilityService(d *Deps) nameFixAdapter[vulnerability.Location, vulnerability.Entry] {
	return nameFixAdapter[vulnerability.Location, vulnerability.Entry]{
		svc:    vulnerability.NewService(d.Client),
		client: d.Client,
		name:   func(e *vulnerability.Entry) string { return e.Name },
	}
}

// VulnerabilityProfileInput is the input for vulnerability profile create and
// update. The per-signature Rules (a pango oneof action), ML-engine, and
// threat-exception subtrees are SDK-only for now; the practical top-level
// inline-inspection controls are modelled.
type VulnerabilityProfileInput struct {
	Name                       string        `json:"name" jsonschema:"Vulnerability protection profile name"`
	Location                   LocationInput `json:"location,omitzero"`
	Description                string        `json:"description,omitempty"`
	CloudInlineAnalysis        *bool         `json:"cloud_inline_analysis,omitempty" jsonschema:"Enable cloud inline analysis"`
	InlineExceptionEdlURLs     []string      `json:"inline_exception_edl_urls,omitempty" jsonschema:"EDL URL inline-detection exceptions; replaces fully when provided, an explicit empty list clears it"`
	InlineExceptionIPAddresses []string      `json:"inline_exception_ip_addresses,omitempty" jsonschema:"Inline-detection IP exceptions: each entry is the name of an ip-type external dynamic list (see panos_edl_create), not an IP literal or address object; replaces fully when provided, an explicit empty list clears it"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildVulnerabilityEntry(in VulnerabilityProfileInput) (*vulnerability.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &vulnerability.Entry{Name: in.Name}
	setStrPtr(&e.Description, in.Description)
	applyVulnerabilityInline(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayVulnerability(e *vulnerability.Entry, in VulnerabilityProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	applyVulnerabilityInline(e, &in)
	return nil
}

// applyVulnerabilityInline applies the inline-detection fields that
// buildVulnerabilityEntry and overlayVulnerability both set: cloud_inline_analysis
// and the two inline_exception lists. Each nil (omitted) value is left unchanged;
// an explicit empty list clears that exception set (issue #61). in is by pointer
// to avoid copying the large input.
//
// Each inline_exception_ip_addresses entry is the NAME of an ip-type external
// dynamic list, not an IP literal or address object: the device rejects any other
// value as "not a valid reference". MEASURED live: the vulnerability profile on a
// PA-VM (#66/#70), and the anti-spyware profile (applySpywareInline) on Panorama
// 11.1.16-h1 (#72), which rejects an IP literal at set time (code 12).
func applyVulnerabilityInline(e *vulnerability.Entry, in *VulnerabilityProfileInput) {
	if in.CloudInlineAnalysis != nil {
		e.CloudInlineAnalysis = in.CloudInlineAnalysis
	}
	if in.InlineExceptionEdlURLs != nil {
		e.InlineExceptionEdlUrl = in.InlineExceptionEdlURLs
	}
	if in.InlineExceptionIPAddresses != nil {
		e.InlineExceptionIpAddress = in.InlineExceptionIPAddresses
	}
}

func vulnerabilitySummary(e *vulnerability.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["cloud_inline_analysis"] = boolVal(e.CloudInlineAnalysis)
	m["inline_exception_edl_urls"] = e.InlineExceptionEdlUrl
	m["inline_exception_ip_addresses"] = e.InlineExceptionIpAddress
	return m
}

// RegisterVulnerabilityProfileTools registers the vulnerability profile tools.
func RegisterVulnerabilityProfileTools(s *mcp.Server, d *Deps) {
	svc := newVulnerabilityService(d)
	resolve := func(in LocationInput) (vulnerability.Location, error) {
		return resolveLocation(d, in, vulnerabilityParts())
	}
	name := svc.name
	loc := func(in VulnerabilityProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vulnerability_profile_list",
		Description: "List vulnerability protection profiles at a location. On a firewall this profile type is managed at shared (pango exposes no vsys location for it). Read-only.",
		Annotations: readOnlyTool("List vulnerability profiles"),
	}, listHandler[vulnerability.Location, vulnerability.Entry](d, "panos_vulnerability_profile_list", svc, resolve, name, vulnerabilitySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vulnerability_profile_get",
		Description: "Get one vulnerability protection profile by name with its managed fields. Per-signature rules are not exposed. Read-only.",
		Annotations: readOnlyTool("Get vulnerability profile"),
	}, getHandler[vulnerability.Location, vulnerability.Entry](d, "panos_vulnerability_profile_get", svc, resolve, vulnerabilitySummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vulnerability_profile_create",
		Description: "Create a vulnerability protection profile in the candidate config. Per-signature rules are SDK-only and not set here, so a profile created with this tool carries no per-signature rules of its own; it models the top-level inline-inspection controls. inline_exception_ip_addresses entries are names of ip-type EDLs (see panos_edl_create), not IP literals or address objects. On a firewall it is created at shared. Run panos_commit to apply.",
		Annotations: createTool("Create vulnerability profile"),
	}, createHandler[vulnerability.Location, vulnerability.Entry, VulnerabilityProfileInput](d, "panos_vulnerability_profile_create", svc, resolve, loc, buildVulnerabilityEntry, vulnerabilitySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vulnerability_profile_update",
		Description: "Update a vulnerability protection profile: read-modify-write, only provided fields change. inline_exception_ip_addresses entries are names of ip-type EDLs (see panos_edl_create), not IP literals or address objects. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update vulnerability profile"),
	}, updateHandler[vulnerability.Location, vulnerability.Entry, VulnerabilityProfileInput](d, "panos_vulnerability_profile_update", svc, resolve, loc,
		func(in VulnerabilityProfileInput) string { return in.Name }, overlayVulnerability, vulnerabilitySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_vulnerability_profile_delete",
		Description: "Delete a vulnerability protection profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete vulnerability profile"),
	}, deleteHandler[vulnerability.Location, vulnerability.Entry](d, "panos_vulnerability_profile_delete", svc, resolve))
}

// --- Anti-spyware ------------------------------------------------------------

// spywareParts supplies anti-spyware profile locations. This is pango's
// security/profiles/spyware package (the objects/profiles tree has no spyware),
// which does model a vsys location.
func spywareParts() locParts[spyware.Location] {
	return locParts[spyware.Location]{
		shared: func(string) spyware.Location {
			return spyware.Location{Shared: &spyware.SharedLocation{}}
		},
		vsys: func(v string) spyware.Location {
			return spyware.Location{Vsys: &spyware.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) spyware.Location {
			return spyware.Location{DeviceGroup: &spyware.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newSpywareService(d *Deps) nameFixAdapter[spyware.Location, spyware.Entry] {
	return nameFixAdapter[spyware.Location, spyware.Entry]{
		svc:    spyware.NewService(d.Client),
		client: d.Client,
		name:   func(e *spyware.Entry) string { return e.Name },
	}
}

// SpywareProfileInput is the input for anti-spyware profile create and update.
// The per-threat Rules (a pango oneof action), the BotnetDomains DNS-security
// subtree, the ML-engine, and threat-exception subtrees are SDK-only for now;
// the practical top-level inline-inspection controls are modelled.
type SpywareProfileInput struct {
	Name                       string        `json:"name" jsonschema:"Anti-spyware profile name"`
	Location                   LocationInput `json:"location,omitzero"`
	Description                string        `json:"description,omitempty"`
	CloudInlineAnalysis        *bool         `json:"cloud_inline_analysis,omitempty" jsonschema:"Enable cloud inline analysis"`
	InlineExceptionEdlURLs     []string      `json:"inline_exception_edl_urls,omitempty" jsonschema:"EDL URL inline-detection exceptions; replaces fully when provided, an explicit empty list clears it"`
	InlineExceptionIPAddresses []string      `json:"inline_exception_ip_addresses,omitempty" jsonschema:"Inline-detection IP exceptions: each entry is the name of an ip-type external dynamic list (see panos_edl_create), not an IP literal or address object; replaces fully when provided, an explicit empty list clears it"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildSpywareEntry(in SpywareProfileInput) (*spyware.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &spyware.Entry{Name: in.Name}
	setStrPtr(&e.Description, in.Description)
	applySpywareInline(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlaySpyware(e *spyware.Entry, in SpywareProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	applySpywareInline(e, &in)
	return nil
}

// applySpywareInline mirrors applyVulnerabilityInline for anti-spyware profiles:
// cloud_inline_analysis and the two inline_exception lists, nil preserves, an
// explicit empty list clears (issue #61).
func applySpywareInline(e *spyware.Entry, in *SpywareProfileInput) {
	if in.CloudInlineAnalysis != nil {
		e.CloudInlineAnalysis = in.CloudInlineAnalysis
	}
	if in.InlineExceptionEdlURLs != nil {
		e.InlineExceptionEdlUrl = in.InlineExceptionEdlURLs
	}
	if in.InlineExceptionIPAddresses != nil {
		e.InlineExceptionIpAddress = in.InlineExceptionIPAddresses
	}
}

func spywareSummary(e *spyware.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["cloud_inline_analysis"] = boolVal(e.CloudInlineAnalysis)
	m["inline_exception_edl_urls"] = e.InlineExceptionEdlUrl
	m["inline_exception_ip_addresses"] = e.InlineExceptionIpAddress
	return m
}

// RegisterSpywareProfileTools registers the anti-spyware profile tools.
func RegisterSpywareProfileTools(s *mcp.Server, d *Deps) {
	svc := newSpywareService(d)
	resolve := func(in LocationInput) (spyware.Location, error) { return resolveLocation(d, in, spywareParts()) }
	name := svc.name
	loc := func(in SpywareProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_anti_spyware_profile_list",
		Description: "List anti-spyware profiles at a location. Read-only.",
		Annotations: readOnlyTool("List anti-spyware profiles"),
	}, listHandler[spyware.Location, spyware.Entry](d, "panos_anti_spyware_profile_list", svc, resolve, name, spywareSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_anti_spyware_profile_get",
		Description: "Get one anti-spyware profile by name with its managed fields. Per-threat rules and DNS-security settings are not exposed. Read-only.",
		Annotations: readOnlyTool("Get anti-spyware profile"),
	}, getHandler[spyware.Location, spyware.Entry](d, "panos_anti_spyware_profile_get", svc, resolve, spywareSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_anti_spyware_profile_create",
		Description: "Create an anti-spyware profile in the candidate config. Per-threat rules and DNS-security (botnet-domains) settings are SDK-only and not set here, so a profile created with this tool carries no per-threat rules of its own; it models the top-level inline-inspection controls. inline_exception_ip_addresses entries are names of ip-type EDLs (see panos_edl_create), not IP literals or address objects. Run panos_commit to apply.",
		Annotations: createTool("Create anti-spyware profile"),
	}, createHandler[spyware.Location, spyware.Entry, SpywareProfileInput](d, "panos_anti_spyware_profile_create", svc, resolve, loc, buildSpywareEntry, spywareSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_anti_spyware_profile_update",
		Description: "Update an anti-spyware profile: read-modify-write, only provided fields change. inline_exception_ip_addresses entries are names of ip-type EDLs (see panos_edl_create), not IP literals or address objects. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update anti-spyware profile"),
	}, updateHandler[spyware.Location, spyware.Entry, SpywareProfileInput](d, "panos_anti_spyware_profile_update", svc, resolve, loc,
		func(in SpywareProfileInput) string { return in.Name }, overlaySpyware, spywareSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_anti_spyware_profile_delete",
		Description: "Delete an anti-spyware profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete anti-spyware profile"),
	}, deleteHandler[spyware.Location, spyware.Entry](d, "panos_anti_spyware_profile_delete", svc, resolve))
}

// --- URL filtering -----------------------------------------------------------

// urlFilteringParts supplies url-filtering profile locations. pango generates no
// vsys location for this type; on a firewall it is managed at shared.
func urlFilteringParts() locParts[urlfiltering.Location] {
	return locParts[urlfiltering.Location]{
		shared: func(string) urlfiltering.Location {
			return urlfiltering.Location{Shared: &urlfiltering.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) urlfiltering.Location {
			return urlfiltering.Location{DeviceGroup: &urlfiltering.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newURLFilteringService(d *Deps) nameFixAdapter[urlfiltering.Location, urlfiltering.Entry] {
	return nameFixAdapter[urlfiltering.Location, urlfiltering.Entry]{
		svc:    urlfiltering.NewService(d.Client),
		client: d.Client,
		name:   func(e *urlfiltering.Entry) string { return e.Name },
	}
}

// URLFilteringProfileInput is the input for url-filtering profile create and
// update. The five category-action lists are the core control; the
// credential-enforcement and http-header-insertion subtrees are SDK-only.
type URLFilteringProfileInput struct {
	Name                   string        `json:"name" jsonschema:"URL filtering profile name"`
	Location               LocationInput `json:"location,omitzero"`
	Description            string        `json:"description,omitempty"`
	Alert                  []string      `json:"alert,omitempty" jsonschema:"Built-in URL categories or custom URL category names set to alert; replaces fully when provided, an explicit empty list clears it"`
	Allow                  []string      `json:"allow,omitempty" jsonschema:"Built-in URL categories or custom URL category names set to allow; replaces fully when provided, an explicit empty list clears it"`
	Block                  []string      `json:"block,omitempty" jsonschema:"Built-in URL categories or custom URL category names set to block; replaces fully when provided, an explicit empty list clears it"`
	Continue               []string      `json:"continue,omitempty" jsonschema:"Built-in URL categories or custom URL category names set to continue; replaces fully when provided, an explicit empty list clears it"`
	Override               []string      `json:"override,omitempty" jsonschema:"Built-in URL categories or custom URL category names set to override; replaces fully when provided, an explicit empty list clears it"`
	SafeSearchEnforcement  *bool         `json:"safe_search_enforcement,omitempty" jsonschema:"Enforce safe search"`
	LogHTTPHeaderXFF       *bool         `json:"log_http_header_xff,omitempty" jsonschema:"Log the X-Forwarded-For HTTP header"`
	LogHTTPHeaderUserAgent *bool         `json:"log_http_header_user_agent,omitempty" jsonschema:"Log the User-Agent HTTP header"`
	LogHTTPHeaderReferer   *bool         `json:"log_http_header_referer,omitempty" jsonschema:"Log the Referer HTTP header"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildURLFilteringEntry(in URLFilteringProfileInput) (*urlfiltering.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &urlfiltering.Entry{
		Name:                  in.Name,
		SafeSearchEnforcement: in.SafeSearchEnforcement,
		LogHttpHdrXff:         in.LogHTTPHeaderXFF,
		LogHttpHdrUserAgent:   in.LogHTTPHeaderUserAgent,
		LogHttpHdrReferer:     in.LogHTTPHeaderReferer,
	}
	setStrPtr(&e.Description, in.Description)
	applyURLFilteringCategories(e, &in)
	return e, nil
}

// applyURLFilteringCategories sets each category-action list when provided: a
// provided list replaces that action's whole category set, and an explicit empty
// list clears it. in is by pointer to
// avoid copying the large input; this private helper is not bound by the generic
// builder contract (see countValueTypes).
func applyURLFilteringCategories(e *urlfiltering.Entry, in *URLFilteringProfileInput) {
	if in.Alert != nil {
		e.Alert = in.Alert
	}
	if in.Allow != nil {
		e.Allow = in.Allow
	}
	if in.Block != nil {
		e.Block = in.Block
	}
	if in.Continue != nil {
		e.Continue = in.Continue
	}
	if in.Override != nil {
		e.Override = in.Override
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayURLFiltering(e *urlfiltering.Entry, in URLFilteringProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	if in.SafeSearchEnforcement != nil {
		e.SafeSearchEnforcement = in.SafeSearchEnforcement
	}
	if in.LogHTTPHeaderXFF != nil {
		e.LogHttpHdrXff = in.LogHTTPHeaderXFF
	}
	if in.LogHTTPHeaderUserAgent != nil {
		e.LogHttpHdrUserAgent = in.LogHTTPHeaderUserAgent
	}
	if in.LogHTTPHeaderReferer != nil {
		e.LogHttpHdrReferer = in.LogHTTPHeaderReferer
	}
	applyURLFilteringCategories(e, &in)
	return nil
}

func urlFilteringSummary(e *urlfiltering.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["alert"] = e.Alert
	m["allow"] = e.Allow
	m["block"] = e.Block
	m["continue"] = e.Continue
	m["override"] = e.Override
	m["safe_search_enforcement"] = boolVal(e.SafeSearchEnforcement)
	m["log_http_header_xff"] = boolVal(e.LogHttpHdrXff)
	m["log_http_header_user_agent"] = boolVal(e.LogHttpHdrUserAgent)
	m["log_http_header_referer"] = boolVal(e.LogHttpHdrReferer)
	return m
}

// RegisterURLFilteringProfileTools registers the url-filtering profile tools.
func RegisterURLFilteringProfileTools(s *mcp.Server, d *Deps) {
	svc := newURLFilteringService(d)
	resolve := func(in LocationInput) (urlfiltering.Location, error) {
		return resolveLocation(d, in, urlFilteringParts())
	}
	name := svc.name
	loc := func(in URLFilteringProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_url_filtering_profile_list",
		Description: "List URL filtering profiles at a location. On a firewall this profile type is managed at shared (pango exposes no vsys location for it). Read-only.",
		Annotations: readOnlyTool("List URL filtering profiles"),
	}, listHandler[urlfiltering.Location, urlfiltering.Entry](d, "panos_url_filtering_profile_list", svc, resolve, name, urlFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_url_filtering_profile_get",
		Description: "Get one URL filtering profile by name with its category actions and managed fields. Read-only.",
		Annotations: readOnlyTool("Get URL filtering profile"),
	}, getHandler[urlfiltering.Location, urlfiltering.Entry](d, "panos_url_filtering_profile_get", svc, resolve, urlFilteringSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_url_filtering_profile_create",
		Description: "Create a URL filtering profile in the candidate config. Set category actions via the alert/allow/block/continue/override lists; each list accepts built-in categories and custom URL category names (see panos_custom_url_category_create). On a firewall it is created at shared. Run panos_commit to apply.",
		Annotations: createTool("Create URL filtering profile"),
	}, createHandler[urlfiltering.Location, urlfiltering.Entry, URLFilteringProfileInput](d, "panos_url_filtering_profile_create", svc, resolve, loc, buildURLFilteringEntry, urlFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_url_filtering_profile_update",
		Description: "Update a URL filtering profile: read-modify-write, only provided fields change; a provided category list replaces that action's whole set, and an explicit empty list clears it. Each list accepts built-in categories and custom URL category names (see panos_custom_url_category_create). Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update URL filtering profile"),
	}, updateHandler[urlfiltering.Location, urlfiltering.Entry, URLFilteringProfileInput](d, "panos_url_filtering_profile_update", svc, resolve, loc,
		func(in URLFilteringProfileInput) string { return in.Name }, overlayURLFiltering, urlFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_url_filtering_profile_delete",
		Description: "Delete a URL filtering profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete URL filtering profile"),
	}, deleteHandler[urlfiltering.Location, urlfiltering.Entry](d, "panos_url_filtering_profile_delete", svc, resolve))
}

// --- File blocking -----------------------------------------------------------

// fileBlockingParts supplies file-blocking profile locations.
func fileBlockingParts() locParts[fileblocking.Location] {
	return locParts[fileblocking.Location]{
		shared: func(string) fileblocking.Location {
			return fileblocking.Location{Shared: &fileblocking.SharedLocation{}}
		},
		vsys: func(v string) fileblocking.Location {
			return fileblocking.Location{Vsys: &fileblocking.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) fileblocking.Location {
			return fileblocking.Location{DeviceGroup: &fileblocking.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newFileBlockingService(d *Deps) nameFixAdapter[fileblocking.Location, fileblocking.Entry] {
	return nameFixAdapter[fileblocking.Location, fileblocking.Entry]{
		svc:    fileblocking.NewService(d.Client),
		client: d.Client,
		name:   func(e *fileblocking.Entry) string { return e.Name },
	}
}

// FileBlockingRuleInput is one rule in a file-blocking profile. action
// (alert, block, continue) and direction (upload, download, both) pass through
// to PAN-OS unchanged.
type FileBlockingRuleInput struct {
	Name         string   `json:"name" jsonschema:"Rule name"`
	Applications []string `json:"applications,omitempty" jsonschema:"Applications the rule matches; omit to match any (device default)"`
	FileTypes    []string `json:"file_types,omitempty" jsonschema:"File types the rule matches; omit to match any (device default)"`
	Direction    string   `json:"direction,omitempty" jsonschema:"Transfer direction: upload, download or both"`
	Action       string   `json:"action,omitempty" jsonschema:"Action: alert, block or continue"`
}

// FileBlockingProfileInput is the input for file-blocking profile create and
// update.
type FileBlockingProfileInput struct {
	Name        string                  `json:"name" jsonschema:"File blocking profile name"`
	Location    LocationInput           `json:"location,omitzero"`
	Description string                  `json:"description,omitempty"`
	Rules       []FileBlockingRuleInput `json:"rules,omitempty" jsonschema:"File-blocking rules; replaces the whole rule set when provided, an explicit empty list clears it"`
}

// buildFileBlockingRules maps the rule inputs onto pango rules, requiring a name
// on each. It returns nil for an empty input.
func buildFileBlockingRules(in []FileBlockingRuleInput) ([]fileblocking.Rules, error) {
	// nil (omitted) preserves; an explicit empty list yields an empty non-nil
	// slice the overlay assigns, clearing the set on update (issue #61).
	if in == nil {
		return nil, nil
	}
	out := make([]fileblocking.Rules, 0, len(in))
	for _, r := range in {
		if r.Name == "" {
			return nil, errors.New("each rule requires a name")
		}
		rule := fileblocking.Rules{Name: r.Name, Application: r.Applications, FileType: r.FileTypes}
		setStrPtr(&rule.Direction, r.Direction)
		setStrPtr(&rule.Action, r.Action)
		out = append(out, rule)
	}
	return out, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildFileBlockingEntry(in FileBlockingProfileInput) (*fileblocking.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	rules, err := buildFileBlockingRules(in.Rules)
	if err != nil {
		return nil, err
	}
	e := &fileblocking.Entry{Name: in.Name, Rules: rules}
	setStrPtr(&e.Description, in.Description)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayFileBlocking(e *fileblocking.Entry, in FileBlockingProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	rules, err := buildFileBlockingRules(in.Rules)
	if err != nil {
		return err
	}
	if rules != nil {
		e.Rules = rules
	}
	return nil
}

func fileBlockingRuleSummaries(rules []fileblocking.Rules) []any {
	out := make([]any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out, map[string]any{
			tagNameKey:     r.Name,
			"applications": r.Application,
			"file_types":   r.FileType,
			"direction":    strVal(r.Direction),
			"action":       strVal(r.Action),
		})
	}
	return out
}

func fileBlockingSummary(e *fileblocking.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["rules"] = fileBlockingRuleSummaries(e.Rules)
	return m
}

// RegisterFileBlockingProfileTools registers the file-blocking profile tools.
func RegisterFileBlockingProfileTools(s *mcp.Server, d *Deps) {
	svc := newFileBlockingService(d)
	resolve := func(in LocationInput) (fileblocking.Location, error) {
		return resolveLocation(d, in, fileBlockingParts())
	}
	name := svc.name
	loc := func(in FileBlockingProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_file_blocking_profile_list",
		Description: "List file-blocking profiles at a location. Read-only.",
		Annotations: readOnlyTool("List file-blocking profiles"),
	}, listHandler[fileblocking.Location, fileblocking.Entry](d, "panos_file_blocking_profile_list", svc, resolve, name, fileBlockingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_file_blocking_profile_get",
		Description: "Get one file-blocking profile by name with its rules. Read-only.",
		Annotations: readOnlyTool("Get file-blocking profile"),
	}, getHandler[fileblocking.Location, fileblocking.Entry](d, "panos_file_blocking_profile_get", svc, resolve, fileBlockingSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_file_blocking_profile_create",
		Description: "Create a file-blocking profile in the candidate config. A profile with no rules blocks nothing; set rules to inspect file transfers. Run panos_commit to apply.",
		Annotations: createTool("Create file-blocking profile"),
	}, createHandler[fileblocking.Location, fileblocking.Entry, FileBlockingProfileInput](d, "panos_file_blocking_profile_create", svc, resolve, loc, buildFileBlockingEntry, fileBlockingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_file_blocking_profile_update",
		Description: "Update a file-blocking profile: read-modify-write, only provided fields change; a provided rules list replaces the whole set, and an explicit empty list clears it. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update file-blocking profile"),
	}, updateHandler[fileblocking.Location, fileblocking.Entry, FileBlockingProfileInput](d, "panos_file_blocking_profile_update", svc, resolve, loc,
		func(in FileBlockingProfileInput) string { return in.Name }, overlayFileBlocking, fileBlockingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_file_blocking_profile_delete",
		Description: "Delete a file-blocking profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete file-blocking profile"),
	}, deleteHandler[fileblocking.Location, fileblocking.Entry](d, "panos_file_blocking_profile_delete", svc, resolve))
}

// --- WildFire analysis -------------------------------------------------------

// wildfireAnalysisParts supplies wildfire-analysis profile locations. pango
// generates no vsys location for this type; on a firewall it is managed at
// shared.
func wildfireAnalysisParts() locParts[wildfireanalysis.Location] {
	return locParts[wildfireanalysis.Location]{
		shared: func(string) wildfireanalysis.Location {
			return wildfireanalysis.Location{Shared: &wildfireanalysis.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) wildfireanalysis.Location {
			return wildfireanalysis.Location{DeviceGroup: &wildfireanalysis.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newWildfireAnalysisService(d *Deps) nameFixAdapter[wildfireanalysis.Location, wildfireanalysis.Entry] {
	return nameFixAdapter[wildfireanalysis.Location, wildfireanalysis.Entry]{
		svc:    wildfireanalysis.NewService(d.Client),
		client: d.Client,
		name:   func(e *wildfireanalysis.Entry) string { return e.Name },
	}
}

// WildfireAnalysisRuleInput is one rule in a wildfire-analysis profile. analysis
// (public-cloud, private-cloud) and direction (upload, download, both) pass
// through to PAN-OS unchanged.
type WildfireAnalysisRuleInput struct {
	Name         string   `json:"name" jsonschema:"Rule name"`
	Applications []string `json:"applications,omitempty" jsonschema:"Applications the rule matches; omit to match any (device default)"`
	FileTypes    []string `json:"file_types,omitempty" jsonschema:"File types the rule matches; omit to match any (device default)"`
	Direction    string   `json:"direction,omitempty" jsonschema:"Transfer direction: upload, download or both"`
	Analysis     string   `json:"analysis,omitempty" jsonschema:"Analysis location: public-cloud or private-cloud"`
}

// WildfireAnalysisProfileInput is the input for wildfire-analysis profile create
// and update.
type WildfireAnalysisProfileInput struct {
	Name        string                      `json:"name" jsonschema:"WildFire analysis profile name"`
	Location    LocationInput               `json:"location,omitzero"`
	Description string                      `json:"description,omitempty"`
	Rules       []WildfireAnalysisRuleInput `json:"rules,omitempty" jsonschema:"WildFire analysis rules; replaces the whole rule set when provided, an explicit empty list clears it"`
}

func buildWildfireAnalysisRules(in []WildfireAnalysisRuleInput) ([]wildfireanalysis.Rules, error) {
	// nil (omitted) preserves; an explicit empty list yields an empty non-nil
	// slice the overlay assigns, clearing the set on update (issue #61).
	if in == nil {
		return nil, nil
	}
	out := make([]wildfireanalysis.Rules, 0, len(in))
	for _, r := range in {
		if r.Name == "" {
			return nil, errors.New("each rule requires a name")
		}
		rule := wildfireanalysis.Rules{Name: r.Name, Application: r.Applications, FileType: r.FileTypes}
		setStrPtr(&rule.Direction, r.Direction)
		setStrPtr(&rule.Analysis, r.Analysis)
		out = append(out, rule)
	}
	return out, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildWildfireAnalysisEntry(in WildfireAnalysisProfileInput) (*wildfireanalysis.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	rules, err := buildWildfireAnalysisRules(in.Rules)
	if err != nil {
		return nil, err
	}
	e := &wildfireanalysis.Entry{Name: in.Name, Rules: rules}
	setStrPtr(&e.Description, in.Description)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayWildfireAnalysis(e *wildfireanalysis.Entry, in WildfireAnalysisProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	rules, err := buildWildfireAnalysisRules(in.Rules)
	if err != nil {
		return err
	}
	if rules != nil {
		e.Rules = rules
	}
	return nil
}

func wildfireAnalysisRuleSummaries(rules []wildfireanalysis.Rules) []any {
	out := make([]any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out, map[string]any{
			tagNameKey:     r.Name,
			"applications": r.Application,
			"file_types":   r.FileType,
			"direction":    strVal(r.Direction),
			"analysis":     strVal(r.Analysis),
		})
	}
	return out
}

func wildfireAnalysisSummary(e *wildfireanalysis.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["rules"] = wildfireAnalysisRuleSummaries(e.Rules)
	return m
}

// RegisterWildfireAnalysisProfileTools registers the wildfire-analysis profile
// tools.
func RegisterWildfireAnalysisProfileTools(s *mcp.Server, d *Deps) {
	svc := newWildfireAnalysisService(d)
	resolve := func(in LocationInput) (wildfireanalysis.Location, error) {
		return resolveLocation(d, in, wildfireAnalysisParts())
	}
	name := svc.name
	loc := func(in WildfireAnalysisProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_wildfire_analysis_profile_list",
		Description: "List WildFire analysis profiles at a location. On a firewall this profile type is managed at shared (pango exposes no vsys location for it). Read-only.",
		Annotations: readOnlyTool("List WildFire analysis profiles"),
	}, listHandler[wildfireanalysis.Location, wildfireanalysis.Entry](d, "panos_wildfire_analysis_profile_list", svc, resolve, name, wildfireAnalysisSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_wildfire_analysis_profile_get",
		Description: "Get one WildFire analysis profile by name with its rules. Read-only.",
		Annotations: readOnlyTool("Get WildFire analysis profile"),
	}, getHandler[wildfireanalysis.Location, wildfireanalysis.Entry](d, "panos_wildfire_analysis_profile_get", svc, resolve, wildfireAnalysisSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_wildfire_analysis_profile_create",
		Description: "Create a WildFire analysis profile in the candidate config. Set rules to route file transfers to public- or private-cloud analysis. On a firewall it is created at shared. Run panos_commit to apply.",
		Annotations: createTool("Create WildFire analysis profile"),
	}, createHandler[wildfireanalysis.Location, wildfireanalysis.Entry, WildfireAnalysisProfileInput](d, "panos_wildfire_analysis_profile_create", svc, resolve, loc, buildWildfireAnalysisEntry, wildfireAnalysisSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_wildfire_analysis_profile_update",
		Description: "Update a WildFire analysis profile: read-modify-write, only provided fields change; a provided rules list replaces the whole set, and an explicit empty list clears it. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update WildFire analysis profile"),
	}, updateHandler[wildfireanalysis.Location, wildfireanalysis.Entry, WildfireAnalysisProfileInput](d, "panos_wildfire_analysis_profile_update", svc, resolve, loc,
		func(in WildfireAnalysisProfileInput) string { return in.Name }, overlayWildfireAnalysis, wildfireAnalysisSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_wildfire_analysis_profile_delete",
		Description: "Delete a WildFire analysis profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete WildFire analysis profile"),
	}, deleteHandler[wildfireanalysis.Location, wildfireanalysis.Entry](d, "panos_wildfire_analysis_profile_delete", svc, resolve))
}

// --- Security profile group --------------------------------------------------

// profileGroupParts supplies security profile group locations. pango generates
// no vsys location for this type; on a firewall it is managed at shared.
func profileGroupParts() locParts[secgroup.Location] {
	return locParts[secgroup.Location]{
		shared: func(string) secgroup.Location {
			return secgroup.Location{Shared: &secgroup.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) secgroup.Location {
			return secgroup.Location{DeviceGroup: &secgroup.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newProfileGroupService(d *Deps) nameFixAdapter[secgroup.Location, secgroup.Entry] {
	return nameFixAdapter[secgroup.Location, secgroup.Entry]{
		svc:    secgroup.NewService(d.Client),
		client: d.Client,
		name:   func(e *secgroup.Entry) string { return e.Name },
	}
}

// ProfileGroupInput is the input for security profile group create and update.
// A group references at most one profile of each type; each field takes a single
// profile name (the mobile-network GTP/SCTP profiles are not modelled here).
type ProfileGroupInput struct {
	Name             string        `json:"name" jsonschema:"Security profile group name"`
	Location         LocationInput `json:"location,omitzero"`
	Antivirus        string        `json:"antivirus,omitempty" jsonschema:"Antivirus profile to include"`
	AntiSpyware      string        `json:"anti_spyware,omitempty" jsonschema:"Anti-spyware profile to include"`
	Vulnerability    string        `json:"vulnerability,omitempty" jsonschema:"Vulnerability protection profile to include"`
	URLFiltering     string        `json:"url_filtering,omitempty" jsonschema:"URL filtering profile to include"`
	FileBlocking     string        `json:"file_blocking,omitempty" jsonschema:"File blocking profile to include"`
	WildfireAnalysis string        `json:"wildfire_analysis,omitempty" jsonschema:"WildFire analysis profile to include"`
	DataFiltering    string        `json:"data_filtering,omitempty" jsonschema:"Data filtering profile to include"`
}

// applyProfileGroupMembers sets each referenced profile when provided, leaving
// omitted slots untouched (read-modify-write preserves an existing member). in
// is by pointer to avoid copying the large input; this private helper is not
// bound by the generic builder contract (see countValueTypes).
func applyProfileGroupMembers(e *secgroup.Entry, in *ProfileGroupInput) {
	setMember(&e.Virus, in.Antivirus)
	setMember(&e.Spyware, in.AntiSpyware)
	setMember(&e.Vulnerability, in.Vulnerability)
	setMember(&e.UrlFiltering, in.URLFiltering)
	setMember(&e.FileBlocking, in.FileBlocking)
	setMember(&e.WildfireAnalysis, in.WildfireAnalysis)
	setMember(&e.DataFiltering, in.DataFiltering)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildProfileGroupEntry(in ProfileGroupInput) (*secgroup.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &secgroup.Entry{Name: in.Name}
	applyProfileGroupMembers(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayProfileGroup(e *secgroup.Entry, in ProfileGroupInput) error {
	applyProfileGroupMembers(e, &in)
	return nil
}

func profileGroupSummary(e *secgroup.Entry) any {
	return map[string]any{
		tagNameKey:          e.Name,
		"antivirus":         firstMember(e.Virus),
		"anti_spyware":      firstMember(e.Spyware),
		"vulnerability":     firstMember(e.Vulnerability),
		"url_filtering":     firstMember(e.UrlFiltering),
		"file_blocking":     firstMember(e.FileBlocking),
		"wildfire_analysis": firstMember(e.WildfireAnalysis),
		"data_filtering":    firstMember(e.DataFiltering),
	}
}

// RegisterProfileGroupTools registers the security profile group tools.
func RegisterProfileGroupTools(s *mcp.Server, d *Deps) {
	svc := newProfileGroupService(d)
	resolve := func(in LocationInput) (secgroup.Location, error) { return resolveLocation(d, in, profileGroupParts()) }
	name := svc.name
	loc := func(in ProfileGroupInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_profile_group_list",
		Description: "List security profile groups at a location. On a firewall these are managed at shared (pango exposes no vsys location for them). Read-only.",
		Annotations: readOnlyTool("List profile groups"),
	}, listHandler[secgroup.Location, secgroup.Entry](d, "panos_profile_group_list", svc, resolve, name, profileGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_profile_group_get",
		Description: "Get one security profile group by name with the profile referenced for each type. Read-only.",
		Annotations: readOnlyTool("Get profile group"),
	}, getHandler[secgroup.Location, secgroup.Entry](d, "panos_profile_group_get", svc, resolve, profileGroupSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_profile_group_create",
		Description: "Create a security profile group in the candidate config, referencing one profile per type. A security rule applies a group via its profile_group field. On a firewall the group is created at shared, and a shared group cannot reference a vsys-scoped profile, so any antivirus/anti-spyware/file-blocking profiles it references must also be created at shared (location.shared: true). Run panos_commit to apply.",
		Annotations: createTool("Create profile group"),
	}, createHandler[secgroup.Location, secgroup.Entry, ProfileGroupInput](d, "panos_profile_group_create", svc, resolve, loc, buildProfileGroupEntry, profileGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_profile_group_update",
		Description: "Update a security profile group: read-modify-write, only provided profile references change. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update profile group"),
	}, updateHandler[secgroup.Location, secgroup.Entry, ProfileGroupInput](d, "panos_profile_group_update", svc, resolve, loc,
		func(in ProfileGroupInput) string { return in.Name }, overlayProfileGroup, profileGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_profile_group_delete",
		Description: "Delete a security profile group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete profile group"),
	}, deleteHandler[secgroup.Location, secgroup.Entry](d, "panos_profile_group_delete", svc, resolve))
}

// --- Log forwarding ----------------------------------------------------------

// logForwardingParts supplies log-forwarding profile locations. pango generates
// no vsys location for this type; on a firewall it is managed at shared
// (resolveLocation's nil-vsys fallback), mirroring the profile group.
func logForwardingParts() locParts[logforwarding.Location] {
	return locParts[logforwarding.Location]{
		shared: func(string) logforwarding.Location {
			return logforwarding.Location{Shared: &logforwarding.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) logforwarding.Location {
			return logforwarding.Location{DeviceGroup: &logforwarding.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newLogForwardingService(d *Deps) nameFixAdapter[logforwarding.Location, logforwarding.Entry] {
	return nameFixAdapter[logforwarding.Location, logforwarding.Entry]{
		svc:    logforwarding.NewService(d.Client),
		client: d.Client,
		name:   func(e *logforwarding.Entry) string { return e.Name },
	}
}

// LogForwardingMatchListInput is one match list in a log-forwarding profile.
// log_type passes through to PAN-OS unchanged (traffic, threat, url, wildfire,
// data, tunnel, auth, decryption, ...); the device validates it. The per-match-
// list built-in actions subtree (tagging/quarantine integration) is SDK-only
// and is dropped when a match list is replaced through this tool.
type LogForwardingMatchListInput struct {
	Name           string   `json:"name" jsonschema:"Match list name"`
	LogType        string   `json:"log_type,omitempty" jsonschema:"Log type this list matches, e.g. traffic, threat, url, wildfire; device-validated"`
	Filter         string   `json:"filter,omitempty" jsonschema:"Log filter query; omit for All Logs"`
	Description    string   `json:"description,omitempty" jsonschema:"Match list description"`
	SendToPanorama *bool    `json:"send_to_panorama,omitempty" jsonschema:"Forward matching logs to Panorama; omit to keep the device default"`
	Quarantine     *bool    `json:"quarantine,omitempty" jsonschema:"Quarantine the source device on match; omit to keep the device default"`
	SendSyslog     []string `json:"send_syslog,omitempty" jsonschema:"Syslog server profile names to forward to"`
	SendSnmptrap   []string `json:"send_snmptrap,omitempty" jsonschema:"SNMP trap server profile names to forward to"`
	SendEmail      []string `json:"send_email,omitempty" jsonschema:"Email server profile names to forward to"`
	SendHTTP       []string `json:"send_http,omitempty" jsonschema:"HTTP server profile names to forward to"`
}

// LogForwardingProfileInput is the input for log-forwarding profile create and
// update.
type LogForwardingProfileInput struct {
	Name                       string                        `json:"name" jsonschema:"Log forwarding profile name"`
	Location                   LocationInput                 `json:"location,omitzero"`
	Description                string                        `json:"description,omitempty"`
	EnhancedApplicationLogging *bool                         `json:"enhanced_application_logging,omitempty" jsonschema:"Enable enhanced application logging to the Palo Alto cloud; omit to keep the device default"`
	MatchLists                 []LogForwardingMatchListInput `json:"match_lists,omitempty" jsonschema:"Match lists; replaces the whole set when provided, an explicit empty list clears it. Any built-in actions on replaced match lists are not preserved."`
}

// buildLogForwardingMatchLists maps match-list inputs onto pango match lists,
// requiring a name on each. nil (omitted) preserves; an explicit empty list
// yields an empty non-nil slice the overlay assigns, clearing the set on update
// (same replace semantics as file-blocking rules, issue #61). The Actions
// subtree of a replaced match list is dropped: whole-set replacement cannot
// carry per-list unknowns, the same accepted tradeoff as the file-blocking
// rules' Misc.
func buildLogForwardingMatchLists(in []LogForwardingMatchListInput) ([]logforwarding.MatchList, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]logforwarding.MatchList, 0, len(in))
	for i := range in {
		ml := &in[i]
		if ml.Name == "" {
			return nil, errors.New("each match list requires a name")
		}
		m := logforwarding.MatchList{
			Name:         ml.Name,
			SendSyslog:   ml.SendSyslog,
			SendSnmptrap: ml.SendSnmptrap,
			SendEmail:    ml.SendEmail,
			SendHttp:     ml.SendHTTP,
		}
		setStrPtr(&m.LogType, ml.LogType)
		setStrPtr(&m.Filter, ml.Filter)
		setStrPtr(&m.ActionDesc, ml.Description)
		setPtr(&m.SendToPanorama, ml.SendToPanorama)
		setPtr(&m.Quarantine, ml.Quarantine)
		out = append(out, m)
	}
	return out, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildLogForwardingEntry(in LogForwardingProfileInput) (*logforwarding.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	mls, err := buildLogForwardingMatchLists(in.MatchLists)
	if err != nil {
		return nil, err
	}
	e := &logforwarding.Entry{Name: in.Name, MatchList: mls}
	setStrPtr(&e.Description, in.Description)
	if in.EnhancedApplicationLogging != nil {
		e.EnhancedApplicationLogging = in.EnhancedApplicationLogging
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayLogForwarding(e *logforwarding.Entry, in LogForwardingProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	if in.EnhancedApplicationLogging != nil {
		e.EnhancedApplicationLogging = in.EnhancedApplicationLogging
	}
	mls, err := buildLogForwardingMatchLists(in.MatchLists)
	if err != nil {
		return err
	}
	if mls != nil {
		e.MatchList = mls
	}
	return nil
}

func logForwardingMatchListSummaries(mls []logforwarding.MatchList) []any {
	out := make([]any, 0, len(mls))
	for i := range mls {
		ml := &mls[i]
		m := map[string]any{
			tagNameKey:      ml.Name,
			"log_type":      strVal(ml.LogType),
			"filter":        strVal(ml.Filter),
			descriptionKey:  strVal(ml.ActionDesc),
			"send_syslog":   ml.SendSyslog,
			"send_snmptrap": ml.SendSnmptrap,
			"send_email":    ml.SendEmail,
			"send_http":     ml.SendHttp,
			// The built-in actions subtree is SDK-only; surface its presence so a
			// get does not silently hide it.
			"has_actions": len(ml.Actions) > 0,
		}
		putBool(m, "send_to_panorama", ml.SendToPanorama)
		putBool(m, "quarantine", ml.Quarantine)
		out = append(out, m)
	}
	return out
}

func logForwardingSummary(e *logforwarding.Entry) any {
	m := nameDescription(e.Name, e.Description)
	putBool(m, "enhanced_application_logging", e.EnhancedApplicationLogging)
	m["match_lists"] = logForwardingMatchListSummaries(e.MatchList)
	return m
}

// RegisterLogForwardingProfileTools registers the log-forwarding profile tools.
func RegisterLogForwardingProfileTools(s *mcp.Server, d *Deps) {
	svc := newLogForwardingService(d)
	resolve := func(in LocationInput) (logforwarding.Location, error) {
		return resolveLocation(d, in, logForwardingParts())
	}
	name := svc.name
	loc := func(in LogForwardingProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_forwarding_profile_list",
		Description: "List log-forwarding profiles at a location. On a firewall these are managed at shared (pango exposes no vsys location for them), so any vsys-scoped log-forwarding profiles created directly on the device are not visible here. Read-only.",
		Annotations: readOnlyTool("List log-forwarding profiles"),
	}, listHandler[logforwarding.Location, logforwarding.Entry](d, "panos_log_forwarding_profile_list", svc, resolve, name, logForwardingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_forwarding_profile_get",
		Description: "Get one log-forwarding profile by name with its match lists. Read-only.",
		Annotations: readOnlyTool("Get log-forwarding profile"),
	}, getHandler[logforwarding.Location, logforwarding.Entry](d, "panos_log_forwarding_profile_get", svc, resolve, logForwardingSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_forwarding_profile_create",
		Description: "Create a log-forwarding profile in the candidate config. Match lists select which logs are forwarded to the listed syslog/SNMP/email/HTTP server profiles or Panorama; a security rule attaches the profile via its log_setting field. Run panos_commit to apply.",
		Annotations: createTool("Create log-forwarding profile"),
	}, createHandler[logforwarding.Location, logforwarding.Entry, LogForwardingProfileInput](d, "panos_log_forwarding_profile_create", svc, resolve, loc, buildLogForwardingEntry, logForwardingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_forwarding_profile_update",
		Description: "Update a log-forwarding profile: read-modify-write, only provided fields change; a provided match_lists list replaces the whole set (an explicit empty list clears it), and any built-in actions on replaced match lists are not preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update log-forwarding profile"),
	}, updateHandler[logforwarding.Location, logforwarding.Entry, LogForwardingProfileInput](d, "panos_log_forwarding_profile_update", svc, resolve, loc,
		func(in LogForwardingProfileInput) string { return in.Name }, overlayLogForwarding, logForwardingSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_forwarding_profile_delete",
		Description: "Delete a log-forwarding profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete log-forwarding profile"),
	}, deleteHandler[logforwarding.Location, logforwarding.Entry](d, "panos_log_forwarding_profile_delete", svc, resolve))
}

// --- Decryption profile ------------------------------------------------------

// decryptionProfileParts supplies decryption profile locations. The name uses
// the DecryptionProfile infix throughout to avoid colliding with the decryption
// *rule* symbols in rulebase_tools.go.
func decryptionProfileParts() locParts[decryption.Location] {
	return locParts[decryption.Location]{
		shared: func(string) decryption.Location {
			return decryption.Location{Shared: &decryption.SharedLocation{}}
		},
		vsys: func(v string) decryption.Location {
			return decryption.Location{Vsys: &decryption.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) decryption.Location {
			return decryption.Location{DeviceGroup: &decryption.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newDecryptionProfileService(d *Deps) nameFixAdapter[decryption.Location, decryption.Entry] {
	return nameFixAdapter[decryption.Location, decryption.Entry]{
		svc:    decryption.NewService(d.Client),
		client: d.Client,
		name:   func(e *decryption.Entry) string { return e.Name },
	}
}

// DecryptionProfileInput is the input for decryption profile create and update.
// pango's decryption.Entry has no description field. The per-mode proxy subtrees
// (ssl-forward-proxy, ssl-inbound-proxy, ssl-no-proxy, ssh-proxy) and the
// per-algorithm SSL protocol toggles are SDK-only; read-modify-write preserves
// them across updates.
type DecryptionProfileInput struct {
	Name          string        `json:"name" jsonschema:"Decryption profile name"`
	Location      LocationInput `json:"location,omitzero"`
	ForwardedOnly *bool         `json:"forwarded_only,omitempty" jsonschema:"Decryption port mirroring: mirror decrypted traffic to the decrypt-mirror interface only after security policy enforcement (allowed traffic only), rather than before policy lookup; omit to keep the device default"`
	SslMinVersion string        `json:"ssl_min_version,omitempty" jsonschema:"Minimum SSL/TLS protocol version, e.g. tls1-0, tls1-1, tls1-2, tls1-3; device-validated. Blank leaves it unchanged"`
	SslMaxVersion string        `json:"ssl_max_version,omitempty" jsonschema:"Maximum SSL/TLS protocol version, e.g. tls1-2, tls1-3, max; device-validated. Blank leaves it unchanged"`
}

// applyDecryptionProfileSslVersions sets the protocol min/max on the EXISTING
// SslProtocolSettings, allocating only when absent: rebuilding the struct would
// drop the per-algorithm toggles this server defers to the SDK.
func applyDecryptionProfileSslVersions(e *decryption.Entry, in *DecryptionProfileInput) {
	if in.SslMinVersion == "" && in.SslMaxVersion == "" {
		return
	}
	ps := e.SslProtocolSettings
	if ps == nil {
		ps = &decryption.SslProtocolSettings{}
		e.SslProtocolSettings = ps
	}
	setStrPtr(&ps.MinVersion, in.SslMinVersion)
	setStrPtr(&ps.MaxVersion, in.SslMaxVersion)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildDecryptionProfileEntry(in DecryptionProfileInput) (*decryption.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &decryption.Entry{Name: in.Name}
	if in.ForwardedOnly != nil {
		e.ForwardedOnly = in.ForwardedOnly
	}
	applyDecryptionProfileSslVersions(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayDecryptionProfile(e *decryption.Entry, in DecryptionProfileInput) error {
	if in.ForwardedOnly != nil {
		e.ForwardedOnly = in.ForwardedOnly
	}
	applyDecryptionProfileSslVersions(e, &in)
	return nil
}

func decryptionProfileSummary(e *decryption.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putBool(m, "forwarded_only", e.ForwardedOnly)
	if ps := e.SslProtocolSettings; ps != nil {
		m["ssl_min_version"] = strVal(ps.MinVersion)
		m["ssl_max_version"] = strVal(ps.MaxVersion)
	}
	m["has_ssl_forward_proxy"] = e.SslForwardProxy != nil
	m["has_ssl_inbound_proxy"] = e.SslInboundProxy != nil
	m["has_ssl_no_proxy"] = e.SslNoProxy != nil
	m["has_ssh_proxy"] = e.SshProxy != nil
	return m
}

// RegisterDecryptionProfileTools registers the decryption profile tools. This is
// the profile at objects/profiles/decryption, distinct from the decryption
// rulebase tools.
func RegisterDecryptionProfileTools(s *mcp.Server, d *Deps) {
	svc := newDecryptionProfileService(d)
	resolve := func(in LocationInput) (decryption.Location, error) {
		return resolveLocation(d, in, decryptionProfileParts())
	}
	name := svc.name
	loc := func(in DecryptionProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_profile_list",
		Description: "List decryption profiles at a location. Read-only.",
		Annotations: readOnlyTool("List decryption profiles"),
	}, listHandler[decryption.Location, decryption.Entry](d, "panos_decryption_profile_list", svc, resolve, name, decryptionProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_profile_get",
		Description: "Get one decryption profile by name with its managed fields (forwarded_only, SSL protocol version bounds) plus presence flags for the SDK-only proxy subtrees. Read-only.",
		Annotations: readOnlyTool("Get decryption profile"),
	}, getHandler[decryption.Location, decryption.Entry](d, "panos_decryption_profile_get", svc, resolve, decryptionProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_profile_create",
		Description: "Create a decryption profile in the candidate config. A decryption rule applies it; the per-mode proxy settings beyond the SSL protocol version bounds are device defaults. Run panos_commit to apply.",
		Annotations: createTool("Create decryption profile"),
	}, createHandler[decryption.Location, decryption.Entry, DecryptionProfileInput](d, "panos_decryption_profile_create", svc, resolve, loc, buildDecryptionProfileEntry, decryptionProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_profile_update",
		Description: "Update a decryption profile: read-modify-write, only provided fields change; the SDK-only proxy subtrees and per-algorithm toggles are preserved. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update decryption profile"),
	}, updateHandler[decryption.Location, decryption.Entry, DecryptionProfileInput](d, "panos_decryption_profile_update", svc, resolve, loc,
		func(in DecryptionProfileInput) string { return in.Name }, overlayDecryptionProfile, decryptionProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_profile_delete",
		Description: "Delete a decryption profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete decryption profile"),
	}, deleteHandler[decryption.Location, decryption.Entry](d, "panos_decryption_profile_delete", svc, resolve))
}
