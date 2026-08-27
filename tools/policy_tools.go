package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	"github.com/PaloAltoNetworks/pango/movement"
	"github.com/PaloAltoNetworks/pango/policies/rules/nat"
	"github.com/PaloAltoNetworks/pango/policies/rules/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// securityParts supplies security rule locations for resolveLocation. Unlike
// the object locations, shared and device-group rulebases carry the
// pre/post-rulebase node (pango rejects an empty Rulebase for both), while a
// firewall vsys has a single rulebase and takes no rulebase argument.
func securityParts() locParts[security.Location] {
	return locParts[security.Location]{
		shared: func(rb string) security.Location {
			return security.Location{Shared: &security.SharedLocation{Rulebase: rb}}
		},
		vsys: func(v string) security.Location {
			return security.Location{Vsys: &security.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, rb string) security.Location {
			return security.Location{DeviceGroup: &security.DeviceGroupLocation{
				PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg, Rulebase: rb,
			}}
		},
		rules: true,
	}
}

// newSecurityRuleService adapts pango's security rule service to crudService
// via the shared nameFixAdapter; pango's raw-name Read/Update would otherwise
// be rejected client-side (see nameFixService).
func newSecurityRuleService(d *Deps) nameFixAdapter[security.Location, security.Entry] {
	return nameFixAdapter[security.Location, security.Entry]{
		svc:    security.NewService(d.Client),
		client: d.Client,
		name:   func(e *security.Entry) string { return e.Name },
	}
}

// SecurityRuleInput is the input for the security rule create and update
// tools. It exposes the practical writable subset of pango's 30+ field Entry;
// schedule and log_setting are settable, and the remaining advanced fields
// (individual profiles, QoS, HIP, negate flags, rule type, ...) are surfaced
// read-only by securityRuleDetail but stay SDK-only on the write path until a
// task needs them.
type SecurityRuleInput struct {
	Name         string        `json:"name" jsonschema:"Rule name"`
	Location     LocationInput `json:"location,omitzero"`
	Action       string        `json:"action,omitempty" jsonschema:"allow, deny, drop, reset-client, reset-server or reset-both; required on create, no default"`
	From         []string      `json:"from,omitempty" jsonschema:"Source zones (create default: any); a non-empty list replaces fully"`
	To           []string      `json:"to,omitempty" jsonschema:"Destination zones (create default: any); a non-empty list replaces fully"`
	Source       []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination  []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Application  []string      `json:"application,omitempty" jsonschema:"Applications (create default: any); a non-empty list replaces fully"`
	Service      []string      `json:"service,omitempty" jsonschema:"Services (create default: application-default); a non-empty list replaces fully"`
	Description  string        `json:"description,omitempty"`
	Tags         []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled     *bool         `json:"disabled,omitempty"`
	ProfileGroup string        `json:"profile_group,omitempty" jsonschema:"Security profile group applied to matching traffic; a provided value replaces the whole profile-setting subtree (clearing any individually assigned profiles). Individual per-type profile assignment is not modelled here."`
	Schedule     string        `json:"schedule,omitempty" jsonschema:"Schedule object name limiting when the rule is active (see panos_schedule_list); a non-empty value sets it, blank leaves it unchanged (clearing in place is not supported)"`
	LogSetting   string        `json:"log_setting,omitempty" jsonschema:"Log-forwarding profile name applied to matching traffic (see panos_log_forwarding_profile_list); a non-empty value sets it, blank leaves it unchanged (clearing in place is not supported)"`
	Position     string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo   string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
}

// validRuleActions are the PAN-OS security rule verdicts.
var validRuleActions = map[string]bool{
	"allow": true, "deny": true, "drop": true,
	"reset-client": true, "reset-server": true, "reset-both": true,
}

// securityActionList is the human-readable verdict list for error messages,
// kept in sync with validRuleActions by review (map iteration order would make
// a derived message non-deterministic).
const securityActionList = "allow, deny, drop, reset-client, reset-server, reset-both"

// orAny returns v, or ["any"] when v is empty: the PAN-OS GUI default for
// rule match fields, and the smallest value that keeps the rule commit-valid.
func orAny(v []string) []string {
	if len(v) == 0 {
		return []string{"any"}
	}
	return v
}

// applyRuleProfileGroup sets a profile group on a rule, clearing any
// individually assigned profiles so the group/profiles oneof is never both-set
// (PAN-OS rejects that), while preserving unknown profile-setting XML
// (Misc/MiscAttributes) across a read-modify-write update. A blank group leaves
// the setting untouched: an existing group cannot be cleared in place, matching
// the other single-value fields.
func applyRuleProfileGroup(e *security.Entry, group string) {
	if group == "" {
		return
	}
	ps := e.ProfileSetting
	if ps == nil {
		ps = &security.ProfileSetting{}
	}
	ps.Group = []string{group}
	ps.Profiles = nil
	e.ProfileSetting = ps
}

// buildSecurityRuleEntry validates input and builds a create entry with the
// PAN-OS-conventional defaults: the match fields default to any and service
// to application-default, mirroring what the GUI pre-fills for a new rule (a
// rule with an empty match member list fails commit validation on the device;
// this is PAN-OS domain knowledge, not exercised by the unit tests, which run
// against a fake API that never commits), and application-default is
// deliberately tighter than any. action is required
// with NO default: a firewall rule's verdict is a security decision the
// caller must make explicitly, never a silent default.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildSecurityRuleEntry(in SecurityRuleInput) (*security.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Action == "" {
		return nil, fmt.Errorf("action is required (one of %s)", securityActionList)
	}
	if !validRuleActions[in.Action] {
		return nil, fmt.Errorf("action must be one of %s; got %q", securityActionList, in.Action)
	}
	svc := in.Service
	if len(svc) == 0 {
		svc = []string{"application-default"}
	}
	e := &security.Entry{
		Name:        in.Name,
		Action:      new(in.Action),
		From:        orAny(in.From),
		To:          orAny(in.To),
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Application: orAny(in.Application),
		Service:     svc,
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	setStrPtr(&e.Description, in.Description)
	setStrPtr(&e.Schedule, in.Schedule)
	setStrPtr(&e.LogSetting, in.LogSetting)
	applyRuleProfileGroup(e, in.ProfileGroup)
	return e, nil
}

// overlaySecurityRule applies only the provided fields onto the current
// entry. The six match lists replace only when non-empty: a rule cannot have
// zero zones/addresses/applications/services (PAN-OS rejects that at
// commit), so a reset is expressed as ["any"], and both an omitted and an
// explicitly empty list leave the field unchanged. tags replace when
// non-nil, so an empty list clears them. description and schedule are
// single-value fields: a non-empty value sets them, a blank leaves them
// unchanged (clearing in place is not supported, matching profile_group).
// position/relative_to are ignored here; the move tool owns placement.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlaySecurityRule(e *security.Entry, in SecurityRuleInput) error {
	if in.Action != "" {
		if !validRuleActions[in.Action] {
			return fmt.Errorf("action must be one of %s; got %q", securityActionList, in.Action)
		}
		e.Action = new(in.Action)
	}
	if len(in.From) > 0 {
		e.From = in.From
	}
	if len(in.To) > 0 {
		e.To = in.To
	}
	if len(in.Source) > 0 {
		e.Source = in.Source
	}
	if len(in.Destination) > 0 {
		e.Destination = in.Destination
	}
	if len(in.Application) > 0 {
		e.Application = in.Application
	}
	if len(in.Service) > 0 {
		e.Service = in.Service
	}
	setStrPtr(&e.Description, in.Description)
	setStrPtr(&e.Schedule, in.Schedule)
	setStrPtr(&e.LogSetting, in.LogSetting)
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	applyRuleProfileGroup(e, in.ProfileGroup)
	return nil
}

// securityRuleProfileGroup returns the profile group applied to a rule, or "".
// A rule may instead carry individually assigned profiles (pango's
// ProfileSetting.Profiles branch), which this server does not model;
// securityRuleHasIndividualProfiles reports that branch so a get does not
// conflate it with a rule that has no security profiles at all.
func securityRuleProfileGroup(ps *security.ProfileSetting) string {
	if ps == nil {
		return ""
	}
	return firstMember(ps.Group)
}

// securityRuleHasIndividualProfiles reports whether the rule assigns profiles
// per type instead of a group. That subtree is SDK-only here, so the read tools
// surface only its presence.
func securityRuleHasIndividualProfiles(ps *security.ProfileSetting) bool {
	return ps != nil && ps.Profiles != nil
}

// securityRuleSummaryMap reduces an entry to the list view fields on top of the
// shared name/description/tags base. It returns the concrete map so
// securityRuleDetail can layer the advanced read-only fields on top without a
// type assertion (issue #51).
func securityRuleSummaryMap(e *security.Entry) map[string]any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["action"] = strVal(e.Action)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["application"] = e.Application
	m["service"] = e.Service
	m["disabled"] = e.Disabled != nil && *e.Disabled
	m["profile_group"] = securityRuleProfileGroup(e.ProfileSetting)
	m["has_individual_profiles"] = securityRuleHasIndividualProfiles(e.ProfileSetting)
	return m
}

// securityRuleSummary is the compact list-view projection; it adapts
// securityRuleSummaryMap to the func(*E) any signature listHandler expects.
func securityRuleSummary(e *security.Entry) any {
	return securityRuleSummaryMap(e)
}

// securityRuleIndividualProfiles projects the security profiles a rule assigns
// per type directly (pango's ProfileSetting.Profiles branch), one scalar
// reference per type, including only the types that are set. It returns nil when
// the rule assigns no individual profiles (it uses a group, or none), so a get
// omits the key rather than emitting an empty object. gtp/sctp (mobile-core
// protection) stay SDK-only as niche.
func securityRuleIndividualProfiles(ps *security.ProfileSetting) map[string]any {
	if ps == nil || ps.Profiles == nil {
		return nil
	}
	p := ps.Profiles
	out := map[string]any{}
	set := func(key string, v []string) {
		if m := firstMember(v); m != "" {
			out[key] = m
		}
	}
	set("antivirus", p.Virus)
	set("anti_spyware", p.Spyware)
	set("vulnerability", p.Vulnerability)
	set("url_filtering", p.UrlFiltering)
	set("file_blocking", p.FileBlocking)
	set("wildfire_analysis", p.WildfireAnalysis)
	set("data_filtering", p.DataFiltering)
	if len(out) == 0 {
		return nil
	}
	return out
}

// securityRuleDetail is the get/create/update projection for a security rule:
// the compact list fields plus the advanced read-only fields pango carries on
// the Entry (schedule, category, rule type, logging, negate flags, source
// users, HIP profiles, group tag, uuid, the individually assigned profiles, and
// presence flags for the QoS and Panorama-target subtrees this server does not
// manage). list keeps the compact securityRuleSummary (issue #51), mirroring
// natRuleSummary/natRuleDetail.
func securityRuleDetail(e *security.Entry) any {
	m := securityRuleSummaryMap(e)
	m["schedule"] = strVal(e.Schedule)
	m["rule_type"] = strVal(e.RuleType)
	m["log_setting"] = strVal(e.LogSetting)
	// setBool records an advanced *bool flag only when the rule explicitly sets
	// the element (present-as-no -> false, present-as-yes -> true); an absent
	// element omits the key rather than reporting a hard false, so the
	// projection reports only what the rule states and never guesses PAN-OS's
	// default for an unset element (MEASURED against PA-VM 12.1.7: a freshly
	// created rule's config carries no <log-start>/<log-end>). Mirrors
	// natRuleDetail, which omits absent translation fields.
	setBool := func(key string, v *bool) {
		if v != nil {
			m[key] = *v
		}
	}
	setBool("log_start", e.LogStart)
	setBool("log_end", e.LogEnd)
	setBool("negate_source", e.NegateSource)
	setBool("negate_destination", e.NegateDestination)
	setBool("disable_server_response_inspection", e.DisableServerResponseInspection)
	setBool("icmp_unreachable", e.IcmpUnreachable)
	m["group_tag"] = strVal(e.GroupTag)
	m["uuid"] = strVal(e.Uuid)
	m["has_qos"] = e.Qos != nil
	m["has_target"] = e.Target != nil
	// Optional scope lists: omit when empty to avoid JSON null noise, matching
	// natRuleDetail's snat_addresses.
	if len(e.Category) > 0 {
		m["category"] = e.Category
	}
	if len(e.SourceUser) > 0 {
		m["source_user"] = e.SourceUser
	}
	if len(e.SourceHip) > 0 {
		m["source_hip"] = e.SourceHip
	}
	if len(e.DestinationHip) > 0 {
		m["destination_hip"] = e.DestinationHip
	}
	if profiles := securityRuleIndividualProfiles(e.ProfileSetting); profiles != nil {
		m["profiles"] = profiles
	}
	return m
}

// movePosition maps the tool-level position words onto pango movement
// positions. before/after require relative_to and place the rule DIRECTLY
// against the pivot (Directly: true): "move X before Y" means immediately
// before, and pango would otherwise treat any earlier slot as already
// satisfied and do nothing. top/bottom reject a relative_to so a confused
// call gets an error instead of a silently dropped argument. Shared by all
// the rule tools.
func movePosition(position, relativeTo string) (movement.Position, error) {
	switch position {
	case "top":
		if relativeTo != "" {
			return nil, fmt.Errorf("relative_to applies only to before/after, not %q", position)
		}
		return movement.PositionFirst{}, nil
	case "bottom":
		if relativeTo != "" {
			return nil, fmt.Errorf("relative_to applies only to before/after, not %q", position)
		}
		return movement.PositionLast{}, nil
	case "before":
		if relativeTo == "" {
			return nil, fmt.Errorf("relative_to is required for position %s", position)
		}
		return movement.PositionBefore{Directly: true, Pivot: relativeTo}, nil
	case "after":
		if relativeTo == "" {
			return nil, fmt.Errorf("relative_to is required for position %s", position)
		}
		return movement.PositionAfter{Directly: true, Pivot: relativeTo}, nil
	default:
		return nil, fmt.Errorf("position must be top, bottom, before or after; got %q", position)
	}
}

// MoveInput is the input for the rule move tools.
type MoveInput struct {
	Name       string        `json:"name" jsonschema:"Rule name to move"`
	Location   LocationInput `json:"location,omitzero"`
	Position   string        `json:"position" jsonschema:"top, bottom, before or after"`
	RelativeTo string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after"`
}

// ruleMover is the one move capability the rule tools need from a raw pango
// rule service. MoveGroup is not part of crudService and the shared
// nameFixAdapter hides its underlying service, so the registration function
// passes the raw service separately for moves. Generic so every rule tool
// shares moveHandler.
type ruleMover[L, E any] interface {
	MoveGroup(ctx context.Context, loc L, position movement.Position, entries []*E, batchSize int) error
}

// moveHandler builds a rule move tool handler: verify the rule exists via
// the name-fixed read (pango's own missing-entry failure inside MoveGroup is
// an unhelpful slice-length error), then let pango compute and issue the
// minimal move operations. MoveGroup lists the rulebase itself and issues
// nothing when the rule already sits at the requested position, so the move
// is idempotent. The write lock covers the read-then-move pair.
func moveHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E], mover ruleMover[L, E],
	resolve func(LocationInput) (L, error),
) func(context.Context, *mcp.CallToolRequest, MoveInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MoveInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		pos, err := movePosition(in.Position, in.RelativeTo)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		loc, err := resolve(in.Location)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		entry, err := svc.Read(ctx, loc, in.Name, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: read %q: %v", tool, in.Name, err)
			return res, v, nil
		}
		if err := mover.MoveGroup(ctx, loc, pos, []*E{entry}, 1); err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		place := in.Position
		if in.RelativeTo != "" {
			place += " " + in.RelativeTo
		}
		res, v := successResult(d.Logger, tool, "moved %q to %s in the candidate config; run panos_commit to apply", in.Name, place)
		return res, v, nil
	}
}

// ruleCreator is the create-and-position surface of a raw pango rule
// service: Create plus the MoveGroup capability shared with moveHandler.
// The create handlers take the raw service alone: nameFixAdapter's Create
// is a pass-through, so raw Create is wire-identical, and MoveGroup only
// exists on the raw service.
type ruleCreator[L, E any] interface {
	Create(ctx context.Context, loc L, entry *E) (*E, error)
	ruleMover[L, E]
}

// ruleCreateHandler builds a rule create tool handler: build and validate
// the entry, validate any requested position BEFORE creating (a malformed
// call leaves no rule behind), create under the write lock, then optionally
// position the new rule via MoveGroup. A position whose relative_to names a
// rule that does not exist passes the syntax check but fails at MoveGroup
// after the create; the result then reports the rule was created but left
// at the rulebase bottom, never silently mispositioned. Shared by the
// rule create tools.
func ruleCreateHandler[L, E, In any](
	d *Deps, tool string, svc ruleCreator[L, E],
	resolve func(LocationInput) (L, error),
	build func(In) (*E, error),
	location func(In) LocationInput,
	name func(In) string,
	posOf func(In) (pos, relativeTo string),
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		entry, err := build(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		var pos movement.Position
		if p, rel := posOf(in); p != "" {
			if pos, err = movePosition(p, rel); err != nil {
				res, v := errorResult("%s: %v", tool, err)
				return res, v, nil
			}
		}
		loc, err := resolve(location(in))
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		created, err := svc.Create(ctx, loc, entry)
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		if pos != nil {
			if err := svc.MoveGroup(ctx, loc, pos, []*E{created}, 1); err != nil {
				d.Logger.Error("failed: "+tool+" move", "error", err)
				res, v := errorResult("rule %q was created but positioning failed: %v; the rule sits at the rulebase bottom", name(in), err)
				return res, v, nil
			}
		}
		d.Logger.Info(tool+" succeeded", "name", name(in))
		res, v := jsonResult(summarize(created))
		return res, v, nil
	}
}

// securityRuleCreateHandler creates a rule and optionally positions it via
// the shared ruleCreateHandler. It is custom rather than the generic
// createHandler because create applies the security defaults (see
// buildSecurityRuleEntry) and supports placement, which needs MoveGroup on
// the raw service (see ruleCreator).
func securityRuleCreateHandler(d *Deps, svc *security.Service) func(context.Context, *mcp.CallToolRequest, SecurityRuleInput) (*mcp.CallToolResult, any, error) {
	return ruleCreateHandler[security.Location, security.Entry, SecurityRuleInput](
		d, "panos_security_rule_create", svc,
		func(in LocationInput) (security.Location, error) { return resolveLocation(d, in, securityParts()) },
		buildSecurityRuleEntry,
		func(in SecurityRuleInput) LocationInput { return in.Location },
		func(in SecurityRuleInput) string { return in.Name },
		func(in SecurityRuleInput) (string, string) { return in.Position, in.RelativeTo },
		securityRuleDetail,
	)
}

// RegisterSecurityRuleTools registers the security rule tools. All four
// mutating tools, including move, are skipped entirely in read-only mode.
func RegisterSecurityRuleTools(s *mcp.Server, d *Deps) {
	svc := newSecurityRuleService(d)
	raw := security.NewService(d.Client)
	resolve := func(in LocationInput) (security.Location, error) { return resolveLocation(d, in, securityParts()) }
	name := svc.name
	loc := func(in SecurityRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_list",
		Description: "List security rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List security rules"),
	}, listHandler[security.Location, security.Entry](d, "panos_security_rule_list", svc, resolve, name, securityRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_get",
		Description: "Get one security rule by name with the managed fields plus the advanced read-only detail (schedule, rule type, logging, negate flags, source users, HIP profiles, category, group tag, uuid, and any individually assigned security profiles). Read-only.",
		Annotations: readOnlyTool("Get security rule"),
	}, getHandler[security.Location, security.Entry](d, "panos_security_rule_get", svc, resolve, securityRuleDetail))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_create",
		Description: "Create a security rule in the candidate config. action is required and has no default; zones, addresses and applications default to any, service to application-default. Optional schedule limits when the rule is active. Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create security rule"),
	}, securityRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_update",
		Description: "Update a security rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). A provided profile_group replaces the whole profile-setting subtree; a provided schedule sets the rule's schedule (blank leaves it unchanged). position is ignored here; use panos_security_rule_move. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update security rule"),
	}, updateHandler[security.Location, security.Entry, SecurityRuleInput](d, "panos_security_rule_update", svc, resolve, loc,
		func(in SecurityRuleInput) string { return in.Name }, overlaySecurityRule, securityRuleDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_delete",
		Description: "Delete a security rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete security rule"),
	}, deleteHandler[security.Location, security.Entry](d, "panos_security_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_move",
		Description: "Move a security rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Move security rule"),
	}, moveHandler[security.Location, security.Entry](d, "panos_security_rule_move", svc, raw, resolve))
}

// natParts supplies NAT rule locations for resolveLocation. Same layout as
// securityParts: shared and device-group rulebases carry the
// pre/post-rulebase node, a firewall vsys has a single rulebase.
func natParts() locParts[nat.Location] {
	return locParts[nat.Location]{
		shared: func(rb string) nat.Location {
			return nat.Location{Shared: &nat.SharedLocation{Rulebase: rb}}
		},
		vsys: func(v string) nat.Location {
			return nat.Location{Vsys: &nat.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, rb string) nat.Location {
			return nat.Location{DeviceGroup: &nat.DeviceGroupLocation{
				PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg, Rulebase: rb,
			}}
		},
		rules: true,
	}
}

// newNatRuleService adapts pango's NAT rule service to crudService via the
// shared nameFixAdapter; pango's raw-name Read/Update would otherwise be
// rejected client-side (see nameFixService).
func newNatRuleService(d *Deps) nameFixAdapter[nat.Location, nat.Entry] {
	return nameFixAdapter[nat.Location, nat.Entry]{
		svc:    nat.NewService(d.Client),
		client: d.Client,
		name:   func(e *nat.Entry) string { return e.Name },
	}
}

// NatRuleInput is the input for the NAT rule create and update tools. The
// flat translation fields cover the two common cases: source NAT via the
// egress interface address or an address pool (both dynamic-ip-and-port),
// and static destination NAT. Other translation forms (dynamic-ip, static-ip,
// dynamic destination translation, DNS rewrite) stay SDK-only until a task
// needs them, and clearing an existing translation, or just its translated
// port, is not expressible here.
type NatRuleInput struct {
	Name          string        `json:"name" jsonschema:"Rule name"`
	Location      LocationInput `json:"location,omitzero"`
	From          []string      `json:"from,omitempty" jsonschema:"Source zones (create default: any); a non-empty list replaces fully"`
	To            []string      `json:"to,omitempty" jsonschema:"Destination zones (create default: any); a non-empty list replaces fully"`
	Source        []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination   []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Service       string        `json:"service,omitempty" jsonschema:"Service name, a single service or any (create default: any)"`
	SNATInterface string        `json:"snat_interface,omitempty" jsonschema:"Source NAT to this egress interface address (dynamic IP and port); mutually exclusive with snat_addresses"`
	SNATAddresses []string      `json:"snat_addresses,omitempty" jsonschema:"Source NAT to this translated address pool (dynamic IP and port); mutually exclusive with snat_interface"`
	DNATAddress   string        `json:"dnat_address,omitempty" jsonschema:"Destination NAT translated address"`
	DNATPort      *int64        `json:"dnat_port,omitempty" jsonschema:"Destination NAT translated port, 1-65535 (requires dnat_address); on update an omitted port keeps the rule's existing translated port"`
	NatType       string        `json:"nat_type,omitempty" jsonschema:"ipv4, nat64 or nptv6 (device default: ipv4)"`
	ToInterface   string        `json:"to_interface,omitempty" jsonschema:"Egress interface constraint for the destination zone"`
	Description   string        `json:"description,omitempty"`
	Tags          []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled      *bool         `json:"disabled,omitempty"`
	Position      string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo    string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
}

// validNatTypes are the PAN-OS nat-type values.
var validNatTypes = map[string]bool{"ipv4": true, "nat64": true, "nptv6": true}

// natTypeList is the human-readable nat-type list for error messages, kept in
// sync with validNatTypes by review (map iteration order would make a derived
// message non-deterministic).
const natTypeList = "ipv4, nat64, nptv6"

// applyNatTranslations validates the flat translation fields and applies them
// onto the entry. A provided SNAT input REPLACES the whole source-translation
// subtree; a provided DNAT input MERGES into any existing destination-
// translation, and unset inputs leave the existing subtree untouched. The
// asymmetry is deliberate. For DNAT the translated address is overwritten and
// the translated port is overwritten only when dnat_port is provided, so an
// existing port (or dns-rewrite) the caller did not mention is preserved:
// replacing the whole subtree on an address-only update would silently drop the
// port, widening a port-forward into a full-IP DNAT. Clearing a port is not
// expressible here; delete and recreate the rule. On create the entry carries
// no destination-translation, so the merge starts fresh and dnat_address alone
// yields address-only DNAT. For SNAT the provided form IS the entire new
// translation (snat_interface and snat_addresses are mutually exclusive), so a
// merge would be incoherent and whole-subtree replace is correct.
// snat_interface and snat_addresses are mutually exclusive: dynamic-ip-and-port
// source NAT translates via EITHER the interface address OR a translated
// address pool. pango models both as independent optional fields and does not
// enforce the choice; that either/or is PAN-OS domain knowledge, not verified
// against a live device this session, so this rejects a combined call
// client-side rather than send an ambiguous mapping (a wrong SNAT mapping is a
// live traffic-rewriting bug). dnat_port alone is rejected: destination
// translation requires a translated address.
//
//nolint:gocritic // hugeParam: in is read-only and passed by value to mirror the buildNatRuleEntry/overlayNatRule callers that share it; see buildAddressEntry.
func applyNatTranslations(e *nat.Entry, in NatRuleInput) error {
	if in.SNATInterface != "" && len(in.SNATAddresses) > 0 {
		return errors.New("provide snat_interface or snat_addresses, not both: dynamic-ip-and-port source NAT translates via the interface address or an address pool, never both")
	}
	if in.SNATInterface != "" {
		e.SourceTranslation = &nat.SourceTranslation{
			DynamicIpAndPort: &nat.SourceTranslationDynamicIpAndPort{
				InterfaceAddress: &nat.SourceTranslationDynamicIpAndPortInterfaceAddress{
					Interface: new(in.SNATInterface),
				},
			},
		}
	}
	if len(in.SNATAddresses) > 0 {
		e.SourceTranslation = &nat.SourceTranslation{
			DynamicIpAndPort: &nat.SourceTranslationDynamicIpAndPort{
				TranslatedAddress: in.SNATAddresses,
			},
		}
	}
	if in.DNATPort != nil && in.DNATAddress == "" {
		return errors.New("dnat_port requires dnat_address")
	}
	if in.DNATPort != nil && (*in.DNATPort < 1 || *in.DNATPort > 65535) {
		return fmt.Errorf("dnat_port must be between 1 and 65535, got %d", *in.DNATPort)
	}
	if in.DNATAddress != "" {
		// Merge into any existing destination-translation instead of rebuilding
		// it: overwrite the address, overwrite the port only when provided, and
		// leave an unmentioned port (or dns-rewrite) in place. On create the
		// entry has no subtree, so this starts fresh. See the doc comment above.
		dt := e.DestinationTranslation
		if dt == nil {
			dt = &nat.DestinationTranslation{}
		}
		dt.TranslatedAddress = new(in.DNATAddress)
		if in.DNATPort != nil {
			dt.TranslatedPort = new(*in.DNATPort)
		}
		e.DestinationTranslation = dt
	}
	return nil
}

// buildNatRuleEntry validates input and builds a create entry with the
// PAN-OS-conventional defaults: the four match fields default to any and
// service to "any", mirroring what the GUI pre-fills for a new NAT rule
// (service is a single value here, not a list, and application-default does
// not exist for NAT); this is PAN-OS domain knowledge, not exercised by the
// unit tests, which run against a fake API that never commits. Unlike security
// rules there is no verdict, so nothing beyond the name is required.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildNatRuleEntry(in NatRuleInput) (*nat.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.NatType != "" && !validNatTypes[in.NatType] {
		return nil, fmt.Errorf("nat_type must be one of %s; got %q", natTypeList, in.NatType)
	}
	svc := cmp.Or(in.Service, "any")
	e := &nat.Entry{
		Name:        in.Name,
		From:        orAny(in.From),
		To:          orAny(in.To),
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Service:     new(svc),
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	setStrPtr(&e.NatType, in.NatType)
	setStrPtr(&e.ToInterface, in.ToInterface)
	setStrPtr(&e.Description, in.Description)
	if err := applyNatTranslations(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

// overlayNatRule applies only the provided fields onto the current entry.
// The four match lists replace only when non-empty (a rule cannot have zero
// zones/addresses; a reset is expressed as ["any"], and both an omitted and
// an explicitly empty list leave the field unchanged). tags replace when
// non-nil, so an empty list clears them. SNAT inputs replace their whole
// subtree and DNAT inputs merge into it, via applyNatTranslations (so an
// address-only DNAT update keeps the existing translated port);
// position/relative_to are ignored here, the move tool owns placement.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayNatRule(e *nat.Entry, in NatRuleInput) error {
	if in.NatType != "" {
		if !validNatTypes[in.NatType] {
			return fmt.Errorf("nat_type must be one of %s; got %q", natTypeList, in.NatType)
		}
		e.NatType = new(in.NatType)
	}
	if len(in.From) > 0 {
		e.From = in.From
	}
	if len(in.To) > 0 {
		e.To = in.To
	}
	if len(in.Source) > 0 {
		e.Source = in.Source
	}
	if len(in.Destination) > 0 {
		e.Destination = in.Destination
	}
	setStrPtr(&e.Service, in.Service)
	setStrPtr(&e.ToInterface, in.ToInterface)
	setStrPtr(&e.Description, in.Description)
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	return applyNatTranslations(e, in)
}

// natRuleCreateHandler creates a NAT rule and optionally positions it via
// the shared ruleCreateHandler (see that handler for the ordering and
// partial-failure contract).
func natRuleCreateHandler(d *Deps, svc *nat.Service) func(context.Context, *mcp.CallToolRequest, NatRuleInput) (*mcp.CallToolResult, any, error) {
	return ruleCreateHandler[nat.Location, nat.Entry, NatRuleInput](
		d, "panos_nat_rule_create", svc,
		func(in LocationInput) (nat.Location, error) { return resolveLocation(d, in, natParts()) },
		buildNatRuleEntry,
		func(in NatRuleInput) LocationInput { return in.Location },
		func(in NatRuleInput) string { return in.Name },
		func(in NatRuleInput) (string, string) { return in.Position, in.RelativeTo },
		natRuleDetail,
	)
}

// natRuleSummary reduces an entry to the list view fields on top of the
// shared name/description/tags base. The translation subtrees are deep; the
// summary carries presence flags and leaves the detail to the get tool.
func natRuleSummary(e *nat.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["service"] = strVal(e.Service)
	m["nat_type"] = strVal(e.NatType)
	m["has_source_translation"] = e.SourceTranslation != nil
	m["has_destination_translation"] = e.DestinationTranslation != nil
	m["disabled"] = e.Disabled != nil && *e.Disabled
	return m
}

// natRuleDetail is the get/create/update projection for a NAT rule: the list
// fields plus the flattened translation details and to_interface, so a get
// returns exactly what create and update accept (snat_interface/snat_addresses,
// dnat_address/dnat_port). list keeps natRuleSummary's compact
// has_*_translation booleans (issue #48).
func natRuleDetail(e *nat.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["service"] = strVal(e.Service)
	m["nat_type"] = strVal(e.NatType)
	m["to_interface"] = strVal(e.ToInterface)
	m["disabled"] = e.Disabled != nil && *e.Disabled
	// Flatten the source translation (dynamic-ip-and-port: egress interface or
	// a translated-address pool, mutually exclusive per applyNatTranslations).
	if st := e.SourceTranslation; st != nil && st.DynamicIpAndPort != nil {
		dip := st.DynamicIpAndPort
		if dip.InterfaceAddress != nil {
			m["snat_interface"] = strVal(dip.InterfaceAddress.Interface)
		}
		if len(dip.TranslatedAddress) > 0 {
			m["snat_addresses"] = dip.TranslatedAddress
		}
	}
	// Flatten the destination translation (address and optional port).
	if dt := e.DestinationTranslation; dt != nil {
		m["dnat_address"] = strVal(dt.TranslatedAddress)
		if dt.TranslatedPort != nil {
			m["dnat_port"] = *dt.TranslatedPort
		}
	}
	return m
}

// RegisterNatRuleTools registers the NAT rule tools. All four mutating
// tools, including move, are skipped entirely in read-only mode.
func RegisterNatRuleTools(s *mcp.Server, d *Deps) {
	svc := newNatRuleService(d)
	raw := nat.NewService(d.Client)
	resolve := func(in LocationInput) (nat.Location, error) { return resolveLocation(d, in, natParts()) }
	name := svc.name
	loc := func(in NatRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_list",
		Description: "List NAT rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List NAT rules"),
	}, listHandler[nat.Location, nat.Entry](d, "panos_nat_rule_list", svc, resolve, name, natRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_get",
		Description: "Get one NAT rule by name with the fields this server manages, including the flattened source and destination translation details. Read-only.",
		Annotations: readOnlyTool("Get NAT rule"),
	}, getHandler[nat.Location, nat.Entry](d, "panos_nat_rule_get", svc, resolve, natRuleDetail))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_create",
		Description: "Create a NAT rule in the candidate config. Zones, addresses and service default to any. Source NAT via snat_interface OR snat_addresses (not both); destination NAT via dnat_address with optional dnat_port. Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create NAT rule"),
	}, natRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_update",
		Description: "Update a NAT rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). A provided snat_ field replaces the WHOLE source translation; a provided dnat_address MERGES into the existing destination translation, so omitting dnat_port keeps the rule's existing translated port (clearing a translation, or just its port, is not supported here: delete and recreate). position is ignored; use panos_nat_rule_move. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update NAT rule"),
	}, updateHandler[nat.Location, nat.Entry, NatRuleInput](d, "panos_nat_rule_update", svc, resolve, loc,
		func(in NatRuleInput) string { return in.Name }, overlayNatRule, natRuleDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_delete",
		Description: "Delete a NAT rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete NAT rule"),
	}, deleteHandler[nat.Location, nat.Entry](d, "panos_nat_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_nat_rule_move",
		Description: "Move a NAT rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Move NAT rule"),
	}, moveHandler[nat.Location, nat.Entry](d, "panos_nat_rule_move", svc, raw, resolve))
}
