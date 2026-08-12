package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/PaloAltoNetworks/pango/movement"
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
// tools. It exposes the practical subset of pango's 30+ field Entry; the
// remaining fields (profiles, QoS, HIP, schedule, log settings, ...) stay
// SDK-only until a task needs them.
type SecurityRuleInput struct {
	Name        string        `json:"name" jsonschema:"Rule name"`
	Location    LocationInput `json:"location,omitempty"`
	Action      string        `json:"action,omitempty" jsonschema:"allow, deny, drop, reset-client, reset-server or reset-both; required on create, no default"`
	From        []string      `json:"from,omitempty" jsonschema:"Source zones (create default: any); a non-empty list replaces fully"`
	To          []string      `json:"to,omitempty" jsonschema:"Destination zones (create default: any); a non-empty list replaces fully"`
	Source      []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Application []string      `json:"application,omitempty" jsonschema:"Applications (create default: any); a non-empty list replaces fully"`
	Service     []string      `json:"service,omitempty" jsonschema:"Services (create default: application-default); a non-empty list replaces fully"`
	Description string        `json:"description,omitempty"`
	Tags        []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled    *bool         `json:"disabled,omitempty"`
	Position    string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo  string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
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
		Action:      ptr(in.Action),
		From:        orAny(in.From),
		To:          orAny(in.To),
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Application: orAny(in.Application),
		Service:     svc,
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return e, nil
}

// overlaySecurityRule applies only the provided fields onto the current
// entry. The six match lists replace only when non-empty: a rule cannot have
// zero zones/addresses/applications/services (PAN-OS rejects that at
// commit), so a reset is expressed as ["any"], and both an omitted and an
// explicitly empty list leave the field unchanged. tags replace when
// non-nil, so an empty list clears them. position/relative_to are ignored
// here; the move tool owns placement.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlaySecurityRule(e *security.Entry, in SecurityRuleInput) error {
	if in.Action != "" {
		if !validRuleActions[in.Action] {
			return fmt.Errorf("action must be one of %s; got %q", securityActionList, in.Action)
		}
		e.Action = ptr(in.Action)
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
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	return nil
}

// securityRuleSummary reduces an entry to the list view fields on top of the
// shared name/description/tags base.
func securityRuleSummary(e *security.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["action"] = strVal(e.Action)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["application"] = e.Application
	m["service"] = e.Service
	m["disabled"] = e.Disabled != nil && *e.Disabled
	return m
}

// movePosition maps the tool-level position words onto pango movement
// positions. before/after require relative_to and place the rule DIRECTLY
// against the pivot (Directly: true): "move X before Y" means immediately
// before, and pango would otherwise treat any earlier slot as already
// satisfied and do nothing. top/bottom reject a relative_to so a confused
// call gets an error instead of a silently dropped argument. Shared with the
// NAT rule tools (Task 10).
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

// MoveInput is the input for the rule move tools (security here, NAT in
// Task 10).
type MoveInput struct {
	Name       string        `json:"name" jsonschema:"Rule name to move"`
	Location   LocationInput `json:"location,omitempty"`
	Position   string        `json:"position" jsonschema:"top, bottom, before or after"`
	RelativeTo string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after"`
}

// ruleMover is the one move capability the rule tools need from a raw pango
// rule service. MoveGroup is not part of crudService and the shared
// nameFixAdapter hides its underlying service, so the registration function
// passes the raw service separately for moves. Generic so the NAT rule tools
// (Task 10) reuse moveHandler unchanged.
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

// securityRuleCreateHandler creates a rule and optionally positions it. It
// is custom rather than the generic createHandler because create applies the
// security defaults (see buildSecurityRuleEntry) and supports placement,
// which needs MoveGroup. It takes the raw service alone: nameFixAdapter's
// Create is a pass-through, so raw Create is wire-identical, and MoveGroup
// only exists on the raw service. A syntactically invalid position (an unknown
// keyword, or before/after with no relative_to) is rejected BEFORE the rule is
// created, so a malformed call leaves no rule behind. A position whose
// relative_to names a rule that does not exist passes that syntax check but
// fails at MoveGroup after the create; the rule is then created and the result
// reports it was left at the rulebase bottom, never silently mispositioned.
func securityRuleCreateHandler(d *Deps, svc *security.Service) func(context.Context, *mcp.CallToolRequest, SecurityRuleInput) (*mcp.CallToolResult, any, error) {
	const tool = "panos_security_rule_create"
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SecurityRuleInput) (*mcp.CallToolResult, any, error) {
		entry, err := buildSecurityRuleEntry(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		var pos movement.Position
		if in.Position != "" {
			if pos, err = movePosition(in.Position, in.RelativeTo); err != nil {
				res, v := errorResult("%s: %v", tool, err)
				return res, v, nil
			}
		}
		loc, err := resolveLocation(d, in.Location, securityParts())
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
			if err := svc.MoveGroup(ctx, loc, pos, []*security.Entry{created}, 1); err != nil {
				d.Logger.Error("failed: "+tool+" move", "error", err)
				res, v := errorResult("rule %q was created but positioning failed: %v; the rule sits at the rulebase bottom", in.Name, err)
				return res, v, nil
			}
		}
		d.Logger.Info(tool+" succeeded", "name", in.Name)
		res, v := jsonResult(created)
		return res, v, nil
	}
}

// RegisterSecurityRuleTools registers the security rule tools. All four
// mutating tools, including move, are skipped entirely in read-only mode.
func RegisterSecurityRuleTools(s *mcp.Server, d *Deps) {
	svc := newSecurityRuleService(d)
	raw := security.NewService(d.Client)
	resolve := func(in LocationInput) (security.Location, error) { return resolveLocation(d, in, securityParts()) }
	name := func(e *security.Entry) string { return e.Name }
	loc := func(in SecurityRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_list",
		Description: "List security rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List security rules"),
	}, listHandler[security.Location, security.Entry](d, "panos_security_rule_list", svc, resolve, name, securityRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_get",
		Description: "Get one security rule by name with all fields. Read-only.",
		Annotations: readOnlyTool("Get security rule"),
	}, getHandler[security.Location, security.Entry](d, "panos_security_rule_get", svc, resolve))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_create",
		Description: "Create a security rule in the candidate config. action is required and has no default; zones, addresses and applications default to any, service to application-default. Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create security rule"),
	}, securityRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_update",
		Description: "Update a security rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). position is ignored here; use panos_security_rule_move. Candidate config only.",
		Annotations: updateTool("Update security rule"),
	}, updateHandler[security.Location, security.Entry, SecurityRuleInput](d, "panos_security_rule_update", svc, resolve, loc,
		func(in SecurityRuleInput) string { return in.Name }, overlaySecurityRule))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_delete",
		Description: "Delete a security rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete security rule"),
	}, deleteHandler[security.Location, security.Entry](d, "panos_security_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_security_rule_move",
		Description: "Move a security rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only.",
		Annotations: updateTool("Move security rule"),
	}, moveHandler[security.Location, security.Entry](d, "panos_security_rule_move", svc, raw, resolve))
}
