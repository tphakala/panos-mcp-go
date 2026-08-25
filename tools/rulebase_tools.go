package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/PaloAltoNetworks/pango/policies/rules/authentication"
	"github.com/PaloAltoNetworks/pango/policies/rules/decryption"
	"github.com/PaloAltoNetworks/pango/policies/rules/pbf"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file adds the decryption, authentication and policy-based forwarding
// (PBF) rulebases. Each mirrors the security and NAT rule tools in
// policy_tools.go: a locParts builder, a nameFixAdapter service, an input
// struct scoped to a practical field subset, build/overlay/summary helpers,
// and a Register function that reuses the shared generic handlers plus
// ruleCreateHandler and moveHandler. Only the per-rulebase field mapping is
// new; the create/move/position machinery is unchanged (issue #53).

// --- Decryption -------------------------------------------------------------

// decryptionParts supplies decryption rule locations for resolveLocation. Same
// layout as securityParts: shared and device-group rulebases carry the
// pre/post-rulebase node, a firewall vsys has a single rulebase.
func decryptionParts() locParts[decryption.Location] {
	return locParts[decryption.Location]{
		shared: func(rb string) decryption.Location {
			return decryption.Location{Shared: &decryption.SharedLocation{Rulebase: rb}}
		},
		vsys: func(v string) decryption.Location {
			return decryption.Location{Vsys: &decryption.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, rb string) decryption.Location {
			return decryption.Location{DeviceGroup: &decryption.DeviceGroupLocation{
				PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg, Rulebase: rb,
			}}
		},
		rules: true,
	}
}

// newDecryptionRuleService adapts pango's decryption rule service to
// crudService via the shared nameFixAdapter; pango's raw-name Read/Update
// would otherwise be rejected client-side (see nameFixService).
func newDecryptionRuleService(d *Deps) nameFixAdapter[decryption.Location, decryption.Entry] {
	return nameFixAdapter[decryption.Location, decryption.Entry]{
		svc:    decryption.NewService(d.Client),
		client: d.Client,
		name:   func(e *decryption.Entry) string { return e.Name },
	}
}

// DecryptionRuleInput is the input for the decryption rule create and update
// tools. It exposes the practical subset of pango's Entry; the remaining
// fields (category, source/destination HIP, source_user, negate flags,
// group_tag, the log_fail/log_success/log_setting logging controls, the
// packet-broker profile, the decryption profile, target, uuid, and the
// decrypt-and-forward (packet-broker) action value) stay SDK-only until a task
// needs them.
type DecryptionRuleInput struct {
	Name           string        `json:"name" jsonschema:"Rule name"`
	Location       LocationInput `json:"location,omitzero"`
	Action         string        `json:"action,omitempty" jsonschema:"decrypt or no-decrypt; required on create, no default"`
	DecryptionType string        `json:"decryption_type,omitempty" jsonschema:"ssh-proxy, ssl-forward-proxy or ssl-inbound-inspection; a provided value replaces the whole type choice on update"`
	Certificates   []string      `json:"certificates,omitempty" jsonschema:"Certificates for ssl-inbound-inspection; requires decryption_type ssl-inbound-inspection"`
	From           []string      `json:"from,omitempty" jsonschema:"Source zones (create default: any); a non-empty list replaces fully"`
	To             []string      `json:"to,omitempty" jsonschema:"Destination zones (create default: any); a non-empty list replaces fully"`
	Source         []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination    []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Service        []string      `json:"service,omitempty" jsonschema:"Services (create default: any); a non-empty list replaces fully"`
	Description    string        `json:"description,omitempty"`
	Tags           []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled       *bool         `json:"disabled,omitempty"`
	Position       string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo     string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
}

// validDecryptionActions are the decryption rule verdicts this tool accepts.
// NOT MEASURED: these values are PAN-OS domain knowledge, not verified against
// a live device this session; decrypt-and-forward (packet broker) is
// deliberately out of scope. Kept as a map plus a fixed string so the error
// message is deterministic (map iteration order is not), mirroring
// validRuleActions/securityActionList in policy_tools.go.
var validDecryptionActions = map[string]bool{"decrypt": true, "no-decrypt": true}

const decryptionActionList = "decrypt, no-decrypt"

// The decryption type oneof member names. These ARE the pango Type struct
// members (decryption.Type), so the list is grounded in the SDK, not guessed.
const (
	decryptionTypeSSHProxy             = "ssh-proxy"
	decryptionTypeSSLForwardProxy      = "ssl-forward-proxy"
	decryptionTypeSSLInboundInspection = "ssl-inbound-inspection"
	decryptionTypeList                 = "ssh-proxy, ssl-forward-proxy, ssl-inbound-inspection"
)

// applyDecryptionType validates the flat type fields and applies them onto the
// entry, mirroring applyNatTranslations (policy_tools.go): a provided
// decryption_type REPLACES the whole Type subtree, so switching between the
// three types clears the previous choice and its certificates. An empty
// decryption_type leaves e.Type untouched, so an update that does not mention
// the type keeps the existing one. certificates apply only to
// ssl-inbound-inspection: they are rejected with any other type, and the
// rejection is checked BEFORE the empty-type shortcut so a caller can never
// silently drop certificates onto a type that ignores them.
//
//nolint:gocritic // hugeParam: in is by value to mirror the buildDecryptionRuleEntry/overlayDecryptionRule callers; see buildAddressEntry.
func applyDecryptionType(e *decryption.Entry, in DecryptionRuleInput) error {
	if len(in.Certificates) > 0 && in.DecryptionType != decryptionTypeSSLInboundInspection {
		return fmt.Errorf("certificates require decryption_type %s", decryptionTypeSSLInboundInspection)
	}
	if in.DecryptionType == "" {
		return nil
	}
	switch in.DecryptionType {
	case decryptionTypeSSHProxy:
		e.Type = &decryption.Type{SshProxy: &decryption.TypeSshProxy{}}
	case decryptionTypeSSLForwardProxy:
		e.Type = &decryption.Type{SslForwardProxy: &decryption.TypeSslForwardProxy{}}
	case decryptionTypeSSLInboundInspection:
		e.Type = &decryption.Type{SslInboundInspection: &decryption.TypeSslInboundInspection{Certificates: in.Certificates}}
	default:
		return fmt.Errorf("decryption_type must be one of %s; got %q", decryptionTypeList, in.DecryptionType)
	}
	return nil
}

// buildDecryptionRuleEntry validates input and builds a create entry with the
// PAN-OS-conventional any defaults on the match fields (a rule with an empty
// match member list fails commit validation on the device; this is PAN-OS
// domain knowledge, not exercised by the unit tests, which run against a fake
// API that never commits). action is required with NO default: a decrypt-or-
// bypass verdict is a security decision the caller must make explicitly.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildDecryptionRuleEntry(in DecryptionRuleInput) (*decryption.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Action == "" {
		return nil, fmt.Errorf("action is required (one of %s)", decryptionActionList)
	}
	if !validDecryptionActions[in.Action] {
		return nil, fmt.Errorf("action must be one of %s; got %q", decryptionActionList, in.Action)
	}
	e := &decryption.Entry{
		Name:        in.Name,
		Action:      new(in.Action),
		From:        orAny(in.From),
		To:          orAny(in.To),
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Service:     orAny(in.Service),
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if err := applyDecryptionType(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

// overlayDecryptionRule applies only the provided fields onto the current
// entry. The five match lists replace only when non-empty (a rule cannot have
// zero members; a reset is expressed as ["any"], and both an omitted and an
// explicitly empty list leave the field unchanged). tags replace when non-nil,
// so an empty list clears them. A provided decryption_type replaces the whole
// type choice via applyDecryptionType; position/relative_to are ignored here,
// the move tool owns placement.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayDecryptionRule(e *decryption.Entry, in DecryptionRuleInput) error {
	if in.Action != "" {
		if !validDecryptionActions[in.Action] {
			return fmt.Errorf("action must be one of %s; got %q", decryptionActionList, in.Action)
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
	if len(in.Service) > 0 {
		e.Service = in.Service
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	return applyDecryptionType(e, in)
}

// decryptionTypeString maps the pango Type oneof back to the tool-level type
// string, so a get returns exactly what create and update accept.
func decryptionTypeString(t *decryption.Type) string {
	switch {
	case t == nil:
		return ""
	case t.SshProxy != nil:
		return decryptionTypeSSHProxy
	case t.SslForwardProxy != nil:
		return decryptionTypeSSLForwardProxy
	case t.SslInboundInspection != nil:
		return decryptionTypeSSLInboundInspection
	default:
		return ""
	}
}

// decryptionRuleSummary reduces an entry to the list/get view fields on top of
// the shared name/description/tags base. certificates appear only for an
// ssl-inbound-inspection rule that has any.
func decryptionRuleSummary(e *decryption.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["action"] = strVal(e.Action)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["service"] = e.Service
	m["decryption_type"] = decryptionTypeString(e.Type)
	if e.Type != nil && e.Type.SslInboundInspection != nil && len(e.Type.SslInboundInspection.Certificates) > 0 {
		m["certificates"] = e.Type.SslInboundInspection.Certificates
	}
	m["disabled"] = e.Disabled != nil && *e.Disabled
	return m
}

// decryptionRuleCreateHandler creates a decryption rule and optionally
// positions it via the shared ruleCreateHandler (see that handler for the
// ordering and partial-failure contract).
func decryptionRuleCreateHandler(d *Deps, svc *decryption.Service) func(context.Context, *mcp.CallToolRequest, DecryptionRuleInput) (*mcp.CallToolResult, any, error) {
	return ruleCreateHandler[decryption.Location, decryption.Entry, DecryptionRuleInput](
		d, "panos_decryption_rule_create", svc,
		func(in LocationInput) (decryption.Location, error) { return resolveLocation(d, in, decryptionParts()) },
		buildDecryptionRuleEntry,
		func(in DecryptionRuleInput) LocationInput { return in.Location },
		func(in DecryptionRuleInput) string { return in.Name },
		func(in DecryptionRuleInput) (string, string) { return in.Position, in.RelativeTo },
		decryptionRuleSummary,
	)
}

// RegisterDecryptionRuleTools registers the decryption rule tools. All four
// mutating tools, including move, are skipped entirely in read-only mode.
func RegisterDecryptionRuleTools(s *mcp.Server, d *Deps) {
	svc := newDecryptionRuleService(d)
	raw := decryption.NewService(d.Client)
	resolve := func(in LocationInput) (decryption.Location, error) { return resolveLocation(d, in, decryptionParts()) }
	name := svc.name
	loc := func(in DecryptionRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_list",
		Description: "List decryption rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List decryption rules"),
	}, listHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_list", svc, resolve, name, decryptionRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_get",
		Description: "Get one decryption rule by name with the fields this server manages (match, action, decryption type and certificates, tags, disabled). Read-only.",
		Annotations: readOnlyTool("Get decryption rule"),
	}, getHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_get", svc, resolve, decryptionRuleSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_create",
		Description: "Create a decryption rule in the candidate config. action is required (decrypt or no-decrypt) and has no default; zones, addresses and service default to any. decryption_type selects ssh-proxy, ssl-forward-proxy or ssl-inbound-inspection (certificates apply to ssl-inbound-inspection only). Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create decryption rule"),
	}, decryptionRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_update",
		Description: "Update a decryption rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). A provided decryption_type replaces the whole type choice. position is ignored here; use panos_decryption_rule_move. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update decryption rule"),
	}, updateHandler[decryption.Location, decryption.Entry, DecryptionRuleInput](d, "panos_decryption_rule_update", svc, resolve, loc,
		func(in DecryptionRuleInput) string { return in.Name }, overlayDecryptionRule, decryptionRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_delete",
		Description: "Delete a decryption rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete decryption rule"),
	}, deleteHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_decryption_rule_move",
		Description: "Move a decryption rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Move decryption rule"),
	}, moveHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_move", svc, raw, resolve))
}

// --- Authentication ---------------------------------------------------------

// authenticationParts supplies authentication rule locations for
// resolveLocation. Same layout as securityParts.
func authenticationParts() locParts[authentication.Location] {
	return locParts[authentication.Location]{
		shared: func(rb string) authentication.Location {
			return authentication.Location{Shared: &authentication.SharedLocation{Rulebase: rb}}
		},
		vsys: func(v string) authentication.Location {
			return authentication.Location{Vsys: &authentication.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, rb string) authentication.Location {
			return authentication.Location{DeviceGroup: &authentication.DeviceGroupLocation{
				PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg, Rulebase: rb,
			}}
		},
		rules: true,
	}
}

// newAuthenticationRuleService adapts pango's authentication rule service to
// crudService via the shared nameFixAdapter.
func newAuthenticationRuleService(d *Deps) nameFixAdapter[authentication.Location, authentication.Entry] {
	return nameFixAdapter[authentication.Location, authentication.Entry]{
		svc:    authentication.NewService(d.Client),
		client: d.Client,
		name:   func(e *authentication.Entry) string { return e.Name },
	}
}

// AuthenticationRuleInput is the input for the authentication rule create and
// update tools. The remaining pango Entry fields (category, source/destination
// HIP, source_user, negate flags, group_tag, log_authentication_timeout,
// log_setting, target, uuid) stay SDK-only until a task needs them.
type AuthenticationRuleInput struct {
	Name                      string        `json:"name" jsonschema:"Rule name"`
	Location                  LocationInput `json:"location,omitzero"`
	AuthenticationEnforcement string        `json:"authentication_enforcement,omitempty" jsonschema:"Authentication enforcement object applied to matching traffic"`
	Timeout                   *int64        `json:"timeout,omitempty" jsonschema:"Authentication session timeout in minutes, at least 1; the device enforces its own upper bound"`
	From                      []string      `json:"from,omitempty" jsonschema:"Source zones (create default: any); a non-empty list replaces fully"`
	To                        []string      `json:"to,omitempty" jsonschema:"Destination zones (create default: any); a non-empty list replaces fully"`
	Source                    []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination               []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Service                   []string      `json:"service,omitempty" jsonschema:"Services (create default: any); a non-empty list replaces fully"`
	Description               string        `json:"description,omitempty"`
	Tags                      []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled                  *bool         `json:"disabled,omitempty"`
	Position                  string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo                string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
}

// buildAuthenticationRuleEntry validates input and builds a create entry with
// the PAN-OS-conventional any defaults on the match fields. Unlike security
// rules there is no verdict, so nothing beyond the name is required (the NAT
// model). timeout, when provided, must be at least 1 minute; no upper bound is
// enforced client-side, the device owns its own range.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildAuthenticationRuleEntry(in AuthenticationRuleInput) (*authentication.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Timeout != nil && *in.Timeout < 1 {
		return nil, fmt.Errorf("timeout must be at least 1 minute; got %d", *in.Timeout)
	}
	e := &authentication.Entry{
		Name:        in.Name,
		From:        orAny(in.From),
		To:          orAny(in.To),
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Service:     orAny(in.Service),
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	if in.AuthenticationEnforcement != "" {
		e.AuthenticationEnforcement = new(in.AuthenticationEnforcement)
	}
	if in.Timeout != nil {
		e.Timeout = in.Timeout
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	return e, nil
}

// overlayAuthenticationRule applies only the provided fields onto the current
// entry. The five match lists replace only when non-empty; tags replace when
// non-nil. position/relative_to are ignored here.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayAuthenticationRule(e *authentication.Entry, in AuthenticationRuleInput) error {
	if in.Timeout != nil && *in.Timeout < 1 {
		return fmt.Errorf("timeout must be at least 1 minute; got %d", *in.Timeout)
	}
	if in.AuthenticationEnforcement != "" {
		e.AuthenticationEnforcement = new(in.AuthenticationEnforcement)
	}
	if in.Timeout != nil {
		e.Timeout = in.Timeout
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
	if len(in.Service) > 0 {
		e.Service = in.Service
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	return nil
}

// authenticationRuleSummary reduces an entry to the list/get view fields on
// top of the shared name/description/tags base. timeout appears only when set.
func authenticationRuleSummary(e *authentication.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["authentication_enforcement"] = strVal(e.AuthenticationEnforcement)
	m["from"] = e.From
	m["to"] = e.To
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["service"] = e.Service
	if e.Timeout != nil {
		m["timeout"] = *e.Timeout
	}
	m["disabled"] = e.Disabled != nil && *e.Disabled
	return m
}

// authenticationRuleCreateHandler creates an authentication rule and optionally
// positions it via the shared ruleCreateHandler.
func authenticationRuleCreateHandler(d *Deps, svc *authentication.Service) func(context.Context, *mcp.CallToolRequest, AuthenticationRuleInput) (*mcp.CallToolResult, any, error) {
	return ruleCreateHandler[authentication.Location, authentication.Entry, AuthenticationRuleInput](
		d, "panos_authentication_rule_create", svc,
		func(in LocationInput) (authentication.Location, error) {
			return resolveLocation(d, in, authenticationParts())
		},
		buildAuthenticationRuleEntry,
		func(in AuthenticationRuleInput) LocationInput { return in.Location },
		func(in AuthenticationRuleInput) string { return in.Name },
		func(in AuthenticationRuleInput) (string, string) { return in.Position, in.RelativeTo },
		authenticationRuleSummary,
	)
}

// RegisterAuthenticationRuleTools registers the authentication rule tools. All
// four mutating tools, including move, are skipped entirely in read-only mode.
func RegisterAuthenticationRuleTools(s *mcp.Server, d *Deps) {
	svc := newAuthenticationRuleService(d)
	raw := authentication.NewService(d.Client)
	resolve := func(in LocationInput) (authentication.Location, error) {
		return resolveLocation(d, in, authenticationParts())
	}
	name := svc.name
	loc := func(in AuthenticationRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_list",
		Description: "List authentication rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List authentication rules"),
	}, listHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_list", svc, resolve, name, authenticationRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_get",
		Description: "Get one authentication rule by name with the fields this server manages (match, authentication_enforcement, timeout, tags, disabled). Read-only.",
		Annotations: readOnlyTool("Get authentication rule"),
	}, getHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_get", svc, resolve, authenticationRuleSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_create",
		Description: "Create an authentication rule in the candidate config. Nothing beyond name is required; zones, addresses and service default to any. authentication_enforcement names the enforcement object applied to matching traffic; timeout is in minutes. Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create authentication rule"),
	}, authenticationRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_update",
		Description: "Update an authentication rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). position is ignored here; use panos_authentication_rule_move. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update authentication rule"),
	}, updateHandler[authentication.Location, authentication.Entry, AuthenticationRuleInput](d, "panos_authentication_rule_update", svc, resolve, loc,
		func(in AuthenticationRuleInput) string { return in.Name }, overlayAuthenticationRule, authenticationRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_delete",
		Description: "Delete an authentication rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete authentication rule"),
	}, deleteHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_authentication_rule_move",
		Description: "Move an authentication rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Move authentication rule"),
	}, moveHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_move", svc, raw, resolve))
}

// --- Policy-based forwarding (PBF) ------------------------------------------

// pbfParts supplies PBF rule locations for resolveLocation. Same layout as
// securityParts.
func pbfParts() locParts[pbf.Location] {
	return locParts[pbf.Location]{
		shared: func(rb string) pbf.Location {
			return pbf.Location{Shared: &pbf.SharedLocation{Rulebase: rb}}
		},
		vsys: func(v string) pbf.Location {
			return pbf.Location{Vsys: &pbf.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, rb string) pbf.Location {
			return pbf.Location{DeviceGroup: &pbf.DeviceGroupLocation{
				PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg, Rulebase: rb,
			}}
		},
		rules: true,
	}
}

// newPbfRuleService adapts pango's PBF rule service to crudService via the
// shared nameFixAdapter.
func newPbfRuleService(d *Deps) nameFixAdapter[pbf.Location, pbf.Entry] {
	return nameFixAdapter[pbf.Location, pbf.Entry]{
		svc:    pbf.NewService(d.Client),
		client: d.Client,
		name:   func(e *pbf.Entry) string { return e.Name },
	}
}

// PbfRuleInput is the input for the PBF rule create and update tools. from
// models source ZONES only; the SDK-only fields (interface-based from, the
// forward monitor, enforce_symmetric_return, schedule,
// active_active_device_binding, source_user, negate flags, group_tag, target,
// uuid) stay SDK-only until a task needs them. PBF has no destination zone, so
// there is deliberately no to field.
type PbfRuleInput struct {
	Name            string        `json:"name" jsonschema:"Rule name"`
	Location        LocationInput `json:"location,omitzero"`
	Action          string        `json:"action,omitempty" jsonschema:"forward, forward-to-vsys, discard or no-pbf; required on create, no default; a provided value replaces the whole action choice on update"`
	EgressInterface string        `json:"egress_interface,omitempty" jsonschema:"Egress interface for action forward (required with forward)"`
	NexthopIP       string        `json:"nexthop_ip,omitempty" jsonschema:"Next-hop IP address for action forward; mutually exclusive with nexthop_fqdn"`
	NexthopFQDN     string        `json:"nexthop_fqdn,omitempty" jsonschema:"Next-hop FQDN for action forward; mutually exclusive with nexthop_ip"`
	ForwardVsys     string        `json:"forward_vsys,omitempty" jsonschema:"Target vsys for action forward-to-vsys (required with it)"`
	From            []string      `json:"from,omitempty" jsonschema:"Source zones; required on create (PBF has no any default); a non-empty list replaces the whole from choice, including an interface-based from"`
	Source          []string      `json:"source,omitempty" jsonschema:"Source addresses (create default: any); a non-empty list replaces fully"`
	Destination     []string      `json:"destination,omitempty" jsonschema:"Destination addresses (create default: any); a non-empty list replaces fully"`
	Service         []string      `json:"service,omitempty" jsonschema:"Services (create default: any); a non-empty list replaces fully"`
	Application     []string      `json:"application,omitempty" jsonschema:"Applications (create default: any); a non-empty list replaces fully"`
	Description     string        `json:"description,omitempty"`
	Tags            []string      `json:"tags,omitempty" jsonschema:"Replaces the full tag list when provided; an empty list clears it"`
	Disabled        *bool         `json:"disabled,omitempty"`
	Position        string        `json:"position,omitempty" jsonschema:"Optional placement on create: top, bottom, before, after (PAN-OS appends at the bottom by default); ignored on update"`
	RelativeTo      string        `json:"relative_to,omitempty" jsonschema:"Rule name for position before/after; ignored on update"`
}

// The PBF action oneof member names. These ARE the pango Action struct members
// (pbf.Action), so the list is grounded in the SDK, not guessed.
const (
	pbfActionForward       = "forward"
	pbfActionForwardToVsys = "forward-to-vsys"
	pbfActionDiscard       = "discard"
	pbfActionNoPbf         = "no-pbf"
	pbfActionList          = "forward, forward-to-vsys, discard, no-pbf"
)

var validPbfActions = map[string]bool{
	pbfActionForward: true, pbfActionForwardToVsys: true, pbfActionDiscard: true, pbfActionNoPbf: true,
}

// applyPbfAction validates the flat action fields and applies them onto the
// entry, mirroring applyNatTranslations: a provided action REPLACES the whole
// Action subtree, so switching between the four actions clears the previous
// choice and its parameters. An empty action leaves e.Action untouched (so an
// update that omits action keeps the existing one), but action-specific
// parameters without an action, or parameters that do not belong to the chosen
// action, are rejected rather than silently dropped: dropping egress_interface
// while the action stays discard would tell the caller traffic is forwarded
// when it is dropped.
//
//nolint:gocritic // hugeParam: in is by value to mirror the buildPbfRuleEntry/overlayPbfRule callers; see buildAddressEntry.
func applyPbfAction(e *pbf.Entry, in PbfRuleInput) error {
	if in.Action == "" {
		if pbfActionParamsSet(in) {
			return errors.New("egress_interface, nexthop_ip, nexthop_fqdn and forward_vsys require an action")
		}
		return nil
	}
	if !validPbfActions[in.Action] {
		return fmt.Errorf("action must be one of %s; got %q", pbfActionList, in.Action)
	}
	act, err := buildPbfAction(in)
	if err != nil {
		return err
	}
	e.Action = act
	return nil
}

// pbfActionParamsSet reports whether any action-specific parameter was
// supplied, so an update with no action still rejects a stray forward or vsys
// parameter instead of silently dropping it.
//
//nolint:gocritic // hugeParam: in is by value to mirror applyPbfAction; see buildAddressEntry.
func pbfActionParamsSet(in PbfRuleInput) bool {
	return in.EgressInterface != "" || in.NexthopIP != "" || in.NexthopFQDN != "" || in.ForwardVsys != ""
}

// buildPbfAction builds the pango Action subtree for a validated action,
// rejecting parameters that do not belong to the chosen action so a caller
// never sends a forward parameter to a discard rule (and vice versa).
//
//nolint:gocritic // hugeParam: in is by value to mirror applyPbfAction; see buildAddressEntry.
func buildPbfAction(in PbfRuleInput) (*pbf.Action, error) {
	if in.Action != pbfActionForward && (in.EgressInterface != "" || in.NexthopIP != "" || in.NexthopFQDN != "") {
		return nil, fmt.Errorf("egress_interface, nexthop_ip and nexthop_fqdn apply only to action %s", pbfActionForward)
	}
	if in.Action != pbfActionForwardToVsys && in.ForwardVsys != "" {
		return nil, fmt.Errorf("forward_vsys applies only to action %s", pbfActionForwardToVsys)
	}
	switch in.Action {
	case pbfActionForward:
		return buildPbfForwardAction(in)
	case pbfActionForwardToVsys:
		if in.ForwardVsys == "" {
			return nil, fmt.Errorf("action %s requires forward_vsys", pbfActionForwardToVsys)
		}
		return &pbf.Action{ForwardToVsys: new(in.ForwardVsys)}, nil
	case pbfActionDiscard:
		return &pbf.Action{Discard: &pbf.ActionDiscard{}}, nil
	default: // no-pbf; validPbfActions already gated the value in applyPbfAction
		return &pbf.Action{NoPbf: &pbf.ActionNoPbf{}}, nil
	}
}

// buildPbfForwardAction builds the forward action: an egress interface with an
// optional next hop (IP or FQDN, never both).
//
//nolint:gocritic // hugeParam: in is by value to mirror applyPbfAction; see buildAddressEntry.
func buildPbfForwardAction(in PbfRuleInput) (*pbf.Action, error) {
	if in.EgressInterface == "" {
		return nil, fmt.Errorf("action %s requires egress_interface", pbfActionForward)
	}
	if in.NexthopIP != "" && in.NexthopFQDN != "" {
		return nil, errors.New("provide nexthop_ip or nexthop_fqdn, not both")
	}
	fwd := &pbf.ActionForward{EgressInterface: new(in.EgressInterface)}
	switch {
	case in.NexthopIP != "":
		fwd.Nexthop = &pbf.ActionForwardNexthop{IpAddress: new(in.NexthopIP)}
	case in.NexthopFQDN != "":
		fwd.Nexthop = &pbf.ActionForwardNexthop{Fqdn: new(in.NexthopFQDN)}
	}
	return &pbf.Action{Forward: fwd}, nil
}

// buildPbfRuleEntry validates input and builds a create entry. action is
// required with NO default (the forwarding verdict is the point of the rule).
// from (source zones) is required and has no any default: the PBF GUI does not
// pre-fill a zone and "any" is not a known-valid from member (NOT MEASURED
// against a live device). source/destination/service/application default to
// any (PAN-OS domain knowledge, not exercised by the unit tests).
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildPbfRuleEntry(in PbfRuleInput) (*pbf.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Action == "" {
		return nil, fmt.Errorf("action is required (one of %s)", pbfActionList)
	}
	if len(in.From) == 0 {
		return nil, errors.New("from is required (one or more source zones)")
	}
	e := &pbf.Entry{
		Name:        in.Name,
		From:        &pbf.From{Zone: in.From},
		Source:      orAny(in.Source),
		Destination: orAny(in.Destination),
		Service:     orAny(in.Service),
		Application: orAny(in.Application),
		Tag:         in.Tags,
		Disabled:    in.Disabled,
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if err := applyPbfAction(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

// overlayPbfRule applies only the provided fields onto the current entry. A
// provided from REPLACES the whole From oneof with a zone-based from, clearing
// an interface-based from a rule may have carried. The match lists replace
// only when non-empty; tags replace when non-nil. A provided action replaces
// the whole action choice via applyPbfAction; position/relative_to are ignored
// here.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayPbfRule(e *pbf.Entry, in PbfRuleInput) error {
	if len(in.From) > 0 {
		e.From = &pbf.From{Zone: in.From}
	}
	if len(in.Source) > 0 {
		e.Source = in.Source
	}
	if len(in.Destination) > 0 {
		e.Destination = in.Destination
	}
	if len(in.Service) > 0 {
		e.Service = in.Service
	}
	if len(in.Application) > 0 {
		e.Application = in.Application
	}
	if in.Description != "" {
		e.Description = new(in.Description)
	}
	if in.Tags != nil {
		e.Tag = in.Tags
	}
	if in.Disabled != nil {
		e.Disabled = in.Disabled
	}
	return applyPbfAction(e, in)
}

// pbfActionString maps the pango Action oneof back to the tool-level action
// string, so a get returns exactly what create and update accept.
func pbfActionString(a *pbf.Action) string {
	switch {
	case a == nil:
		return ""
	case a.Forward != nil:
		return pbfActionForward
	case a.ForwardToVsys != nil:
		return pbfActionForwardToVsys
	case a.Discard != nil:
		return pbfActionDiscard
	case a.NoPbf != nil:
		return pbfActionNoPbf
	default:
		return ""
	}
}

// pbfRuleSummary reduces an entry to the list/get view fields on top of the
// shared name/description/tags base. The forward parameters and from_interfaces
// appear only when the entry carries them (an interface-based from is read
// faithfully even though create/update model zones only).
func pbfRuleSummary(e *pbf.Entry) any {
	m := summaryBase(e.Name, e.Description, e.Tag)
	m["action"] = pbfActionString(e.Action)
	if a := e.Action; a != nil {
		if a.Forward != nil {
			m["egress_interface"] = strVal(a.Forward.EgressInterface)
			if nh := a.Forward.Nexthop; nh != nil {
				if nh.IpAddress != nil {
					m["nexthop_ip"] = strVal(nh.IpAddress)
				}
				if nh.Fqdn != nil {
					m["nexthop_fqdn"] = strVal(nh.Fqdn)
				}
			}
		}
		if a.ForwardToVsys != nil {
			m["forward_vsys"] = strVal(a.ForwardToVsys)
		}
	}
	if e.From != nil {
		m["from"] = e.From.Zone
		if len(e.From.Interface) > 0 {
			m["from_interfaces"] = e.From.Interface
		}
	}
	m["source"] = e.Source
	m["destination"] = e.Destination
	m["service"] = e.Service
	m["application"] = e.Application
	m["disabled"] = e.Disabled != nil && *e.Disabled
	return m
}

// pbfRuleCreateHandler creates a PBF rule and optionally positions it via the
// shared ruleCreateHandler.
func pbfRuleCreateHandler(d *Deps, svc *pbf.Service) func(context.Context, *mcp.CallToolRequest, PbfRuleInput) (*mcp.CallToolResult, any, error) {
	return ruleCreateHandler[pbf.Location, pbf.Entry, PbfRuleInput](
		d, "panos_pbf_rule_create", svc,
		func(in LocationInput) (pbf.Location, error) { return resolveLocation(d, in, pbfParts()) },
		buildPbfRuleEntry,
		func(in PbfRuleInput) LocationInput { return in.Location },
		func(in PbfRuleInput) string { return in.Name },
		func(in PbfRuleInput) (string, string) { return in.Position, in.RelativeTo },
		pbfRuleSummary,
	)
}

// RegisterPbfRuleTools registers the PBF rule tools. All four mutating tools,
// including move, are skipped entirely in read-only mode.
func RegisterPbfRuleTools(s *mcp.Server, d *Deps) {
	svc := newPbfRuleService(d)
	raw := pbf.NewService(d.Client)
	resolve := func(in LocationInput) (pbf.Location, error) { return resolveLocation(d, in, pbfParts()) }
	name := svc.name
	loc := func(in PbfRuleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_list",
		Description: "List policy-based forwarding rules in evaluation order at a location. On Panorama set location.rulebase to pre (default) or post. Read-only.",
		Annotations: readOnlyTool("List PBF rules"),
	}, listHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_list", svc, resolve, name, pbfRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_get",
		Description: "Get one policy-based forwarding rule by name with the fields this server manages (match, action and its forward parameters, tags, disabled). Read-only.",
		Annotations: readOnlyTool("Get PBF rule"),
	}, getHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_get", svc, resolve, pbfRuleSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_create",
		Description: "Create a policy-based forwarding rule in the candidate config. action is required (forward, forward-to-vsys, discard or no-pbf) and from (source zones) is required; source addresses, destination, service and application default to any. action forward requires egress_interface with optional nexthop_ip OR nexthop_fqdn; action forward-to-vsys requires forward_vsys. Optional position places the rule (PAN-OS default: bottom). Run panos_commit to apply.",
		Annotations: createTool("Create PBF rule"),
	}, pbfRuleCreateHandler(d, raw))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_update",
		Description: "Update a policy-based forwarding rule: read-modify-write, only provided fields change; non-empty lists replace fully (send [\"any\"] to reset a match field). A provided action replaces the whole action choice, and a provided from replaces the whole from choice. position is ignored here; use panos_pbf_rule_move. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update PBF rule"),
	}, updateHandler[pbf.Location, pbf.Entry, PbfRuleInput](d, "panos_pbf_rule_update", svc, resolve, loc,
		func(in PbfRuleInput) string { return in.Name }, overlayPbfRule, pbfRuleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_delete",
		Description: "Delete a policy-based forwarding rule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete PBF rule"),
	}, deleteHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_delete", svc, resolve))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_pbf_rule_move",
		Description: "Move a policy-based forwarding rule within its rulebase: top, bottom, or directly before/after another rule. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Move PBF rule"),
	}, moveHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_move", svc, raw, resolve))
}
