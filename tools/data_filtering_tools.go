package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/profiles/datafiltering"
	"github.com/PaloAltoNetworks/pango/objects/profiles/dataobjects"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file adds CRUD tools for the data-filtering surface: the data-filtering
// security profile (device/profiles/datafiltering) and the data patterns it
// matches on (objects/profiles/dataobjects, the "Data Patterns" custom objects).
// Both fill a hole in the surface this server already ships: a security rule's
// profile settings and a security profile group already reference a
// data-filtering profile, and a data-filtering rule references a data pattern, so
// the objects they point at are now creatable here rather than only referenceable.
//
// Both follow the object_tools.go quintet (parts/service/input/build/overlay/
// summary + Register) over the shared generic handlers, at object scope
// (LocationInput), exactly like the antivirus and vulnerability profiles. Neither
// family carries a secret, so no withSecrets extractor is wired; that absence is
// intentional, not an omission.

// Summary keys shared by the data-filtering rule and data-pattern projections,
// factored out because each appears often enough across the two summaries to
// trip goconst.
const (
	directionKey = "direction"
	fileTypeKey  = "file_type"
)

// --- Data filtering profile (device/profiles/datafiltering) ------------------

// dataFilteringParts supplies data-filtering profile locations. Like the
// vulnerability profile, pango generates no vsys location for this type; on a
// firewall it is managed at shared (resolveLocation's nil-vsys fallback).
func dataFilteringParts() locParts[datafiltering.Location] {
	return locParts[datafiltering.Location]{
		shared: func(string) datafiltering.Location {
			return datafiltering.Location{Shared: &datafiltering.SharedLocation{}}
		},
		deviceGroup: func(dg, _ string) datafiltering.Location {
			return datafiltering.Location{DeviceGroup: &datafiltering.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newDataFilteringService(d *Deps) nameFixAdapter[datafiltering.Location, datafiltering.Entry] {
	return nameFixAdapter[datafiltering.Location, datafiltering.Entry]{
		svc:    datafiltering.NewService(d.Client),
		client: d.Client,
		name:   func(e *datafiltering.Entry) string { return e.Name },
	}
}

// DataFilteringRuleInput is one match rule in a data-filtering profile. Enum
// values (direction, log_severity) pass through to PAN-OS unchanged; the device
// validates them.
type DataFilteringRuleInput struct {
	Name           string   `json:"name" jsonschema:"Rule name"`
	DataObject     *string  `json:"data_object,omitzero" jsonschema:"Name of the data pattern this rule matches (create one with panos_data_pattern_create)"`
	Direction      *string  `json:"direction,omitzero" jsonschema:"Traffic direction: download, upload, or both"`
	AlertThreshold *int64   `json:"alert_threshold,omitzero" jsonschema:"Number of matches before an alert is logged"`
	BlockThreshold *int64   `json:"block_threshold,omitzero" jsonschema:"Number of matches before the transfer is blocked"`
	LogSeverity    *string  `json:"log_severity,omitzero" jsonschema:"Log severity recorded on a match"`
	Application    []string `json:"application,omitempty" jsonschema:"Applications the rule applies to (use 'any' for all)"`
	FileType       []string `json:"file_type,omitempty" jsonschema:"File types the rule applies to (use 'any' for all)"`
}

// DataFilteringProfileInput is the input for data-filtering profile create and
// update.
type DataFilteringProfileInput struct {
	Name            string                   `json:"name" jsonschema:"Data filtering profile name"`
	Location        LocationInput            `json:"location,omitzero"`
	Description     string                   `json:"description,omitempty"`
	DataCapture     *bool                    `json:"data_capture,omitempty" jsonschema:"Capture the matching data when a rule triggers"`
	DisableOverride *string                  `json:"disable_override,omitzero" jsonschema:"Panorama only: 'yes' disallows overriding this profile in a child device group"`
	Rules           []DataFilteringRuleInput `json:"rules,omitempty" jsonschema:"Match rules; replaces the whole set when provided, an explicit empty list clears it"`
}

// buildDataFilteringRules maps the rule inputs onto pango rules, requiring a name
// on each. It returns nil for an omitted (nil) input so the overlay leaves the
// stored rules untouched; an explicit empty list yields an empty non-nil slice
// the overlay assigns, clearing the set on update. Each rule is built fresh, so
// the whole set replaces rather than merges by name; the rules carry no secret,
// so the merge-by-name preservation the server-profile lists need does not apply.
func buildDataFilteringRules(in []DataFilteringRuleInput) ([]datafiltering.Rules, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]datafiltering.Rules, 0, len(in))
	for i := range in {
		r := &in[i]
		if r.Name == "" {
			return nil, errors.New("each rule requires a name")
		}
		rule := datafiltering.Rules{Name: r.Name}
		setPtr(&rule.DataObject, r.DataObject)
		setPtr(&rule.Direction, r.Direction)
		setPtr(&rule.AlertThreshold, r.AlertThreshold)
		setPtr(&rule.BlockThreshold, r.BlockThreshold)
		setPtr(&rule.LogSeverity, r.LogSeverity)
		rule.Application = r.Application
		rule.FileType = r.FileType
		out = append(out, rule)
	}
	return out, nil
}

// applyDataFiltering overlays the managed fields onto e, applying only what the
// caller provided. Shared by build and overlay so create and update agree.
func applyDataFiltering(e *datafiltering.Entry, in *DataFilteringProfileInput) error {
	setStrPtr(&e.Description, in.Description)
	if in.DataCapture != nil {
		e.DataCapture = in.DataCapture
	}
	setPtr(&e.DisableOverride, in.DisableOverride)
	rules, err := buildDataFilteringRules(in.Rules)
	if err != nil {
		return err
	}
	if rules != nil {
		e.Rules = rules
	}
	return nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildDataFilteringEntry(in DataFilteringProfileInput) (*datafiltering.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &datafiltering.Entry{Name: in.Name}
	if err := applyDataFiltering(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract; see buildAddressEntry.
func overlayDataFiltering(e *datafiltering.Entry, in DataFilteringProfileInput) error {
	return applyDataFiltering(e, &in)
}

// dataFilteringRuleSummaries reduces the pango rules to the clean tool view.
func dataFilteringRuleSummaries(rules []datafiltering.Rules) []any {
	out := make([]any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		m := map[string]any{
			tagNameKey:     r.Name,
			"data_object":  strVal(r.DataObject),
			directionKey:   strVal(r.Direction),
			"log_severity": strVal(r.LogSeverity),
			"application":  strList(r.Application),
			fileTypeKey:    strList(r.FileType),
		}
		putInt(m, "alert_threshold", r.AlertThreshold)
		putInt(m, "block_threshold", r.BlockThreshold)
		out = append(out, m)
	}
	return out
}

func dataFilteringSummary(e *datafiltering.Entry) any {
	m := nameDescription(e.Name, e.Description)
	putBool(m, "data_capture", e.DataCapture)
	m["disable_override"] = strVal(e.DisableOverride)
	m["rules"] = dataFilteringRuleSummaries(e.Rules)
	return m
}

// RegisterDataFilteringProfileTools registers the data-filtering profile tools.
// Mutating tools are skipped in read-only mode.
func RegisterDataFilteringProfileTools(s *mcp.Server, d *Deps) {
	svc := newDataFilteringService(d)
	resolve := func(in LocationInput) (datafiltering.Location, error) {
		return resolveLocation(d, in, dataFilteringParts())
	}
	name := svc.name
	loc := func(in DataFilteringProfileInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_filtering_profile_list",
		Description: "List data filtering profiles at a location. On a firewall this profile type is managed at shared (pango exposes no vsys location for it). Read-only.",
		Annotations: readOnlyTool("List data filtering profiles"),
	}, listHandler[datafiltering.Location, datafiltering.Entry](d, "panos_data_filtering_profile_list", svc, resolve, name, dataFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_filtering_profile_get",
		Description: "Get one data filtering profile by name with its managed fields (description, data_capture, disable_override, rules). Read-only.",
		Annotations: readOnlyTool("Get data filtering profile"),
	}, getHandler[datafiltering.Location, datafiltering.Entry](d, "panos_data_filtering_profile_get", svc, resolve, dataFilteringSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_filtering_profile_create",
		Description: "Create a data filtering profile in the candidate config. Each rule's data_object names a data pattern (create one with panos_data_pattern_create). On a firewall it is created at shared. Run panos_commit to apply.",
		Annotations: createTool("Create data filtering profile"),
	}, createHandler[datafiltering.Location, datafiltering.Entry, DataFilteringProfileInput](d, "panos_data_filtering_profile_create", svc, resolve, loc, buildDataFilteringEntry, dataFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name: "panos_data_filtering_profile_update",
		Description: "Update a data filtering profile: read-modify-write, only provided fields change; a provided rules list replaces the whole set, and an explicit empty list clears it. " +
			"Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update data filtering profile"),
	}, updateHandler[datafiltering.Location, datafiltering.Entry, DataFilteringProfileInput](d, "panos_data_filtering_profile_update", svc, resolve, loc,
		func(in DataFilteringProfileInput) string { return in.Name }, overlayDataFiltering, dataFilteringSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_filtering_profile_delete",
		Description: "Delete a data filtering profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete data filtering profile"),
	}, deleteHandler[datafiltering.Location, datafiltering.Entry](d, "panos_data_filtering_profile_delete", svc, resolve))
}

// --- Data patterns (objects/profiles/dataobjects) ----------------------------

// dataPatternParts supplies data-pattern locations: shared, a firewall vsys, or a
// Panorama device group (the antivirus profile scope shape).
func dataPatternParts() locParts[dataobjects.Location] {
	return locParts[dataobjects.Location]{
		shared: func(string) dataobjects.Location {
			return dataobjects.Location{Shared: &dataobjects.SharedLocation{}}
		},
		vsys: func(v string) dataobjects.Location {
			return dataobjects.Location{Vsys: &dataobjects.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) dataobjects.Location {
			return dataobjects.Location{DeviceGroup: &dataobjects.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newDataPatternService(d *Deps) nameFixAdapter[dataobjects.Location, dataobjects.Entry] {
	return nameFixAdapter[dataobjects.Location, dataobjects.Entry]{
		svc:    dataobjects.NewService(d.Client),
		client: d.Client,
		name:   func(e *dataobjects.Entry) string { return e.Name },
	}
}

// DataPatternFilePropertyInput is one entry under the file_properties pattern
// type.
type DataPatternFilePropertyInput struct {
	Name          string  `json:"name" jsonschema:"Pattern entry name"`
	FileType      *string `json:"file_type,omitzero" jsonschema:"File type this entry applies to"`
	FileProperty  *string `json:"file_property,omitzero" jsonschema:"Document property to match"`
	PropertyValue *string `json:"property_value,omitzero" jsonschema:"Value the property must contain"`
}

// DataPatternPredefinedInput is one entry under the predefined pattern type.
type DataPatternPredefinedInput struct {
	Name     string   `json:"name" jsonschema:"Predefined pattern name (for example 'Credit Card Numbers')"`
	FileType []string `json:"file_type,omitempty" jsonschema:"File types to match"`
}

// DataPatternRegexInput is one entry under the regex pattern type.
type DataPatternRegexInput struct {
	Name     string   `json:"name" jsonschema:"Pattern entry name"`
	FileType []string `json:"file_type,omitempty" jsonschema:"File types to match"`
	Regex    *string  `json:"regex,omitzero" jsonschema:"Regular expression to match"`
}

// DataPatternFilePropertiesInput selects the file-properties pattern type.
type DataPatternFilePropertiesInput struct {
	Patterns []DataPatternFilePropertyInput `json:"patterns,omitempty" jsonschema:"File-property entries; replaces the stored entries when provided"`
}

// DataPatternPredefinedListInput selects the predefined pattern type.
type DataPatternPredefinedListInput struct {
	Patterns []DataPatternPredefinedInput `json:"patterns,omitempty" jsonschema:"Predefined entries; replaces the stored entries when provided"`
}

// DataPatternRegexListInput selects the regex pattern type.
type DataPatternRegexListInput struct {
	Patterns []DataPatternRegexInput `json:"patterns,omitempty" jsonschema:"Regular-expression entries; replaces the stored entries when provided"`
}

// DataPatternInput is the input for data-pattern create and update. At most one
// pattern-type branch (file_properties, predefined, regex) may be set; providing
// none leaves the stored pattern type untouched.
type DataPatternInput struct {
	Name            string                          `json:"name" jsonschema:"Data pattern name"`
	Location        LocationInput                   `json:"location,omitzero"`
	Description     string                          `json:"description,omitempty"`
	DisableOverride *string                         `json:"disable_override,omitzero" jsonschema:"Panorama only: 'yes' disallows overriding this object in a child device group"`
	FileProperties  *DataPatternFilePropertiesInput `json:"file_properties,omitzero" jsonschema:"Match on file properties; at most one pattern-type branch may be set. Send {} to select without changing entries"`
	Predefined      *DataPatternPredefinedListInput `json:"predefined,omitzero" jsonschema:"Match on predefined data patterns; at most one pattern-type branch may be set"`
	Regex           *DataPatternRegexListInput      `json:"regex,omitzero" jsonschema:"Match on regular expressions; at most one pattern-type branch may be set"`
}

// dataPatternBranchNames lists the pattern-type input fields in the order the
// too-many-branches error reports them.
const dataPatternBranchNames = "file_properties, predefined, regex"

func buildFilePropertyPatterns(in []DataPatternFilePropertyInput) ([]dataobjects.PatternTypeFilePropertiesPattern, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]dataobjects.PatternTypeFilePropertiesPattern, 0, len(in))
	for i := range in {
		p := &in[i]
		if p.Name == "" {
			return nil, errors.New("each file_properties pattern requires a name")
		}
		x := dataobjects.PatternTypeFilePropertiesPattern{Name: p.Name}
		setPtr(&x.FileType, p.FileType)
		setPtr(&x.FileProperty, p.FileProperty)
		setPtr(&x.PropertyValue, p.PropertyValue)
		out = append(out, x)
	}
	return out, nil
}

func buildPredefinedPatterns(in []DataPatternPredefinedInput) ([]dataobjects.PatternTypePredefinedPattern, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]dataobjects.PatternTypePredefinedPattern, 0, len(in))
	for i := range in {
		p := &in[i]
		if p.Name == "" {
			return nil, errors.New("each predefined pattern requires a name")
		}
		out = append(out, dataobjects.PatternTypePredefinedPattern{Name: p.Name, FileType: p.FileType})
	}
	return out, nil
}

func buildRegexPatterns(in []DataPatternRegexInput) ([]dataobjects.PatternTypeRegexPattern, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]dataobjects.PatternTypeRegexPattern, 0, len(in))
	for i := range in {
		p := &in[i]
		if p.Name == "" {
			return nil, errors.New("each regex pattern requires a name")
		}
		x := dataobjects.PatternTypeRegexPattern{Name: p.Name, FileType: p.FileType}
		setPtr(&x.Regex, p.Regex)
		out = append(out, x)
	}
	return out, nil
}

// applyDataPatternType sets the pattern type. PAN-OS treats the three children of
// <pattern-type> as a choice, but pango does not enforce it: the marshaller writes
// every non-nil branch independently, so setting one without clearing the others
// leaves the device a document it rejects. Selection is by field PRESENCE, so an
// empty object (for example {"file_properties": {}}) selects a branch without
// changing its entries. Providing no branch leaves the stored pattern type
// untouched. The chosen branch is seeded from the value captured BEFORE the clear
// so a same-branch rebuild keeps that branch's unmodeled Misc, and a nil patterns
// list preserves the branch's stored entries.
func applyDataPatternType(e *dataobjects.Entry, in *DataPatternInput) error {
	n := countSet(in.FileProperties != nil, in.Predefined != nil, in.Regex != nil)
	if n == 0 {
		return nil
	}
	if n > 1 {
		return errors.New("at most one of " + dataPatternBranchNames + " may be set")
	}

	if e.PatternType == nil {
		e.PatternType = &dataobjects.PatternType{}
	}
	pt := e.PatternType

	// Capture before the clear so a same-branch rebuild seeds from the stored value.
	oldFileProps, oldPredefined, oldRegex := pt.FileProperties, pt.Predefined, pt.Regex
	pt.FileProperties, pt.Predefined, pt.Regex = nil, nil, nil

	switch {
	case in.FileProperties != nil:
		b := seedBranch(oldFileProps)
		pats, err := buildFilePropertyPatterns(in.FileProperties.Patterns)
		if err != nil {
			return err
		}
		if pats != nil {
			b.Pattern = pats
		}
		pt.FileProperties = b
	case in.Predefined != nil:
		b := seedBranch(oldPredefined)
		pats, err := buildPredefinedPatterns(in.Predefined.Patterns)
		if err != nil {
			return err
		}
		if pats != nil {
			b.Pattern = pats
		}
		pt.Predefined = b
	default: // in.Regex != nil
		b := seedBranch(oldRegex)
		pats, err := buildRegexPatterns(in.Regex.Patterns)
		if err != nil {
			return err
		}
		if pats != nil {
			b.Pattern = pats
		}
		pt.Regex = b
	}
	return nil
}

// applyDataPattern overlays the managed fields onto e, applying only what the
// caller provided. Shared by build and overlay so create and update agree.
func applyDataPattern(e *dataobjects.Entry, in *DataPatternInput) error {
	setStrPtr(&e.Description, in.Description)
	setPtr(&e.DisableOverride, in.DisableOverride)
	return applyDataPatternType(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildDataPattern(in DataPatternInput) (*dataobjects.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &dataobjects.Entry{Name: in.Name}
	if err := applyDataPattern(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayDataPattern(e *dataobjects.Entry, in DataPatternInput) error {
	return applyDataPattern(e, &in)
}

// dataPatternTypeString names the active pattern-type branch. An empty string
// means no pattern type is configured.
func dataPatternTypeString(pt *dataobjects.PatternType) string {
	if pt == nil {
		return ""
	}
	switch {
	case pt.FileProperties != nil:
		return "file-properties"
	case pt.Predefined != nil:
		return "predefined"
	case pt.Regex != nil:
		return "regex"
	default:
		return ""
	}
}

// dataPatternTypeDetail projects the entries of the active pattern-type branch.
// The arms follow dataPatternTypeString's precedence order exactly, so an entry
// written by another tool that carries several branches is described by the same
// one the string names.
func dataPatternTypeDetail(pt *dataobjects.PatternType) []any {
	if pt == nil {
		return nil
	}
	switch {
	case pt.FileProperties != nil:
		out := make([]any, 0, len(pt.FileProperties.Pattern))
		for i := range pt.FileProperties.Pattern {
			p := &pt.FileProperties.Pattern[i]
			out = append(out, map[string]any{
				tagNameKey:       p.Name,
				fileTypeKey:      strVal(p.FileType),
				"file_property":  strVal(p.FileProperty),
				"property_value": strVal(p.PropertyValue),
			})
		}
		return out
	case pt.Predefined != nil:
		out := make([]any, 0, len(pt.Predefined.Pattern))
		for i := range pt.Predefined.Pattern {
			p := &pt.Predefined.Pattern[i]
			out = append(out, map[string]any{tagNameKey: p.Name, fileTypeKey: strList(p.FileType)})
		}
		return out
	case pt.Regex != nil:
		out := make([]any, 0, len(pt.Regex.Pattern))
		for i := range pt.Regex.Pattern {
			p := &pt.Regex.Pattern[i]
			out = append(out, map[string]any{tagNameKey: p.Name, fileTypeKey: strList(p.FileType), "regex": strVal(p.Regex)})
		}
		return out
	default:
		return nil
	}
}

func dataPatternSummary(e *dataobjects.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["disable_override"] = strVal(e.DisableOverride)
	m["pattern_type"] = dataPatternTypeString(e.PatternType)
	if detail := dataPatternTypeDetail(e.PatternType); len(detail) > 0 {
		m["patterns"] = detail
	}
	return m
}

// RegisterDataPatternTools registers the data-pattern (data object) tools.
// Mutating tools are skipped in read-only mode.
func RegisterDataPatternTools(s *mcp.Server, d *Deps) {
	svc := newDataPatternService(d)
	resolve := func(in LocationInput) (dataobjects.Location, error) {
		return resolveLocation(d, in, dataPatternParts())
	}
	name := svc.name
	loc := func(in DataPatternInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_pattern_list",
		Description: "List data patterns at a location. Read-only.",
		Annotations: readOnlyTool("List data patterns"),
	}, listHandler[dataobjects.Location, dataobjects.Entry](d, "panos_data_pattern_list", svc, resolve, name, dataPatternSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_pattern_get",
		Description: "Get one data pattern by name with its pattern type and entries. Read-only.",
		Annotations: readOnlyTool("Get data pattern"),
	}, getHandler[dataobjects.Location, dataobjects.Entry](d, "panos_data_pattern_get", svc, resolve, dataPatternSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_pattern_create",
		Description: "Create a data pattern in the candidate config. Set at most one pattern-type branch: file_properties, predefined, or regex. Run panos_commit to apply.",
		Annotations: createTool("Create data pattern"),
	}, createHandler[dataobjects.Location, dataobjects.Entry, DataPatternInput](d, "panos_data_pattern_create", svc, resolve, loc, buildDataPattern, dataPatternSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name: "panos_data_pattern_update",
		Description: "Update a data pattern: read-modify-write, only provided fields change. Setting one pattern-type branch clears the others, because PAN-OS allows exactly one; " +
			"providing no branch leaves the stored pattern type untouched, and sending a branch with no patterns list keeps its stored entries. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update data pattern"),
	}, updateHandler[dataobjects.Location, dataobjects.Entry, DataPatternInput](d, "panos_data_pattern_update", svc, resolve, loc,
		func(in DataPatternInput) string { return in.Name }, overlayDataPattern, dataPatternSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_data_pattern_delete",
		Description: "Delete a data pattern from the candidate config. Fails while a data filtering profile still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete data pattern"),
	}, deleteHandler[dataobjects.Location, dataobjects.Entry](d, "panos_data_pattern_delete", svc, resolve))
}
