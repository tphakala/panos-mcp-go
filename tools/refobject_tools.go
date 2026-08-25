package tools

// Tools for the config objects rules reference: application groups, external
// dynamic lists (EDLs), custom URL categories, and schedules (issue #54). Each
// reuses the generic CRUD handlers, nameFixAdapter, and resolveLocation like the
// address/service/tag tools; only the per-resource input/build/overlay/summary
// and the oneof handling (EDL type, schedule recurrence) are new.

import (
	"errors"
	"fmt"

	application_group "github.com/PaloAltoNetworks/pango/objects/application/group"
	"github.com/PaloAltoNetworks/pango/objects/extdynlist"
	"github.com/PaloAltoNetworks/pango/objects/profiles/customurlcategory"
	"github.com/PaloAltoNetworks/pango/objects/schedules"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// typeKey is the shared summary map key for a resource's discriminator type.
const typeKey = "type"

// ptrIfSet returns a pointer to s, or nil when s is empty, for optional string
// entry fields that must be omitted rather than sent empty.
func ptrIfSet(s string) *string {
	if s == "" {
		return nil
	}
	return ptr(s)
}

// --- Application groups (objects/application/group) --------------------------

// appGroupParts supplies application group locations for resolveLocation.
func appGroupParts() locParts[application_group.Location] {
	return locParts[application_group.Location]{
		shared: func(string) application_group.Location {
			return application_group.Location{Shared: &application_group.SharedLocation{}}
		},
		vsys: func(v string) application_group.Location {
			return application_group.Location{Vsys: &application_group.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) application_group.Location {
			return application_group.Location{DeviceGroup: &application_group.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newApplicationGroupService(d *Deps) nameFixAdapter[application_group.Location, application_group.Entry] {
	return nameFixAdapter[application_group.Location, application_group.Entry]{
		svc:    application_group.NewService(d.Client),
		client: d.Client,
		name:   func(e *application_group.Entry) string { return e.Name },
	}
}

// ApplicationGroupInput is the input for application group create and update.
type ApplicationGroupInput struct {
	Name     string        `json:"name" jsonschema:"Application group name"`
	Location LocationInput `json:"location,omitempty"`
	Members  []string      `json:"members,omitempty" jsonschema:"Applications, application filters, or nested application groups; replaces the full member list when provided"`
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildApplicationGroupEntry(in ApplicationGroupInput) (*application_group.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if len(in.Members) == 0 {
		return nil, errors.New("members must have at least one entry")
	}
	return &application_group.Entry{Name: in.Name, Members: in.Members}, nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayApplicationGroup(e *application_group.Entry, in ApplicationGroupInput) error {
	return replaceListOrRejectEmpty(&e.Members, in.Members,
		"members must have at least one entry; a group cannot be emptied in place (delete the group instead)")
}

// applicationGroupSummary reduces an entry to the view fields. Application groups
// have no description or tags (pango objects/application/group Entry), so this
// hand-rolls the map rather than building on summaryBase.
func applicationGroupSummary(e *application_group.Entry) any {
	return map[string]any{tagNameKey: e.Name, "members": e.Members}
}

// RegisterApplicationGroupTools registers the application group tools. Mutating
// tools are skipped entirely in read-only mode.
func RegisterApplicationGroupTools(s *mcp.Server, d *Deps) {
	svc := newApplicationGroupService(d)
	resolve := func(in LocationInput) (application_group.Location, error) {
		return resolveLocation(d, in, appGroupParts())
	}
	name := svc.name
	loc := func(in ApplicationGroupInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_application_group_list",
		Description: "List application groups (named sets of applications, filters, and nested groups) at a location. Read-only.",
		Annotations: readOnlyTool("List application groups"),
	}, listHandler[application_group.Location, application_group.Entry](d, "panos_application_group_list", svc, resolve, name, applicationGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_application_group_get",
		Description: "Get one application group by name with its members. Read-only.",
		Annotations: readOnlyTool("Get application group"),
	}, getHandler[application_group.Location, application_group.Entry](d, "panos_application_group_get", svc, resolve, applicationGroupSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_application_group_create",
		Description: "Create an application group in the candidate config. At least one member is required. Run panos_commit to apply.",
		Annotations: createTool("Create application group"),
	}, createHandler[application_group.Location, application_group.Entry, ApplicationGroupInput](d, "panos_application_group_create", svc, resolve, loc, buildApplicationGroupEntry, applicationGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_application_group_update",
		Description: "Update an application group: read-modify-write, only provided fields change. A non-empty members list replaces the full membership; an explicitly empty members list is rejected (delete the group instead). Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update application group"),
	}, updateHandler[application_group.Location, application_group.Entry, ApplicationGroupInput](d, "panos_application_group_update", svc, resolve, loc,
		func(in ApplicationGroupInput) string { return in.Name }, overlayApplicationGroup, applicationGroupSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_application_group_delete",
		Description: "Delete an application group from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete application group"),
	}, deleteHandler[application_group.Location, application_group.Entry](d, "panos_application_group_delete", svc, resolve))
}

// --- Custom URL categories (objects/profiles/customurlcategory) -------------

const (
	customURLCategoryTypeURLList       = "URL List"
	customURLCategoryTypeCategoryMatch = "Category Match"
	customURLCategoryTypeListStr       = customURLCategoryTypeURLList + ", " + customURLCategoryTypeCategoryMatch
)

// validCustomURLCategoryTypes holds the exact PAN-OS wire values for the type
// field. The spaces and capitals are literal: the device rejects any other
// spelling. NOT MEASURED against a live device this session (see the PR notes);
// do not lowercase or hyphenate these.
var validCustomURLCategoryTypes = map[string]bool{
	customURLCategoryTypeURLList:       true,
	customURLCategoryTypeCategoryMatch: true,
}

func customURLCategoryParts() locParts[customurlcategory.Location] {
	return locParts[customurlcategory.Location]{
		shared: func(string) customurlcategory.Location {
			return customurlcategory.Location{Shared: &customurlcategory.SharedLocation{}}
		},
		vsys: func(v string) customurlcategory.Location {
			return customurlcategory.Location{Vsys: &customurlcategory.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) customurlcategory.Location {
			return customurlcategory.Location{DeviceGroup: &customurlcategory.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newCustomURLCategoryService(d *Deps) nameFixAdapter[customurlcategory.Location, customurlcategory.Entry] {
	return nameFixAdapter[customurlcategory.Location, customurlcategory.Entry]{
		svc:    customurlcategory.NewService(d.Client),
		client: d.Client,
		name:   func(e *customurlcategory.Entry) string { return e.Name },
	}
}

// CustomURLCategoryInput is the input for custom URL category create and update.
type CustomURLCategoryInput struct {
	Name        string        `json:"name" jsonschema:"Custom URL category name"`
	Location    LocationInput `json:"location,omitempty"`
	Type        string        `json:"type,omitempty" jsonschema:"Category kind: 'URL List' (members are URLs) or 'Category Match' (members are built-in category names). Required on create; exact spelling and capitalization"`
	Members     []string      `json:"members,omitempty" jsonschema:"Category members (URLs or built-in category names per type); replaces the full list when provided"`
	Description string        `json:"description,omitempty"`
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildCustomURLCategoryEntry(in CustomURLCategoryInput) (*customurlcategory.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Type == "" {
		return nil, errors.New("type is required; one of " + customURLCategoryTypeListStr)
	}
	if !validCustomURLCategoryTypes[in.Type] {
		return nil, fmt.Errorf("type must be one of %s, got %q", customURLCategoryTypeListStr, in.Type)
	}
	if len(in.Members) == 0 {
		return nil, errors.New("members must have at least one entry")
	}
	e := &customurlcategory.Entry{Name: in.Name, Type: ptr(in.Type), List: in.Members}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return e, nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayCustomURLCategory(e *customurlcategory.Entry, in CustomURLCategoryInput) error {
	if in.Type != "" && !validCustomURLCategoryTypes[in.Type] {
		return fmt.Errorf("type must be one of %s, got %q", customURLCategoryTypeListStr, in.Type)
	}
	// Validate (and apply) members before mutating any other field so an invalid
	// empty list is rejected before e is touched.
	if err := replaceListOrRejectEmpty(&e.List, in.Members,
		"members must have at least one entry; a category cannot be emptied in place (delete it instead)"); err != nil {
		return err
	}
	if in.Type != "" {
		e.Type = ptr(in.Type)
	}
	if in.Description != "" {
		e.Description = ptr(in.Description)
	}
	return nil
}

func customURLCategorySummary(e *customurlcategory.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m[typeKey] = strVal(e.Type)
	m["members"] = e.List
	return m
}

// RegisterCustomURLCategoryTools registers the custom URL category tools.
// Mutating tools are skipped entirely in read-only mode.
func RegisterCustomURLCategoryTools(s *mcp.Server, d *Deps) {
	svc := newCustomURLCategoryService(d)
	resolve := func(in LocationInput) (customurlcategory.Location, error) {
		return resolveLocation(d, in, customURLCategoryParts())
	}
	name := svc.name
	loc := func(in CustomURLCategoryInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_custom_url_category_list",
		Description: "List custom URL categories (URL lists or category-match sets) at a location. Read-only.",
		Annotations: readOnlyTool("List custom URL categories"),
	}, listHandler[customurlcategory.Location, customurlcategory.Entry](d, "panos_custom_url_category_list", svc, resolve, name, customURLCategorySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_custom_url_category_get",
		Description: "Get one custom URL category by name with its type and members. Read-only.",
		Annotations: readOnlyTool("Get custom URL category"),
	}, getHandler[customurlcategory.Location, customurlcategory.Entry](d, "panos_custom_url_category_get", svc, resolve, customURLCategorySummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_custom_url_category_create",
		Description: "Create a custom URL category in the candidate config. type is required ('URL List' or 'Category Match') and has no default; at least one member is required. Run panos_commit to apply.",
		Annotations: createTool("Create custom URL category"),
	}, createHandler[customurlcategory.Location, customurlcategory.Entry, CustomURLCategoryInput](d, "panos_custom_url_category_create", svc, resolve, loc, buildCustomURLCategoryEntry, customURLCategorySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_custom_url_category_update",
		Description: "Update a custom URL category: read-modify-write, only provided fields change. A non-empty members list replaces the full list; an explicitly empty list is rejected. Switching type keeps the existing members (one shared list on the wire); the members must match the new kind, so change type and members together. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update custom URL category"),
	}, updateHandler[customurlcategory.Location, customurlcategory.Entry, CustomURLCategoryInput](d, "panos_custom_url_category_update", svc, resolve, loc,
		func(in CustomURLCategoryInput) string { return in.Name }, overlayCustomURLCategory, customURLCategorySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_custom_url_category_delete",
		Description: "Delete a custom URL category from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete custom URL category"),
	}, deleteHandler[customurlcategory.Location, customurlcategory.Entry](d, "panos_custom_url_category_delete", svc, resolve))
}

// --- Schedules (objects/schedules) ------------------------------------------

const (
	scheduleTypeNonRecurring = "non-recurring"
	scheduleTypeDaily        = "daily"
	scheduleTypeWeekly       = "weekly"
	scheduleTypeListStr      = "non-recurring, daily, weekly"
)

var validScheduleTypes = map[string]bool{
	scheduleTypeNonRecurring: true,
	scheduleTypeDaily:        true,
	scheduleTypeWeekly:       true,
}

func scheduleParts() locParts[schedules.Location] {
	return locParts[schedules.Location]{
		shared: func(string) schedules.Location {
			return schedules.Location{Shared: &schedules.SharedLocation{}}
		},
		vsys: func(v string) schedules.Location {
			return schedules.Location{Vsys: &schedules.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) schedules.Location {
			return schedules.Location{DeviceGroup: &schedules.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newScheduleService(d *Deps) nameFixAdapter[schedules.Location, schedules.Entry] {
	return nameFixAdapter[schedules.Location, schedules.Entry]{
		svc:    schedules.NewService(d.Client),
		client: d.Client,
		name:   func(e *schedules.Entry) string { return e.Name },
	}
}

// ScheduleInput is the input for schedule create and update. A schedule is one
// of three kinds, chosen by schedule_type: non-recurring or daily use
// time_ranges; weekly uses the per-day lists.
type ScheduleInput struct {
	Name         string        `json:"name" jsonschema:"Schedule name"`
	Location     LocationInput `json:"location,omitempty"`
	ScheduleType string        `json:"schedule_type,omitempty" jsonschema:"non-recurring, daily, or weekly. Required on create; on update a provided value replaces the whole schedule definition"`
	TimeRanges   []string      `json:"time_ranges,omitempty" jsonschema:"non-recurring: 'YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM' ranges; daily: 'HH:MM-HH:MM' ranges. Replaces fully when provided. Device-validated format"`
	Monday       []string      `json:"monday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Monday"`
	Tuesday      []string      `json:"tuesday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Tuesday"`
	Wednesday    []string      `json:"wednesday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Wednesday"`
	Thursday     []string      `json:"thursday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Thursday"`
	Friday       []string      `json:"friday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Friday"`
	Saturday     []string      `json:"saturday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Saturday"`
	Sunday       []string      `json:"sunday,omitempty" jsonschema:"Weekly 'HH:MM-HH:MM' ranges for Sunday"`
}

func scheduleAnyDayProvided(in *ScheduleInput) bool {
	return in.Monday != nil || in.Tuesday != nil || in.Wednesday != nil ||
		in.Thursday != nil || in.Friday != nil || in.Saturday != nil || in.Sunday != nil
}

// scheduleWeeklyFromInput builds a weekly struct from the provided day lists.
// A nil day stays nil (that day is omitted), so it is used only for the
// wholesale build/switch path where the caller supplies the full week.
func scheduleWeeklyFromInput(in *ScheduleInput) *schedules.ScheduleTypeRecurringWeekly {
	return &schedules.ScheduleTypeRecurringWeekly{
		Monday: in.Monday, Tuesday: in.Tuesday, Wednesday: in.Wednesday,
		Thursday: in.Thursday, Friday: in.Friday, Saturday: in.Saturday, Sunday: in.Sunday,
	}
}

func scheduleWeeklyHasAny(w *schedules.ScheduleTypeRecurringWeekly) bool {
	if w == nil {
		return false
	}
	return len(w.Monday)+len(w.Tuesday)+len(w.Wednesday)+len(w.Thursday)+
		len(w.Friday)+len(w.Saturday)+len(w.Sunday) > 0
}

// scheduleOverlayWeeklyDays replaces each day whose input list is non-nil,
// leaving unmentioned days untouched. A non-nil empty list clears that day.
func scheduleOverlayWeeklyDays(w *schedules.ScheduleTypeRecurringWeekly, in *ScheduleInput) {
	if in.Monday != nil {
		w.Monday = in.Monday
	}
	if in.Tuesday != nil {
		w.Tuesday = in.Tuesday
	}
	if in.Wednesday != nil {
		w.Wednesday = in.Wednesday
	}
	if in.Thursday != nil {
		w.Thursday = in.Thursday
	}
	if in.Friday != nil {
		w.Friday = in.Friday
	}
	if in.Saturday != nil {
		w.Saturday = in.Saturday
	}
	if in.Sunday != nil {
		w.Sunday = in.Sunday
	}
}

// applyScheduleType validates and applies the schedule oneof. A provided
// schedule_type rebuilds the whole schedule-type subtree from the input; an
// omitted schedule_type overlays within the existing branch. Cross-field checks
// run before any early return so a mismatched combination is never silently
// dropped.
func applyScheduleType(e *schedules.Entry, in *ScheduleInput) error {
	if in.ScheduleType != "" && !validScheduleTypes[in.ScheduleType] {
		return fmt.Errorf("schedule_type must be one of %s, got %q", scheduleTypeListStr, in.ScheduleType)
	}
	daysProvided := scheduleAnyDayProvided(in)
	timesProvided := in.TimeRanges != nil
	if timesProvided && daysProvided {
		return errors.New("time_ranges and per-day lists are mutually exclusive")
	}
	switch in.ScheduleType {
	case scheduleTypeNonRecurring, scheduleTypeDaily:
		if daysProvided {
			return fmt.Errorf("per-day lists apply to a weekly schedule, not %s", in.ScheduleType)
		}
	case scheduleTypeWeekly:
		if timesProvided {
			return errors.New("time_ranges apply to a non-recurring or daily schedule, not weekly")
		}
	}
	if in.ScheduleType == "" {
		if !timesProvided && !daysProvided {
			return nil
		}
		return overlayScheduleInBranch(e, in, timesProvided, daysProvided)
	}
	return buildScheduleBranch(e, in)
}

// buildScheduleBranch rebuilds the schedule-type subtree wholesale from the
// input. It reuses the existing *ScheduleType (and *ScheduleTypeRecurring where
// applicable) so nested Misc survives a branch switch, mirroring the profile
// group nested-Misc lesson from PR #62.
func buildScheduleBranch(e *schedules.Entry, in *ScheduleInput) error {
	st := e.ScheduleType
	if st == nil {
		st = &schedules.ScheduleType{}
		e.ScheduleType = st
	}
	switch in.ScheduleType {
	case scheduleTypeNonRecurring:
		if len(in.TimeRanges) == 0 {
			return errors.New("a non-recurring schedule requires time_ranges")
		}
		st.NonRecurring = in.TimeRanges
		st.Recurring = nil
	case scheduleTypeDaily:
		if len(in.TimeRanges) == 0 {
			return errors.New("a daily schedule requires time_ranges")
		}
		st.NonRecurring = nil
		rec := st.Recurring
		if rec == nil {
			rec = &schedules.ScheduleTypeRecurring{}
			st.Recurring = rec
		}
		rec.Daily = in.TimeRanges
		rec.Weekly = nil
	case scheduleTypeWeekly:
		w := scheduleWeeklyFromInput(in)
		if !scheduleWeeklyHasAny(w) {
			return errors.New("a weekly schedule requires at least one day with time ranges")
		}
		st.NonRecurring = nil
		rec := st.Recurring
		if rec == nil {
			rec = &schedules.ScheduleTypeRecurring{}
			st.Recurring = rec
		}
		// Carry the existing weekly struct's unknown XML across the rebuild so a
		// same-type update preserves nested Misc (the PR #62 lesson), consistent
		// with the reuse of *ScheduleType and *ScheduleTypeRecurring above.
		if rec.Weekly != nil {
			w.Misc, w.MiscAttributes = rec.Weekly.Misc, rec.Weekly.MiscAttributes
		}
		rec.Daily = nil
		rec.Weekly = w
	}
	return nil
}

// overlayScheduleInBranch applies time_ranges or per-day lists within the
// schedule's existing branch, leaving the branch kind unchanged.
func overlayScheduleInBranch(e *schedules.Entry, in *ScheduleInput, timesProvided, daysProvided bool) error {
	st := e.ScheduleType
	if st == nil {
		return errors.New("this schedule has no type set; provide schedule_type")
	}
	switch {
	case st.NonRecurring != nil:
		if daysProvided {
			return errors.New("this schedule is non-recurring; set schedule_type to weekly to use per-day lists")
		}
		if len(in.TimeRanges) == 0 {
			return errors.New("time_ranges cannot be emptied in place; delete the schedule instead")
		}
		st.NonRecurring = in.TimeRanges
	case st.Recurring != nil && st.Recurring.Daily != nil:
		if daysProvided {
			return errors.New("this schedule is daily; set schedule_type to weekly to use per-day lists")
		}
		if len(in.TimeRanges) == 0 {
			return errors.New("time_ranges cannot be emptied in place; delete the schedule instead")
		}
		st.Recurring.Daily = in.TimeRanges
	case st.Recurring != nil && st.Recurring.Weekly != nil:
		if timesProvided {
			return errors.New("this schedule is weekly; use the per-day lists, not time_ranges")
		}
		// Overlay onto a copy and commit only when valid, so a rejected overlay
		// leaves the entry untouched (the invariant the sibling overlays hold).
		// The shallow copy is safe: the day lists are replaced wholesale, never
		// mutated in place, and the copy carries the struct's Misc.
		merged := *st.Recurring.Weekly
		scheduleOverlayWeeklyDays(&merged, in)
		if !scheduleWeeklyHasAny(&merged) {
			return errors.New("a weekly schedule must keep at least one day with time ranges")
		}
		*st.Recurring.Weekly = merged
	default:
		return errors.New("this schedule has no recognized type; provide schedule_type")
	}
	return nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildScheduleEntry(in ScheduleInput) (*schedules.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.ScheduleType == "" {
		return nil, errors.New("schedule_type is required; one of " + scheduleTypeListStr)
	}
	e := &schedules.Entry{Name: in.Name}
	if err := applyScheduleType(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlaySchedule(e *schedules.Entry, in ScheduleInput) error {
	return applyScheduleType(e, &in)
}

// scheduleTypeString maps the pango ScheduleType oneof back to the tool-level
// schedule_type string.
func scheduleTypeString(st *schedules.ScheduleType) string {
	switch {
	case st == nil:
		return ""
	case st.NonRecurring != nil:
		return scheduleTypeNonRecurring
	case st.Recurring != nil && st.Recurring.Daily != nil:
		return scheduleTypeDaily
	case st.Recurring != nil && st.Recurring.Weekly != nil:
		return scheduleTypeWeekly
	default:
		return ""
	}
}

// scheduleWeeklyDays projects the non-empty per-day lists to a map.
func scheduleWeeklyDays(w *schedules.ScheduleTypeRecurringWeekly) map[string]any {
	days := map[string]any{}
	for _, d := range []struct {
		name string
		v    []string
	}{
		{"monday", w.Monday}, {"tuesday", w.Tuesday}, {"wednesday", w.Wednesday},
		{"thursday", w.Thursday}, {"friday", w.Friday}, {"saturday", w.Saturday}, {"sunday", w.Sunday},
	} {
		if len(d.v) > 0 {
			days[d.name] = d.v
		}
	}
	return days
}

func scheduleSummary(e *schedules.Entry) any {
	st := e.ScheduleType
	m := map[string]any{tagNameKey: e.Name, "schedule_type": scheduleTypeString(st)}
	switch {
	case st == nil:
	case st.NonRecurring != nil:
		m["time_ranges"] = st.NonRecurring
	case st.Recurring != nil && st.Recurring.Daily != nil:
		m["time_ranges"] = st.Recurring.Daily
	case st.Recurring != nil && st.Recurring.Weekly != nil:
		m["days"] = scheduleWeeklyDays(st.Recurring.Weekly)
	}
	return m
}

// RegisterScheduleTools registers the schedule tools. Mutating tools are skipped
// entirely in read-only mode.
func RegisterScheduleTools(s *mcp.Server, d *Deps) {
	svc := newScheduleService(d)
	resolve := func(in LocationInput) (schedules.Location, error) { return resolveLocation(d, in, scheduleParts()) }
	name := svc.name
	loc := func(in ScheduleInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_schedule_list",
		Description: "List schedules (time windows a rule can be bound to) at a location. Read-only.",
		Annotations: readOnlyTool("List schedules"),
	}, listHandler[schedules.Location, schedules.Entry](d, "panos_schedule_list", svc, resolve, name, scheduleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_schedule_get",
		Description: "Get one schedule by name with its type and time ranges. Read-only.",
		Annotations: readOnlyTool("Get schedule"),
	}, getHandler[schedules.Location, schedules.Entry](d, "panos_schedule_get", svc, resolve, scheduleSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_schedule_create",
		Description: "Create a schedule in the candidate config. schedule_type is required (non-recurring, daily, or weekly) and has no default; non-recurring and daily need time_ranges, weekly needs at least one per-day list. Run panos_commit to apply.",
		Annotations: createTool("Create schedule"),
	}, createHandler[schedules.Location, schedules.Entry, ScheduleInput](d, "panos_schedule_create", svc, resolve, loc, buildScheduleEntry, scheduleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_schedule_update",
		Description: "Update a schedule: read-modify-write, only provided fields change. A provided schedule_type replaces the whole definition; without it, time_ranges (or per-day lists for a weekly schedule) overlay within the current type. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update schedule"),
	}, updateHandler[schedules.Location, schedules.Entry, ScheduleInput](d, "panos_schedule_update", svc, resolve, loc,
		func(in ScheduleInput) string { return in.Name }, overlaySchedule, scheduleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_schedule_delete",
		Description: "Delete a schedule from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete schedule"),
	}, deleteHandler[schedules.Location, schedules.Entry](d, "panos_schedule_delete", svc, resolve))
}

// --- External dynamic lists (objects/extdynlist) ----------------------------

const (
	edlTypeIP            = "ip"
	edlTypeDomain        = "domain"
	edlTypeURL           = "url"
	edlTypePredefinedIP  = "predefined-ip"
	edlTypePredefinedURL = "predefined-url"
	edlTypeImei          = "imei"
	edlTypeImsi          = "imsi"
	edlTypeListStr       = "ip, domain, url, predefined-ip, predefined-url"

	edlRecurringFiveMinute = "five-minute"
	edlRecurringHourly     = "hourly"
	edlRecurringDaily      = "daily"
	edlRecurringWeekly     = "weekly"
	edlRecurringMonthly    = "monthly"
	edlRecurringListStr    = "five-minute, hourly, daily, weekly, monthly"
)

var validEdlSettableTypes = map[string]bool{
	edlTypeIP:            true,
	edlTypeDomain:        true,
	edlTypeURL:           true,
	edlTypePredefinedIP:  true,
	edlTypePredefinedURL: true,
}

var validEdlRecurring = map[string]bool{
	edlRecurringFiveMinute: true,
	edlRecurringHourly:     true,
	edlRecurringDaily:      true,
	edlRecurringWeekly:     true,
	edlRecurringMonthly:    true,
}

func edlIsPredefined(t string) bool {
	return t == edlTypePredefinedIP || t == edlTypePredefinedURL
}

func edlParts() locParts[extdynlist.Location] {
	return locParts[extdynlist.Location]{
		shared: func(string) extdynlist.Location {
			return extdynlist.Location{Shared: &extdynlist.SharedLocation{}}
		},
		vsys: func(v string) extdynlist.Location {
			return extdynlist.Location{Vsys: &extdynlist.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}
		},
		deviceGroup: func(dg, _ string) extdynlist.Location {
			return extdynlist.Location{DeviceGroup: &extdynlist.DeviceGroupLocation{PanoramaDevice: defaultPanoramaDevice, DeviceGroup: dg}}
		},
	}
}

func newEdlService(d *Deps) nameFixAdapter[extdynlist.Location, extdynlist.Entry] {
	return nameFixAdapter[extdynlist.Location, extdynlist.Entry]{
		svc:    extdynlist.NewService(d.Client),
		client: d.Client,
		name:   func(e *extdynlist.Entry) string { return e.Name },
	}
}

// EdlInput is the input for EDL create and update. The list source is a oneof
// selected by type; a provided type replaces the whole source definition.
type EdlInput struct {
	Name                string        `json:"name" jsonschema:"External dynamic list name"`
	Location            LocationInput `json:"location,omitempty"`
	Type                string        `json:"type,omitempty" jsonschema:"List type: ip, domain, url, predefined-ip, predefined-url. Required on create; on update a provided type replaces the whole source definition. imei/imsi are reported by get but not settable"`
	URL                 string        `json:"url,omitempty" jsonschema:"Source URL; for predefined-ip/predefined-url the built-in list name. Required on create and when switching type"`
	Description         string        `json:"description,omitempty"`
	ExceptionList       []string      `json:"exception_list,omitempty" jsonschema:"Entries excluded from the list; replaces fully when provided, an explicitly empty list clears it"`
	CertificateProfile  string        `json:"certificate_profile,omitempty" jsonschema:"Certificate profile for HTTPS source validation; ip, domain, and url types only"`
	ExpandDomain        *bool         `json:"expand_domain,omitempty" jsonschema:"Expand to include subdomains; domain type only"`
	Recurring           string        `json:"recurring,omitempty" jsonschema:"Refresh interval: five-minute, hourly, daily, weekly, monthly. Required whenever type is ip, domain, or url (the device rejects the commit without a refresh schedule); not accepted for predefined types. On a type-less update, omitted leaves the current schedule unchanged"`
	RecurringAt         string        `json:"recurring_at,omitempty" jsonschema:"Refresh time; daily, weekly, and monthly intervals only. Device-validated format"`
	RecurringDayOfWeek  string        `json:"recurring_day_of_week,omitempty" jsonschema:"Weekly refresh day (sunday..saturday); weekly interval only"`
	RecurringDayOfMonth *int64        `json:"recurring_day_of_month,omitempty" jsonschema:"Monthly refresh day 1-31; monthly interval only"`
}

// edlRecurringSpec is the type-independent view of a recurring block, so the
// per-branch pango types (TypeIpRecurring, TypeDomainRecurring, TypeUrlRecurring)
// can be built and read through one shape.
type edlRecurringSpec struct {
	freq       string
	at         string
	dayOfWeek  string
	dayOfMonth *int64
}

func edlRecurringSpecFrom(in *EdlInput) *edlRecurringSpec {
	if in.Recurring == "" {
		return nil
	}
	return &edlRecurringSpec{
		freq:       in.Recurring,
		at:         in.RecurringAt,
		dayOfWeek:  in.RecurringDayOfWeek,
		dayOfMonth: in.RecurringDayOfMonth,
	}
}

// validateEdlParams runs the cross-field checks that must hold regardless of
// whether a type is provided, before any branch is built or overlaid.
//
//nolint:gocognit,gocyclo // exhaustive cross-field validation; each check is one short guard.
func validateEdlParams(in *EdlInput) error {
	if in.Type != "" && !validEdlSettableTypes[in.Type] {
		if in.Type == edlTypeImei || in.Type == edlTypeImsi {
			return fmt.Errorf("type %q is not managed by this server; managed types are %s", in.Type, edlTypeListStr)
		}
		return fmt.Errorf("type must be one of %s, got %q", edlTypeListStr, in.Type)
	}
	if in.Recurring != "" && !validEdlRecurring[in.Recurring] {
		return fmt.Errorf("recurring must be one of %s, got %q", edlRecurringListStr, in.Recurring)
	}
	if in.RecurringAt != "" && in.Recurring != edlRecurringDaily && in.Recurring != edlRecurringWeekly && in.Recurring != edlRecurringMonthly {
		return errors.New("recurring_at requires recurring to be daily, weekly, or monthly")
	}
	if in.RecurringDayOfWeek != "" && in.Recurring != edlRecurringWeekly {
		return errors.New("recurring_day_of_week requires recurring to be weekly")
	}
	if in.RecurringDayOfMonth != nil {
		if in.Recurring != edlRecurringMonthly {
			return errors.New("recurring_day_of_month requires recurring to be monthly")
		}
		if *in.RecurringDayOfMonth < 1 || *in.RecurringDayOfMonth > 31 {
			return fmt.Errorf("recurring_day_of_month must be between 1 and 31, got %d", *in.RecurringDayOfMonth)
		}
	}
	if edlIsPredefined(in.Type) {
		if in.Recurring != "" {
			return errors.New("predefined lists refresh with content updates; recurring is not configurable")
		}
		if in.CertificateProfile != "" {
			return errors.New("certificate_profile does not apply to predefined lists")
		}
		if in.ExpandDomain != nil {
			return errors.New("expand_domain does not apply to predefined lists")
		}
	}
	if in.ExpandDomain != nil && in.Type != "" && in.Type != edlTypeDomain {
		return errors.New("expand_domain applies to the domain type only")
	}
	return nil
}

func edlIPRecurring(s *edlRecurringSpec) *extdynlist.TypeIpRecurring {
	if s == nil {
		return nil
	}
	r := &extdynlist.TypeIpRecurring{}
	switch s.freq {
	case edlRecurringFiveMinute:
		r.FiveMinute = &extdynlist.TypeIpRecurringFiveMinute{}
	case edlRecurringHourly:
		r.Hourly = &extdynlist.TypeIpRecurringHourly{}
	case edlRecurringDaily:
		r.Daily = &extdynlist.TypeIpRecurringDaily{At: ptrIfSet(s.at)}
	case edlRecurringWeekly:
		r.Weekly = &extdynlist.TypeIpRecurringWeekly{At: ptrIfSet(s.at), DayOfWeek: ptrIfSet(s.dayOfWeek)}
	case edlRecurringMonthly:
		r.Monthly = &extdynlist.TypeIpRecurringMonthly{At: ptrIfSet(s.at), DayOfMonth: s.dayOfMonth}
	}
	return r
}

func edlDomainRecurring(s *edlRecurringSpec) *extdynlist.TypeDomainRecurring {
	if s == nil {
		return nil
	}
	r := &extdynlist.TypeDomainRecurring{}
	switch s.freq {
	case edlRecurringFiveMinute:
		r.FiveMinute = &extdynlist.TypeDomainRecurringFiveMinute{}
	case edlRecurringHourly:
		r.Hourly = &extdynlist.TypeDomainRecurringHourly{}
	case edlRecurringDaily:
		r.Daily = &extdynlist.TypeDomainRecurringDaily{At: ptrIfSet(s.at)}
	case edlRecurringWeekly:
		r.Weekly = &extdynlist.TypeDomainRecurringWeekly{At: ptrIfSet(s.at), DayOfWeek: ptrIfSet(s.dayOfWeek)}
	case edlRecurringMonthly:
		r.Monthly = &extdynlist.TypeDomainRecurringMonthly{At: ptrIfSet(s.at), DayOfMonth: s.dayOfMonth}
	}
	return r
}

func edlURLRecurring(s *edlRecurringSpec) *extdynlist.TypeUrlRecurring {
	if s == nil {
		return nil
	}
	r := &extdynlist.TypeUrlRecurring{}
	switch s.freq {
	case edlRecurringFiveMinute:
		r.FiveMinute = &extdynlist.TypeUrlRecurringFiveMinute{}
	case edlRecurringHourly:
		r.Hourly = &extdynlist.TypeUrlRecurringHourly{}
	case edlRecurringDaily:
		r.Daily = &extdynlist.TypeUrlRecurringDaily{At: ptrIfSet(s.at)}
	case edlRecurringWeekly:
		r.Weekly = &extdynlist.TypeUrlRecurringWeekly{At: ptrIfSet(s.at), DayOfWeek: ptrIfSet(s.dayOfWeek)}
	case edlRecurringMonthly:
		r.Monthly = &extdynlist.TypeUrlRecurringMonthly{At: ptrIfSet(s.at), DayOfMonth: s.dayOfMonth}
	}
	return r
}

func edlIPRecurringSpec(r *extdynlist.TypeIpRecurring) *edlRecurringSpec {
	switch {
	case r == nil:
		return nil
	case r.FiveMinute != nil:
		return &edlRecurringSpec{freq: edlRecurringFiveMinute}
	case r.Hourly != nil:
		return &edlRecurringSpec{freq: edlRecurringHourly}
	case r.Daily != nil:
		return &edlRecurringSpec{freq: edlRecurringDaily, at: strVal(r.Daily.At)}
	case r.Weekly != nil:
		return &edlRecurringSpec{freq: edlRecurringWeekly, at: strVal(r.Weekly.At), dayOfWeek: strVal(r.Weekly.DayOfWeek)}
	case r.Monthly != nil:
		return &edlRecurringSpec{freq: edlRecurringMonthly, at: strVal(r.Monthly.At), dayOfMonth: r.Monthly.DayOfMonth}
	default:
		return nil
	}
}

func edlDomainRecurringSpec(r *extdynlist.TypeDomainRecurring) *edlRecurringSpec {
	switch {
	case r == nil:
		return nil
	case r.FiveMinute != nil:
		return &edlRecurringSpec{freq: edlRecurringFiveMinute}
	case r.Hourly != nil:
		return &edlRecurringSpec{freq: edlRecurringHourly}
	case r.Daily != nil:
		return &edlRecurringSpec{freq: edlRecurringDaily, at: strVal(r.Daily.At)}
	case r.Weekly != nil:
		return &edlRecurringSpec{freq: edlRecurringWeekly, at: strVal(r.Weekly.At), dayOfWeek: strVal(r.Weekly.DayOfWeek)}
	case r.Monthly != nil:
		return &edlRecurringSpec{freq: edlRecurringMonthly, at: strVal(r.Monthly.At), dayOfMonth: r.Monthly.DayOfMonth}
	default:
		return nil
	}
}

func edlURLRecurringSpec(r *extdynlist.TypeUrlRecurring) *edlRecurringSpec {
	switch {
	case r == nil:
		return nil
	case r.FiveMinute != nil:
		return &edlRecurringSpec{freq: edlRecurringFiveMinute}
	case r.Hourly != nil:
		return &edlRecurringSpec{freq: edlRecurringHourly}
	case r.Daily != nil:
		return &edlRecurringSpec{freq: edlRecurringDaily, at: strVal(r.Daily.At)}
	case r.Weekly != nil:
		return &edlRecurringSpec{freq: edlRecurringWeekly, at: strVal(r.Weekly.At), dayOfWeek: strVal(r.Weekly.DayOfWeek)}
	case r.Monthly != nil:
		return &edlRecurringSpec{freq: edlRecurringMonthly, at: strVal(r.Monthly.At), dayOfMonth: r.Monthly.DayOfMonth}
	default:
		return nil
	}
}

// buildEdlType builds a fresh Type subtree for the provided type from the input
// only. url is required (a source-less list fails commit; for predefined types
// it is the built-in list name), and recurring is required for the ip, domain,
// and url types (a schedule-less list fails commit the same way). Every
// non-chosen branch is left nil.
func buildEdlType(in *EdlInput) (*extdynlist.Type, error) {
	if in.URL == "" {
		return nil, errors.New("url is required when type is set")
	}
	// ip, domain, and url lists need a refresh schedule or the device rejects the
	// commit ("... is missing 'recurring'"). Predefined types refresh with content
	// updates and take none (already rejected upstream in validateEdlParams).
	// MEASURED live: ip on PAN-OS 12.1.7 (#69); domain and url on Panorama
	// 11.1.16-h1 (#72), where validate flags the same missing-recurring error.
	if !edlIsPredefined(in.Type) && in.Recurring == "" {
		return nil, errors.New("recurring is required for the ip, domain, and url types (the device rejects the commit without a refresh schedule); one of " + edlRecurringListStr)
	}
	spec := edlRecurringSpecFrom(in)
	switch in.Type {
	case edlTypeIP:
		return &extdynlist.Type{Ip: &extdynlist.TypeIp{
			Url:                ptr(in.URL),
			Description:        ptrIfSet(in.Description),
			ExceptionList:      in.ExceptionList,
			CertificateProfile: ptrIfSet(in.CertificateProfile),
			Recurring:          edlIPRecurring(spec),
		}}, nil
	case edlTypeDomain:
		return &extdynlist.Type{Domain: &extdynlist.TypeDomain{
			Url:                ptr(in.URL),
			Description:        ptrIfSet(in.Description),
			ExceptionList:      in.ExceptionList,
			CertificateProfile: ptrIfSet(in.CertificateProfile),
			ExpandDomain:       in.ExpandDomain,
			Recurring:          edlDomainRecurring(spec),
		}}, nil
	case edlTypeURL:
		return &extdynlist.Type{Url: &extdynlist.TypeUrl{
			Url:                ptr(in.URL),
			Description:        ptrIfSet(in.Description),
			ExceptionList:      in.ExceptionList,
			CertificateProfile: ptrIfSet(in.CertificateProfile),
			Recurring:          edlURLRecurring(spec),
		}}, nil
	case edlTypePredefinedIP:
		return &extdynlist.Type{PredefinedIp: &extdynlist.TypePredefinedIp{
			Url:           ptr(in.URL),
			Description:   ptrIfSet(in.Description),
			ExceptionList: in.ExceptionList,
		}}, nil
	case edlTypePredefinedURL:
		return &extdynlist.Type{PredefinedUrl: &extdynlist.TypePredefinedUrl{
			Url:           ptr(in.URL),
			Description:   ptrIfSet(in.Description),
			ExceptionList: in.ExceptionList,
		}}, nil
	default:
		return nil, fmt.Errorf("type must be one of %s, got %q", edlTypeListStr, in.Type)
	}
}

// overlayEdlInBranch applies provided fields within the EDL's existing branch,
// leaving the type unchanged. It is used only when no type is provided.
func overlayEdlInBranch(e *extdynlist.Entry, in *EdlInput) error {
	if e.Type == nil {
		return errors.New("this EDL has no source set; provide type to set one")
	}
	spec := edlRecurringSpecFrom(in)
	switch {
	case e.Type.Ip != nil:
		b := e.Type.Ip
		if in.ExpandDomain != nil {
			return errors.New("expand_domain applies to the domain type only")
		}
		edlOverlayCommon(in, &b.Url, &b.Description, &b.CertificateProfile, &b.ExceptionList)
		if spec != nil {
			b.Recurring = edlIPRecurring(spec)
		}
	case e.Type.Domain != nil:
		b := e.Type.Domain
		edlOverlayCommon(in, &b.Url, &b.Description, &b.CertificateProfile, &b.ExceptionList)
		if in.ExpandDomain != nil {
			b.ExpandDomain = in.ExpandDomain
		}
		if spec != nil {
			b.Recurring = edlDomainRecurring(spec)
		}
	case e.Type.Url != nil:
		b := e.Type.Url
		if in.ExpandDomain != nil {
			return errors.New("expand_domain applies to the domain type only")
		}
		edlOverlayCommon(in, &b.Url, &b.Description, &b.CertificateProfile, &b.ExceptionList)
		if spec != nil {
			b.Recurring = edlURLRecurring(spec)
		}
	case e.Type.PredefinedIp != nil:
		if err := edlOverlayPredefined(in, spec, &e.Type.PredefinedIp.Url, &e.Type.PredefinedIp.Description, &e.Type.PredefinedIp.ExceptionList); err != nil {
			return err
		}
	case e.Type.PredefinedUrl != nil:
		if err := edlOverlayPredefined(in, spec, &e.Type.PredefinedUrl.Url, &e.Type.PredefinedUrl.Description, &e.Type.PredefinedUrl.ExceptionList); err != nil {
			return err
		}
	default:
		return errors.New("this EDL has a type this server does not manage (imei/imsi); recreate with a managed type to change it")
	}
	return nil
}

// edlOverlayPredefined overlays the three fields a predefined branch exposes,
// rejecting the fields predefined lists do not support.
func edlOverlayPredefined(in *EdlInput, spec *edlRecurringSpec, url, description **string, exceptions *[]string) error {
	if in.CertificateProfile != "" || spec != nil || in.ExpandDomain != nil {
		return errors.New("predefined lists have no recurring, certificate_profile, or expand_domain to update")
	}
	if in.URL != "" {
		*url = ptr(in.URL)
	}
	if in.Description != "" {
		*description = ptr(in.Description)
	}
	if in.ExceptionList != nil {
		*exceptions = in.ExceptionList
	}
	return nil
}

// edlOverlayCommon applies the four fields the ip, domain, and url branches
// share (url, description, exception_list, certificate_profile). recurring and
// expand_domain differ per branch and stay inline in overlayEdlInBranch. An
// explicit empty exception_list clears the list (the field's documented
// contract); omitted string fields are left unchanged.
func edlOverlayCommon(in *EdlInput, url, description, certProfile **string, exceptions *[]string) {
	if in.URL != "" {
		*url = ptr(in.URL)
	}
	if in.Description != "" {
		*description = ptr(in.Description)
	}
	if in.ExceptionList != nil {
		*exceptions = in.ExceptionList
	}
	if in.CertificateProfile != "" {
		*certProfile = ptr(in.CertificateProfile)
	}
}

// applyEdlSource validates and applies the EDL source oneof. A provided type
// rebuilds the whole source; an omitted type overlays within the existing
// branch. Cross-field checks run first, before either path.
func applyEdlSource(e *extdynlist.Entry, in *EdlInput) error {
	if err := validateEdlParams(in); err != nil {
		return err
	}
	if in.Type == "" {
		return overlayEdlInBranch(e, in)
	}
	t, err := buildEdlType(in)
	if err != nil {
		return err
	}
	// Carry the <type> element's unknown XML across the wholesale rebuild (the
	// PR #62 nested-Misc lesson), matching how schedule and zone preserve their
	// container Misc. The chosen branch is redefined from the input by design (a
	// provided type is a full source redefinition), so only the type-container
	// Misc carries over, not the old branch's.
	if e.Type != nil {
		t.Misc, t.MiscAttributes = e.Type.Misc, e.Type.MiscAttributes
	}
	e.Type = t
	return nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func buildEdlEntry(in EdlInput) (*extdynlist.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.Type == "" {
		return nil, errors.New("type is required; one of " + edlTypeListStr)
	}
	e := &extdynlist.Entry{Name: in.Name}
	if err := applyEdlSource(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: In is by value to satisfy the generic builder contract; see buildAddressEntry.
func overlayEdl(e *extdynlist.Entry, in EdlInput) error {
	return applyEdlSource(e, &in)
}

// edlTypeString maps the pango Type oneof back to the tool-level type string.
// imei and imsi are reported honestly so a get never misrepresents an EDL this
// server cannot fully model.
func edlTypeString(t *extdynlist.Type) string {
	switch {
	case t == nil:
		return ""
	case t.Ip != nil:
		return edlTypeIP
	case t.Domain != nil:
		return edlTypeDomain
	case t.Url != nil:
		return edlTypeURL
	case t.PredefinedIp != nil:
		return edlTypePredefinedIP
	case t.PredefinedUrl != nil:
		return edlTypePredefinedURL
	case t.Imei != nil:
		return edlTypeImei
	case t.Imsi != nil:
		return edlTypeImsi
	default:
		return ""
	}
}

// edlView is the type-independent read view of an EDL source branch.
type edlView struct {
	typ                string
	url                string
	description        string
	certificateProfile string
	exceptionList      []string
	expandDomain       *bool
	recurring          *edlRecurringSpec
}

func edlExtract(t *extdynlist.Type) edlView {
	v := edlView{typ: edlTypeString(t)}
	if t == nil {
		return v
	}
	switch {
	case t.Ip != nil:
		b := t.Ip
		v.url, v.description, v.certificateProfile = strVal(b.Url), strVal(b.Description), strVal(b.CertificateProfile)
		v.exceptionList, v.recurring = b.ExceptionList, edlIPRecurringSpec(b.Recurring)
	case t.Domain != nil:
		b := t.Domain
		v.url, v.description, v.certificateProfile = strVal(b.Url), strVal(b.Description), strVal(b.CertificateProfile)
		v.exceptionList, v.expandDomain, v.recurring = b.ExceptionList, b.ExpandDomain, edlDomainRecurringSpec(b.Recurring)
	case t.Url != nil:
		b := t.Url
		v.url, v.description, v.certificateProfile = strVal(b.Url), strVal(b.Description), strVal(b.CertificateProfile)
		v.exceptionList, v.recurring = b.ExceptionList, edlURLRecurringSpec(b.Recurring)
	case t.PredefinedIp != nil:
		b := t.PredefinedIp
		v.url, v.description, v.exceptionList = strVal(b.Url), strVal(b.Description), b.ExceptionList
	case t.PredefinedUrl != nil:
		b := t.PredefinedUrl
		v.url, v.description, v.exceptionList = strVal(b.Url), strVal(b.Description), b.ExceptionList
	}
	return v
}

// edlSummary is the compact list view: name, type, url, description.
func edlSummary(e *extdynlist.Entry) any {
	v := edlExtract(e.Type)
	return map[string]any{tagNameKey: e.Name, typeKey: v.typ, "url": v.url, descriptionKey: v.description}
}

// edlDetail is the full get/create/update view, adding the source fields the
// compact summary omits (NAT summary-vs-detail precedent).
func edlDetail(e *extdynlist.Entry) any {
	v := edlExtract(e.Type)
	m := map[string]any{
		tagNameKey:       e.Name,
		typeKey:          v.typ,
		"url":            v.url,
		descriptionKey:   v.description,
		"exception_list": v.exceptionList,
	}
	if v.certificateProfile != "" {
		m["certificate_profile"] = v.certificateProfile
	}
	if v.expandDomain != nil {
		m["expand_domain"] = *v.expandDomain
	}
	if v.recurring != nil {
		m["recurring"] = v.recurring.freq
		if v.recurring.at != "" {
			m["recurring_at"] = v.recurring.at
		}
		if v.recurring.dayOfWeek != "" {
			m["recurring_day_of_week"] = v.recurring.dayOfWeek
		}
		if v.recurring.dayOfMonth != nil {
			m["recurring_day_of_month"] = *v.recurring.dayOfMonth
		}
	}
	return m
}

// RegisterEdlTools registers the external dynamic list tools. Mutating tools are
// skipped entirely in read-only mode.
func RegisterEdlTools(s *mcp.Server, d *Deps) {
	svc := newEdlService(d)
	resolve := func(in LocationInput) (extdynlist.Location, error) { return resolveLocation(d, in, edlParts()) }
	name := svc.name
	loc := func(in EdlInput) LocationInput { return in.Location }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_edl_list",
		Description: "List external dynamic lists (EDLs) at a location with their type and source URL. Read-only.",
		Annotations: readOnlyTool("List EDLs"),
	}, listHandler[extdynlist.Location, extdynlist.Entry](d, "panos_edl_list", svc, resolve, name, edlSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_edl_get",
		Description: "Get one external dynamic list by name with its type, source, exceptions, and refresh schedule. Read-only.",
		Annotations: readOnlyTool("Get EDL"),
	}, getHandler[extdynlist.Location, extdynlist.Entry](d, "panos_edl_get", svc, resolve, edlDetail))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_edl_create",
		Description: "Create an external dynamic list in the candidate config. type is required (ip, domain, url, predefined-ip, predefined-url) and url is required (the source URL, or the built-in list name for predefined types). recurring sets the refresh interval and is required for the ip, domain, and url types (the device rejects the commit without one); predefined types refresh with content updates and take none. credentials (auth) are not settable through this server. Run panos_commit to apply.",
		Annotations: createTool("Create EDL"),
	}, createHandler[extdynlist.Location, extdynlist.Entry, EdlInput](d, "panos_edl_create", svc, resolve, loc, buildEdlEntry, edlDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_edl_update",
		Description: "Update an external dynamic list: read-modify-write, only provided fields change. A provided type replaces the whole source definition (url required, and recurring required for the ip, domain, and url types); without a type, the source fields (url, description, exception_list, certificate_profile, expand_domain, recurring) overlay within the current type, and a field not valid for that type is rejected (for example expand_domain applies to domain only, and predefined lists take none of certificate_profile, expand_domain, or recurring). exception_list replaces fully (an empty list clears it). Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update EDL"),
	}, updateHandler[extdynlist.Location, extdynlist.Entry, EdlInput](d, "panos_edl_update", svc, resolve, loc,
		func(in EdlInput) string { return in.Name }, overlayEdl, edlDetail))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_edl_delete",
		Description: "Delete an external dynamic list from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete EDL"),
	}, deleteHandler[extdynlist.Location, extdynlist.Entry](d, "panos_edl_delete", svc, resolve))
}
