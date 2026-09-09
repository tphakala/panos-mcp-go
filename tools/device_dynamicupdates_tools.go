package tools

// Dynamic-update schedules (device/dynamicupdates)
// ---------------------------------------------------------------------------
//
// The update-schedule config is a device singleton (one per device, no name)
// that lives under deviceconfig/system, so it shares the {System | Template |
// TemplateStack} scope and the get/update singleton handlers in system_scope.go
// with the DNS/NTP/general/proxy settings.
//
// The config models eight features. Seven are a recurrence "one-of": the caller
// picks exactly one cadence (none, daily, weekly, hourly, or a per-feature set of
// minute cadences) and the fields that cadence carries. The eighth, the
// statistics service, is a flat set of telemetry toggles. A single UpdateScheduleInput
// plus a per-feature featureSpec table drives the validation and routing for all
// seven recurring features, so each feature needs only a small build switch over
// its own pango cadence types.
//
// There are no secrets in this config, so the update needs no redaction seam.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	dyncfg "github.com/PaloAltoNetworks/pango/device/dynamicupdates"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Cadence selectors, update actions, feature names and the summary/error field
// keys are shared across the spec table, the overlay switches, the validation
// helpers and the summaries (goconst). "threshold" is deliberately NOT a constant
// here: a bare "threshold" literal already exists elsewhere in the package and a
// second constant for the same value would be redundant, so it stays a single
// literal in the summary.
const (
	cadenceNone        = "none"
	cadenceDaily       = "daily"
	cadenceWeekly      = "weekly"
	cadenceHourly      = "hourly"
	cadenceEvery30Mins = "every-30-mins"
	cadenceEvery15Mins = "every-15-mins"
	cadenceEvery5Mins  = "every-5-mins"
	cadenceEveryHour   = "every-hour"
	cadenceEveryMin    = "every-min"
	cadenceRealTime    = "real-time"

	updateActionDownloadOnly       = "download-only"
	updateActionDownloadAndInstall = "download-and-install"

	featAntiVirus       = "anti_virus"
	featAppProfile      = "app_profile"
	featThreats         = "threats"
	featWildfire        = "wildfire"
	featWfPrivate       = "wf_private"
	featGpDatafile      = "global_protect_datafile"
	featGpClientlessVpn = "global_protect_clientless_vpn"

	recurrenceKey        = "recurrence"
	atKey                = "at"
	dayOfWeekKey         = "day_of_week"
	syncToPeerKey        = "sync_to_peer"
	newAppThresholdKey   = "new_app_threshold"
	disableNewContentKey = "disable_new_content"
	statisticsServiceKey = "statistics_service"

	// cadenceListDailyWeeklyHourly is the supported-cadence message shared by the
	// three features whose cadences are none, daily, weekly and hourly (antivirus
	// and both GlobalProtect feeds).
	cadenceListDailyWeeklyHourly = "none, daily, weekly, hourly"
)

// Validation bounds this server enforces client-side so a bad value fails with a
// clear error instead of at commit. The "at" maximum is the minutes-past-the-
// boundary offset each minute cadence accepts; daily and weekly use a wall-clock
// time instead. These mirror the published PAN-OS dynamic-update schedule model;
// they are not measured against a live device, so the device stays the final
// authority and a future PAN-OS change is a one-line edit here.
const (
	atMaxHourly    int64 = 59
	atMaxEveryHour int64 = 59
	atMaxEvery30   int64 = 29
	atMaxEvery15   int64 = 14
	atMaxEvery5    int64 = 4
	thresholdMin   int64 = 1
	thresholdMax   int64 = 336
	clockHourMax         = 23
	clockMinuteMax       = 59
)

// atKind says how a cadence expresses its "at" time.
type atKind uint8

const (
	atNone      atKind = iota // none, real-time, every-min: no time
	atWallClock               // daily, weekly: "HH:MM"
	atMinutes                 // hourly, every-N-mins: minutes past the boundary
)

// syncLevel says where a feature stores sync-to-peer: not at all, on the
// recurring container (shared by all its cadences), or on each cadence node.
type syncLevel uint8

const (
	syncNone syncLevel = iota
	syncRecurring
	syncCadence
)

// cadenceSpec describes one cadence's shape for validation.
type cadenceSpec struct {
	atKind               atKind
	atMax                int64 // for atMinutes
	hasAction            bool  // false for none and real-time
	hasDay               bool  // weekly
	hasSync              bool  // wildfire cadence-level sync-to-peer
	hasDisableNewContent bool  // threats cadences
}

// featureSpec is a feature's contract: which cadences it supports and which
// recurring-level fields it carries.
type featureSpec struct {
	name              string
	cadenceList       string // for error messages
	sync              syncLevel
	threshold         bool
	newAppThreshold   bool
	disableNewContent bool
	cadences          map[string]cadenceSpec
}

// schedulePlan is a validated, cadence-routed UpdateScheduleInput. cadence is "" when
// the caller omitted recurrence (a recurring-scalar-only edit).
type schedulePlan struct {
	cadence           string
	action            *string
	atStr             *string // daily, weekly
	atMin             *int64  // minute cadences
	dayOfWeek         *string
	syncToPeer        *bool
	threshold         *int64
	newAppThreshold   *int64
	disableNewContent *bool
}

func (p *schedulePlan) assignScalars(in *UpdateScheduleInput) {
	p.action = in.Action
	p.dayOfWeek = in.DayOfWeek
	p.syncToPeer = in.SyncToPeer
	p.threshold = in.Threshold
	p.newAppThreshold = in.NewAppThreshold
	p.disableNewContent = in.DisableNewContent
}

var (
	validUpdateActions = []string{updateActionDownloadOnly, updateActionDownloadAndInstall}
	updateActionsList  = strings.Join(validUpdateActions, ", ")
	validDaysOfWeek    = map[string]bool{
		"sunday": true, "monday": true, "tuesday": true, "wednesday": true,
		"thursday": true, "friday": true, "saturday": true,
	}
	daysOfWeekList = "sunday, monday, tuesday, wednesday, thursday, friday, saturday"
)

var antiVirusSpec = featureSpec{
	name: featAntiVirus, cadenceList: cadenceListDailyWeeklyHourly,
	sync: syncRecurring, threshold: true,
	cadences: map[string]cadenceSpec{
		cadenceNone:   {},
		cadenceDaily:  {atKind: atWallClock, hasAction: true},
		cadenceWeekly: {atKind: atWallClock, hasAction: true, hasDay: true},
		cadenceHourly: {atKind: atMinutes, atMax: atMaxHourly, hasAction: true},
	},
}

var appProfileSpec = featureSpec{
	name: featAppProfile, cadenceList: "none, daily, weekly",
	sync: syncRecurring, threshold: true,
	cadences: map[string]cadenceSpec{
		cadenceNone:   {},
		cadenceDaily:  {atKind: atWallClock, hasAction: true},
		cadenceWeekly: {atKind: atWallClock, hasAction: true, hasDay: true},
	},
}

var threatsSpec = featureSpec{
	name: featThreats, cadenceList: "none, daily, weekly, hourly, every-30-mins",
	sync: syncRecurring, threshold: true, newAppThreshold: true, disableNewContent: true,
	cadences: map[string]cadenceSpec{
		cadenceNone:        {},
		cadenceDaily:       {atKind: atWallClock, hasAction: true, hasDisableNewContent: true},
		cadenceWeekly:      {atKind: atWallClock, hasAction: true, hasDay: true, hasDisableNewContent: true},
		cadenceHourly:      {atKind: atMinutes, atMax: atMaxHourly, hasAction: true, hasDisableNewContent: true},
		cadenceEvery30Mins: {atKind: atMinutes, atMax: atMaxEvery30, hasAction: true, hasDisableNewContent: true},
	},
}

var wildfireSpec = featureSpec{
	name: featWildfire, cadenceList: "none, real-time, every-min, every-15-mins, every-30-mins, every-hour",
	sync: syncCadence,
	cadences: map[string]cadenceSpec{
		cadenceNone:        {},
		cadenceRealTime:    {},
		cadenceEveryMin:    {atKind: atNone, hasAction: true, hasSync: true},
		cadenceEvery15Mins: {atKind: atMinutes, atMax: atMaxEvery15, hasAction: true, hasSync: true},
		cadenceEvery30Mins: {atKind: atMinutes, atMax: atMaxEvery30, hasAction: true, hasSync: true},
		cadenceEveryHour:   {atKind: atMinutes, atMax: atMaxEveryHour, hasAction: true, hasSync: true},
	},
}

var wfPrivateSpec = featureSpec{
	name: featWfPrivate, cadenceList: "none, every-5-mins, every-15-mins, every-30-mins, every-hour",
	sync: syncRecurring,
	cadences: map[string]cadenceSpec{
		cadenceNone:        {},
		cadenceEvery5Mins:  {atKind: atMinutes, atMax: atMaxEvery5, hasAction: true},
		cadenceEvery15Mins: {atKind: atMinutes, atMax: atMaxEvery15, hasAction: true},
		cadenceEvery30Mins: {atKind: atMinutes, atMax: atMaxEvery30, hasAction: true},
		cadenceEveryHour:   {atKind: atMinutes, atMax: atMaxEveryHour, hasAction: true},
	},
}

var gpDatafileSpec = featureSpec{
	name: featGpDatafile, cadenceList: cadenceListDailyWeeklyHourly,
	sync: syncNone,
	cadences: map[string]cadenceSpec{
		cadenceNone:   {},
		cadenceDaily:  {atKind: atWallClock, hasAction: true},
		cadenceWeekly: {atKind: atWallClock, hasAction: true, hasDay: true},
		cadenceHourly: {atKind: atMinutes, atMax: atMaxHourly, hasAction: true},
	},
}

var gpClientlessSpec = featureSpec{
	name: featGpClientlessVpn, cadenceList: cadenceListDailyWeeklyHourly,
	sync: syncNone,
	cadences: map[string]cadenceSpec{
		cadenceNone:   {},
		cadenceDaily:  {atKind: atWallClock, hasAction: true},
		cadenceWeekly: {atKind: atWallClock, hasAction: true, hasDay: true},
		cadenceHourly: {atKind: atMinutes, atMax: atMaxHourly, hasAction: true},
	},
}

// UpdateScheduleInput is one feature's update schedule. Providing recurrence replaces
// that feature's cadence: a cadence switch builds a fresh node (so action and at
// must be given), a same-cadence edit keeps the stored fields it does not
// override. Omitting recurrence edits only the recurring-level scalars and
// requires a schedule to already exist.
type UpdateScheduleInput struct {
	Recurrence        *string `json:"recurrence,omitzero" jsonschema:"Cadence: one of none, daily, weekly, hourly, every-30-mins, every-15-mins, every-5-mins, every-hour, every-min, real-time. Each feature supports a subset (see the tool description). Required whenever action, at, day_of_week or disable_new_content is given, and when the feature has no schedule yet"`
	Action            *string `json:"action,omitzero" jsonschema:"download-only or download-and-install. Required on a fresh or switched cadence; kept from the stored schedule on a same-cadence edit"`
	At                *string `json:"at,omitzero" jsonschema:"When within the period: HH:MM (24-hour) for daily and weekly; minutes past the boundary as a number for hourly and every-hour (0-59), every-30-mins (0-29), every-15-mins (0-14), every-5-mins (0-4). Not accepted for none, every-min or real-time"`
	DayOfWeek         *string `json:"day_of_week,omitzero" jsonschema:"Weekly only: sunday, monday, tuesday, wednesday, thursday, friday or saturday"`
	SyncToPeer        *bool   `json:"sync_to_peer,omitzero" jsonschema:"Sync the downloaded content to the HA peer. For anti_virus, app_profile, threats and wf_private it is schedule-level; for wildfire it is stored on the cadence and so requires recurrence; it is not available for the GlobalProtect features"`
	Threshold         *int64  `json:"threshold,omitzero" jsonschema:"Hours a release must have been available before it is installed, 1-336 (anti_virus, app_profile and threats only)"`
	NewAppThreshold   *int64  `json:"new_app_threshold,omitzero" jsonschema:"threats only: hours a release that introduces new App-IDs must have been available before install, 1-336"`
	DisableNewContent *bool   `json:"disable_new_content,omitzero" jsonschema:"threats only: install the update but leave newly introduced App-IDs disabled; requires recurrence"`
}

// StatisticsServiceInput toggles telemetry categories. Each is tri-state: omit to
// leave the stored value unchanged.
type StatisticsServiceInput struct {
	ApplicationReports          *bool `json:"application_reports,omitzero" jsonschema:"Share application usage reports"`
	FileIdentificationReports   *bool `json:"file_identification_reports,omitzero" jsonschema:"Share file-type identification reports"`
	HealthPerformanceReports    *bool `json:"health_performance_reports,omitzero" jsonschema:"Share device health and performance reports"`
	PassiveDnsMonitoring        *bool `json:"passive_dns_monitoring,omitzero" jsonschema:"Share passive DNS monitoring data"`
	ThreatPreventionInformation *bool `json:"threat_prevention_information,omitzero" jsonschema:"Share threat prevention information"`
	ThreatPreventionPcap        *bool `json:"threat_prevention_pcap,omitzero" jsonschema:"Share threat prevention packet captures"`
	ThreatPreventionReports     *bool `json:"threat_prevention_reports,omitzero" jsonschema:"Share threat prevention reports"`
	UrlReports                  *bool `json:"url_reports,omitzero" jsonschema:"Share URL filtering reports"`
}

// DynamicUpdatesInput is the input for panos_dynamic_updates_update. A feature
// left out is untouched; at least one must be provided.
type DynamicUpdatesInput struct {
	SystemScopeInput
	AntiVirus                  *UpdateScheduleInput    `json:"anti_virus,omitzero" jsonschema:"Antivirus and WildFire content schedule: none, daily, weekly or hourly; sync_to_peer and threshold"`
	AppProfile                 *UpdateScheduleInput    `json:"app_profile,omitzero" jsonschema:"Applications-only content schedule: none, daily or weekly; sync_to_peer and threshold"`
	Threats                    *UpdateScheduleInput    `json:"threats,omitzero" jsonschema:"Applications and threats content schedule: none, daily, weekly, hourly or every-30-mins; sync_to_peer, threshold, new_app_threshold and disable_new_content"`
	Wildfire                   *UpdateScheduleInput    `json:"wildfire,omitzero" jsonschema:"WildFire signature schedule: none, real-time, every-min, every-15-mins, every-30-mins or every-hour; sync_to_peer is set on the cadence"`
	WfPrivate                  *UpdateScheduleInput    `json:"wf_private,omitzero" jsonschema:"WildFire private-cloud schedule: none, every-5-mins, every-15-mins, every-30-mins or every-hour; sync_to_peer"`
	GlobalProtectDatafile      *UpdateScheduleInput    `json:"global_protect_datafile,omitzero" jsonschema:"GlobalProtect data file schedule: none, daily, weekly or hourly"`
	GlobalProtectClientlessVpn *UpdateScheduleInput    `json:"global_protect_clientless_vpn,omitzero" jsonschema:"GlobalProtect clientless VPN schedule: none, daily, weekly or hourly"`
	StatisticsService          *StatisticsServiceInput `json:"statistics_service,omitzero" jsonschema:"Telemetry (statistics service) category toggles"`
}

func dynamicUpdatesParts() systemScopeParts[dyncfg.Location] {
	return systemScopeParts[dyncfg.Location]{
		system: func() dyncfg.Location {
			return dyncfg.Location{System: &dyncfg.SystemLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) dyncfg.Location {
			return dyncfg.Location{Template: &dyncfg.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) dyncfg.Location {
			return dyncfg.Location{TemplateStack: &dyncfg.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// --- Validation -------------------------------------------------------------

func parseSchedule(spec *featureSpec, in *UpdateScheduleInput) (schedulePlan, error) {
	var p schedulePlan
	if err := validateFeatureScalars(spec, in); err != nil {
		return p, err
	}
	if err := validateScheduleEnums(spec, in); err != nil {
		return p, err
	}
	if in.Recurrence == nil {
		if err := rejectCadenceFieldsWhenNoRecurrence(spec, in); err != nil {
			return p, err
		}
		p.assignScalars(in)
		return p, nil
	}
	cadence := *in.Recurrence
	cs, ok := spec.cadences[cadence]
	if !ok {
		return p, fmt.Errorf("%s: recurrence must be one of %s; got %q", spec.name, spec.cadenceList, cadence)
	}
	if err := validateCadenceFields(spec, cadence, cs, in); err != nil {
		return p, err
	}
	atStr, atMin, err := parseScheduleAt(spec.name, cadence, cs, in.At)
	if err != nil {
		return p, err
	}
	p.cadence = cadence
	p.atStr, p.atMin = atStr, atMin
	p.assignScalars(in)
	return p, nil
}

func validateFeatureScalars(spec *featureSpec, in *UpdateScheduleInput) error {
	if err := validateThresholds(spec, in); err != nil {
		return err
	}
	if in.DisableNewContent != nil && !spec.disableNewContent {
		return unsupportedFieldErr(spec.name, disableNewContentKey)
	}
	if in.SyncToPeer != nil && spec.sync == syncNone {
		return unsupportedFieldErr(spec.name, syncToPeerKey)
	}
	return nil
}

func validateThresholds(spec *featureSpec, in *UpdateScheduleInput) error {
	if in.Threshold != nil {
		if !spec.threshold {
			return fmt.Errorf("%s: threshold is not supported for this feature", spec.name)
		}
		if *in.Threshold < thresholdMin || *in.Threshold > thresholdMax {
			return fmt.Errorf("%s: threshold must be %d-%d hours; got %d", spec.name, thresholdMin, thresholdMax, *in.Threshold)
		}
	}
	if in.NewAppThreshold != nil {
		if !spec.newAppThreshold {
			return unsupportedFieldErr(spec.name, newAppThresholdKey)
		}
		if *in.NewAppThreshold < thresholdMin || *in.NewAppThreshold > thresholdMax {
			return fmt.Errorf("%s: %s must be %d-%d hours; got %d", spec.name, newAppThresholdKey, thresholdMin, thresholdMax, *in.NewAppThreshold)
		}
	}
	return nil
}

func validateScheduleEnums(spec *featureSpec, in *UpdateScheduleInput) error {
	if in.Action != nil && !slices.Contains(validUpdateActions, *in.Action) {
		return fmt.Errorf("%s: action must be one of %s; got %q", spec.name, updateActionsList, *in.Action)
	}
	if in.DayOfWeek != nil && !validDaysOfWeek[*in.DayOfWeek] {
		return fmt.Errorf("%s: day_of_week must be one of %s; got %q", spec.name, daysOfWeekList, *in.DayOfWeek)
	}
	return nil
}

// validateCadenceFields rejects a field the selected cadence does not carry, so a
// caller-supplied value cannot be silently dropped.
func validateCadenceFields(spec *featureSpec, cadence string, cs cadenceSpec, in *UpdateScheduleInput) error {
	if in.Action != nil && !cs.hasAction {
		return notForCadenceErr(spec.name, actionKey, cadence)
	}
	if in.DayOfWeek != nil && !cs.hasDay {
		return notForCadenceErr(spec.name, dayOfWeekKey, cadence)
	}
	if in.DisableNewContent != nil && !cs.hasDisableNewContent {
		return notForCadenceErr(spec.name, disableNewContentKey, cadence)
	}
	if in.SyncToPeer != nil && spec.sync == syncCadence && !cs.hasSync {
		return notForCadenceErr(spec.name, syncToPeerKey, cadence)
	}
	return nil
}

// rejectCadenceFieldsWhenNoRecurrence fires when recurrence is omitted: a
// cadence-level field then has no cadence to attach to. sync_to_peer is only
// cadence-level for wildfire; for the schedule-level features it is a valid
// recurring-scalar-only edit.
func rejectCadenceFieldsWhenNoRecurrence(spec *featureSpec, in *UpdateScheduleInput) error {
	switch {
	case in.Action != nil:
		return requiresRecurrenceErr(spec.name, actionKey)
	case in.At != nil:
		return requiresRecurrenceErr(spec.name, atKey)
	case in.DayOfWeek != nil:
		return requiresRecurrenceErr(spec.name, dayOfWeekKey)
	case in.DisableNewContent != nil:
		return requiresRecurrenceErr(spec.name, disableNewContentKey)
	case in.SyncToPeer != nil && spec.sync == syncCadence:
		return requiresRecurrenceErr(spec.name, syncToPeerKey)
	}
	return nil
}

func parseScheduleAt(feature, cadence string, cs cadenceSpec, at *string) (atStr *string, atMin *int64, err error) {
	if at == nil {
		return nil, nil, nil
	}
	switch cs.atKind {
	case atNone:
		return nil, nil, notForCadenceErr(feature, atKey, cadence)
	case atWallClock:
		norm, werr := parseWallClock(*at)
		if werr != nil {
			return nil, nil, fmt.Errorf("%s: %w", feature, werr)
		}
		return &norm, nil, nil
	case atMinutes:
		n, cerr := strconv.Atoi(strings.TrimSpace(*at))
		if cerr != nil {
			return nil, nil, fmt.Errorf("%s: at must be a whole number of minutes for recurrence %s; got %q", feature, cadence, *at)
		}
		if n < 0 || int64(n) > cs.atMax {
			return nil, nil, fmt.Errorf("%s: at must be 0-%d minutes for recurrence %s; got %d", feature, cs.atMax, cadence, n)
		}
		v := int64(n)
		return nil, &v, nil
	}
	return nil, nil, nil
}

// parseWallClock validates a daily or weekly "HH:MM" time and returns it
// normalized to zero-padded form, so the value written to the device is always
// canonical (PAN-OS expects HH:MM) and a get summary round-trips cleanly into an
// update. A leading sign or any non-digit in either half is rejected, which a
// bare strconv.Atoi would accept.
func parseWallClock(at string) (string, error) {
	hh, mm, found := strings.Cut(at, ":")
	h, herr := strconv.Atoi(hh)
	m, merr := strconv.Atoi(mm)
	if !found || !allDigits(hh) || !allDigits(mm) || herr != nil || merr != nil || h > clockHourMax || m > clockMinuteMax {
		return "", fmt.Errorf("at must be HH:MM between 00:00 and 23:59; got %q", at)
	}
	return fmt.Sprintf("%02d:%02d", h, m), nil
}

// allDigits reports whether s is one or more ASCII digits, with no sign, space
// or other character, so a value strconv.Atoi would leniently accept (a leading
// + or -) is rejected.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func unsupportedFieldErr(feature, field string) error {
	return fmt.Errorf("%s: %s is not supported for this feature", feature, field)
}

func notForCadenceErr(feature, field, cadence string) error {
	return fmt.Errorf("%s: %s is not valid for recurrence %s", feature, field, cadence)
}

func requiresRecurrenceErr(feature, field string) error {
	return fmt.Errorf("%s: %s requires recurrence to be set", feature, field)
}

func missingCadenceField(feature, field, cadence string) error {
	return fmt.Errorf("%s: %s is required when selecting recurrence %s", feature, field, cadence)
}

// requireOneCadence fires when recurrence was omitted but the feature has no
// stored cadence to edit, so the recurring-scalar-only write has nothing to
// attach to.
func requireOneCadence(feature string, present ...bool) error {
	if countSet(present...) == 0 {
		return fmt.Errorf("%s: recurrence is required (no schedule exists yet to update)", feature)
	}
	return nil
}

// guardScheduled is the freshness guard: a freshly built scheduled cadence node
// must carry an action and an at, whether the cadence was switched or written for
// the first time. A same-cadence edit (fresh == false) inherits the stored node's
// fields and is not re-checked, so a value the device filled with a default is
// preserved rather than demanded back.
func guardScheduled(feature, cadence string, fresh, hasAction, hasAt bool) error {
	if !fresh {
		return nil
	}
	if !hasAction {
		return missingCadenceField(feature, actionKey, cadence)
	}
	if !hasAt {
		return missingCadenceField(feature, atKey, cadence)
	}
	return nil
}

func guardWeekly(feature string, fresh, hasAction, hasAt, hasDay bool) error {
	if err := guardScheduled(feature, cadenceWeekly, fresh, hasAction, hasAt); err != nil {
		return err
	}
	if fresh && !hasDay {
		return missingCadenceField(feature, dayOfWeekKey, cadenceWeekly)
	}
	return nil
}

func guardActionOnly(feature, cadence string, fresh, hasAction bool) error {
	if fresh && !hasAction {
		return missingCadenceField(feature, actionKey, cadence)
	}
	return nil
}

// --- Overlay ----------------------------------------------------------------

//nolint:gocritic // hugeParam: in is by value to satisfy the singleton overlay contract.
func overlayDynamicUpdates(c *dyncfg.Config, in DynamicUpdatesInput) error {
	if countSet(
		in.AntiVirus != nil, in.AppProfile != nil, in.Threats != nil, in.Wildfire != nil,
		in.WfPrivate != nil, in.GlobalProtectDatafile != nil, in.GlobalProtectClientlessVpn != nil,
		in.StatisticsService != nil,
	) == 0 {
		return errors.New("at least one schedule (anti_virus, app_profile, threats, wildfire, wf_private, global_protect_datafile, global_protect_clientless_vpn) or statistics_service must be provided")
	}
	if c.UpdateSchedule == nil {
		c.UpdateSchedule = &dyncfg.UpdateSchedule{}
	}
	us := c.UpdateSchedule
	if err := applyAntiVirusSchedule(us, in.AntiVirus); err != nil {
		return err
	}
	if err := applyAppProfileSchedule(us, in.AppProfile); err != nil {
		return err
	}
	if err := applyThreatsSchedule(us, in.Threats); err != nil {
		return err
	}
	if err := applyWildfireSchedule(us, in.Wildfire); err != nil {
		return err
	}
	if err := applyWfPrivateSchedule(us, in.WfPrivate); err != nil {
		return err
	}
	if err := applyGpDatafileSchedule(us, in.GlobalProtectDatafile); err != nil {
		return err
	}
	if err := applyGpClientlessSchedule(us, in.GlobalProtectClientlessVpn); err != nil {
		return err
	}
	applyStatisticsService(us, in.StatisticsService)
	return nil
}

func applyAntiVirusSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&antiVirusSpec, in)
	if err != nil {
		return err
	}
	if us.AntiVirus == nil {
		us.AntiVirus = &dyncfg.UpdateScheduleAntiVirus{}
	}
	r := us.AntiVirus.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleAntiVirusRecurring{}
		us.AntiVirus.Recurring = r
	}
	setPtr(&r.SyncToPeer, plan.syncToPeer)
	setPtr(&r.Threshold, plan.threshold)
	if plan.cadence == "" {
		return requireOneCadence(featAntiVirus, r.Daily != nil, r.Hourly != nil, r.Weekly != nil, r.None != nil)
	}
	return buildAntiVirusCadence(r, &plan)
}

func buildAntiVirusCadence(r *dyncfg.UpdateScheduleAntiVirusRecurring, plan *schedulePlan) error {
	oldDaily, oldHourly, oldNone, oldWeekly := r.Daily, r.Hourly, r.None, r.Weekly
	r.Daily, r.Hourly, r.None, r.Weekly = nil, nil, nil, nil
	switch plan.cadence {
	case cadenceDaily:
		b := seedBranch(oldDaily)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		if err := guardScheduled(featAntiVirus, cadenceDaily, oldDaily == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Daily = b
	case cadenceHourly:
		b := seedBranch(oldHourly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featAntiVirus, cadenceHourly, oldHourly == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Hourly = b
	case cadenceWeekly:
		b := seedBranch(oldWeekly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DayOfWeek, plan.dayOfWeek)
		if err := guardWeekly(featAntiVirus, oldWeekly == nil, b.Action != nil, b.At != nil, b.DayOfWeek != nil); err != nil {
			return err
		}
		r.Weekly = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyAppProfileSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&appProfileSpec, in)
	if err != nil {
		return err
	}
	if us.AppProfile == nil {
		us.AppProfile = &dyncfg.UpdateScheduleAppProfile{}
	}
	r := us.AppProfile.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleAppProfileRecurring{}
		us.AppProfile.Recurring = r
	}
	setPtr(&r.SyncToPeer, plan.syncToPeer)
	setPtr(&r.Threshold, plan.threshold)
	if plan.cadence == "" {
		return requireOneCadence(featAppProfile, r.Daily != nil, r.Weekly != nil, r.None != nil)
	}
	return buildAppProfileCadence(r, &plan)
}

func buildAppProfileCadence(r *dyncfg.UpdateScheduleAppProfileRecurring, plan *schedulePlan) error {
	oldDaily, oldNone, oldWeekly := r.Daily, r.None, r.Weekly
	r.Daily, r.None, r.Weekly = nil, nil, nil
	switch plan.cadence {
	case cadenceDaily:
		b := seedBranch(oldDaily)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		if err := guardScheduled(featAppProfile, cadenceDaily, oldDaily == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Daily = b
	case cadenceWeekly:
		b := seedBranch(oldWeekly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DayOfWeek, plan.dayOfWeek)
		if err := guardWeekly(featAppProfile, oldWeekly == nil, b.Action != nil, b.At != nil, b.DayOfWeek != nil); err != nil {
			return err
		}
		r.Weekly = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyThreatsSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&threatsSpec, in)
	if err != nil {
		return err
	}
	if us.Threats == nil {
		us.Threats = &dyncfg.UpdateScheduleThreats{}
	}
	r := us.Threats.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleThreatsRecurring{}
		us.Threats.Recurring = r
	}
	setPtr(&r.SyncToPeer, plan.syncToPeer)
	setPtr(&r.Threshold, plan.threshold)
	setPtr(&r.NewAppThreshold, plan.newAppThreshold)
	if plan.cadence == "" {
		return requireOneCadence(featThreats, r.Daily != nil, r.Hourly != nil, r.Every30Mins != nil, r.Weekly != nil, r.None != nil)
	}
	return buildThreatsCadence(r, &plan)
}

func buildThreatsCadence(r *dyncfg.UpdateScheduleThreatsRecurring, plan *schedulePlan) error {
	oldDaily, oldHourly, oldEvery30, oldNone, oldWeekly := r.Daily, r.Hourly, r.Every30Mins, r.None, r.Weekly
	r.Daily, r.Hourly, r.Every30Mins, r.None, r.Weekly = nil, nil, nil, nil, nil
	switch plan.cadence {
	case cadenceDaily:
		b := seedBranch(oldDaily)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DisableNewContent, plan.disableNewContent)
		if err := guardScheduled(featThreats, cadenceDaily, oldDaily == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Daily = b
	case cadenceHourly:
		b := seedBranch(oldHourly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		setPtr(&b.DisableNewContent, plan.disableNewContent)
		if err := guardScheduled(featThreats, cadenceHourly, oldHourly == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Hourly = b
	case cadenceEvery30Mins:
		b := seedBranch(oldEvery30)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		setPtr(&b.DisableNewContent, plan.disableNewContent)
		if err := guardScheduled(featThreats, cadenceEvery30Mins, oldEvery30 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every30Mins = b
	case cadenceWeekly:
		b := seedBranch(oldWeekly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DayOfWeek, plan.dayOfWeek)
		setPtr(&b.DisableNewContent, plan.disableNewContent)
		if err := guardWeekly(featThreats, oldWeekly == nil, b.Action != nil, b.At != nil, b.DayOfWeek != nil); err != nil {
			return err
		}
		r.Weekly = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyWildfireSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&wildfireSpec, in)
	if err != nil {
		return err
	}
	if us.Wildfire == nil {
		us.Wildfire = &dyncfg.UpdateScheduleWildfire{}
	}
	r := us.Wildfire.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleWildfireRecurring{}
		us.Wildfire.Recurring = r
	}
	if plan.cadence == "" {
		return requireOneCadence(featWildfire,
			r.Every15Mins != nil, r.Every30Mins != nil, r.EveryHour != nil, r.EveryMin != nil, r.None != nil, r.RealTime != nil)
	}
	return buildWildfireCadence(r, &plan)
}

func buildWildfireCadence(r *dyncfg.UpdateScheduleWildfireRecurring, plan *schedulePlan) error {
	oldE15, oldE30, oldHour, oldMin, oldNone, oldRealTime := r.Every15Mins, r.Every30Mins, r.EveryHour, r.EveryMin, r.None, r.RealTime
	r.Every15Mins, r.Every30Mins, r.EveryHour, r.EveryMin, r.None, r.RealTime = nil, nil, nil, nil, nil, nil
	switch plan.cadence {
	case cadenceEvery15Mins:
		b := seedBranch(oldE15)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		setPtr(&b.SyncToPeer, plan.syncToPeer)
		if err := guardScheduled(featWildfire, cadenceEvery15Mins, oldE15 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every15Mins = b
	case cadenceEvery30Mins:
		b := seedBranch(oldE30)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		setPtr(&b.SyncToPeer, plan.syncToPeer)
		if err := guardScheduled(featWildfire, cadenceEvery30Mins, oldE30 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every30Mins = b
	case cadenceEveryHour:
		b := seedBranch(oldHour)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		setPtr(&b.SyncToPeer, plan.syncToPeer)
		if err := guardScheduled(featWildfire, cadenceEveryHour, oldHour == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.EveryHour = b
	case cadenceEveryMin:
		b := seedBranch(oldMin)
		setPtr(&b.Action, plan.action)
		setPtr(&b.SyncToPeer, plan.syncToPeer)
		if err := guardActionOnly(featWildfire, cadenceEveryMin, oldMin == nil, b.Action != nil); err != nil {
			return err
		}
		r.EveryMin = b
	case cadenceRealTime:
		r.RealTime = seedBranch(oldRealTime)
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyWfPrivateSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&wfPrivateSpec, in)
	if err != nil {
		return err
	}
	if us.WfPrivate == nil {
		us.WfPrivate = &dyncfg.UpdateScheduleWfPrivate{}
	}
	r := us.WfPrivate.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleWfPrivateRecurring{}
		us.WfPrivate.Recurring = r
	}
	setPtr(&r.SyncToPeer, plan.syncToPeer)
	if plan.cadence == "" {
		return requireOneCadence(featWfPrivate,
			r.Every5Mins != nil, r.Every15Mins != nil, r.Every30Mins != nil, r.EveryHour != nil, r.None != nil)
	}
	return buildWfPrivateCadence(r, &plan)
}

func buildWfPrivateCadence(r *dyncfg.UpdateScheduleWfPrivateRecurring, plan *schedulePlan) error {
	oldE5, oldE15, oldE30, oldHour, oldNone := r.Every5Mins, r.Every15Mins, r.Every30Mins, r.EveryHour, r.None
	r.Every5Mins, r.Every15Mins, r.Every30Mins, r.EveryHour, r.None = nil, nil, nil, nil, nil
	switch plan.cadence {
	case cadenceEvery5Mins:
		b := seedBranch(oldE5)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featWfPrivate, cadenceEvery5Mins, oldE5 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every5Mins = b
	case cadenceEvery15Mins:
		b := seedBranch(oldE15)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featWfPrivate, cadenceEvery15Mins, oldE15 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every15Mins = b
	case cadenceEvery30Mins:
		b := seedBranch(oldE30)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featWfPrivate, cadenceEvery30Mins, oldE30 == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Every30Mins = b
	case cadenceEveryHour:
		b := seedBranch(oldHour)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featWfPrivate, cadenceEveryHour, oldHour == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.EveryHour = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyGpDatafileSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&gpDatafileSpec, in)
	if err != nil {
		return err
	}
	if us.GlobalProtectDatafile == nil {
		us.GlobalProtectDatafile = &dyncfg.UpdateScheduleGlobalProtectDatafile{}
	}
	r := us.GlobalProtectDatafile.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleGlobalProtectDatafileRecurring{}
		us.GlobalProtectDatafile.Recurring = r
	}
	if plan.cadence == "" {
		return requireOneCadence(featGpDatafile, r.Daily != nil, r.Hourly != nil, r.Weekly != nil, r.None != nil)
	}
	return buildGpDatafileCadence(r, &plan)
}

func buildGpDatafileCadence(r *dyncfg.UpdateScheduleGlobalProtectDatafileRecurring, plan *schedulePlan) error {
	oldDaily, oldHourly, oldNone, oldWeekly := r.Daily, r.Hourly, r.None, r.Weekly
	r.Daily, r.Hourly, r.None, r.Weekly = nil, nil, nil, nil
	switch plan.cadence {
	case cadenceDaily:
		b := seedBranch(oldDaily)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		if err := guardScheduled(featGpDatafile, cadenceDaily, oldDaily == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Daily = b
	case cadenceHourly:
		b := seedBranch(oldHourly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featGpDatafile, cadenceHourly, oldHourly == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Hourly = b
	case cadenceWeekly:
		b := seedBranch(oldWeekly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DayOfWeek, plan.dayOfWeek)
		if err := guardWeekly(featGpDatafile, oldWeekly == nil, b.Action != nil, b.At != nil, b.DayOfWeek != nil); err != nil {
			return err
		}
		r.Weekly = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyGpClientlessSchedule(us *dyncfg.UpdateSchedule, in *UpdateScheduleInput) error {
	if in == nil {
		return nil
	}
	plan, err := parseSchedule(&gpClientlessSpec, in)
	if err != nil {
		return err
	}
	if us.GlobalProtectClientlessVpn == nil {
		us.GlobalProtectClientlessVpn = &dyncfg.UpdateScheduleGlobalProtectClientlessVpn{}
	}
	r := us.GlobalProtectClientlessVpn.Recurring
	if r == nil {
		r = &dyncfg.UpdateScheduleGlobalProtectClientlessVpnRecurring{}
		us.GlobalProtectClientlessVpn.Recurring = r
	}
	if plan.cadence == "" {
		return requireOneCadence(featGpClientlessVpn, r.Daily != nil, r.Hourly != nil, r.Weekly != nil, r.None != nil)
	}
	return buildGpClientlessCadence(r, &plan)
}

func buildGpClientlessCadence(r *dyncfg.UpdateScheduleGlobalProtectClientlessVpnRecurring, plan *schedulePlan) error {
	oldDaily, oldHourly, oldNone, oldWeekly := r.Daily, r.Hourly, r.None, r.Weekly
	r.Daily, r.Hourly, r.None, r.Weekly = nil, nil, nil, nil
	switch plan.cadence {
	case cadenceDaily:
		b := seedBranch(oldDaily)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		if err := guardScheduled(featGpClientlessVpn, cadenceDaily, oldDaily == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Daily = b
	case cadenceHourly:
		b := seedBranch(oldHourly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atMin)
		if err := guardScheduled(featGpClientlessVpn, cadenceHourly, oldHourly == nil, b.Action != nil, b.At != nil); err != nil {
			return err
		}
		r.Hourly = b
	case cadenceWeekly:
		b := seedBranch(oldWeekly)
		setPtr(&b.Action, plan.action)
		setPtr(&b.At, plan.atStr)
		setPtr(&b.DayOfWeek, plan.dayOfWeek)
		if err := guardWeekly(featGpClientlessVpn, oldWeekly == nil, b.Action != nil, b.At != nil, b.DayOfWeek != nil); err != nil {
			return err
		}
		r.Weekly = b
	default: // cadenceNone
		r.None = seedBranch(oldNone)
	}
	return nil
}

func applyStatisticsService(us *dyncfg.UpdateSchedule, in *StatisticsServiceInput) {
	if in == nil {
		return
	}
	if us.StatisticsService == nil {
		us.StatisticsService = &dyncfg.UpdateScheduleStatisticsService{}
	}
	s := us.StatisticsService
	setPtr(&s.ApplicationReports, in.ApplicationReports)
	setPtr(&s.FileIdentificationReports, in.FileIdentificationReports)
	setPtr(&s.HealthPerformanceReports, in.HealthPerformanceReports)
	setPtr(&s.PassiveDnsMonitoring, in.PassiveDnsMonitoring)
	setPtr(&s.ThreatPreventionInformation, in.ThreatPreventionInformation)
	setPtr(&s.ThreatPreventionPcap, in.ThreatPreventionPcap)
	setPtr(&s.ThreatPreventionReports, in.ThreatPreventionReports)
	setPtr(&s.UrlReports, in.UrlReports)
}

// --- Summary ----------------------------------------------------------------

func dynamicUpdatesSummary(c *dyncfg.Config) any {
	m := map[string]any{}
	us := c.UpdateSchedule
	if us == nil {
		return m
	}
	if us.AntiVirus != nil {
		m[featAntiVirus] = antiVirusScheduleSummary(us.AntiVirus.Recurring)
	}
	if us.AppProfile != nil {
		m[featAppProfile] = appProfileScheduleSummary(us.AppProfile.Recurring)
	}
	if us.Threats != nil {
		m[featThreats] = threatsScheduleSummary(us.Threats.Recurring)
	}
	if us.Wildfire != nil {
		m[featWildfire] = wildfireScheduleSummary(us.Wildfire.Recurring)
	}
	if us.WfPrivate != nil {
		m[featWfPrivate] = wfPrivateScheduleSummary(us.WfPrivate.Recurring)
	}
	if us.GlobalProtectDatafile != nil {
		m[featGpDatafile] = gpDatafileScheduleSummary(us.GlobalProtectDatafile.Recurring)
	}
	if us.GlobalProtectClientlessVpn != nil {
		m[featGpClientlessVpn] = gpClientlessScheduleSummary(us.GlobalProtectClientlessVpn.Recurring)
	}
	if us.StatisticsService != nil {
		m[statisticsServiceKey] = statisticsServiceSummary(us.StatisticsService)
	}
	return m
}

// scheduleFields is the cadence-agnostic projection every per-feature summary
// feeds into. recurrence is always present ("" when no cadence is set); the
// other keys follow the #128 omit-when-nil convention.
//
//nolint:gocritic // hugeParam is not applicable; this takes pointers and scalars by design.
func scheduleFields(cadence string, action *string, at string, day *string, sync *bool, threshold, newApp *int64, disableNew *bool) map[string]any {
	m := map[string]any{recurrenceKey: cadence}
	if cadence != "" && cadence != cadenceNone && cadence != cadenceRealTime {
		m[actionKey] = strVal(action)
		if cadence != cadenceEveryMin {
			m[atKey] = at
		}
	}
	if day != nil {
		m[dayOfWeekKey] = *day
	}
	putBool(m, syncToPeerKey, sync)
	putInt(m, "threshold", threshold)
	putInt(m, newAppThresholdKey, newApp)
	putBool(m, disableNewContentKey, disableNew)
	return m
}

// minuteAt renders a minutes-past offset for a summary so a get round-trips back
// into an update's string "at" field.
func minuteAt(v *int64) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(int(*v))
}

func antiVirusScheduleSummary(r *dyncfg.UpdateScheduleAntiVirusRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Daily != nil:
		return scheduleFields(cadenceDaily, r.Daily.Action, strVal(r.Daily.At), nil, r.SyncToPeer, r.Threshold, nil, nil)
	case r.Hourly != nil:
		return scheduleFields(cadenceHourly, r.Hourly.Action, minuteAt(r.Hourly.At), nil, r.SyncToPeer, r.Threshold, nil, nil)
	case r.Weekly != nil:
		return scheduleFields(cadenceWeekly, r.Weekly.Action, strVal(r.Weekly.At), r.Weekly.DayOfWeek, r.SyncToPeer, r.Threshold, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, r.SyncToPeer, r.Threshold, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, r.SyncToPeer, r.Threshold, nil, nil)
	}
}

func appProfileScheduleSummary(r *dyncfg.UpdateScheduleAppProfileRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Daily != nil:
		return scheduleFields(cadenceDaily, r.Daily.Action, strVal(r.Daily.At), nil, r.SyncToPeer, r.Threshold, nil, nil)
	case r.Weekly != nil:
		return scheduleFields(cadenceWeekly, r.Weekly.Action, strVal(r.Weekly.At), r.Weekly.DayOfWeek, r.SyncToPeer, r.Threshold, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, r.SyncToPeer, r.Threshold, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, r.SyncToPeer, r.Threshold, nil, nil)
	}
}

func threatsScheduleSummary(r *dyncfg.UpdateScheduleThreatsRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Daily != nil:
		return scheduleFields(cadenceDaily, r.Daily.Action, strVal(r.Daily.At), nil, r.SyncToPeer, r.Threshold, r.NewAppThreshold, r.Daily.DisableNewContent)
	case r.Hourly != nil:
		return scheduleFields(cadenceHourly, r.Hourly.Action, minuteAt(r.Hourly.At), nil, r.SyncToPeer, r.Threshold, r.NewAppThreshold, r.Hourly.DisableNewContent)
	case r.Every30Mins != nil:
		return scheduleFields(cadenceEvery30Mins, r.Every30Mins.Action, minuteAt(r.Every30Mins.At), nil, r.SyncToPeer, r.Threshold, r.NewAppThreshold, r.Every30Mins.DisableNewContent)
	case r.Weekly != nil:
		return scheduleFields(cadenceWeekly, r.Weekly.Action, strVal(r.Weekly.At), r.Weekly.DayOfWeek, r.SyncToPeer, r.Threshold, r.NewAppThreshold, r.Weekly.DisableNewContent)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, r.SyncToPeer, r.Threshold, r.NewAppThreshold, nil)
	default:
		return scheduleFields("", nil, "", nil, r.SyncToPeer, r.Threshold, r.NewAppThreshold, nil)
	}
}

func wildfireScheduleSummary(r *dyncfg.UpdateScheduleWildfireRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Every15Mins != nil:
		return scheduleFields(cadenceEvery15Mins, r.Every15Mins.Action, minuteAt(r.Every15Mins.At), nil, r.Every15Mins.SyncToPeer, nil, nil, nil)
	case r.Every30Mins != nil:
		return scheduleFields(cadenceEvery30Mins, r.Every30Mins.Action, minuteAt(r.Every30Mins.At), nil, r.Every30Mins.SyncToPeer, nil, nil, nil)
	case r.EveryHour != nil:
		return scheduleFields(cadenceEveryHour, r.EveryHour.Action, minuteAt(r.EveryHour.At), nil, r.EveryHour.SyncToPeer, nil, nil, nil)
	case r.EveryMin != nil:
		return scheduleFields(cadenceEveryMin, r.EveryMin.Action, "", nil, r.EveryMin.SyncToPeer, nil, nil, nil)
	case r.RealTime != nil:
		return scheduleFields(cadenceRealTime, nil, "", nil, nil, nil, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, nil, nil, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
}

func wfPrivateScheduleSummary(r *dyncfg.UpdateScheduleWfPrivateRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Every5Mins != nil:
		return scheduleFields(cadenceEvery5Mins, r.Every5Mins.Action, minuteAt(r.Every5Mins.At), nil, r.SyncToPeer, nil, nil, nil)
	case r.Every15Mins != nil:
		return scheduleFields(cadenceEvery15Mins, r.Every15Mins.Action, minuteAt(r.Every15Mins.At), nil, r.SyncToPeer, nil, nil, nil)
	case r.Every30Mins != nil:
		return scheduleFields(cadenceEvery30Mins, r.Every30Mins.Action, minuteAt(r.Every30Mins.At), nil, r.SyncToPeer, nil, nil, nil)
	case r.EveryHour != nil:
		return scheduleFields(cadenceEveryHour, r.EveryHour.Action, minuteAt(r.EveryHour.At), nil, r.SyncToPeer, nil, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, r.SyncToPeer, nil, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, r.SyncToPeer, nil, nil, nil)
	}
}

func gpDatafileScheduleSummary(r *dyncfg.UpdateScheduleGlobalProtectDatafileRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Daily != nil:
		return scheduleFields(cadenceDaily, r.Daily.Action, strVal(r.Daily.At), nil, nil, nil, nil, nil)
	case r.Hourly != nil:
		return scheduleFields(cadenceHourly, r.Hourly.Action, minuteAt(r.Hourly.At), nil, nil, nil, nil, nil)
	case r.Weekly != nil:
		return scheduleFields(cadenceWeekly, r.Weekly.Action, strVal(r.Weekly.At), r.Weekly.DayOfWeek, nil, nil, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, nil, nil, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
}

func gpClientlessScheduleSummary(r *dyncfg.UpdateScheduleGlobalProtectClientlessVpnRecurring) any {
	if r == nil {
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
	switch {
	case r.Daily != nil:
		return scheduleFields(cadenceDaily, r.Daily.Action, strVal(r.Daily.At), nil, nil, nil, nil, nil)
	case r.Hourly != nil:
		return scheduleFields(cadenceHourly, r.Hourly.Action, minuteAt(r.Hourly.At), nil, nil, nil, nil, nil)
	case r.Weekly != nil:
		return scheduleFields(cadenceWeekly, r.Weekly.Action, strVal(r.Weekly.At), r.Weekly.DayOfWeek, nil, nil, nil, nil)
	case r.None != nil:
		return scheduleFields(cadenceNone, nil, "", nil, nil, nil, nil, nil)
	default:
		return scheduleFields("", nil, "", nil, nil, nil, nil, nil)
	}
}

func statisticsServiceSummary(s *dyncfg.UpdateScheduleStatisticsService) map[string]any {
	m := map[string]any{}
	putBool(m, "application_reports", s.ApplicationReports)
	putBool(m, "file_identification_reports", s.FileIdentificationReports)
	putBool(m, "health_performance_reports", s.HealthPerformanceReports)
	putBool(m, "passive_dns_monitoring", s.PassiveDnsMonitoring)
	putBool(m, "threat_prevention_information", s.ThreatPreventionInformation)
	putBool(m, "threat_prevention_pcap", s.ThreatPreventionPcap)
	putBool(m, "threat_prevention_reports", s.ThreatPreventionReports)
	putBool(m, "url_reports", s.UrlReports)
	return m
}

// --- Registration -----------------------------------------------------------

// RegisterDynamicUpdatesTools registers the dynamic-update schedule get and
// update tools on both firewall and Panorama.
func RegisterDynamicUpdatesTools(s *mcp.Server, d *Deps) {
	svc := dyncfg.NewService(d.Client)
	parts := dynamicUpdatesParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_updates_get",
		Description: "Get the device dynamic-update schedules (antivirus, applications-only, applications and threats, WildFire, WildFire private cloud, GlobalProtect data file and clientless VPN: the active recurrence, action, time, day, sync-to-peer and thresholds) plus the telemetry statistics-service toggles. Firewall: local system scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("Get dynamic update schedules"),
	}, systemGetHandler(d, "panos_dynamic_updates_get", svc, parts, dynamicUpdatesSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dynamic_updates_update",
		Description: "Update the device dynamic-update schedules: read-modify-write, only provided features change, and at least one feature must be given. Providing a feature's recurrence replaces that feature's cadence (the other cadences are cleared); a same-cadence edit keeps stored fields it does not override, a cadence switch needs action and at (and day_of_week for weekly). Supported cadences per feature: anti_virus none/daily/weekly/hourly; app_profile none/daily/weekly; threats none/daily/weekly/hourly/every-30-mins; wildfire none/real-time/every-min/every-15-mins/every-30-mins/every-hour; wf_private none/every-5-mins/every-15-mins/every-30-mins/every-hour; global_protect_datafile and global_protect_clientless_vpn none/daily/weekly/hourly. The statistics_service field sets the telemetry (statistics service) category toggles. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: updateTool("Update dynamic update schedules"),
	}, systemUpdateHandler(d, "panos_dynamic_updates_update", svc, parts, overlayDynamicUpdates, dynamicUpdatesSummary))
}
