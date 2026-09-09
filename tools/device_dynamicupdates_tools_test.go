package tools

import (
	"strings"
	"testing"

	dyncfg "github.com/PaloAltoNetworks/pango/device/dynamicupdates"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// overlayOK runs the overlay and fails on error.
//
//nolint:gocritic // hugeParam: mirrors overlayDynamicUpdates's by-value contract.
func overlayOK(t *testing.T, c *dyncfg.Config, in DynamicUpdatesInput) {
	t.Helper()
	if err := overlayDynamicUpdates(c, in); err != nil {
		t.Fatalf("overlay: unexpected error: %v", err)
	}
}

// overlayErr runs the overlay, requires an error and returns its text.
//
//nolint:gocritic // hugeParam: mirrors overlayDynamicUpdates's by-value contract.
func overlayErr(t *testing.T, in DynamicUpdatesInput) string {
	t.Helper()
	err := overlayDynamicUpdates(&dyncfg.Config{}, in)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	return err.Error()
}

func avRecurring(c *dyncfg.Config) *dyncfg.UpdateScheduleAntiVirusRecurring {
	return c.UpdateSchedule.AntiVirus.Recurring
}

// TestDynamicUpdatesParts pins that the three scope constructors build valid pango
// locations for each device type.
// Sabotage: drop NgfwDevice from the template constructor and IsValid fails.
func TestDynamicUpdatesParts(t *testing.T) {
	p := dynamicUpdatesParts()
	for name, loc := range map[string]dyncfg.Location{
		"system":        p.system(),
		"template":      p.template("t1"),
		"templateStack": p.templateStack("s1"),
	} {
		if err := loc.IsValid(); err != nil {
			t.Errorf("%s location invalid: %v", name, err)
		}
	}
	if p.system().System == nil || p.system().System.NgfwDevice != defaultNgfwDevice {
		t.Error("system scope must set the ngfw device")
	}
	if p.template("t1").Template == nil || p.template("t1").Template.Template != "t1" {
		t.Error("template scope must carry the template name")
	}
	if p.templateStack("s1").TemplateStack == nil || p.templateStack("s1").TemplateStack.TemplateStack != "s1" {
		t.Error("template-stack scope must carry the stack name")
	}
}

// TestScheduleCadenceBuildWallClock pins that a daily/weekly build sets the right
// pango node with the action, the wall-clock at, and (weekly) the day.
// Sabotage: comment out `r.Daily = b` (or swap atStr/atMin) and the asserts fail.
func TestScheduleCadenceBuildWallClock(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{
			Recurrence: new(cadenceDaily), Action: new(updateActionDownloadAndInstall), At: new("01:30"),
		},
	})
	d := avRecurring(c).Daily
	if d == nil {
		t.Fatal("daily node must be built")
	}
	if strVal(d.Action) != updateActionDownloadAndInstall || strVal(d.At) != "01:30" {
		t.Fatalf("daily node wrong: action=%q at=%q", strVal(d.Action), strVal(d.At))
	}

	c = &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{
			Recurrence: new(cadenceWeekly), Action: new(updateActionDownloadOnly), At: new("02:00"), DayOfWeek: new("sunday"),
		},
	})
	w := avRecurring(c).Weekly
	if w == nil || strVal(w.At) != "02:00" || strVal(w.DayOfWeek) != "sunday" {
		t.Fatalf("weekly node wrong: %+v", w)
	}
}

// TestScheduleCadenceBuildMinutes pins that a minute cadence routes `at` into the
// int64 field.
// Sabotage: in buildAntiVirusCadence replace setPtr(&b.At, plan.atMin) with
// plan.atStr and the hourly At stays nil.
func TestScheduleCadenceBuildMinutes(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{
			Recurrence: new(cadenceHourly), Action: new(updateActionDownloadOnly), At: new("45"),
		},
	})
	h := avRecurring(c).Hourly
	if h == nil || h.At == nil || *h.At != 45 {
		t.Fatalf("hourly at must be int64 45; got %+v", h)
	}
}

// TestThreatsCadenceBuild pins the threats-only fields: every-30-mins with
// disable_new_content, plus the recurring-level new_app_threshold.
// Sabotage: drop setPtr(&b.DisableNewContent, ...) in buildThreatsCadence.
func TestThreatsCadenceBuild(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		Threats: &UpdateScheduleInput{
			Recurrence: new(cadenceEvery30Mins), Action: new(updateActionDownloadAndInstall), At: new("5"),
			DisableNewContent: new(true), NewAppThreshold: new(int64(48)), Threshold: new(int64(24)),
		},
	})
	r := c.UpdateSchedule.Threats.Recurring
	if r.Every30Mins == nil || r.Every30Mins.At == nil || *r.Every30Mins.At != 5 {
		t.Fatalf("every-30-mins node wrong: %+v", r.Every30Mins)
	}
	if r.Every30Mins.DisableNewContent == nil || !*r.Every30Mins.DisableNewContent {
		t.Error("disable_new_content must be set on the cadence node")
	}
	if r.NewAppThreshold == nil || *r.NewAppThreshold != 48 || r.Threshold == nil || *r.Threshold != 24 {
		t.Errorf("recurring-level thresholds wrong: %+v", r)
	}
}

// TestWildfireCadenceBuild pins the wildfire per-cadence sync-to-peer and the
// every-min node that carries no `at`.
// Sabotage: drop setPtr(&b.SyncToPeer, plan.syncToPeer) in the every-15-mins arm.
func TestWildfireCadenceBuild(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		Wildfire: &UpdateScheduleInput{
			Recurrence: new(cadenceEvery15Mins), Action: new(updateActionDownloadAndInstall), At: new("3"), SyncToPeer: new(true),
		},
	})
	w := c.UpdateSchedule.Wildfire.Recurring.Every15Mins
	if w == nil || w.At == nil || *w.At != 3 || w.SyncToPeer == nil || !*w.SyncToPeer {
		t.Fatalf("every-15-mins node wrong: %+v", w)
	}

	c = &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceEveryMin), Action: new(updateActionDownloadOnly)},
	})
	if c.UpdateSchedule.Wildfire.Recurring.EveryMin == nil {
		t.Fatal("every-min node must be built without an at")
	}
}

// TestScheduleSwitchClearsSiblings pins that switching a feature's cadence clears
// the previously set cadence.
// Sabotage: remove the `r.Daily, ... = nil, ...` clear line in buildAntiVirusCadence.
func TestScheduleSwitchClearsSiblings(t *testing.T) {
	c := seededDailyAV(updateActionDownloadOnly)
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceHourly), Action: new(updateActionDownloadOnly), At: new("10")},
	})
	r := avRecurring(c)
	if r.Daily != nil {
		t.Error("switching to hourly must clear the stored daily cadence")
	}
	if r.Hourly == nil {
		t.Error("hourly cadence must be set")
	}
}

// TestScheduleSameCadenceKeepsStoredFields pins that a same-cadence edit inherits
// the stored fields it does not override (agy review finding #2 and the seedBranch
// contract).
// Sabotage: replace seedBranch(oldDaily) with new(...) and the stored action is lost.
func TestScheduleSameCadenceKeepsStoredFields(t *testing.T) {
	c := seededDailyAV(updateActionDownloadAndInstall)
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), At: new("03:00")},
	})
	d := avRecurring(c).Daily
	if d == nil || strVal(d.Action) != "download-and-install" {
		t.Fatalf("same-cadence edit must keep the stored action; got %+v", d)
	}
	if strVal(d.At) != "03:00" {
		t.Errorf("same-cadence edit must apply the new at; got %q", strVal(d.At))
	}
}

// TestScheduleSwitchRequiresCompleteCadence pins the freshness guard: a cadence
// switch must carry action, at and (weekly) day_of_week.
// Sabotage: make guardScheduled return nil and the at/action cases pass.
func TestScheduleSwitchRequiresCompleteCadence(t *testing.T) {
	cases := []struct {
		name string
		in   *UpdateScheduleInput
		want string
	}{
		{"hourly missing at", &UpdateScheduleInput{Recurrence: new(cadenceHourly), Action: new(updateActionDownloadOnly)}, "at is required"},
		{"hourly missing action", &UpdateScheduleInput{Recurrence: new(cadenceHourly), At: new("5")}, "action is required"},
		{"weekly missing day", &UpdateScheduleInput{Recurrence: new(cadenceWeekly), Action: new(updateActionDownloadOnly), At: new("01:00")}, "day_of_week is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := seededDailyAV(updateActionDownloadOnly)
			err := overlayDynamicUpdates(c, DynamicUpdatesInput{AntiVirus: tc.in})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q; got %v", tc.want, err)
			}
		})
	}
}

// TestScheduleFirstWriteRequiresCompleteCadence pins that a first write on an
// absent singleton must supply a complete cadence (the #132-class keyless-node
// hazard on a brand-new node).
// Sabotage: same guard as above.
func TestScheduleFirstWriteRequiresCompleteCadence(t *testing.T) {
	msg := overlayErr(t, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), At: new("01:00")},
	})
	if !strings.Contains(msg, "action is required") {
		t.Fatalf("a fresh daily node without action must be rejected; got %q", msg)
	}
}

// TestScalarsOnlyRequireExistingCadence pins that a recurring-scalar-only edit
// needs an existing cadence, and that it preserves that cadence.
// Sabotage: make requireOneCadence return nil.
func TestScalarsOnlyRequireExistingCadence(t *testing.T) {
	msg := overlayErr(t, DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Threshold: new(int64(24))}})
	if !strings.Contains(msg, "recurrence is required") {
		t.Fatalf("a scalar-only write onto an empty feature must be rejected; got %q", msg)
	}

	c := seededDailyAV(updateActionDownloadOnly)
	overlayOK(t, c, DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Threshold: new(int64(24))}})
	r := avRecurring(c)
	if r.Daily == nil {
		t.Error("a scalar-only edit must keep the existing cadence")
	}
	if r.Threshold == nil || *r.Threshold != 24 {
		t.Error("the recurring-level threshold must be applied")
	}
}

// TestScheduleAtRouting pins the string-vs-int routing and the per-cadence ranges,
// including a non-zero-padded wall-clock time (agy review finding #4).
// Sabotage: change atMaxEvery30 to 59, or drop the hour-range check in parseWallClock.
func TestScheduleAtRouting(t *testing.T) {
	good := []struct {
		cadence string
		at      string
	}{
		{cadenceHourly, "5"}, {cadenceDaily, "05:00"}, {cadenceDaily, "1:30"},
		{cadenceEvery30Mins, "29"}, {cadenceHourly, "0"},
	}
	for _, g := range good {
		t.Run("ok/"+g.cadence+"/"+g.at, func(t *testing.T) {
			in := &UpdateScheduleInput{Recurrence: new(g.cadence), Action: new(updateActionDownloadOnly), At: new(g.at)}
			if err := overlayDynamicUpdates(&dyncfg.Config{}, DynamicUpdatesInput{Threats: in}); err != nil {
				t.Fatalf("%s at=%q must be accepted; got %v", g.cadence, g.at, err)
			}
		})
	}
	bad := []struct {
		cadence string
		at      string
	}{
		{cadenceHourly, "05:00"}, {cadenceDaily, "5"}, {cadenceDaily, "24:00"},
		{cadenceHourly, "60"}, {cadenceEvery30Mins, "30"}, {cadenceDaily, "12:60"},
	}
	for _, b := range bad {
		t.Run("bad/"+b.cadence+"/"+b.at, func(t *testing.T) {
			in := &UpdateScheduleInput{Recurrence: new(b.cadence), Action: new(updateActionDownloadOnly), At: new(b.at)}
			if err := overlayDynamicUpdates(&dyncfg.Config{}, DynamicUpdatesInput{Threats: in}); err == nil {
				t.Fatalf("%s at=%q must be rejected", b.cadence, b.at)
			}
		})
	}
}

// TestUnsupportedCadenceForFeature pins that a feature rejects a cadence it does
// not support.
// Sabotage: add cadenceHourly to appProfileSpec.cadences.
func TestUnsupportedCadenceForFeature(t *testing.T) {
	cases := []struct {
		name string
		in   DynamicUpdatesInput
	}{
		{"app_profile hourly", DynamicUpdatesInput{AppProfile: &UpdateScheduleInput{Recurrence: new(cadenceHourly), Action: new(updateActionDownloadOnly), At: new("5")}}},
		{"wildfire daily", DynamicUpdatesInput{Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00")}}},
		{"gp_datafile every-hour", DynamicUpdatesInput{GlobalProtectDatafile: &UpdateScheduleInput{Recurrence: new(cadenceEveryHour), Action: new(updateActionDownloadOnly), At: new("5")}}},
		{"wf_private daily", DynamicUpdatesInput{WfPrivate: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := overlayDynamicUpdates(&dyncfg.Config{}, tc.in); err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
		})
	}
}

// TestScheduleFieldRejects pins the per-field validation: enums, ranges,
// feature-support and cadence-applicability.
// Sabotage: remove any single guard in validate* and its case passes.
func TestScheduleFieldRejects(t *testing.T) {
	cases := []struct {
		name string
		in   DynamicUpdatesInput
	}{
		{"bad recurrence", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new("fortnightly")}}},
		{"bad action", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new("install"), At: new("01:00")}}},
		{"capitalized day", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceWeekly), Action: new(updateActionDownloadOnly), At: new("01:00"), DayOfWeek: new("Monday")}}},
		{"threshold too low", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), Threshold: new(int64(0))}}},
		{"threshold too high", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), Threshold: new(int64(337))}}},
		{"new_app_threshold unsupported", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), NewAppThreshold: new(int64(24))}}},
		{"disable_new_content unsupported", DynamicUpdatesInput{Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceEveryMin), Action: new(updateActionDownloadOnly), DisableNewContent: new(true)}}},
		{"sync unsupported feature", DynamicUpdatesInput{GlobalProtectDatafile: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), SyncToPeer: new(true)}}},
		{"day on non-weekly cadence", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), DayOfWeek: new("sunday")}}},
		{"action on none", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceNone), Action: new(updateActionDownloadOnly)}}},
		{"at without recurrence", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{At: new("01:00")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := overlayDynamicUpdates(&dyncfg.Config{}, tc.in); err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
		})
	}
}

// TestGpDatafileDailyActionPassThrough pins that download-only is accepted for the
// GlobalProtect data file daily cadence: the server does not enforce the
// spec-only "install only" narrowing (agy review finding #3, forward-compat).
// Sabotage: reintroduce a per-feature action allowlist that excludes download-only.
func TestGpDatafileDailyActionPassThrough(t *testing.T) {
	err := overlayDynamicUpdates(&dyncfg.Config{}, DynamicUpdatesInput{
		GlobalProtectDatafile: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00")},
	})
	if err != nil {
		t.Fatalf("download-only must pass through for gp_datafile daily; got %v", err)
	}
}

// TestSyncToPeerLevels pins the recurring-level vs cadence-level sync-to-peer rule.
// Sabotage: set wildfireSpec.sync to syncRecurring and the no-recurrence case stops erroring.
func TestSyncToPeerLevels(t *testing.T) {
	// Schedule-level: a scalar-only sync edit is valid when a cadence already exists.
	c := seededDailyAV(updateActionDownloadOnly)
	overlayOK(t, c, DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{SyncToPeer: new(true)}})
	if r := avRecurring(c); r.SyncToPeer == nil || !*r.SyncToPeer {
		t.Error("anti_virus sync_to_peer must apply at the recurring level")
	}

	// Cadence-level: wildfire sync without a recurrence has no cadence to attach to.
	msg := overlayErr(t, DynamicUpdatesInput{Wildfire: &UpdateScheduleInput{SyncToPeer: new(true)}})
	if !strings.Contains(msg, "requires recurrence") {
		t.Fatalf("wildfire sync_to_peer without recurrence must be rejected; got %q", msg)
	}
}

// TestOverlayNoFeaturesErrors pins that an update with no feature is a tool error,
// not a silent empty write (agy review finding #1).
// Sabotage: remove the countSet==0 guard in overlayDynamicUpdates.
func TestOverlayNoFeaturesErrors(t *testing.T) {
	c := &dyncfg.Config{}
	err := overlayDynamicUpdates(c, DynamicUpdatesInput{})
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("an empty update must be rejected; got %v", err)
	}
	if c.UpdateSchedule != nil {
		t.Error("a rejected empty update must not allocate an update-schedule node")
	}
}

// TestStatisticsServiceOverlay pins that only provided toggles are set and a nil
// input leaves the node absent.
// Sabotage: replace a setPtr with a direct assignment in applyStatisticsService.
func TestStatisticsServiceOverlay(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{StatisticsService: &StatisticsServiceInput{ApplicationReports: new(true)}})
	s := c.UpdateSchedule.StatisticsService
	if s == nil || s.ApplicationReports == nil || !*s.ApplicationReports {
		t.Fatal("application_reports must be set")
	}
	if s.UrlReports != nil {
		t.Error("an unspecified toggle must stay nil")
	}
}

// TestDynamicUpdatesSummaryOmitsAbsent pins the #128 omit-when-nil summary shape.
// Sabotage: replace putInt with a direct map assignment in scheduleFields.
func TestDynamicUpdatesSummaryOmitsAbsent(t *testing.T) {
	if m := asMap(t, dynamicUpdatesSummary(&dyncfg.Config{})); len(m) != 0 {
		t.Fatalf("an absent config must summarize to an empty map; got %v", m)
	}

	c := seededDailyAV(updateActionDownloadOnly)
	av := asMap(t, asMap(t, dynamicUpdatesSummary(c))[featAntiVirus])
	if _, ok := av[syncToPeerKey]; ok {
		t.Error("sync_to_peer must be omitted when unset")
	}
	if _, ok := av["threshold"]; ok {
		t.Error("threshold must be omitted when unset")
	}

	c = seededDailyAV(updateActionDownloadOnly)
	avRecurring(c).SyncToPeer = new(true)
	avRecurring(c).Threshold = new(int64(12))
	av = asMap(t, asMap(t, dynamicUpdatesSummary(c))[featAntiVirus])
	if av[syncToPeerKey] != true || av["threshold"] != int64(12) {
		t.Errorf("set tri-state fields must appear; got %v", av)
	}
}

// TestDynamicUpdatesSummaryPerCadence pins the rendered fields per cadence,
// including the minute-to-string round-trip and the empty markers.
// Sabotage: swap two cadence names in antiVirusScheduleSummary.
func TestDynamicUpdatesSummaryPerCadence(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceHourly), Action: new(updateActionDownloadOnly), At: new("45")},
	})
	av := asMap(t, asMap(t, dynamicUpdatesSummary(c))[featAntiVirus])
	if av[recurrenceKey] != cadenceHourly || av[atKey] != "45" {
		t.Fatalf("hourly summary must render recurrence and a string at; got %v", av)
	}

	c = &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceRealTime)},
	})
	wf := asMap(t, asMap(t, dynamicUpdatesSummary(c))[featWildfire])
	if wf[recurrenceKey] != cadenceRealTime {
		t.Fatalf("real-time summary must render its recurrence; got %v", wf)
	}
	if _, ok := wf[atKey]; ok {
		t.Error("real-time has no at")
	}
}

// --- Handler-level tests ----------------------------------------------------

// TestDynamicUpdatesGetReturnsEmptyWhenAbsent pins that an unconfigured singleton
// is reported as an empty schedule, not an error.
// Sabotage: register the get with a summary that panics on an empty config.
func TestDynamicUpdatesGetReturnsEmptyWhenAbsent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUpdatesTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dynamic_updates_get", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("an absent schedule must not be a tool error: %s", textContent(t, res))
	}
}

// TestDynamicUpdatesUpdateCreatesWhenAbsent pins that a first write goes through
// Create (set), not Update (edit).
// Sabotage: force the handler to always Update and the CREATE marker disappears.
func TestDynamicUpdatesUpdateCreatesWhenAbsent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>CREATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUpdatesTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dynamic_updates_update", Arguments: map[string]any{
		"anti_virus": map[string]any{"recurrence": "daily", "action": "download-only", "at": "01:00"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := textContent(t, res)
	if !strings.Contains(text, "CREATE-PATH-MARKER") {
		t.Fatalf("absent singleton must be written via Create (set); got: %s", text)
	}
}

// TestDynamicUpdatesValidationErrorIsToolError pins that a validation failure
// surfaces as a tool error and submits no write request.
// Sabotage: move the overlay validation after the device write in systemUpdateHandler.
func TestDynamicUpdatesValidationErrorIsToolError(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="success"><result/></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUpdatesTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dynamic_updates_update", Arguments: map[string]any{
		"anti_virus": map[string]any{"recurrence": "fortnightly"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("an invalid recurrence must surface as a tool error")
	}
	for _, r := range f.Requests() {
		if a := r.Get("action"); a == "set" || a == "edit" || a == "multi-config" {
			t.Fatalf("a rejected update must not submit a %q write", a)
		}
	}
}

// TestDynamicUpdatesPanoramaScope pins that a Panorama connection with neither
// scope set is rejected before any pango location is built. The guard is the
// shared resolveSystemScope, not this tool's parts closures.
// Sabotage: in resolveSystemScope, make the `case d.IsPanorama` branch fall
// through to the system scope instead of returning the template-required error.
func TestDynamicUpdatesPanoramaScope(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterDynamicUpdatesTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_dynamic_updates_get", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textContent(t, res), "template") {
		t.Fatalf("Panorama without a template must be a tool error naming template; got: %s", textContent(t, res))
	}
}

// TestDynamicUpdatesReadOnlyGating pins that the get is always exposed and the
// update only when writes are enabled.
// Sabotage: delete the `if d.ReadOnly { return }` guard in RegisterDynamicUpdatesTools.
func TestDynamicUpdatesReadOnlyGating(t *testing.T) {
	assertReadOnlyGating(t, RegisterDynamicUpdatesTools,
		[]string{"panos_dynamic_updates_get"},
		[]string{"panos_dynamic_updates_update"})
}

// seededDailyAV returns a config whose antivirus schedule is a daily cadence.
func seededDailyAV(action string) *dyncfg.Config {
	return &dyncfg.Config{UpdateSchedule: &dyncfg.UpdateSchedule{
		AntiVirus: &dyncfg.UpdateScheduleAntiVirus{Recurring: &dyncfg.UpdateScheduleAntiVirusRecurring{
			Daily: &dyncfg.UpdateScheduleAntiVirusRecurringDaily{Action: new(action), At: new("01:00")},
		}},
	}}
}

// scheduleInputFor builds a DynamicUpdatesInput that sets exactly one feature's
// schedule, so a single table can drive every feature's build and summary.
func scheduleInputFor(feat, cadence, action, at, day string) DynamicUpdatesInput {
	si := &UpdateScheduleInput{Recurrence: new(cadence)}
	if action != "" {
		si.Action = new(action)
	}
	if at != "" {
		si.At = new(at)
	}
	if day != "" {
		si.DayOfWeek = new(day)
	}
	var in DynamicUpdatesInput
	switch feat {
	case featAntiVirus:
		in.AntiVirus = si
	case featAppProfile:
		in.AppProfile = si
	case featThreats:
		in.Threats = si
	case featWildfire:
		in.Wildfire = si
	case featWfPrivate:
		in.WfPrivate = si
	case featGpDatafile:
		in.GlobalProtectDatafile = si
	case featGpClientlessVpn:
		in.GlobalProtectClientlessVpn = si
	}
	return in
}

// assertScheduleSummary checks a per-feature summary map renders the expected
// recurrence and, for a scheduled cadence, the action/at/day (and that each is
// omitted when not expected).
func assertScheduleSummary(t *testing.T, m map[string]any, cadence, wantAction, wantAt, wantDay string) {
	t.Helper()
	if m[recurrenceKey] != cadence {
		t.Errorf("recurrence: got %v, want %q", m[recurrenceKey], cadence)
	}
	assertSummaryField(t, m, actionKey, wantAction)
	assertSummaryField(t, m, atKey, wantAt)
	assertSummaryField(t, m, dayOfWeekKey, wantDay)
}

func assertSummaryField(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	got, ok := m[key]
	switch {
	case want == "" && ok:
		t.Errorf("%s must be omitted; got %v", key, got)
	case want != "" && got != want:
		t.Errorf("%s: got %v, want %q", key, got, want)
	}
}

// TestDynamicUpdatesRoundTripPerFeature exercises every feature's build arm and
// its summary arm in one overlay-then-summarize round trip, so a copy-paste
// defect in any of the seven hand-written per-feature switches (a wrong cadence
// constant, a dropped setPtr, a swapped summary cadence) turns a row red.
// Sabotage: swap two cadence names in any build or summary switch, or drop a
// setPtr, and the matching row fails.
func TestDynamicUpdatesRoundTripPerFeature(t *testing.T) {
	const dl = updateActionDownloadOnly
	cases := []struct {
		feat, cadence, action, at, day string
	}{
		{featAntiVirus, cadenceDaily, dl, "01:00", ""},
		{featAntiVirus, cadenceWeekly, dl, "02:00", "monday"},
		{featAntiVirus, cadenceHourly, dl, "5", ""},
		{featAntiVirus, cadenceNone, "", "", ""},
		{featAppProfile, cadenceDaily, dl, "01:00", ""},
		{featAppProfile, cadenceWeekly, dl, "02:00", "tuesday"},
		{featAppProfile, cadenceNone, "", "", ""},
		{featThreats, cadenceDaily, dl, "01:00", ""},
		{featThreats, cadenceHourly, dl, "5", ""},
		{featThreats, cadenceEvery30Mins, dl, "10", ""},
		{featThreats, cadenceWeekly, dl, "02:00", "wednesday"},
		{featThreats, cadenceNone, "", "", ""},
		{featWildfire, cadenceEvery15Mins, dl, "5", ""},
		{featWildfire, cadenceEvery30Mins, dl, "10", ""},
		{featWildfire, cadenceEveryHour, dl, "15", ""},
		{featWildfire, cadenceEveryMin, dl, "", ""},
		{featWildfire, cadenceRealTime, "", "", ""},
		{featWildfire, cadenceNone, "", "", ""},
		{featWfPrivate, cadenceEvery5Mins, dl, "2", ""},
		{featWfPrivate, cadenceEvery15Mins, dl, "5", ""},
		{featWfPrivate, cadenceEvery30Mins, dl, "10", ""},
		{featWfPrivate, cadenceEveryHour, dl, "15", ""},
		{featWfPrivate, cadenceNone, "", "", ""},
		{featGpDatafile, cadenceDaily, dl, "01:00", ""},
		{featGpDatafile, cadenceHourly, dl, "5", ""},
		{featGpDatafile, cadenceWeekly, dl, "02:00", "thursday"},
		{featGpDatafile, cadenceNone, "", "", ""},
		{featGpClientlessVpn, cadenceDaily, dl, "01:00", ""},
		{featGpClientlessVpn, cadenceHourly, dl, "5", ""},
		{featGpClientlessVpn, cadenceWeekly, dl, "02:00", "friday"},
		{featGpClientlessVpn, cadenceNone, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.feat+"/"+tc.cadence, func(t *testing.T) {
			c := &dyncfg.Config{}
			overlayOK(t, c, scheduleInputFor(tc.feat, tc.cadence, tc.action, tc.at, tc.day))
			m := asMap(t, asMap(t, dynamicUpdatesSummary(c))[tc.feat])
			assertScheduleSummary(t, m, tc.cadence, tc.action, tc.at, tc.day)
		})
	}
}

// TestScheduleAtWallClockNormalizes pins that a daily/weekly at is normalized to
// zero-padded HH:MM before it is stored, so the device gets a canonical value and
// a get round-trips into an update.
// Sabotage: in parseWallClock return the raw `at` instead of the Sprintf form.
func TestScheduleAtWallClockNormalizes(t *testing.T) {
	c := &dyncfg.Config{}
	overlayOK(t, c, DynamicUpdatesInput{
		AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("1:3")},
	})
	if got := strVal(avRecurring(c).Daily.At); got != "01:03" {
		t.Fatalf("wall-clock at must normalize to 01:03; got %q", got)
	}
}

// TestScheduleAtWallClockRejectsSignAndSpace pins that a sign or whitespace in a
// wall-clock time is rejected client-side rather than shipped to the device.
// Sabotage: remove the allDigits guards in parseWallClock.
func TestScheduleAtWallClockRejectsSignAndSpace(t *testing.T) {
	for _, at := range []string{"+1:30", "1:+30", " 1:30", "ab:cd"} {
		in := DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new(at)}}
		if err := overlayDynamicUpdates(&dyncfg.Config{}, in); err == nil {
			t.Errorf("wall-clock at %q must be rejected", at)
		}
	}
}

// TestAtWithoutRecurrenceOnExistingSchedule pins that a cadence-level field with
// no recurrence is rejected by the requires-recurrence guard specifically, on a
// feature that ALREADY has a stored cadence (so the requireOneCadence backstop
// cannot be the reason it is rejected).
// Sabotage: delete the `case in.At != nil` branch in rejectCadenceFieldsWhenNoRecurrence.
func TestAtWithoutRecurrenceOnExistingSchedule(t *testing.T) {
	c := seededDailyAV(updateActionDownloadOnly)
	err := overlayDynamicUpdates(c, DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{At: new("05:00")}})
	if err == nil || !strings.Contains(err.Error(), "requires recurrence") {
		t.Fatalf("at without recurrence on an existing schedule must report requires-recurrence; got %v", err)
	}
}

// TestStatisticsServicePreservesStored pins that a partial statistics-service
// update leaves the stored toggles it does not mention unchanged (the RMW
// preserve-on-nil contract of setPtr), so a partial write cannot silently clear
// other telemetry categories.
// Sabotage: replace a setPtr with a direct assignment in applyStatisticsService.
func TestStatisticsServicePreservesStored(t *testing.T) {
	c := &dyncfg.Config{UpdateSchedule: &dyncfg.UpdateSchedule{
		StatisticsService: &dyncfg.UpdateScheduleStatisticsService{
			ApplicationReports: new(true), UrlReports: new(true),
		},
	}}
	overlayOK(t, c, DynamicUpdatesInput{StatisticsService: &StatisticsServiceInput{PassiveDnsMonitoring: new(true)}})
	s := c.UpdateSchedule.StatisticsService
	if s.PassiveDnsMonitoring == nil || !*s.PassiveDnsMonitoring {
		t.Error("the provided toggle must be applied")
	}
	if s.ApplicationReports == nil || !*s.ApplicationReports || s.UrlReports == nil || !*s.UrlReports {
		t.Error("stored toggles not mentioned in the update must be preserved")
	}
}

// TestStatisticsServiceSummaryRenders pins that the statistics-service summary
// renders set toggles (including an explicit false) and omits unset ones, through
// dynamicUpdatesSummary so the render path is exercised.
// Sabotage: drop a putBool in statisticsServiceSummary and its key disappears.
func TestStatisticsServiceSummaryRenders(t *testing.T) {
	c := &dyncfg.Config{UpdateSchedule: &dyncfg.UpdateSchedule{
		StatisticsService: &dyncfg.UpdateScheduleStatisticsService{
			ApplicationReports: new(true), UrlReports: new(false),
		},
	}}
	s := asMap(t, asMap(t, dynamicUpdatesSummary(c))[statisticsServiceKey])
	if s["application_reports"] != true {
		t.Errorf("application_reports must render true; got %v", s["application_reports"])
	}
	if s["url_reports"] != false {
		t.Errorf("url_reports must render explicit false; got %v", s["url_reports"])
	}
	if _, ok := s["passive_dns_monitoring"]; ok {
		t.Error("an unset toggle must be omitted")
	}
}

// TestScheduleFieldRejectsFineGrained covers the validation branches the main
// rejects table does not reach: an at on a no-time cadence, a fresh every-min
// node without an action, an out-of-range threats new_app_threshold, and a
// cadence-level sync on a wildfire cadence that has no sync field.
// Sabotage: remove the matching guard and the case stops erroring.
func TestScheduleFieldRejectsFineGrained(t *testing.T) {
	cases := []struct {
		name string
		in   DynamicUpdatesInput
	}{
		{"at on none", DynamicUpdatesInput{AntiVirus: &UpdateScheduleInput{Recurrence: new(cadenceNone), At: new("01:00")}}},
		{"every-min without action", DynamicUpdatesInput{Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceEveryMin)}}},
		{"new_app_threshold out of range", DynamicUpdatesInput{Threats: &UpdateScheduleInput{Recurrence: new(cadenceDaily), Action: new(updateActionDownloadOnly), At: new("01:00"), NewAppThreshold: new(int64(0))}}},
		{"sync on wildfire real-time", DynamicUpdatesInput{Wildfire: &UpdateScheduleInput{Recurrence: new(cadenceRealTime), SyncToPeer: new(true)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := overlayDynamicUpdates(&dyncfg.Config{}, tc.in); err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
		})
	}
}
