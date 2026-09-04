package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/services/logexport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestLogExportScheduleBuildFtp builds a fresh FTP entry and checks the fields
// land, including the write-only password. Sabotage: drop the setPtr calls in the
// ftp branch of overlayLogExportScheduleFields and the fields go unset.
func TestLogExportScheduleBuildFtp(t *testing.T) {
	e, err := buildLogExportSchedule(LogExportScheduleInput{
		Name:      "sched1",
		Enable:    new(true),
		LogType:   new("traffic"),
		StartTime: new("02:00"),
		Ftp: &LogExportFtpInput{
			Hostname:    new("ftp.example.com"),
			Username:    new("ftpuser"),
			Password:    new("FTPSECRET"),
			Path:        new("/logs"),
			Port:        new(int64(21)),
			PassiveMode: new(true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Protocol == nil || e.Protocol.Ftp == nil {
		t.Fatalf("ftp block must be set, got %+v", e.Protocol)
	}
	if e.Protocol.Scp != nil {
		t.Fatal("scp block must be nil when only ftp is provided")
	}
	mustStrPtr(t, e.Protocol.Ftp.Hostname, "ftp.example.com", "ftp hostname")
	mustStrPtr(t, e.Protocol.Ftp.Password, "FTPSECRET", "ftp password")
	mustInt64(t, e.Protocol.Ftp.Port, 21, "ftp port")
}

// TestLogExportScheduleBuildRequiresName pins the client-side name guard.
// Sabotage: delete the name check in buildLogExportSchedule.
func TestLogExportScheduleBuildRequiresName(t *testing.T) {
	if _, err := buildLogExportSchedule(LogExportScheduleInput{}); err == nil {
		t.Fatal("a create without a name must be rejected")
	}
}

// TestLogExportScheduleTransportMutualExclusion pins that setting one transport
// clears the other (a switch never leaves both FTP and SCP present, which the
// device rejects), and that providing both in one call is a client error.
// Sabotage: remove `e.Protocol.Ftp = nil` from the scp branch of
// overlayLogExportScheduleFields and the switch leaves both present.
func TestLogExportScheduleTransportMutualExclusion(t *testing.T) {
	// Start from an FTP entry, then update to SCP: the FTP block must be cleared.
	e := &logexport.Entry{Name: "sched1", Protocol: &logexport.Protocol{
		Ftp: &logexport.ProtocolFtp{Hostname: new("ftp.example.com"), Password: new("OLD")},
	}}
	if err := overlayLogExportSchedule(e, LogExportScheduleInput{
		Name: "sched1",
		Scp:  &LogExportScpInput{Hostname: new("scp.example.com"), Password: new("SCPSECRET")},
	}); err != nil {
		t.Fatal(err)
	}
	if e.Protocol.Ftp != nil {
		t.Fatal("switching to scp must clear the ftp block")
	}
	if e.Protocol.Scp == nil {
		t.Fatal("scp block must be set after the switch")
	}
	mustStrPtr(t, e.Protocol.Scp.Hostname, "scp.example.com", "scp hostname")

	// Providing both transports in one call is a client error.
	if err := overlayLogExportSchedule(&logexport.Entry{Name: "s"}, LogExportScheduleInput{
		Name: "s",
		Ftp:  &LogExportFtpInput{Hostname: new("f")},
		Scp:  &LogExportScpInput{Hostname: new("s")},
	}); err == nil {
		t.Fatal("providing both ftp and scp in one call must be rejected")
	}
}

// TestLogExportScheduleUpdatePreservesPassword pins the read-modify-write on a
// same-transport update: omitting the password keeps the stored one (issue #99).
// Sabotage: change setPtr(&f.Password, in.Ftp.Password) to an unconditional
// assignment and the omitted password wipes the stored one.
func TestLogExportScheduleUpdatePreservesPassword(t *testing.T) {
	e := &logexport.Entry{Name: "sched1", Protocol: &logexport.Protocol{
		Ftp: &logexport.ProtocolFtp{Hostname: new("ftp.example.com"), Password: new("STOREDPW")},
	}}
	if err := overlayLogExportSchedule(e, LogExportScheduleInput{
		Name: "sched1",
		Ftp:  &LogExportFtpInput{Hostname: new("ftp2.example.com")}, // no password
	}); err != nil {
		t.Fatal(err)
	}
	mustStrPtr(t, e.Protocol.Ftp.Hostname, "ftp2.example.com", "ftp hostname changed")
	mustStrPtr(t, e.Protocol.Ftp.Password, "STOREDPW", "stored password preserved")
}

// TestLogExportScheduleSummaryOmitsPassword pins that the get summary reports the
// transport and whether a password is set, but never the password itself.
// Sabotage: emit strVal(f.Password) as a value instead of the password_set bool.
func TestLogExportScheduleSummaryOmitsPassword(t *testing.T) {
	e := &logexport.Entry{
		Name:        "sched1",
		Description: new("nightly"),
		Enable:      new(true),
		LogType:     new("traffic"),
		StartTime:   new("02:00"),
		Protocol: &logexport.Protocol{Ftp: &logexport.ProtocolFtp{
			Hostname:    new("ftp.example.com"),
			Username:    new("ftpuser"),
			Password:    new("FTPPWLEAK"),
			Path:        new("/logs"),
			Port:        new(int64(21)),
			PassiveMode: new(true),
		}},
	}
	m := asMap(t, logExportScheduleSummary(e))
	if m[tagNameKey] != "sched1" || m[descriptionKey] != "nightly" {
		t.Fatalf("summary scalars wrong: %v", m)
	}
	if m["protocol"] != "ftp" {
		t.Fatalf("protocol must be ftp, got %v", m["protocol"])
	}
	ftp := asMap(t, m["ftp"])
	if ftp["hostname"] != "ftp.example.com" || ftp["username"] != "ftpuser" {
		t.Fatalf("ftp summary scalars wrong: %v", ftp)
	}
	if ftp["password_set"] != true {
		t.Fatalf("password_set must be true when a password is stored, got %v", ftp["password_set"])
	}
	assertNoLeak(t, m, "FTPPWLEAK")
}

// TestLogExportScheduleSummaryBare pins that an entry with no transport renders
// protocol "" and no ftp/scp block, and enable is omitted when nil (tri-state).
// Sabotage: default protocol to "ftp" and the empty case reports a phantom
// transport.
func TestLogExportScheduleSummaryBare(t *testing.T) {
	m := asMap(t, logExportScheduleSummary(&logexport.Entry{Name: "sched1"}))
	if m["protocol"] != "" {
		t.Fatalf("bare entry must have empty protocol, got %v", m["protocol"])
	}
	if _, ok := m["ftp"]; ok {
		t.Fatalf("bare entry must not carry an ftp block: %v", m["ftp"])
	}
	if _, ok := m["enable"]; ok {
		t.Fatalf("a nil Enable must be omitted (tri-state): %v", m["enable"])
	}
}

// TestLogExportScheduleSummaryScpOmitsPassword mirrors the FTP omission guard for
// the SCP transport branch, which the FTP-only summary test did not exercise.
// Sabotage: change the scp "password_set" to strVal(s.Password) and the leak
// assertion reddens.
func TestLogExportScheduleSummaryScpOmitsPassword(t *testing.T) {
	e := &logexport.Entry{
		Name: "sched1",
		Protocol: &logexport.Protocol{Scp: &logexport.ProtocolScp{
			Hostname: new("scp.example.com"),
			Username: new("scpuser"),
			Password: new("SCPPWLEAK"),
			Path:     new("/logs"),
			Port:     new(int64(22)),
		}},
	}
	m := asMap(t, logExportScheduleSummary(e))
	if m["protocol"] != "scp" {
		t.Fatalf("protocol must be scp, got %v", m["protocol"])
	}
	scp := asMap(t, m["scp"])
	if scp["hostname"] != "scp.example.com" || scp["username"] != "scpuser" {
		t.Fatalf("scp summary scalars wrong: %v", scp)
	}
	if scp["password_set"] != true {
		t.Fatalf("password_set must be true when a password is stored, got %v", scp["password_set"])
	}
	if scp["port"] != int64(22) {
		t.Fatalf("scp port wrong: %v", scp["port"])
	}
	assertNoLeak(t, m, "SCPPWLEAK")
}

// TestLogExportScheduleReadOnlyGating pins that the read tools survive read-only
// mode and the write tools are withheld. Sabotage: move the create/update/delete
// registrations above the `if d.ReadOnly { return }` guard.
func TestLogExportScheduleReadOnlyGating(t *testing.T) {
	assertReadOnlyGating(t, RegisterLogExportScheduleTools,
		[]string{"panos_log_export_schedule_list", "panos_log_export_schedule_get"},
		[]string{
			"panos_log_export_schedule_create",
			"panos_log_export_schedule_update",
			"panos_log_export_schedule_delete",
		})
}

// TestLogExportScheduleGetSingleWrapsName pins that a get reaches the API with the
// entry name wrapped exactly once by nameFixAdapter. Sabotage: drop the
// util.AsEntryXpath wrap in nameFixAdapter.Read and the raw name is rejected or
// the wrap disappears.
func TestLogExportScheduleGetSingleWrapsName(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="error"><msg><line>Object not found</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogExportScheduleTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_export_schedule_get", Arguments: map[string]any{"name": "nope"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a missing entry must surface as a tool error")
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// TestLogExportScheduleNoOpUpdateIssuesNoWrite drives the update tool with no
// changed fields: the seed read succeeds and, because nothing changed, no config
// write is issued. This exercises the whole system-entry update path (resolve,
// seed read, summary) end to end. Sabotage: break resolveSystemScope wiring in
// systemEntryUpdateHandler and the seed read never happens.
func TestLogExportScheduleNoOpUpdateIssuesNoWrite(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="sched1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogExportScheduleTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_export_schedule_update", Arguments: map[string]any{"name": "sched1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// TestLogExportScheduleCreateRedactsPasswordOnError drives
// panos_log_export_schedule_create through the registered handler: the device
// rejects the write with an error echoing the submitted FTP password, and the
// tool result must not carry it. Sabotage: remove withSecrets(logExportScheduleSecrets)
// from the panos_log_export_schedule_create registration; this test turns red.
func TestLogExportScheduleCreateRedactsPasswordOnError(t *testing.T) {
	const fixture = "FTP-CREATE-SECRET-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogExportScheduleTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_export_schedule_create", Arguments: map[string]any{
			"name": "sched1",
			"ftp":  map[string]any{"hostname": "ftp.example.com", "password": fixture},
		},
	})
	assertRedactsSecret(t, res, err, fixture)
}

// TestLogExportScheduleUpdateRedactsPasswordOnError is the update-path twin,
// exercising the SCP transport. Sabotage: remove withSecrets(logExportScheduleSecrets)
// from the panos_log_export_schedule_update registration; this test turns red.
func TestLogExportScheduleUpdateRedactsPasswordOnError(t *testing.T) {
	const fixture = "SCP-UPDATE-SECRET-def456"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="sched1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogExportScheduleTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_export_schedule_update", Arguments: map[string]any{
			"name": "sched1",
			"scp":  map[string]any{"hostname": "scp.example.com", "password": fixture},
		},
	})
	assertRedactsSecret(t, res, err, fixture)
}

// TestLogExportScheduleBothTransportsErrorNoLeak pins that the client-side
// both-transports rejection (which is returned from the overlay, bypassing the
// device-error redactor) does not echo either submitted password. Sabotage: make
// the both-transports error message interpolate a password.
func TestLogExportScheduleBothTransportsErrorNoLeak(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLogExportScheduleTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_log_export_schedule_create", Arguments: map[string]any{
			"name": "sched1",
			"ftp":  map[string]any{"hostname": "f", "password": "FTPLEAK"},
			"scp":  map[string]any{"hostname": "s", "password": "SCPLEAK"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("providing both transports must surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, "FTPLEAK") || strings.Contains(out, "SCPLEAK") {
		t.Fatalf("a validation error must not echo a submitted password: %q", out)
	}
}

// TestLogExportScheduleScopeParts pins the per-family scope constructors: the
// firewall path resolves to the System location, and a Panorama template resolves
// to the Template location. Sabotage: build a wrong sub-location in
// logExportScheduleParts.
func TestLogExportScheduleScopeParts(t *testing.T) {
	parts := logExportScheduleParts()
	fw, _ := newTestDeps(t, "PA-VM")
	loc, err := resolveSystemScope(fw, SystemScopeInput{}, parts)
	if err != nil || loc.System == nil {
		t.Fatalf("firewall bare scope must resolve to System: loc=%+v err=%v", loc, err)
	}
	pano, _ := newTestDeps(t, "Panorama")
	loc, err = resolveSystemScope(pano, SystemScopeInput{Template: "edge"}, parts)
	if err != nil || loc.Template == nil {
		t.Fatalf("panorama template scope must resolve to Template: loc=%+v err=%v", loc, err)
	}
}
