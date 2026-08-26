package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/profiles/bfd"
	"github.com/PaloAltoNetworks/pango/network/profiles/interface_management"
	"github.com/PaloAltoNetworks/pango/network/profiles/lldp"
	"github.com/PaloAltoNetworks/pango/network/profiles/monitor"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mustBoolPtr fails unless got points to want; keeps the toggle-mapping
// assertions out of the test body so it stays under the complexity limit.
func mustBoolPtr(t *testing.T, got *bool, want bool, label string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s: want %v, got %v", label, want, got)
	}
}

// --- build --------------------------------------------------------------------

// TestInterfaceManagementProfileBuild pins the field mapping: a set toggle
// reaches the matching Entry field, an explicit false is kept as present-false,
// an unset toggle stays nil, and permitted_ip maps to PermittedIp[].Name in
// order. Empty name is rejected.
func TestInterfaceManagementProfileBuild(t *testing.T) {
	e, err := buildInterfaceManagementProfile(InterfaceManagementProfileInput{
		Name: "mgmt", Https: new(true), Ssh: new(true), Telnet: new(false),
		PermittedIp: []string{"10.0.0.0/8", "192.168.1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustBoolPtr(t, e.Https, true, "https -> Entry.Https")
	mustBoolPtr(t, e.Ssh, true, "ssh -> Entry.Ssh")
	mustBoolPtr(t, e.Telnet, false, "telnet false -> Entry.Telnet present-false")
	if e.Http != nil {
		t.Fatalf("an unset http toggle must stay nil, got %v", *e.Http)
	}
	if len(e.PermittedIp) != 2 || e.PermittedIp[0].Name != "10.0.0.0/8" || e.PermittedIp[1].Name != "192.168.1.1" {
		t.Fatalf("permitted_ip not mapped to PermittedIp[].Name in order: %+v", e.PermittedIp)
	}
	if _, err := buildInterfaceManagementProfile(InterfaceManagementProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

// TestInterfaceManagementProfileSummary pins the summary projection: set
// toggles report their value, an explicit false reports false, an unset toggle
// is omitted entirely, and permitted_ip renders as a []string in order.
// Sabotage: replacing putBool with boolVal makes the unset-toggle subcheck fail.
func TestInterfaceManagementProfileSummary(t *testing.T) {
	e := &interface_management.Entry{
		Name: "mgmt", Https: new(true), Ssh: new(true), Telnet: new(false),
		PermittedIp: []interface_management.PermittedIp{{Name: "10.0.0.0/8"}, {Name: "192.168.1.1"}},
	}
	m := asMap(t, interfaceManagementProfileSummary(e))
	if m["https"] != true || m["ssh"] != true {
		t.Fatalf("summary must report set toggles: %v", m)
	}
	if m["telnet"] != false {
		t.Fatalf("summary must report an explicit-false toggle as false: %v", m["telnet"])
	}
	if _, ok := m["http"]; ok {
		t.Fatalf("summary must omit an unset toggle, got http=%v", m["http"])
	}
	ips, ok := m["permitted_ip"].([]string)
	if !ok || len(ips) != 2 || ips[0] != "10.0.0.0/8" || ips[1] != "192.168.1.1" {
		t.Fatalf("summary permitted_ip wrong: %v", m["permitted_ip"])
	}
}

// --- wire-level create xpath --------------------------------------------------

// assertSetXpathContains scans the recorded requests for a config set and
// requires its xpath to contain every want substring, failing if no set was
// recorded at all.
func assertSetXpathContains(t *testing.T, f *fakeAPI, want []string) {
	t.Helper()
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") != "set" {
			continue
		}
		sawSet = true
		xp := req.Get("xpath")
		for _, w := range want {
			if !strings.Contains(xp, w) {
				t.Fatalf("create xpath must contain %q: %s", w, xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// TestInterfaceManagementProfileCreateXpath drives the create tool over a
// registered server on a firewall (Ngfw scope) and a Panorama template, and
// asserts the set reaches the interface-management-profile node. The node-name
// substring is the sabotage anchor: if the pango location's node drifts the
// firewall case fails, and if the net-scope template wiring drifts the Panorama
// case (which also requires the template name in the xpath) fails.
func TestInterfaceManagementProfileCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="mgmt"/></result></response>`
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  []string
	}{
		{"firewall ngfw", "PA-VM", map[string]any{"name": "mgmt", "https": true}, []string{"interface-management-profile"}},
		{"panorama template", "Panorama", map[string]any{"name": "mgmt", "https": true, "template": "tmpl-a"},
			[]string{"interface-management-profile", "template", "tmpl-a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterInterfaceManagementProfileTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_interface_mgmt_profile_create", Arguments: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("create failed: %s", textContent(t, res))
			}
			assertSetXpathContains(t, f, c.want)
		})
	}
}

// --- net-scope gating ---------------------------------------------------------

// TestInterfaceManagementProfileNetScopeGating pins resolveNetScope's routing
// through the registered create/list handlers: on Panorama a missing
// template/template_stack is rejected before any write, and a template supplied
// against a firewall is rejected too.
func TestInterfaceManagementProfileNetScopeGating(t *testing.T) {
	call := func(t *testing.T, model, tool string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		d, f := newTestDeps(t, model)
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterInterfaceManagementProfileTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConfigWrite(t, f)
		return res
	}
	mustErr := func(t *testing.T, res *mcp.CallToolResult, want string) {
		t.Helper()
		if !res.IsError || !strings.Contains(textContent(t, res), want) {
			t.Fatalf("must error with %q: isErr=%v %s", want, res.IsError, textContent(t, res))
		}
	}

	t.Run("panorama create without template errors", func(t *testing.T) {
		res := call(t, "Panorama", "panos_interface_mgmt_profile_create", map[string]any{"name": "mgmt"})
		mustErr(t, res, "template or template_stack is required on Panorama")
	})
	t.Run("panorama list without template errors", func(t *testing.T) {
		res := call(t, "Panorama", "panos_interface_mgmt_profile_list", map[string]any{})
		mustErr(t, res, "template or template_stack is required on Panorama")
	})
	t.Run("template on a firewall errors", func(t *testing.T) {
		res := call(t, "PA-VM", "panos_interface_mgmt_profile_create", map[string]any{"name": "mgmt", "template": "tmpl-a"})
		mustErr(t, res, "template requires a Panorama connection")
	})
}

// --- no-op update -------------------------------------------------------------

// TestInterfaceManagementProfileNoOpUpdate proves an update that changes nothing
// issues no config write: the overlay leaves the read entry untouched, so
// pango's SpecMatches short-circuits and no multi-config reaches the API.
// Sabotage: if overlayInterfaceManagementProfile forced a toggle or replaced
// permitted_ip unconditionally, the entry would differ from the read-back and a
// multi-config edit would fire, tripping assertNoConfigWrite.
func TestInterfaceManagementProfileNoOpUpdate(t *testing.T) {
	// The current entry carries both a toggle and a permitted-ip so a dropped
	// setPtr guard (clearing the toggle) OR a dropped permitted_ip nil-guard
	// (replacing the list with an empty one) would differ from the read-back and
	// force a write.
	current := `<response status="success"><result><entry name="mgmt"><https>yes</https>` +
		`<permitted-ip><entry name="10.0.0.0/8"/></permitted-ip></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterInterfaceManagementProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_interface_mgmt_profile_update", Arguments: map[string]any{"name": "mgmt"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- read-only gating ---------------------------------------------------------

func TestInterfaceManagementProfileReadOnlyGating(t *testing.T) {
	base := "panos_interface_mgmt_profile"
	assertReadOnlyGating(t, RegisterInterfaceManagementProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// ---------------------------------------------------------------------------
// LLDP profile
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestLldpProfileBuild(t *testing.T) {
	e, err := buildLldpProfile(LldpProfileInput{
		Name:                   "lldp1",
		Mode:                   new("transmit-receive"),
		SnmpSyslogNotification: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "lldp1" {
		t.Fatalf("name wrong: got %q, want %q", e.Name, "lldp1")
	}
	mustStrPtr(t, e.Mode, "transmit-receive", "mode -> Entry.Mode")
	mustBoolPtr(t, e.SnmpSyslogNotification, true, "snmp_syslog_notification -> Entry.SnmpSyslogNotification")

	e2, err := buildLldpProfile(LldpProfileInput{Name: "lldp2"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Mode != nil {
		t.Fatalf("unset mode must stay nil, got %v", *e2.Mode)
	}
	if e2.SnmpSyslogNotification != nil {
		t.Fatalf("unset snmp_syslog_notification must stay nil, got %v", *e2.SnmpSyslogNotification)
	}

	if _, err := buildLldpProfile(LldpProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestLldpProfileSummary(t *testing.T) {
	e := &lldp.Entry{
		Name:                   "lldp1",
		Mode:                   new("transmit-receive"),
		SnmpSyslogNotification: new(true),
	}
	m := asMap(t, lldpProfileSummary(e))
	if m[tagNameKey] != "lldp1" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	if m["mode"] != "transmit-receive" {
		t.Fatalf("summary mode wrong: %v", m["mode"])
	}
	if m["snmp_syslog_notification"] != true {
		t.Fatalf("summary snmp_syslog_notification wrong: %v", m["snmp_syslog_notification"])
	}

	eFalse := &lldp.Entry{
		Name:                   "lldp-f",
		SnmpSyslogNotification: new(false),
	}
	mFalse := asMap(t, lldpProfileSummary(eFalse))
	if mFalse["snmp_syslog_notification"] != false {
		t.Fatalf("summary must report explicit false: %v", mFalse["snmp_syslog_notification"])
	}

	eUnset := &lldp.Entry{Name: "lldp2"}
	mUnset := asMap(t, lldpProfileSummary(eUnset))
	if _, ok := mUnset["snmp_syslog_notification"]; ok {
		t.Fatalf("summary must omit unset snmp_syslog_notification, got %v", mUnset["snmp_syslog_notification"])
	}
}

// --- read-only gating ---------------------------------------------------------

func TestLldpProfileReadOnlyGating(t *testing.T) {
	base := "panos_lldp_profile"
	assertReadOnlyGating(t, RegisterLldpProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// ---------------------------------------------------------------------------
// BFD profile
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestBfdProfileBuild(t *testing.T) {
	e, err := buildBfdProfile(BfdProfileInput{
		Name:                "bfd1",
		Mode:                new("active"),
		MinTxInterval:       new(int64(100)),
		MinRxInterval:       new(int64(200)),
		DetectionMultiplier: new(int64(3)),
		HoldTime:            new(int64(500)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "bfd1" {
		t.Fatalf("name wrong: got %q, want %q", e.Name, "bfd1")
	}
	mustStrPtr(t, e.Mode, "active", "mode -> Entry.Mode")
	mustInt64(t, e.MinTxInterval, 100, "min_tx_interval -> Entry.MinTxInterval")
	mustInt64(t, e.MinRxInterval, 200, "min_rx_interval -> Entry.MinRxInterval")
	mustInt64(t, e.DetectionMultiplier, 3, "detection_multiplier -> Entry.DetectionMultiplier")
	mustInt64(t, e.HoldTime, 500, "hold_time -> Entry.HoldTime")

	e2, err := buildBfdProfile(BfdProfileInput{Name: "bfd2"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Mode != nil {
		t.Fatalf("unset mode must stay nil, got %v", *e2.Mode)
	}
	mustNilInt64(t, e2.MinTxInterval, "unset min_tx_interval")
	mustNilInt64(t, e2.MinRxInterval, "unset min_rx_interval")
	mustNilInt64(t, e2.DetectionMultiplier, "unset detection_multiplier")
	mustNilInt64(t, e2.HoldTime, "unset hold_time")

	if _, err := buildBfdProfile(BfdProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestBfdProfileSummary(t *testing.T) {
	e := &bfd.Entry{
		Name:                "bfd1",
		Mode:                new("active"),
		MinTxInterval:       new(int64(100)),
		MinRxInterval:       new(int64(200)),
		DetectionMultiplier: new(int64(3)),
		HoldTime:            new(int64(500)),
	}
	m := asMap(t, bfdProfileSummary(e))
	if m[tagNameKey] != "bfd1" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	if m["mode"] != "active" {
		t.Fatalf("summary mode wrong: %v", m["mode"])
	}
	if m["min_tx_interval"] != int64(100) {
		t.Fatalf("summary min_tx_interval wrong: %v", m["min_tx_interval"])
	}
	if m["min_rx_interval"] != int64(200) {
		t.Fatalf("summary min_rx_interval wrong: %v", m["min_rx_interval"])
	}
	if m["detection_multiplier"] != int64(3) {
		t.Fatalf("summary detection_multiplier wrong: %v", m["detection_multiplier"])
	}
	if m["hold_time"] != int64(500) {
		t.Fatalf("summary hold_time wrong: %v", m["hold_time"])
	}

	eUnset := &bfd.Entry{Name: "bfd2"}
	mUnset := asMap(t, bfdProfileSummary(eUnset))
	for _, key := range []string{"min_tx_interval", "min_rx_interval", "detection_multiplier", "hold_time"} {
		if _, ok := mUnset[key]; ok {
			t.Fatalf("summary must omit unset %s, got %v", key, mUnset[key])
		}
	}
}

// --- read-only gating ---------------------------------------------------------

func TestBfdProfileReadOnlyGating(t *testing.T) {
	base := "panos_bfd_profile"
	assertReadOnlyGating(t, RegisterBfdProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// ---------------------------------------------------------------------------
// Monitor profile
// ---------------------------------------------------------------------------

// --- build --------------------------------------------------------------------

func TestMonitorProfileBuild(t *testing.T) {
	e, err := buildMonitorProfile(MonitorProfileInput{
		Name:      "mon1",
		Action:    new("wait-recover"),
		Interval:  new(int64(3)),
		Threshold: new(int64(5)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "mon1" {
		t.Fatalf("name wrong: got %q, want %q", e.Name, "mon1")
	}
	mustStrPtr(t, e.Action, "wait-recover", "action -> Entry.Action")
	mustInt64(t, e.Interval, 3, "interval -> Entry.Interval")
	mustInt64(t, e.Threshold, 5, "threshold -> Entry.Threshold")

	e2, err := buildMonitorProfile(MonitorProfileInput{Name: "mon2"})
	if err != nil {
		t.Fatal(err)
	}
	if e2.Action != nil {
		t.Fatalf("unset action must stay nil, got %v", *e2.Action)
	}
	mustNilInt64(t, e2.Interval, "unset interval")
	mustNilInt64(t, e2.Threshold, "unset threshold")

	if _, err := buildMonitorProfile(MonitorProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// --- summary ------------------------------------------------------------------

func TestMonitorProfileSummary(t *testing.T) {
	e := &monitor.Entry{
		Name:      "mon1",
		Action:    new("wait-recover"),
		Interval:  new(int64(3)),
		Threshold: new(int64(5)),
	}
	m := asMap(t, monitorProfileSummary(e))
	if m[tagNameKey] != "mon1" {
		t.Fatalf("summary name wrong: %v", m[tagNameKey])
	}
	if m["action"] != "wait-recover" {
		t.Fatalf("summary action wrong: %v", m["action"])
	}
	if m["interval"] != int64(3) {
		t.Fatalf("summary interval wrong: %v", m["interval"])
	}
	if m["threshold"] != int64(5) {
		t.Fatalf("summary threshold wrong: %v", m["threshold"])
	}

	eUnset := &monitor.Entry{Name: "mon2"}
	mUnset := asMap(t, monitorProfileSummary(eUnset))
	for _, key := range []string{"interval", "threshold"} {
		if _, ok := mUnset[key]; ok {
			t.Fatalf("summary must omit unset %s, got %v", key, mUnset[key])
		}
	}
}

// --- read-only gating ---------------------------------------------------------

func TestMonitorProfileReadOnlyGating(t *testing.T) {
	base := "panos_monitor_profile"
	assertReadOnlyGating(t, RegisterMonitorProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}
