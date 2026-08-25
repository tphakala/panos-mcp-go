package tools

import (
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/application"
	application_group "github.com/PaloAltoNetworks/pango/objects/application/group"
	"github.com/PaloAltoNetworks/pango/objects/extdynlist"
	"github.com/PaloAltoNetworks/pango/objects/profiles/customurlcategory"
	"github.com/PaloAltoNetworks/pango/objects/schedules"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertReadOnlyGating pins that register exposes reads in both modes and writes
// only when writes are enabled. Shared by the refobject registration tests.
func assertReadOnlyGating(t *testing.T, register func(*mcp.Server, *Deps), reads, writes []string) {
	t.Helper()
	writeMode := func(readOnly bool) map[string]bool {
		d, _ := newTestDeps(t, "PA-VM")
		d.ReadOnly = readOnly
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		register(srv, d)
		return serverToolNames(t, srv)
	}
	full := writeMode(false)
	for _, n := range slices.Concat(reads, writes) {
		if !full[n] {
			t.Errorf("write mode must expose %q", n)
		}
	}
	ro := writeMode(true)
	for _, n := range reads {
		if !ro[n] {
			t.Errorf("read-only mode must still expose read tool %q", n)
		}
	}
	for _, n := range writes {
		if ro[n] {
			t.Errorf("read-only mode must not expose write tool %q", n)
		}
	}
}

// --- Application groups -------------------------------------------------------

func TestBuildApplicationGroupEntry(t *testing.T) {
	e, err := buildApplicationGroupEntry(ApplicationGroupInput{Name: "apps", Members: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "apps" || len(e.Members) != 2 || e.Members[0] != "a" {
		t.Fatalf("entry built wrong: %+v", e)
	}
}

func TestBuildApplicationGroupEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            ApplicationGroupInput
	}{
		{"no name", "name is required", ApplicationGroupInput{Members: []string{"a"}}},
		{"no members", "members must have at least one entry", ApplicationGroupInput{Name: "g"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildApplicationGroupEntry(c.in); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

func TestOverlayApplicationGroup(t *testing.T) {
	t.Run("non-empty members replace", func(t *testing.T) {
		e := &application_group.Entry{Name: "g", Members: []string{"a"}}
		if err := overlayApplicationGroup(e, ApplicationGroupInput{Members: []string{"b", "c"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Members) != 2 || e.Members[0] != "b" {
			t.Fatalf("members not replaced: %v", e.Members)
		}
	})
	t.Run("explicitly empty members rejected", func(t *testing.T) {
		e := &application_group.Entry{Name: "g", Members: []string{"a"}}
		err := overlayApplicationGroup(e, ApplicationGroupInput{Members: []string{}})
		if err == nil || !strings.Contains(err.Error(), "cannot be emptied in place") {
			t.Fatalf("empty members must be rejected, got %v", err)
		}
		if len(e.Members) != 1 {
			t.Fatalf("rejected overlay must leave members untouched: %v", e.Members)
		}
	})
	t.Run("nil members keep", func(t *testing.T) {
		e := &application_group.Entry{Name: "g", Members: []string{"a"}}
		if err := overlayApplicationGroup(e, ApplicationGroupInput{}); err != nil {
			t.Fatal(err)
		}
		if len(e.Members) != 1 {
			t.Fatalf("nil members must keep the list: %v", e.Members)
		}
	})
}

func TestApplicationGroupSummary(t *testing.T) {
	m := asMap(t, applicationGroupSummary(&application_group.Entry{Name: "g", Members: []string{"a", "b"}}))
	if m[tagNameKey] != "g" {
		t.Fatalf("name wrong: %v", m[tagNameKey])
	}
	if members, ok := m["members"].([]string); !ok || len(members) != 2 {
		t.Fatalf("members wrong: %v", m["members"])
	}
}

const applicationGroupCreatedBody = `<response status="success"><result>` +
	`<entry name="apps-web"><members><member>web-browsing</member></members></entry></result></response>`

func TestApplicationGroupCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: applicationGroupCreatedBody},
	)
	h := createHandler[application_group.Location, application_group.Entry, ApplicationGroupInput](d, "panos_application_group_create",
		newApplicationGroupService(d), func(in LocationInput) (application_group.Location, error) {
			return resolveLocation(d, in, appGroupParts())
		},
		func(in ApplicationGroupInput) LocationInput { return in.Location }, buildApplicationGroupEntry, applicationGroupSummary)

	res, _, err := h(t.Context(), nil, ApplicationGroupInput{Name: "apps-web", Members: []string{"web-browsing"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			sawSet = true
			el := req.Get("element")
			if !strings.Contains(el, `name="apps-web"`) || !strings.Contains(el, "<member>web-browsing</member>") {
				t.Fatalf("set element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "application-group") {
				t.Fatalf("xpath missing vsys or application-group endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
	assertReadBackGet(t, f)
}

func TestApplicationGroupAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[application_group.Location, application_group.Entry](d, "panos_application_group_get",
		newApplicationGroupService(d), func(in LocationInput) (application_group.Location, error) {
			return resolveLocation(d, in, appGroupParts())
		}, applicationGroupSummary)
	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textContent(t, res), "invalid object") {
		t.Fatalf("API error must surface: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

func TestRegisterApplicationGroupToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterApplicationGroupTools,
		[]string{"panos_application_group_list", "panos_application_group_get"},
		[]string{"panos_application_group_create", "panos_application_group_update", "panos_application_group_delete"})
}

// --- Custom applications -----------------------------------------------------

// applicationBoolField pins one *bool input->entry mapping so that deleting the
// mapping line (which leaves the entry field nil) turns this red. Distinct
// per-field want values also catch a copy-paste swap between two fields.
type applicationBoolField struct {
	name string
	got  func(*application.Entry) *bool
	want bool
}

//nolint:gocyclo // exhaustive field-mapping assertions across the built entry.
func TestBuildApplicationEntry(t *testing.T) {
	// Every *bool characteristic, alternating true/false so a swap between an
	// adjacent pair is caught, not only a dropped line.
	flags := []applicationBoolField{
		{"evasive_behavior", func(e *application.Entry) *bool { return e.EvasiveBehavior }, true},
		{"has_known_vulnerability", func(e *application.Entry) *bool { return e.HasKnownVulnerability }, false},
		{"used_by_malware", func(e *application.Entry) *bool { return e.UsedByMalware }, true},
		{"able_to_transfer_file", func(e *application.Entry) *bool { return e.AbleToTransferFile }, false},
		{"prone_to_misuse", func(e *application.Entry) *bool { return e.ProneToMisuse }, true},
		{"pervasive_use", func(e *application.Entry) *bool { return e.PervasiveUse }, false},
		{"tunnel_applications", func(e *application.Entry) *bool { return e.TunnelApplications }, true},
	}
	e, err := buildApplicationEntry(ApplicationInput{
		Name: "my-app", Description: "d", Category: "business-systems", Subcategory: "management",
		Technology: "client-server", Risk: new(int64(4)), DefaultPorts: []string{"tcp/8080"},
		Timeout: new(int64(60)), TCPTimeout: new(int64(30)), UDPTimeout: new(int64(20)),
		EvasiveBehavior: new(true), HasKnownVulnerability: new(false), UsedByMalware: new(true),
		AbleToTransferFile: new(false), ProneToMisuse: new(true), PervasiveUse: new(false),
		TunnelApplications: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "my-app" || strVal(e.Description) != "d" || strVal(e.Category) != "business-systems" ||
		strVal(e.Subcategory) != "management" || strVal(e.Technology) != "client-server" {
		t.Fatalf("classification mapped wrong: %+v", e)
	}
	if e.Risk == nil || *e.Risk != 4 {
		t.Fatalf("risk mapped wrong: %v", e.Risk)
	}
	if e.Default == nil || len(e.Default.Port) != 1 || e.Default.Port[0] != "tcp/8080" {
		t.Fatalf("default ports mapped wrong: %+v", e.Default)
	}
	if e.Timeout == nil || *e.Timeout != 60 || e.TcpTimeout == nil || *e.TcpTimeout != 30 || e.UdpTimeout == nil || *e.UdpTimeout != 20 {
		t.Fatalf("timeouts mapped wrong: %+v", e)
	}
	for _, fl := range flags {
		got := fl.got(e)
		if got == nil || *got != fl.want {
			t.Fatalf("%s mapped wrong: got %v want %v", fl.name, got, fl.want)
		}
	}
}

func TestBuildApplicationEntryIPProtocol(t *testing.T) {
	e, err := buildApplicationEntry(ApplicationInput{Name: "proto-app", DefaultIPProtocol: "6"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Default == nil || strVal(e.Default.IdentByIpProtocol) != "6" {
		t.Fatalf("default_ip_protocol must map to Default.IdentByIpProtocol: %+v", e.Default)
	}
	if len(e.Default.Port) != 0 {
		t.Fatalf("ip-protocol default must carry no ports: %+v", e.Default)
	}
}

func TestBuildApplicationEntryRejects(t *testing.T) {
	if _, err := buildApplicationEntry(ApplicationInput{}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("empty name must be rejected, got %v", err)
	}
	for _, r := range []int64{0, 6} {
		if _, err := buildApplicationEntry(ApplicationInput{Name: "a", Risk: new(r)}); err == nil || !strings.Contains(err.Error(), "risk must be between 1 and 5") {
			t.Fatalf("risk %d must be rejected, got %v", r, err)
		}
	}
	_, err := buildApplicationEntry(ApplicationInput{Name: "a", DefaultPorts: []string{"tcp/80"}, DefaultIPProtocol: "6"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("port and ip-protocol together must be rejected, got %v", err)
	}
}

//nolint:gocyclo,gocognit // exhaustive overlay assertions across the preserve/replace/clear/reject/no-op scenarios.
func TestOverlayApplication(t *testing.T) {
	t.Run("untouched default preserves existing ident", func(t *testing.T) {
		e := &application.Entry{Name: "a", Default: &application.Default{IdentByIcmpType: &application.DefaultIdentByIcmpType{Type: new("8")}}, Risk: new(int64(3))}
		if err := overlayApplication(e, ApplicationInput{Description: "d"}); err != nil {
			t.Fatal(err)
		}
		if e.Default == nil || e.Default.IdentByIcmpType == nil || strVal(e.Default.IdentByIcmpType.Type) != "8" {
			t.Fatalf("untouched default must preserve the existing ICMP ident: %+v", e.Default)
		}
		if e.Risk == nil || *e.Risk != 3 {
			t.Fatalf("untouched risk must survive: %v", e.Risk)
		}
	})
	t.Run("provided ports replace the whole default oneof", func(t *testing.T) {
		e := &application.Entry{Name: "a", Default: &application.Default{IdentByIcmpType: &application.DefaultIdentByIcmpType{Type: new("8")}}}
		if err := overlayApplication(e, ApplicationInput{DefaultPorts: []string{"tcp/443"}}); err != nil {
			t.Fatal(err)
		}
		if e.Default == nil || len(e.Default.Port) != 1 || e.Default.Port[0] != "tcp/443" {
			t.Fatalf("ports must be set: %+v", e.Default)
		}
		if e.Default.IdentByIcmpType != nil {
			t.Fatalf("setting a port must clear the mutually-exclusive ICMP ident: %+v", e.Default)
		}
	})
	t.Run("ip-protocol replaces an existing port default", func(t *testing.T) {
		e := &application.Entry{Name: "a", Default: &application.Default{Port: []string{"tcp/80"}}}
		if err := overlayApplication(e, ApplicationInput{DefaultIPProtocol: "47"}); err != nil {
			t.Fatal(err)
		}
		if e.Default == nil || strVal(e.Default.IdentByIpProtocol) != "47" || len(e.Default.Port) != 0 {
			t.Fatalf("ip-protocol must replace the whole default, clearing the port branch: %+v", e.Default)
		}
	})
	t.Run("explicit empty ports clears the default", func(t *testing.T) {
		e := &application.Entry{Name: "a", Default: &application.Default{IdentByIcmpType: &application.DefaultIdentByIcmpType{Type: new("8")}}}
		if err := overlayApplication(e, ApplicationInput{DefaultPorts: []string{}}); err != nil {
			t.Fatal(err)
		}
		if e.Default != nil {
			t.Fatalf("an explicit empty default_ports must clear the default identification: %+v", e.Default)
		}
	})
	t.Run("empty ports and ip-protocol together are rejected", func(t *testing.T) {
		e := &application.Entry{Name: "a"}
		if err := overlayApplication(e, ApplicationInput{DefaultPorts: []string{}, DefaultIPProtocol: "6"}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("empty default_ports with an ip-protocol must be rejected, got %v", err)
		}
	})
	t.Run("all-nil input changes nothing", func(t *testing.T) {
		e := &application.Entry{Name: "a"}
		if err := overlayApplication(e, ApplicationInput{}); err != nil {
			t.Fatal(err)
		}
		if e.Category != nil || e.Subcategory != nil || e.Technology != nil || e.Description != nil ||
			e.Risk != nil || e.Timeout != nil || e.TcpTimeout != nil || e.UdpTimeout != nil ||
			e.EvasiveBehavior != nil || e.HasKnownVulnerability != nil || e.UsedByMalware != nil ||
			e.AbleToTransferFile != nil || e.ProneToMisuse != nil || e.PervasiveUse != nil ||
			e.TunnelApplications != nil || e.Default != nil {
			t.Fatalf("all-nil overlay must leave the entry untouched: %+v", e)
		}
	})
}

//nolint:gocyclo,gocognit // exhaustive summary assertions across the omit, present-value and ip/icmp scenarios.
func TestApplicationSummary(t *testing.T) {
	t.Run("nil optionals omit keys", func(t *testing.T) {
		m := asMap(t, applicationSummary(&application.Entry{Name: "a"}))
		for _, k := range []string{"risk", "timeout", "tcp_timeout", "udp_timeout", "evasive_behavior", "has_known_vulnerability", "used_by_malware", "able_to_transfer_file", "prone_to_misuse", "pervasive_use", "tunnel_applications", "default_ports", "default_ip_protocol"} {
			if _, ok := m[k]; ok {
				t.Fatalf("nil %s must be omitted, not coerced: %v", k, m[k])
			}
		}
		if v, ok := m["has_signatures"].(bool); !ok || v {
			t.Fatalf("has_signatures must be present and false: %v", m["has_signatures"])
		}
		if v, ok := m["has_icmp_ident"].(bool); !ok || v {
			t.Fatalf("has_icmp_ident must be present and false when no default: %v", m["has_icmp_ident"])
		}
	})
	t.Run("present values emitted", func(t *testing.T) {
		e := &application.Entry{
			Name: "a", Description: new("d"), Category: new("business-systems"),
			Subcategory: new("email"), Technology: new("client-server"), Risk: new(int64(2)),
			Default: &application.Default{Port: []string{"tcp/80"}},
			Timeout: new(int64(60)), TcpTimeout: new(int64(30)), UdpTimeout: new(int64(20)),
			EvasiveBehavior: new(false), HasKnownVulnerability: new(true), UsedByMalware: new(false),
			AbleToTransferFile: new(true), ProneToMisuse: new(false), PervasiveUse: new(true),
			TunnelApplications: new(false),
			Signature:          []application.Signature{{Name: "s1"}},
		}
		m := asMap(t, applicationSummary(e))
		strChecks := map[string]string{"description": "d", "category": "business-systems", "subcategory": "email", "technology": "client-server"}
		for k, want := range strChecks {
			if m[k] != want {
				t.Fatalf("%s wrong: got %v want %q", k, m[k], want)
			}
		}
		intChecks := map[string]int64{"risk": 2, "timeout": 60, "tcp_timeout": 30, "udp_timeout": 20}
		for k, want := range intChecks {
			if v, ok := m[k].(int64); !ok || v != want {
				t.Fatalf("%s wrong: got %v want %d", k, m[k], want)
			}
		}
		boolChecks := map[string]bool{"evasive_behavior": false, "has_known_vulnerability": true, "used_by_malware": false, "able_to_transfer_file": true, "prone_to_misuse": false, "pervasive_use": true, "tunnel_applications": false}
		for k, want := range boolChecks {
			if v, ok := m[k].(bool); !ok || v != want {
				t.Fatalf("%s wrong: got %v want %v", k, m[k], want)
			}
		}
		if ports, ok := m["default_ports"].([]string); !ok || len(ports) != 1 || ports[0] != "tcp/80" {
			t.Fatalf("default_ports wrong: %v", m["default_ports"])
		}
		if v, ok := m["has_signatures"].(bool); !ok || !v {
			t.Fatalf("has_signatures must be true when signatures present: %v", m["has_signatures"])
		}
	})
	t.Run("ip-protocol and icmp ident surfaced", func(t *testing.T) {
		ip := asMap(t, applicationSummary(&application.Entry{Name: "a", Default: &application.Default{IdentByIpProtocol: new("6")}}))
		if ip["default_ip_protocol"] != "6" {
			t.Fatalf("default_ip_protocol wrong: %v", ip["default_ip_protocol"])
		}
		if v, ok := ip["has_icmp_ident"].(bool); !ok || v {
			t.Fatalf("has_icmp_ident must be false for an ip-protocol default: %v", ip["has_icmp_ident"])
		}
		icmp := asMap(t, applicationSummary(&application.Entry{Name: "a", Default: &application.Default{IdentByIcmpType: &application.DefaultIdentByIcmpType{Type: new("8")}}}))
		if v, ok := icmp["has_icmp_ident"].(bool); !ok || !v {
			t.Fatalf("has_icmp_ident must be true when the default identifies by ICMP: %v", icmp["has_icmp_ident"])
		}
	})
}

func TestApplicationCreate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: minimalEntryBody("my-app")},
	)
	h := createHandler[application.Location, application.Entry, ApplicationInput](d, "panos_application_create",
		newApplicationService(d), func(in LocationInput) (application.Location, error) {
			return resolveLocation(d, in, applicationParts())
		},
		func(in ApplicationInput) LocationInput { return in.Location }, buildApplicationEntry, applicationSummary)
	res, _, err := h(t.Context(), nil, ApplicationInput{
		Name: "my-app", Category: "business-systems", Subcategory: "management", Technology: "client-server",
		Risk: new(int64(4)), DefaultPorts: []string{"tcp/8080"}, EvasiveBehavior: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{`name="my-app"`, `<category>business-systems</category>`, `<risk>4</risk>`, `<default><port><member>tcp/8080</member></port></default>`, `<evasive-behavior>yes</evasive-behavior>`} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xp := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "/application/") {
		t.Fatalf("create did not target the firewall application node: %s", xp)
	}
	assertReadBackGet(t, f)
}

func TestApplicationAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[application.Location, application.Entry](d, "panos_application_get",
		newApplicationService(d), func(in LocationInput) (application.Location, error) {
			return resolveLocation(d, in, applicationParts())
		}, applicationSummary)
	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textContent(t, res), "invalid object") {
		t.Fatalf("API error must surface: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

func TestRegisterApplicationToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterApplicationTools,
		[]string{"panos_application_list", "panos_application_get"},
		[]string{"panos_application_create", "panos_application_update", "panos_application_delete"})
}

// --- Custom URL categories ---------------------------------------------------

func TestBuildCustomURLCategoryEntry(t *testing.T) {
	e, err := buildCustomURLCategoryEntry(CustomURLCategoryInput{Name: "cat", Type: customURLCategoryTypeURLList, Members: []string{"x.com"}, Description: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "cat" || strVal(e.Type) != "URL List" || len(e.List) != 1 || strVal(e.Description) != "d" {
		t.Fatalf("entry built wrong: %+v", e)
	}
}

func TestBuildCustomURLCategoryEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            CustomURLCategoryInput
	}{
		{"no name", "name is required", CustomURLCategoryInput{Type: "URL List", Members: []string{"x"}}},
		{"no type", "type is required", CustomURLCategoryInput{Name: "c", Members: []string{"x"}}},
		{"bad type", "type must be one of", CustomURLCategoryInput{Name: "c", Type: "url-list", Members: []string{"x"}}},
		{"no members", "members must have at least one entry", CustomURLCategoryInput{Name: "c", Type: "URL List"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildCustomURLCategoryEntry(c.in); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

func TestOverlayCustomURLCategory(t *testing.T) {
	t.Run("type replaces when valid", func(t *testing.T) {
		e := &customurlcategory.Entry{Name: "c", Type: new("URL List"), List: []string{"x"}}
		if err := overlayCustomURLCategory(e, CustomURLCategoryInput{Type: "Category Match"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Type) != "Category Match" {
			t.Fatalf("type not replaced: %v", strVal(e.Type))
		}
	})
	t.Run("bad type rejected", func(t *testing.T) {
		e := &customurlcategory.Entry{Name: "c", Type: new("URL List")}
		if err := overlayCustomURLCategory(e, CustomURLCategoryInput{Type: "bogus"}); err == nil || !strings.Contains(err.Error(), "type must be one of") {
			t.Fatalf("bad type must be rejected: %v", err)
		}
	})
	t.Run("non-empty members replace, empty rejected", func(t *testing.T) {
		e := &customurlcategory.Entry{Name: "c", Type: new("URL List"), List: []string{"x"}}
		if err := overlayCustomURLCategory(e, CustomURLCategoryInput{Members: []string{"y", "z"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.List) != 2 {
			t.Fatalf("members not replaced: %v", e.List)
		}
		if err := overlayCustomURLCategory(e, CustomURLCategoryInput{Members: []string{}}); err == nil || !strings.Contains(err.Error(), "cannot be emptied in place") {
			t.Fatalf("empty members must be rejected: %v", err)
		}
	})
	t.Run("empty overlay keeps entry", func(t *testing.T) {
		e := &customurlcategory.Entry{Name: "c", Type: new("URL List"), List: []string{"x"}, Description: new("d")}
		if err := overlayCustomURLCategory(e, CustomURLCategoryInput{}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Type) != "URL List" || len(e.List) != 1 || strVal(e.Description) != "d" {
			t.Fatalf("empty overlay changed entry: %+v", e)
		}
	})
}

func TestCustomURLCategorySummary(t *testing.T) {
	m := asMap(t, customURLCategorySummary(&customurlcategory.Entry{Name: "c", Type: new("Category Match"), List: []string{"a"}, Description: new("d")}))
	if m[tagNameKey] != "c" || m["type"] != "Category Match" || m[descriptionKey] != "d" {
		t.Fatalf("summary wrong: %v", m)
	}
	if members, ok := m["members"].([]string); !ok || len(members) != 1 {
		t.Fatalf("members wrong: %v", m["members"])
	}
}

func TestRegisterCustomURLCategoryToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterCustomURLCategoryTools,
		[]string{"panos_custom_url_category_list", "panos_custom_url_category_get"},
		[]string{"panos_custom_url_category_create", "panos_custom_url_category_update", "panos_custom_url_category_delete"})
}

// --- Schedules ---------------------------------------------------------------

func TestBuildScheduleEntry(t *testing.T) {
	t.Run("non-recurring", func(t *testing.T) {
		e, err := buildScheduleEntry(ScheduleInput{Name: "s", ScheduleType: "non-recurring", TimeRanges: []string{"2026/01/01@09:00-2026/01/01@17:00"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.ScheduleType == nil || len(e.ScheduleType.NonRecurring) != 1 || e.ScheduleType.Recurring != nil {
			t.Fatalf("non-recurring built wrong: %+v", e.ScheduleType)
		}
	})
	t.Run("daily", func(t *testing.T) {
		e, err := buildScheduleEntry(ScheduleInput{Name: "s", ScheduleType: "daily", TimeRanges: []string{"09:00-17:00"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.ScheduleType.Recurring == nil || len(e.ScheduleType.Recurring.Daily) != 1 || e.ScheduleType.Recurring.Weekly != nil {
			t.Fatalf("daily built wrong: %+v", e.ScheduleType)
		}
	})
	t.Run("weekly", func(t *testing.T) {
		e, err := buildScheduleEntry(ScheduleInput{Name: "s", ScheduleType: "weekly", Monday: []string{"09:00-17:00"}})
		if err != nil {
			t.Fatal(err)
		}
		w := e.ScheduleType.Recurring.Weekly
		if w == nil || len(w.Monday) != 1 || e.ScheduleType.Recurring.Daily != nil {
			t.Fatalf("weekly built wrong: %+v", e.ScheduleType.Recurring)
		}
	})
}

func TestBuildScheduleEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            ScheduleInput
	}{
		{"no name", "name is required", ScheduleInput{ScheduleType: "daily", TimeRanges: []string{"09:00-17:00"}}},
		{"no type", "schedule_type is required", ScheduleInput{Name: "s", TimeRanges: []string{"09:00-17:00"}}},
		{"bad type", "schedule_type must be one of", ScheduleInput{Name: "s", ScheduleType: "monthly", TimeRanges: []string{"09:00-17:00"}}},
		{"non-recurring needs times", "requires time_ranges", ScheduleInput{Name: "s", ScheduleType: "non-recurring"}},
		{"daily needs times", "requires time_ranges", ScheduleInput{Name: "s", ScheduleType: "daily"}},
		{"weekly needs a day", "at least one day", ScheduleInput{Name: "s", ScheduleType: "weekly"}},
		{"times and days exclusive", "mutually exclusive", ScheduleInput{Name: "s", ScheduleType: "weekly", TimeRanges: []string{"09:00-17:00"}, Monday: []string{"09:00-17:00"}}},
		{"days with daily rejected", "per-day lists apply to a weekly", ScheduleInput{Name: "s", ScheduleType: "daily", Monday: []string{"09:00-17:00"}}},
		{"times with weekly rejected", "time_ranges apply to a non-recurring or daily", ScheduleInput{Name: "s", ScheduleType: "weekly", TimeRanges: []string{"09:00-17:00"}}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildScheduleEntry(c.in); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

// TestOverlayScheduleTypeSwitchClearsOldBranch is the headline schedule oneof
// test: switching type must clear the previous branch wholesale.
func TestOverlayScheduleTypeSwitchClearsOldBranch(t *testing.T) {
	t.Run("daily to weekly", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Daily: []string{"09:00-17:00"}}}}
		if err := overlaySchedule(e, ScheduleInput{ScheduleType: "weekly", Monday: []string{"08:00-12:00"}}); err != nil {
			t.Fatal(err)
		}
		if e.ScheduleType.Recurring.Daily != nil {
			t.Fatalf("switching to weekly must clear Daily, got %v", e.ScheduleType.Recurring.Daily)
		}
		if e.ScheduleType.Recurring.Weekly == nil || len(e.ScheduleType.Recurring.Weekly.Monday) != 1 {
			t.Fatalf("weekly branch not set: %+v", e.ScheduleType.Recurring)
		}
	})
	t.Run("weekly to non-recurring clears recurring", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Weekly: &schedules.ScheduleTypeRecurringWeekly{Monday: []string{"09:00-17:00"}}}}}
		if err := overlaySchedule(e, ScheduleInput{ScheduleType: "non-recurring", TimeRanges: []string{"2026/01/01@09:00-2026/01/01@17:00"}}); err != nil {
			t.Fatal(err)
		}
		if e.ScheduleType.Recurring != nil {
			t.Fatalf("switching to non-recurring must clear Recurring, got %+v", e.ScheduleType.Recurring)
		}
		if len(e.ScheduleType.NonRecurring) != 1 {
			t.Fatalf("non-recurring not set: %v", e.ScheduleType.NonRecurring)
		}
	})
}

// TestOverlayScheduleSubtreeMiscPreserved pins that a branch switch reuses the
// existing *ScheduleType so unknown nested XML survives (the PR #62 lesson).
func TestOverlayScheduleSubtreeMiscPreserved(t *testing.T) {
	e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
		Recurring:      &schedules.ScheduleTypeRecurring{Daily: []string{"09:00-17:00"}},
	}}
	if err := overlaySchedule(e, ScheduleInput{ScheduleType: "non-recurring", TimeRanges: []string{"2026/01/01@09:00-2026/01/01@17:00"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.ScheduleType.MiscAttributes) != 1 || e.ScheduleType.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("schedule-type unknown XML must survive a branch switch: %+v", e.ScheduleType.MiscAttributes)
	}
}

func TestOverlayScheduleInBranch(t *testing.T) {
	t.Run("time_ranges replace daily", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Daily: []string{"09:00-17:00"}}}}
		if err := overlaySchedule(e, ScheduleInput{TimeRanges: []string{"08:00-12:00", "13:00-18:00"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.ScheduleType.Recurring.Daily) != 2 {
			t.Fatalf("daily times not replaced: %v", e.ScheduleType.Recurring.Daily)
		}
	})
	t.Run("weekly per-day non-nil replaces, empty clears one day", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Weekly: &schedules.ScheduleTypeRecurringWeekly{
			Monday: []string{"09:00-17:00"}, Tuesday: []string{"09:00-17:00"},
		}}}}
		if err := overlaySchedule(e, ScheduleInput{Monday: []string{"08:00-10:00"}, Tuesday: []string{}}); err != nil {
			t.Fatal(err)
		}
		w := e.ScheduleType.Recurring.Weekly
		if len(w.Monday) != 1 || w.Monday[0] != "08:00-10:00" {
			t.Fatalf("monday not replaced: %v", w.Monday)
		}
		if len(w.Tuesday) != 0 {
			t.Fatalf("tuesday must be cleared by an explicit empty list: %v", w.Tuesday)
		}
	})
	t.Run("clearing every weekly day rejected leaves entry untouched", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Weekly: &schedules.ScheduleTypeRecurringWeekly{
			Monday: []string{"09:00-17:00"},
		}}}}
		if err := overlaySchedule(e, ScheduleInput{Monday: []string{}}); err == nil || !strings.Contains(err.Error(), "at least one day") {
			t.Fatalf("emptying the last day must be rejected: %v", err)
		}
		// A rejected overlay must not have mutated the entry (the invariant the
		// sibling overlays hold; the overlay applies onto a copy and commits only
		// when valid).
		if len(e.ScheduleType.Recurring.Weekly.Monday) != 1 {
			t.Fatalf("a rejected weekly overlay must leave Monday untouched, got: %v", e.ScheduleType.Recurring.Weekly.Monday)
		}
	})
	t.Run("no type and no fields on a typeless schedule leaves it", func(t *testing.T) {
		e := &schedules.Entry{Name: "s"}
		if err := overlaySchedule(e, ScheduleInput{}); err != nil {
			t.Fatal(err)
		}
		if e.ScheduleType != nil {
			t.Fatalf("an empty overlay must not create a schedule type: %+v", e.ScheduleType)
		}
	})
}

func TestScheduleSummary(t *testing.T) {
	t.Run("weekly emits only non-empty days", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Weekly: &schedules.ScheduleTypeRecurringWeekly{
			Monday: []string{"09:00-17:00"},
		}}}}
		m := asMap(t, scheduleSummary(e))
		if m["schedule_type"] != "weekly" {
			t.Fatalf("type wrong: %v", m["schedule_type"])
		}
		days := asMap(t, m["days"])
		if _, ok := days["monday"]; !ok {
			t.Fatalf("monday missing: %v", days)
		}
		if _, ok := days["tuesday"]; ok {
			t.Fatalf("empty tuesday must be omitted: %v", days)
		}
	})
	t.Run("daily exposes time_ranges", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Daily: []string{"09:00-17:00"}}}}
		m := asMap(t, scheduleSummary(e))
		tr, ok := m["time_ranges"].([]string)
		if m["schedule_type"] != "daily" || !ok || len(tr) != 1 {
			t.Fatalf("daily summary wrong: %v", m)
		}
	})
	t.Run("non-recurring exposes time_ranges", func(t *testing.T) {
		e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{NonRecurring: []string{"2026/01/01@09:00-2026/01/01@17:00"}}}
		m := asMap(t, scheduleSummary(e))
		tr, ok := m["time_ranges"].([]string)
		if m["schedule_type"] != "non-recurring" || !ok || len(tr) != 1 {
			t.Fatalf("non-recurring summary wrong: %v", m)
		}
	})
}

func TestRegisterScheduleToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterScheduleTools,
		[]string{"panos_schedule_list", "panos_schedule_get"},
		[]string{"panos_schedule_create", "panos_schedule_update", "panos_schedule_delete"})
}

// --- External dynamic lists --------------------------------------------------

func TestBuildEdlEntry(t *testing.T) {
	t.Run("ip builds the ip branch", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "ip", URL: "https://x/l.txt", Description: "d", ExceptionList: []string{"1.2.3.4"}, CertificateProfile: "cp", Recurring: "hourly"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.Ip == nil || strVal(e.Type.Ip.Url) != "https://x/l.txt" || strVal(e.Type.Ip.Description) != "d" ||
			len(e.Type.Ip.ExceptionList) != 1 || strVal(e.Type.Ip.CertificateProfile) != "cp" || e.Type.Ip.Recurring.Hourly == nil {
			t.Fatalf("ip branch wrong: %+v", e.Type.Ip)
		}
	})
	t.Run("domain carries expand_domain", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "domain", URL: "https://x", ExpandDomain: new(true), Recurring: "hourly"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.Domain == nil || e.Type.Domain.ExpandDomain == nil || !*e.Type.Domain.ExpandDomain {
			t.Fatalf("domain branch wrong: %+v", e.Type.Domain)
		}
	})
	t.Run("predefined-ip builds the predefined branch", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "predefined-ip", URL: "panw-known-ip-list"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.PredefinedIp == nil || strVal(e.Type.PredefinedIp.Url) != "panw-known-ip-list" {
			t.Fatalf("predefined-ip branch wrong: %+v", e.Type.PredefinedIp)
		}
	})
}

func TestBuildEdlEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            EdlInput
	}{
		{"no name", "name is required", EdlInput{Type: "ip", URL: "x"}},
		{"no type", "type is required", EdlInput{Name: "e", URL: "x"}},
		{"no url", "url is required", EdlInput{Name: "e", Type: "ip"}},
		{"imei not managed", "not managed by this server", EdlInput{Name: "e", Type: "imei", URL: "x"}},
		{"bad type", "type must be one of", EdlInput{Name: "e", Type: "bogus", URL: "x"}},
		{"predefined with recurring", "predefined lists refresh", EdlInput{Name: "e", Type: "predefined-ip", URL: "x", Recurring: "hourly"}},
		{"predefined with cert", "certificate_profile does not apply", EdlInput{Name: "e", Type: "predefined-ip", URL: "x", CertificateProfile: "cp"}},
		{"expand_domain on ip", "expand_domain applies to the domain type only", EdlInput{Name: "e", Type: "ip", URL: "x", ExpandDomain: new(true)}},
		{"ip without recurring", "recurring is required", EdlInput{Name: "e", Type: "ip", URL: "x"}},
		{"domain without recurring", "recurring is required", EdlInput{Name: "e", Type: "domain", URL: "x"}},
		{"url without recurring", "recurring is required", EdlInput{Name: "e", Type: "url", URL: "x"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildEdlEntry(c.in); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

//nolint:gocognit,gocyclo // independent recurring-validation subtests kept in one place.
func TestEdlRecurringValidation(t *testing.T) {
	base := func() EdlInput { return EdlInput{Name: "e", Type: "ip", URL: "x"} }
	t.Run("bad interval", func(t *testing.T) {
		in := base()
		in.Recurring = "yearly"
		if _, err := buildEdlEntry(in); err == nil || !strings.Contains(err.Error(), "recurring must be one of") {
			t.Fatalf("bad interval must be rejected: %v", err)
		}
	})
	t.Run("at without valid interval", func(t *testing.T) {
		in := base()
		in.Recurring = "hourly"
		in.RecurringAt = "03"
		if _, err := buildEdlEntry(in); err == nil || !strings.Contains(err.Error(), "recurring_at requires recurring") {
			t.Fatalf("at with hourly must be rejected: %v", err)
		}
	})
	t.Run("day_of_week without weekly", func(t *testing.T) {
		in := base()
		in.Recurring = "daily"
		in.RecurringDayOfWeek = "monday"
		if _, err := buildEdlEntry(in); err == nil || !strings.Contains(err.Error(), "recurring_day_of_week requires recurring to be weekly") {
			t.Fatalf("dow with daily must be rejected: %v", err)
		}
	})
	t.Run("day_of_month range", func(t *testing.T) {
		in := base()
		in.Recurring = "monthly"
		in.RecurringDayOfMonth = new(int64(32))
		if _, err := buildEdlEntry(in); err == nil || !strings.Contains(err.Error(), "between 1 and 31") {
			t.Fatalf("dom 32 must be rejected: %v", err)
		}
	})
	t.Run("valid weekly builds at and day", func(t *testing.T) {
		in := base()
		in.Recurring = "weekly"
		in.RecurringAt = "03"
		in.RecurringDayOfWeek = "monday"
		e, err := buildEdlEntry(in)
		if err != nil {
			t.Fatal(err)
		}
		w := e.Type.Ip.Recurring.Weekly
		if w == nil || strVal(w.At) != "03" || strVal(w.DayOfWeek) != "monday" {
			t.Fatalf("weekly recurring wrong: %+v", w)
		}
	})
	t.Run("valid monthly builds day_of_month", func(t *testing.T) {
		in := base()
		in.Recurring = "monthly"
		in.RecurringDayOfMonth = new(int64(15))
		e, err := buildEdlEntry(in)
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.Ip.Recurring.Monthly == nil || *e.Type.Ip.Recurring.Monthly.DayOfMonth != 15 {
			t.Fatalf("monthly recurring wrong: %+v", e.Type.Ip.Recurring.Monthly)
		}
	})
}

// TestOverlayEdlTypeSwitchClearsOldBranch is the headline EDL oneof test.
func TestOverlayEdlTypeSwitchClearsOldBranch(t *testing.T) {
	e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{Url: new("https://old")}}}
	if err := overlayEdl(e, EdlInput{Type: "domain", URL: "https://new", Recurring: "hourly"}); err != nil {
		t.Fatal(err)
	}
	if e.Type.Ip != nil {
		t.Fatalf("switching to domain must clear the ip branch, got %+v", e.Type.Ip)
	}
	if e.Type.Domain == nil || strVal(e.Type.Domain.Url) != "https://new" {
		t.Fatalf("domain branch not set: %+v", e.Type.Domain)
	}
}

// TestOverlayEdlTypeSwitchRequiresRecurring pins that a type switch on update
// runs through the same recurring guard as create: rebuilding the source for an
// ip/domain/url type without a schedule is rejected, so the update path cannot
// produce an un-committable EDL either.
func TestOverlayEdlTypeSwitchRequiresRecurring(t *testing.T) {
	e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{Url: new("https://old"), Recurring: &extdynlist.TypeIpRecurring{Hourly: &extdynlist.TypeIpRecurringHourly{}}}}}
	if err := overlayEdl(e, EdlInput{Type: "url", URL: "https://new"}); err == nil || !strings.Contains(err.Error(), "recurring is required") {
		t.Fatalf("type switch to url without recurring must be rejected, got %v", err)
	}
}

func TestOverlayEdlInBranch(t *testing.T) {
	t.Run("fields overlay, recurring replaces wholesale", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{
			Url:         new("https://old"),
			Description: new("old"),
			Recurring:   &extdynlist.TypeIpRecurring{Monthly: &extdynlist.TypeIpRecurringMonthly{DayOfMonth: new(int64(1))}},
		}}}
		if err := overlayEdl(e, EdlInput{URL: "https://new", Recurring: "hourly"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Type.Ip.Url) != "https://new" {
			t.Fatalf("url not overlaid: %v", strVal(e.Type.Ip.Url))
		}
		if strVal(e.Type.Ip.Description) != "old" {
			t.Fatalf("unmentioned description must survive: %v", strVal(e.Type.Ip.Description))
		}
		if e.Type.Ip.Recurring.Monthly != nil || e.Type.Ip.Recurring.Hourly == nil {
			t.Fatalf("a provided recurring must replace the whole subtree: %+v", e.Type.Ip.Recurring)
		}
	})
	t.Run("exception_list empty clears", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{Url: new("https://x"), ExceptionList: []string{"1.1.1.1"}}}}
		if err := overlayEdl(e, EdlInput{ExceptionList: []string{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Type.Ip.ExceptionList) != 0 {
			t.Fatalf("empty exception_list must clear: %v", e.Type.Ip.ExceptionList)
		}
	})
	t.Run("no type and no branch errors", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e"}
		if err := overlayEdl(e, EdlInput{URL: "x"}); err == nil || !strings.Contains(err.Error(), "no source set") {
			t.Fatalf("overlay with no branch must error: %v", err)
		}
	})
	t.Run("imei branch is unmanaged", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Imei: &extdynlist.TypeImei{Url: new("x")}}}
		if err := overlayEdl(e, EdlInput{Description: "d"}); err == nil || !strings.Contains(err.Error(), "does not manage") {
			t.Fatalf("overlay on an imei branch must error: %v", err)
		}
	})
}

// TestEdlOrphanChecksRunBeforeEmptyTypeReturn proves the cross-field checks run
// before the no-type early return, so a bad recurring combination is caught even
// when no type is provided.
func TestEdlOrphanChecksRunBeforeEmptyTypeReturn(t *testing.T) {
	e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{Url: new("https://x")}}}
	if err := overlayEdl(e, EdlInput{RecurringAt: "03"}); err == nil || !strings.Contains(err.Error(), "recurring_at requires recurring") {
		t.Fatalf("orphan recurring_at must be rejected on the no-type path: %v", err)
	}
}

func TestEdlSummaryAndDetail(t *testing.T) {
	e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{Ip: &extdynlist.TypeIp{
		Url:           new("https://x/l.txt"),
		Description:   new("d"),
		ExceptionList: []string{"1.1.1.1"},
		Recurring:     &extdynlist.TypeIpRecurring{Weekly: &extdynlist.TypeIpRecurringWeekly{At: new("03"), DayOfWeek: new("monday")}},
	}}}
	sum := asMap(t, edlSummary(e))
	if sum["type"] != "ip" || sum["url"] != "https://x/l.txt" {
		t.Fatalf("summary wrong: %v", sum)
	}
	if _, ok := sum["exception_list"]; ok {
		t.Fatalf("summary must not carry exception_list: %v", sum)
	}
	det := asMap(t, edlDetail(e))
	if det["recurring"] != "weekly" || det["recurring_day_of_week"] != "monday" || det["recurring_at"] != "03" {
		t.Fatalf("detail recurring wrong: %v", det)
	}
	if el, ok := det["exception_list"].([]string); !ok || len(el) != 1 {
		t.Fatalf("detail must carry exception_list: %v", det["exception_list"])
	}
	// imei is reported honestly by the type string.
	imei := &extdynlist.Entry{Name: "m", Type: &extdynlist.Type{Imei: &extdynlist.TypeImei{Url: new("x")}}}
	if asMap(t, edlSummary(imei))["type"] != "imei" {
		t.Fatalf("imei type must be reported honestly")
	}
}

const edlCreatedBody = `<response status="success"><result>` +
	`<entry name="edl1"><type><ip><url>https://ex.com/l.txt</url><recurring><hourly/></recurring></ip></type></entry></result></response>`

func TestEdlCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: edlCreatedBody},
	)
	h := createHandler[extdynlist.Location, extdynlist.Entry, EdlInput](d, "panos_edl_create",
		newEdlService(d), func(in LocationInput) (extdynlist.Location, error) { return resolveLocation(d, in, edlParts()) },
		func(in EdlInput) LocationInput { return in.Location }, buildEdlEntry, edlDetail)
	res, _, err := h(t.Context(), nil, EdlInput{Name: "edl1", Type: "ip", URL: "https://ex.com/l.txt", Recurring: "hourly"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			sawSet = true
			el := req.Get("element")
			if !strings.Contains(el, `name="edl1"`) || !strings.Contains(el, "<ip>") || !strings.Contains(el, "<url>https://ex.com/l.txt</url>") || !strings.Contains(el, "<hourly") {
				t.Fatalf("set element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "external-list") {
				t.Fatalf("xpath missing external-list endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
	assertReadBackGet(t, f)
}

func TestEdlAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[extdynlist.Location, extdynlist.Entry](d, "panos_edl_get",
		newEdlService(d), func(in LocationInput) (extdynlist.Location, error) { return resolveLocation(d, in, edlParts()) }, edlDetail)
	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textContent(t, res), "invalid object") {
		t.Fatalf("API error must surface: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

func TestRegisterEdlToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterEdlTools,
		[]string{"panos_edl_list", "panos_edl_get"},
		[]string{"panos_edl_create", "panos_edl_update", "panos_edl_delete"})
}

// TestBuildEdlUrlAndPredefinedUrl covers the two settable types the other build
// tests omit (url and predefined-url), so their build branches are exercised.
func TestBuildEdlUrlAndPredefinedUrl(t *testing.T) {
	t.Run("url type builds the url branch with recurring", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "url", URL: "https://x/list", Description: "d", CertificateProfile: "cp", Recurring: "five-minute"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.Url == nil || strVal(e.Type.Url.Url) != "https://x/list" || strVal(e.Type.Url.CertificateProfile) != "cp" || e.Type.Url.Recurring.FiveMinute == nil {
			t.Fatalf("url branch wrong: %+v", e.Type.Url)
		}
		if asMap(t, edlDetail(e))[typeKey] != "url" {
			t.Fatalf("url detail type wrong")
		}
	})
	t.Run("predefined-url builds the predefined-url branch", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "predefined-url", URL: "panw-auth-portal-exclude-list", ExceptionList: []string{"x.com"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.PredefinedUrl == nil || strVal(e.Type.PredefinedUrl.Url) != "panw-auth-portal-exclude-list" || len(e.Type.PredefinedUrl.ExceptionList) != 1 {
			t.Fatalf("predefined-url branch wrong: %+v", e.Type.PredefinedUrl)
		}
		det := asMap(t, edlDetail(e))
		if det[typeKey] != "predefined-url" || det["url"] != "panw-auth-portal-exclude-list" {
			t.Fatalf("predefined-url detail wrong: %v", det)
		}
	})
}

// TestEdlRecurringMatrixBuildAndReadback exercises every recurring frequency
// through build and the edlDetail readback, closing the partial-matrix gap.
//
//nolint:gocognit,gocyclo // one independent subtest per recurring frequency.
func TestEdlRecurringMatrixBuildAndReadback(t *testing.T) {
	ip := func(rec, at, dow string, dom *int64) *extdynlist.Entry {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "ip", URL: "x", Recurring: rec, RecurringAt: at, RecurringDayOfWeek: dow, RecurringDayOfMonth: dom})
		if err != nil {
			t.Fatalf("build %s: %v", rec, err)
		}
		return e
	}
	t.Run("five-minute", func(t *testing.T) {
		e := ip("five-minute", "", "", nil)
		if e.Type.Ip.Recurring.FiveMinute == nil {
			t.Fatal("five-minute branch not built")
		}
		if asMap(t, edlDetail(e))["recurring"] != "five-minute" {
			t.Fatal("five-minute readback wrong")
		}
	})
	t.Run("daily", func(t *testing.T) {
		e := ip("daily", "03:00", "", nil)
		if e.Type.Ip.Recurring.Daily == nil || strVal(e.Type.Ip.Recurring.Daily.At) != "03:00" {
			t.Fatalf("daily branch wrong: %+v", e.Type.Ip.Recurring.Daily)
		}
		if asMap(t, edlDetail(e))["recurring_at"] != "03:00" {
			t.Fatal("daily at readback wrong")
		}
	})
	t.Run("monthly day_of_month readback", func(t *testing.T) {
		e := ip("monthly", "03:00", "", new(int64(15)))
		if e.Type.Ip.Recurring.Monthly == nil || *e.Type.Ip.Recurring.Monthly.DayOfMonth != 15 {
			t.Fatalf("monthly branch wrong: %+v", e.Type.Ip.Recurring.Monthly)
		}
		det := asMap(t, edlDetail(e))
		if det["recurring"] != "monthly" || det["recurring_day_of_month"] != int64(15) {
			t.Fatalf("monthly readback wrong: %v", det)
		}
	})
	t.Run("domain hourly", func(t *testing.T) {
		e, err := buildEdlEntry(EdlInput{Name: "e", Type: "domain", URL: "x", Recurring: "hourly"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Type.Domain.Recurring.Hourly == nil {
			t.Fatalf("domain hourly not built: %+v", e.Type.Domain.Recurring)
		}
		if asMap(t, edlDetail(e))["recurring"] != "hourly" {
			t.Fatal("domain hourly readback wrong")
		}
	})
}

// TestOverlayEdlPredefinedInBranch exercises the predefined in-branch overlay
// arm (edlOverlayPredefined), which the ip-only overlay test does not reach.
func TestOverlayEdlPredefinedInBranch(t *testing.T) {
	t.Run("url and description overlay", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{PredefinedIp: &extdynlist.TypePredefinedIp{Url: new("old")}}}
		if err := overlayEdl(e, EdlInput{URL: "new", Description: "d"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Type.PredefinedIp.Url) != "new" || strVal(e.Type.PredefinedIp.Description) != "d" {
			t.Fatalf("predefined overlay wrong: %+v", e.Type.PredefinedIp)
		}
	})
	t.Run("recurring rejected on a predefined branch", func(t *testing.T) {
		e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{PredefinedUrl: &extdynlist.TypePredefinedUrl{Url: new("x")}}}
		if err := overlayEdl(e, EdlInput{Recurring: "hourly"}); err == nil || !strings.Contains(err.Error(), "predefined lists have no recurring") {
			t.Fatalf("recurring on a predefined branch must be rejected: %v", err)
		}
	})
}

// TestOverlayEdlTypeSwitchPreservesTypeMisc pins that the <type> element's
// unknown XML survives a wholesale type switch (consistent with schedule/zone).
func TestOverlayEdlTypeSwitchPreservesTypeMisc(t *testing.T) {
	e := &extdynlist.Entry{Name: "e", Type: &extdynlist.Type{
		Ip:             &extdynlist.TypeIp{Url: new("old")},
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}}
	if err := overlayEdl(e, EdlInput{Type: "domain", URL: "new", Recurring: "hourly"}); err != nil {
		t.Fatal(err)
	}
	if len(e.Type.MiscAttributes) != 1 || e.Type.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("the <type> element's unknown XML must survive a type switch: %+v", e.Type.MiscAttributes)
	}
}

// TestBuildScheduleWeeklyPreservesMisc pins that a same-type weekly rebuild keeps
// the weekly struct's unknown XML while wholesale-replacing the days.
func TestBuildScheduleWeeklyPreservesMisc(t *testing.T) {
	e := &schedules.Entry{Name: "s", ScheduleType: &schedules.ScheduleType{Recurring: &schedules.ScheduleTypeRecurring{Weekly: &schedules.ScheduleTypeRecurringWeekly{
		Monday:         []string{"09:00-17:00"},
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}}}}
	if err := overlaySchedule(e, ScheduleInput{ScheduleType: "weekly", Tuesday: []string{"08:00-12:00"}}); err != nil {
		t.Fatal(err)
	}
	w := e.ScheduleType.Recurring.Weekly
	if len(w.MiscAttributes) != 1 || w.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("weekly unknown XML must survive a rebuild: %+v", w.MiscAttributes)
	}
	// A provided schedule_type is a wholesale rebuild: Monday (absent from the
	// input) is cleared, Tuesday is set.
	if len(w.Monday) != 0 {
		t.Fatalf("wholesale weekly rebuild must clear an unprovided day, got Monday=%v", w.Monday)
	}
	if len(w.Tuesday) != 1 {
		t.Fatalf("tuesday not set: %v", w.Tuesday)
	}
}
