package tools

import (
	"errors"
	"strings"
	"testing"

	dnscfg "github.com/PaloAltoNetworks/pango/device/services/dns"
	generalcfg "github.com/PaloAltoNetworks/pango/device/services/general"
	ntpcfg "github.com/PaloAltoNetworks/pango/device/services/ntp"
	proxycfg "github.com/PaloAltoNetworks/pango/device/services/proxy"
	panoserr "github.com/PaloAltoNetworks/pango/errors"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSingletonAbsentMatchesEmptyGet pins the two shapes isSingletonAbsent must
// treat as "not configured yet". The got-0 case is produced by driving a real
// pango singleton Read against a fake that returns an empty result, so a change
// to pango's wording fails here rather than silently making an unconfigured
// singleton error on get and update. A got-2 (more than one) must NOT match.
func TestSingletonAbsentMatchesEmptyGet(t *testing.T) {
	if !isSingletonAbsent(panoserr.ObjectNotFound()) {
		t.Error("PAN-OS code 7 must be treated as an absent singleton")
	}

	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
	)
	svc := dnscfg.NewService(d.Client)
	loc := dnscfg.Location{System: &dnscfg.SystemLocation{Device: defaultNgfwDevice}}
	_, err := svc.Read(t.Context(), loc, "get")
	if err == nil {
		t.Fatal("an empty result must make pango's singleton Read return an error")
	}
	if !isSingletonAbsent(err) {
		t.Fatalf("pango's empty-get error must be treated as absent, got: %v", err)
	}

	// A genuine "more than one" error is not absent and must surface.
	if isSingletonAbsent(errors.New(`expected to "get" 1 entry, got 2`)) {
		t.Fatal("a got-2 error must not be treated as absent")
	}
}

// --- system scope resolution -------------------------------------------------

func TestResolveSystemScope(t *testing.T) {
	parts := dnsSettingsParts()

	fw, _ := newTestDeps(t, "PA-VM")
	loc, err := resolveSystemScope(fw, SystemScopeInput{}, parts)
	if err != nil {
		t.Fatalf("firewall bare scope: %v", err)
	}
	if loc.System == nil {
		t.Fatal("firewall bare scope must resolve to the System location")
	}
	if _, err := resolveSystemScope(fw, SystemScopeInput{Template: "t1"}, parts); err == nil {
		t.Fatal("template on a firewall must be rejected")
	}

	pano, _ := newTestDeps(t, "Panorama")
	if _, err := resolveSystemScope(pano, SystemScopeInput{}, parts); err == nil {
		t.Fatal("Panorama with no template/template_stack must be rejected")
	}
	loc, err = resolveSystemScope(pano, SystemScopeInput{Template: "t1"}, parts)
	if err != nil || loc.Template == nil {
		t.Fatalf("Panorama template scope: loc=%+v err=%v", loc, err)
	}
	loc, err = resolveSystemScope(pano, SystemScopeInput{TemplateStack: "s1"}, parts)
	if err != nil || loc.TemplateStack == nil {
		t.Fatalf("Panorama template_stack scope: loc=%+v err=%v", loc, err)
	}
	if _, err := resolveSystemScope(pano, SystemScopeInput{Template: "t1", TemplateStack: "s1"}, parts); err == nil {
		t.Fatal("naming both template and template_stack must be rejected")
	}
}

// --- general settings --------------------------------------------------------

func TestGeneralSettingsOverlayAndSummary(t *testing.T) {
	c := &generalcfg.Config{}
	if err := overlayGeneralSettings(c, GeneralSettingsInput{
		Hostname:     new("fw1"),
		Domain:       new("example.com"),
		Timezone:     new("Europe/Helsinki"),
		GeoLatitude:  new("60.1"),
		GeoLongitude: new("24.9"),
	}); err != nil {
		t.Fatal(err)
	}
	mustStrPtr(t, c.Hostname, "fw1", "hostname")
	mustStrPtr(t, c.Domain, "example.com", "domain")
	mustStrPtr(t, c.Timezone, "Europe/Helsinki", "timezone")
	if c.GeoLocation == nil {
		t.Fatal("geo fields must allocate GeoLocation")
	}
	mustStrPtr(t, c.GeoLocation.Latitude, "60.1", "geo latitude")

	m := asMap(t, generalSettingsSummary(c))
	if m["hostname"] != "fw1" || m["geo_latitude"] != "60.1" {
		t.Fatalf("summary wrong: %v", m)
	}
	// Geo omitted leaves the pointer nil and the summary reports empty strings.
	c2 := &generalcfg.Config{Hostname: new("fw2")}
	m2 := asMap(t, generalSettingsSummary(c2))
	if m2["geo_latitude"] != "" || m2["geo_longitude"] != "" {
		t.Fatalf("absent geo must summarize as empty, got %v", m2)
	}
}

// --- NTP settings: nested allocation, secret omission ------------------------

func TestNtpSettingsOverlayAllocatesNested(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{PrimaryNtpServer: new("10.0.0.1"), SecondaryNtpServer: new("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	if c.NtpServers == nil || c.NtpServers.PrimaryNtpServer == nil || c.NtpServers.SecondaryNtpServer == nil {
		t.Fatalf("overlay must allocate the nested NtpServers tree, got %+v", c.NtpServers)
	}
	mustStrPtr(t, c.NtpServers.PrimaryNtpServer.NtpServerAddress, "10.0.0.1", "primary ntp address")
	mustStrPtr(t, c.NtpServers.SecondaryNtpServer.NtpServerAddress, "10.0.0.2", "secondary ntp address")
}

// TestNtpSettingsSummaryOmitsKeys pins that the summary reports auth as a bool
// and never surfaces key material read back from the device.
func TestNtpSettingsSummaryOmitsKeys(t *testing.T) {
	c := &ntpcfg.Config{NtpServers: &ntpcfg.NtpServers{
		PrimaryNtpServer: &ntpcfg.NtpServersPrimaryNtpServer{
			NtpServerAddress:   new("10.0.0.1"),
			AuthenticationType: &ntpcfg.NtpServersPrimaryNtpServerAuthenticationType{},
		},
	}}
	m := asMap(t, ntpSettingsSummary(c))
	if m["primary_ntp_server"] != "10.0.0.1" {
		t.Fatalf("primary address wrong: %v", m["primary_ntp_server"])
	}
	if m["primary_auth_configured"] != true {
		t.Fatalf("primary_auth_configured should be true when auth is set, got %v", m["primary_auth_configured"])
	}
	if m["secondary_auth_configured"] != false {
		t.Fatalf("secondary_auth_configured should be false, got %v", m["secondary_auth_configured"])
	}
	// The summary carries no field named like a key or password.
	for k := range m {
		if strings.Contains(k, "key") || strings.Contains(k, "password") {
			t.Fatalf("ntp summary must not expose a key/password field, found %q", k)
		}
	}
}

// --- proxy settings: password omission ---------------------------------------

func TestProxySettingsSummaryOmitsPassword(t *testing.T) {
	c := &proxycfg.Config{
		SecureProxyServer:   new("proxy.example.com"),
		SecureProxyPort:     new(int64(8080)),
		SecureProxyUser:     new("puser"),
		SecureProxyPassword: new("PROXYPWLEAK"),
		LcaasUseProxy:       new(true),
	}
	m := asMap(t, proxySettingsSummary(c))
	if m["secure_proxy_server"] != "proxy.example.com" || m["secure_proxy_user"] != "puser" {
		t.Fatalf("summary scalars wrong: %v", m)
	}
	if m["secure_proxy_port"] != int64(8080) || m["lcaas_use_proxy"] != true {
		t.Fatalf("summary port/flag wrong: %v", m)
	}
	if m["has_password"] != true {
		t.Fatalf("has_password should be true, got %v", m["has_password"])
	}
	assertNoLeak(t, m, "PROXYPWLEAK")
}

// --- DNS settings ------------------------------------------------------------

func TestDnsSettingsOverlayAndSummary(t *testing.T) {
	c := &dnscfg.Config{}
	if err := overlayDnsSettings(c, DnsSettingsInput{
		PrimaryDnsServer:   new("8.8.8.8"),
		SecondaryDnsServer: new("8.8.4.4"),
		FqdnRefreshTime:    new(int64(1800)),
	}); err != nil {
		t.Fatal(err)
	}
	if c.DnsSetting == nil || c.DnsSetting.Servers == nil {
		t.Fatalf("overlay must allocate DnsSetting.Servers, got %+v", c.DnsSetting)
	}
	mustStrPtr(t, c.DnsSetting.Servers.Primary, "8.8.8.8", "primary dns")
	mustInt64(t, c.FqdnRefreshTime, 1800, "fqdn refresh")

	m := asMap(t, dnsSettingsSummary(c))
	if m["primary_dns_server"] != "8.8.8.8" || m["secondary_dns_server"] != "8.8.4.4" {
		t.Fatalf("summary wrong: %v", m)
	}
	if m["fqdn_refresh_time"] != int64(1800) {
		t.Fatalf("summary fqdn_refresh_time wrong: %v", m["fqdn_refresh_time"])
	}
}

// --- read-only gating: get is read-only, update is write ---------------------

func TestSystemServiceReadOnlyGating(t *testing.T) {
	cases := []struct {
		base     string
		register func(*mcp.Server, *Deps)
	}{
		{"panos_dns_settings", RegisterDnsSettingsTools},
		{"panos_ntp_settings", RegisterNtpSettingsTools},
		{"panos_general_settings", RegisterGeneralSettingsTools},
		{"panos_proxy_settings", RegisterProxySettingsTools},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			assertReadOnlyGating(t, c.register,
				[]string{c.base + "_get"},
				[]string{c.base + "_update"})
		})
	}
}

// TestSingletonGetReturnsEmptyWhenAbsent drives a *_settings_get tool against a
// device with the setting unconfigured (the config get returns an empty result,
// pango's "got 0"): systemGetHandler must report an empty config, NOT surface
// the device error.
// Sabotage: delete `cfg = new(C)` in systemGetHandler and the empty read panics
// or surfaces an error instead of the empty summary.
func TestSingletonGetReturnsEmptyWhenAbsent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterGeneralSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_general_settings_get", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("an unconfigured singleton get must not be an error: %s", textContent(t, res))
	}
	text := textContent(t, res)
	if !strings.Contains(text, `"hostname": ""`) {
		t.Fatalf("absent config must summarize with empty fields, got: %s", text)
	}
}

// TestSingletonUpdateCreatesWhenAbsent pins the upsert branch: when the seed
// read finds no config node, the write goes through Create (a "set"), not
// Update (which pango implements with an "edit" preceded by its own read that
// would fail on the absent node). The fake returns distinct markers per action
// so the error identifies which path ran.
// Sabotage: force the handler to always call svc.Update and this turns red with
// the got-0 error from Update's internal read.
func TestSingletonUpdateCreatesWhenAbsent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>CREATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterGeneralSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_general_settings_update", Arguments: map[string]any{
		"hostname": "fw-new",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("the write must surface as a tool error in this fixture")
	}
	text := textContent(t, res)
	if !strings.Contains(text, "CREATE-PATH-MARKER") {
		t.Fatalf("absent node must be written via Create (set); got: %s", text)
	}
	if strings.Contains(text, "UPDATE-PATH-MARKER") {
		t.Fatalf("absent node must not go through Update; got: %s", text)
	}
}
