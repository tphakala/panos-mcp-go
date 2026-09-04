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
	// A nil error is not "absent" and must not panic (the helper is called only
	// under `err != nil` today, but stays nil-safe like isObjectNotFound).
	if isSingletonAbsent(nil) {
		t.Error("a nil error must not be treated as absent")
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

// TestNtpSettingsSymmetricKeyOverlay pins the nested symmetric-key tree the
// overlay builds for each server: the primary as md5, the secondary as sha1, with
// key_id and the write-only key set on the correct algorithm node. Sabotage:
// write in.AuthenticationKey to the wrong algorithm node in applyNtpPrimaryAuth.
func TestNtpSettingsSymmetricKeyOverlay(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimaryNtpServer:      new("10.0.0.1"),
		PrimarySymmetricKey:   &NtpSymmetricKeyInput{KeyId: new(int64(7)), Algorithm: new("md5"), AuthenticationKey: new("PRIMKEY")},
		SecondaryNtpServer:    new("10.0.0.2"),
		SecondarySymmetricKey: &NtpSymmetricKeyInput{KeyId: new(int64(9)), Algorithm: new("sha1"), AuthenticationKey: new("SECKEY")},
	}); err != nil {
		t.Fatal(err)
	}
	p := c.NtpServers.PrimaryNtpServer.AuthenticationType
	if p == nil || p.SymmetricKey == nil || p.SymmetricKey.Algorithm == nil || p.SymmetricKey.Algorithm.Md5 == nil {
		t.Fatalf("primary must build the md5 symmetric-key tree, got %+v", p)
	}
	if p.SymmetricKey.Algorithm.Sha1 != nil {
		t.Fatal("primary md5 must leave the sha1 node nil")
	}
	mustInt64(t, p.SymmetricKey.KeyId, 7, "primary key_id")
	mustStrPtr(t, p.SymmetricKey.Algorithm.Md5.AuthenticationKey, "PRIMKEY", "primary md5 key")

	sec := c.NtpServers.SecondaryNtpServer.AuthenticationType
	if sec == nil || sec.SymmetricKey == nil || sec.SymmetricKey.Algorithm == nil || sec.SymmetricKey.Algorithm.Sha1 == nil {
		t.Fatalf("secondary must build the sha1 symmetric-key tree, got %+v", sec)
	}
	mustStrPtr(t, sec.SymmetricKey.Algorithm.Sha1.AuthenticationKey, "SECKEY", "secondary sha1 key")
}

// TestNtpSettingsAuthTypeMutualExclusion pins that setting a symmetric key clears
// a previously-configured autokey/none on that server: AuthenticationType is a
// one-of, so leaving both marshals invalid XML the device rejects. Sabotage:
// remove `at.Autokey = nil` from applyNtpPrimaryAuth.
func TestNtpSettingsAuthTypeMutualExclusion(t *testing.T) {
	c := &ntpcfg.Config{NtpServers: &ntpcfg.NtpServers{
		PrimaryNtpServer: &ntpcfg.NtpServersPrimaryNtpServer{
			AuthenticationType: &ntpcfg.NtpServersPrimaryNtpServerAuthenticationType{
				Autokey: &ntpcfg.NtpServersPrimaryNtpServerAuthenticationTypeAutokey{},
			},
		},
	}}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5"), AuthenticationKey: new("K")},
	}); err != nil {
		t.Fatal(err)
	}
	at := c.NtpServers.PrimaryNtpServer.AuthenticationType
	if at.Autokey != nil {
		t.Fatal("setting a symmetric key must clear the previous autokey")
	}
	if at.SymmetricKey == nil {
		t.Fatal("symmetric key must be set")
	}
}

// TestNtpSettingsAlgorithmSwitchClearsSibling pins that switching md5 -> sha1
// clears the md5 node so the config never carries both algorithms. Sabotage:
// remove `alg.Md5 = nil` from the sha1 branch of applyNtpPrimaryAuth.
func TestNtpSettingsAlgorithmSwitchClearsSibling(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5"), AuthenticationKey: new("MD5KEY")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("sha1"), AuthenticationKey: new("SHA1KEY")},
	}); err != nil {
		t.Fatal(err)
	}
	alg := c.NtpServers.PrimaryNtpServer.AuthenticationType.SymmetricKey.Algorithm
	if alg.Md5 != nil {
		t.Fatal("switching to sha1 must clear the md5 node")
	}
	mustStrPtr(t, alg.Sha1.AuthenticationKey, "SHA1KEY", "sha1 key after switch")
}

// TestNtpSettingsAuthKeyPreservedOnUpdate pins the read-modify-write on the auth
// key: a same-algorithm update that omits authentication_key keeps the stored
// key. Sabotage: assign in.AuthenticationKey unconditionally instead of setPtr.
func TestNtpSettingsAuthKeyPreservedOnUpdate(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{KeyId: new(int64(1)), Algorithm: new("md5"), AuthenticationKey: new("STOREDKEY")},
	}); err != nil {
		t.Fatal(err)
	}
	// Update the key_id only, omitting the key.
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{KeyId: new(int64(2)), Algorithm: new("md5")},
	}); err != nil {
		t.Fatal(err)
	}
	sk := c.NtpServers.PrimaryNtpServer.AuthenticationType.SymmetricKey
	mustInt64(t, sk.KeyId, 2, "updated key_id")
	mustStrPtr(t, sk.Algorithm.Md5.AuthenticationKey, "STOREDKEY", "stored key preserved")
}

// TestNtpSettingsAlgorithmValidation pins that a symmetric-key block needs a valid
// algorithm. Sabotage: delete the validate calls in overlayNtpSettings.
func TestNtpSettingsAlgorithmValidation(t *testing.T) {
	if err := overlayNtpSettings(&ntpcfg.Config{}, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{AuthenticationKey: new("K")},
	}); err == nil {
		t.Fatal("a symmetric key without an algorithm must be rejected")
	}
	if err := overlayNtpSettings(&ntpcfg.Config{}, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("sha256"), AuthenticationKey: new("K")},
	}); err == nil {
		t.Fatal("an unsupported algorithm must be rejected")
	}
}

// TestNtpSettingsAuthKeyRequiredOnSetAndChange pins that a symmetric key set for
// the first time, or an algorithm switch, must supply authentication_key: a fresh
// algorithm node has no stored key and PAN-OS rejects keyless symmetric auth. An
// omitted key is allowed only when the algorithm is unchanged (the stored key is
// preserved). Sabotage: drop the `fresh && in.AuthenticationKey == nil` guard in
// applyNtpPrimaryAuth/applyNtpSecondaryAuth and the reject subtests turn green.
func TestNtpSettingsAuthKeyRequiredOnSetAndChange(t *testing.T) {
	// First-time set with no key: rejected.
	if err := overlayNtpSettings(&ntpcfg.Config{}, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5")},
	}); err == nil {
		t.Fatal("setting a symmetric key for the first time without authentication_key must be rejected")
	}
	// Algorithm switch (md5 -> sha1) with no key: rejected, on the primary server.
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5"), AuthenticationKey: new("MD5KEY")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("sha1")}, // no key on the switch
	}); err == nil {
		t.Fatal("switching the primary algorithm without authentication_key must be rejected")
	}
	// Same for the secondary server's distinct type tree.
	sc := &ntpcfg.Config{}
	if err := overlayNtpSettings(sc, NtpSettingsInput{
		SecondarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("sha1"), AuthenticationKey: new("SHA1KEY")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := overlayNtpSettings(sc, NtpSettingsInput{
		SecondarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5")}, // no key on the switch
	}); err == nil {
		t.Fatal("switching the secondary algorithm without authentication_key must be rejected")
	}
	// Same-algorithm update with the key omitted is allowed (key preserved).
	pc := &ntpcfg.Config{}
	if err := overlayNtpSettings(pc, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5"), AuthenticationKey: new("STORED")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := overlayNtpSettings(pc, NtpSettingsInput{
		PrimarySymmetricKey: &NtpSymmetricKeyInput{Algorithm: new("md5"), KeyId: new(int64(3))},
	}); err != nil {
		t.Fatalf("a same-algorithm update omitting the key must be allowed: %v", err)
	}
	mustStrPtr(t, pc.NtpServers.PrimaryNtpServer.AuthenticationType.SymmetricKey.Algorithm.Md5.AuthenticationKey,
		"STORED", "same-algorithm update preserves the stored key")
}

// TestNtpSettingsSummaryReportsSymmetricKey pins that the summary reports the
// symmetric-key algorithm and key_id but never the key material. Sabotage: emit
// the AuthenticationKey in ntpPrimaryAuthSummary.
func TestNtpSettingsSummaryReportsSymmetricKey(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		PrimaryNtpServer:    new("10.0.0.1"),
		PrimarySymmetricKey: &NtpSymmetricKeyInput{KeyId: new(int64(5)), Algorithm: new("md5"), AuthenticationKey: new("SUMMARYKEYLEAK")},
	}); err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ntpSettingsSummary(c))
	if m["primary_auth_configured"] != true {
		t.Fatalf("primary_auth_configured must be true, got %v", m["primary_auth_configured"])
	}
	auth := asMap(t, m["primary_auth"])
	if auth["type"] != "symmetric-key" || auth["algorithm"] != "md5" {
		t.Fatalf("primary_auth type/algorithm wrong: %v", auth)
	}
	if auth["key_id"] != int64(5) {
		t.Fatalf("primary_auth key_id wrong: %v", auth["key_id"])
	}
	assertNoLeak(t, m, "SUMMARYKEYLEAK")
}

// TestNtpSettingsUpdateRedactsAuthKeyOnError drives panos_ntp_settings_update
// through the registered handler: the device rejects the write with an error
// echoing the submitted authentication key, and the tool result must not carry
// it. Sabotage: remove withSecrets(ntpSettingsSecrets) from the
// panos_ntp_settings_update registration; this test turns red.
func TestNtpSettingsUpdateRedactsAuthKeyOnError(t *testing.T) {
	const key = "NTP-AUTH-KEY-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><ntp-servers/></result></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for key ` + key + `</line></msg></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for key ` + key + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterNtpSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_ntp_settings_update", Arguments: map[string]any{
			"primary_ntp_server":    "10.0.0.1",
			"primary_symmetric_key": map[string]any{"algorithm": "md5", "authentication_key": key},
		},
	})
	assertRedactsSecret(t, res, err, key)
}

// TestNtpSettingsBadAlgorithmNoLeak pins that the client-side algorithm-validation
// error (returned from the overlay, bypassing the device-error redactor) does not
// echo the submitted key. Sabotage: interpolate in.AuthenticationKey into the
// validateNtpSymmetricKey error message.
func TestNtpSettingsBadAlgorithmNoLeak(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><ntp-servers/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterNtpSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_ntp_settings_update", Arguments: map[string]any{
			"primary_symmetric_key": map[string]any{"algorithm": "bogus", "authentication_key": "NTPKEYLEAK"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a bad algorithm must surface as a tool error")
	}
	if out := textContent(t, res); strings.Contains(out, "NTPKEYLEAK") {
		t.Fatalf("a validation error must not echo the submitted key: %q", out)
	}
}

// TestNtpSettingsSummaryReportsSecondarySymmetricKey mirrors the primary-server
// summary guard for the SECONDARY server's symmetric-key projection (a distinct
// pango type tree, so it needs its own coverage). Sabotage: emit the key in
// ntpSecondaryAuthSummary.
func TestNtpSettingsSummaryReportsSecondarySymmetricKey(t *testing.T) {
	c := &ntpcfg.Config{}
	if err := overlayNtpSettings(c, NtpSettingsInput{
		SecondaryNtpServer:    new("10.0.0.2"),
		SecondarySymmetricKey: &NtpSymmetricKeyInput{KeyId: new(int64(6)), Algorithm: new("sha1"), AuthenticationKey: new("SECSUMMARYLEAK")},
	}); err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ntpSettingsSummary(c))
	if m["secondary_auth_configured"] != true {
		t.Fatalf("secondary_auth_configured must be true, got %v", m["secondary_auth_configured"])
	}
	auth := asMap(t, m["secondary_auth"])
	if auth["type"] != "symmetric-key" || auth["algorithm"] != "sha1" {
		t.Fatalf("secondary_auth type/algorithm wrong: %v", auth)
	}
	if auth["key_id"] != int64(6) {
		t.Fatalf("secondary_auth key_id wrong: %v", auth["key_id"])
	}
	assertNoLeak(t, m, "SECSUMMARYLEAK")
}

// TestNtpSettingsUpdateRedactsSecondaryAuthKeyOnError pins that the SECONDARY
// server's auth key is scrubbed from a device error too: ntpSettingsSecrets
// appends both servers' keys. Sabotage: drop the SecondarySymmetricKey append in
// ntpSettingsSecrets and this key leaks through the device error.
func TestNtpSettingsUpdateRedactsSecondaryAuthKeyOnError(t *testing.T) {
	const key = "NTP-SECONDARY-KEY-xyz789"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><ntp-servers/></result></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for key ` + key + `</line></msg></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for key ` + key + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterNtpSettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_ntp_settings_update", Arguments: map[string]any{
			"secondary_ntp_server":    "10.0.0.2",
			"secondary_symmetric_key": map[string]any{"algorithm": "sha1", "authentication_key": key},
		},
	})
	assertRedactsSecret(t, res, err, key)
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

// TestSingletonUpdateUsesUpdateWhenPresent is the twin of the absent case: when
// the seed read finds an existing config node, the write must go through Update
// (an "edit"/"multi-config"), not Create (a "set"). The seed get returns one
// populated <system> entry so isSingletonAbsent is false; the per-action markers
// identify which write path ran.
// Sabotage: force the handler to always call svc.Create and this turns red with
// the CREATE-PATH-MARKER.
func TestSingletonUpdateUsesUpdateWhenPresent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><system><hostname>oldfw</hostname></system></result></response>`},
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
	if !strings.Contains(text, "UPDATE-PATH-MARKER") {
		t.Fatalf("a present node must be written via Update (edit); got: %s", text)
	}
	if strings.Contains(text, "CREATE-PATH-MARKER") {
		t.Fatalf("a present node must not go through Create; got: %s", text)
	}
}
