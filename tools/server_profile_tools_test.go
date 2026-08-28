package tools

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/profiles/email"
	"github.com/PaloAltoNetworks/pango/device/profiles/ldap"
	"github.com/PaloAltoNetworks/pango/device/profiles/radius"
	"github.com/PaloAltoNetworks/pango/device/profiles/snmptrap"
	"github.com/PaloAltoNetworks/pango/device/profiles/syslog"
	"github.com/PaloAltoNetworks/pango/device/profiles/tacacsplus"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertNoSecretLeak walks a summary map (including nested []any of maps) and
// fails if any string value contains one of the given secrets. This is the
// guard that the write-only secret fields never surface in a get/list
// projection. It matches by containment rather than equality so a secret
// embedded in a larger string ("keytab=" + value) is caught too; see
// TestAssertNoSecretLeakSkipsEmptyNeedle for why an empty secret is skipped.
// nonEmptyNeedles drops the empty strings from ss. strings.Contains reports
// true for "" against every string, so an unset optional secret reaching a
// containment check would match every value and the failure would read as a
// leak rather than as a bad call.
func nonEmptyNeedles(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func assertNoSecretLeak(t *testing.T, m map[string]any, secrets ...string) {
	t.Helper()
	needles := nonEmptyNeedles(secrets)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, s := range needles {
				if strings.Contains(x, s) {
					t.Fatalf("secret %q leaked into the summary", s)
				}
			}
		case map[string]any:
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		case []string:
			// Guard fails closed: a future summary that projects a secret inside a
			// []string (via strList) is still caught.
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(m)
}

// TestAssertNoSecretLeakSkipsEmptyNeedle pins the empty-needle guard in
// assertNoSecretLeak. strings.Contains reports true for "" against every
// string, so without the guard an unset optional secret reaching the helper
// would fail every summary unconditionally, and the failure would read as a
// leak rather than as a bad call. Sabotage: delete the `if s == ""` continue in
// assertNoSecretLeak and the first subtest turns red.
func TestAssertNoSecretLeakSkipsEmptyNeedle(t *testing.T) {
	m := map[string]any{"name": "p1", "servers": []any{map[string]any{"address": "10.0.0.1"}}}

	t.Run("an empty needle matches nothing", func(t *testing.T) {
		assertNoSecretLeak(t, m, "")
	})

	// The guard must not weaken the real check: a non-empty needle that is
	// genuinely embedded in a larger value still has to fail. Sabotage: change
	// strings.Contains back to an equality comparison and this turns red.
	t.Run("a non-empty needle is still matched by containment", func(t *testing.T) {
		leaky := map[string]any{"address": "host=10.0.0.1;key=TOPSECRET"}
		fake := &testing.T{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			assertNoSecretLeak(fake, leaky, "TOPSECRET")
		}()
		<-done
		if !fake.Failed() {
			t.Fatal("an embedded secret must still be caught by containment")
		}
	})
}

// --- LDAP ---------------------------------------------------------------------

// TestLdapProfileBuildAndSummary pins the field mapping (including a per-server
// address/port and the write-only bind password) and the summary projection:
// has_bind_password reports presence, and the raw password never appears.
// Sabotage: dropping setPtr(&e.BindPassword, ...) fails the build subcheck;
// echoing the password in the summary fails assertNoSecretLeak.
func TestLdapProfileBuildAndSummary(t *testing.T) {
	e, err := buildLdapProfile(LdapProfileInput{
		Name: "ad", Base: new("dc=example"), BindDn: new("cn=svc"), BindPassword: new("s3cret"),
		Ssl: new(true), Timelimit: new(int64(30)),
		Servers: []LdapServerInput{{Name: "s1", Address: new("10.0.0.1"), Port: new(int64(636))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.BindPassword == nil || *e.BindPassword != "s3cret" {
		t.Fatalf("bind_password must map to Entry.BindPassword: %v", e.BindPassword)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s1" || e.Server[0].Address == nil || *e.Server[0].Address != "10.0.0.1" || e.Server[0].Port == nil || *e.Server[0].Port != 636 {
		t.Fatalf("server not mapped: %+v", e.Server)
	}
	if _, err := buildLdapProfile(LdapProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}

	m := asMap(t, ldapProfileSummary(&ldap.Entry{
		Name: "ad", Base: new("dc=example"), BindPassword: new("s3cret"),
		Server: []ldap.Server{{Name: "s1", Address: new("10.0.0.1"), Port: new(int64(636))}},
	}))
	if m["has_bind_password"] != true {
		t.Fatalf("has_bind_password must be true when a password is set: %v", m["has_bind_password"])
	}
	assertNoSecretLeak(t, m, "s3cret")
	// Absent password reports false.
	m2 := asMap(t, ldapProfileSummary(&ldap.Entry{Name: "ad"}))
	if m2["has_bind_password"] != false {
		t.Fatalf("has_bind_password must be false when unset: %v", m2["has_bind_password"])
	}
}

// --- TACACS+ ------------------------------------------------------------------

// TestTacacsProfileBuildAndSummary pins the per-server write-only secret: it maps
// onto Server[].Secret and the summary reports has_secret without the value.
func TestTacacsProfileBuildAndSummary(t *testing.T) {
	e, err := buildTacacsProfile(TacacsProfileInput{
		Name: "tac", Protocol: new("PAP"),
		Servers: []TacacsServerInput{{Name: "s1", Address: new("10.0.0.1"), Secret: new("topsecret"), Port: new(int64(49))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Secret == nil || *e.Server[0].Secret != "topsecret" {
		t.Fatalf("server secret not mapped: %+v", e.Server)
	}
	m := asMap(t, tacacsProfileSummary(&tacacsplus.Entry{
		Name: "tac", Protocol: new("PAP"),
		Server: []tacacsplus.Server{{Name: "s1", Address: new("10.0.0.1"), Secret: new("topsecret")}},
	}))
	servers, ok := m["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers projection wrong: %v", m["servers"])
	}
	sm, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("server entry is not a map: %T", servers[0])
	}
	if sm["has_secret"] != true {
		t.Fatalf("has_secret must be true: %v", sm)
	}
	assertNoSecretLeak(t, m, "topsecret")
}

// --- RADIUS -------------------------------------------------------------------

// TestRadiusProfileBuildAndSummary pins the RADIUS server IpAddress/Secret
// mapping and the has_secret projection, and that the unmanaged Protocol subtree
// is reported via has_protocol without leaking anything.
func TestRadiusProfileBuildAndSummary(t *testing.T) {
	e, err := buildRadiusProfile(RadiusProfileInput{
		Name: "rad", Timeout: new(int64(3)),
		Servers: []RadiusServerInput{{Name: "s1", IpAddress: new("10.0.0.2"), Secret: new("radsecret"), Port: new(int64(1812))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].IpAddress == nil || *e.Server[0].IpAddress != "10.0.0.2" || e.Server[0].Secret == nil || *e.Server[0].Secret != "radsecret" {
		t.Fatalf("radius server not mapped: %+v", e.Server)
	}
	m := asMap(t, radiusProfileSummary(&radius.Entry{
		Name:   "rad",
		Server: []radius.Server{{Name: "s1", IpAddress: new("10.0.0.2"), Secret: new("radsecret")}},
	}))
	if m["has_protocol"] != false {
		t.Fatalf("has_protocol must be false when the subtree is unset: %v", m["has_protocol"])
	}
	assertNoSecretLeak(t, m, "radsecret")
}

// --- SNMP trap: the v2c/v3 one-of ---------------------------------------------

// TestSnmpTrapProfileBuildBranches pins the mutually-exclusive version model on
// create: building v2c populates only the v2c branch (and maps the community),
// building v3 populates only the v3 branch, an empty version is rejected, and an
// invalid version is rejected.
func TestSnmpTrapProfileBuildBranches(t *testing.T) {
	v2c, err := buildSnmpTrapProfile(SnmpTrapProfileInput{
		Name: "snmp", Version: "v2c",
		V2cServers: []SnmpV2cServerInput{{Name: "s1", Manager: new("10.0.0.3"), Community: new("public-secret")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2c.Version == nil || v2c.Version.V2c == nil || v2c.Version.V3 != nil {
		t.Fatalf("v2c build must set only the v2c branch: %+v", v2c.Version)
	}
	if len(v2c.Version.V2c.Server) != 1 || v2c.Version.V2c.Server[0].Community == nil || *v2c.Version.V2c.Server[0].Community != "public-secret" {
		t.Fatalf("v2c community not mapped: %+v", v2c.Version.V2c.Server)
	}

	v3, err := buildSnmpTrapProfile(SnmpTrapProfileInput{
		Name: "snmp", Version: "v3",
		V3Servers: []SnmpV3ServerInput{{Name: "s1", Manager: new("10.0.0.3"), User: new("u"), AuthPassword: new("authpw"), PrivPassword: new("privpw")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v3.Version == nil || v3.Version.V3 == nil || v3.Version.V2c != nil {
		t.Fatalf("v3 build must set only the v3 branch: %+v", v3.Version)
	}

	if _, err := buildSnmpTrapProfile(SnmpTrapProfileInput{Name: "snmp"}); err == nil {
		t.Fatal("create without a version must be rejected")
	}
	if _, err := buildSnmpTrapProfile(SnmpTrapProfileInput{Name: "snmp", Version: "v4"}); err == nil {
		t.Fatal("an invalid version must be rejected")
	}
}

// TestSnmpTrapProfileOverlayAndSummary pins the update-side branch handling:
// switching an existing v2c profile to v3 clears the v2c branch (so the entry
// never carries both subtrees), supplying v3_servers against a v2c profile is
// rejected, and the summary reports the version without leaking any secret.
func TestSnmpTrapProfileOverlayAndSummary(t *testing.T) {
	existing := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V2c: &snmptrap.VersionV2c{
		Server: []snmptrap.VersionV2cServer{{Name: "s1", Community: new("public-secret")}},
	}}}
	if err := overlaySnmpTrapProfile(existing, SnmpTrapProfileInput{Name: "snmp", Version: "v3"}); err != nil {
		t.Fatal(err)
	}
	if existing.Version.V2c != nil || existing.Version.V3 == nil {
		t.Fatalf("switching to v3 must clear the v2c branch: %+v", existing.Version)
	}

	v2cEntry := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V2c: &snmptrap.VersionV2c{}}}
	if err := overlaySnmpTrapProfile(v2cEntry, SnmpTrapProfileInput{Name: "snmp", V3Servers: []SnmpV3ServerInput{{Name: "s1"}}}); err == nil {
		t.Fatal("v3_servers with a v2c profile must be rejected")
	}

	e := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V3: &snmptrap.VersionV3{
		Server: []snmptrap.VersionV3Server{{Name: "s1", Authpwd: new("authpw"), Privpwd: new("privpw")}},
	}}}
	m := asMap(t, snmpTrapProfileSummary(e))
	if m["version"] != "v3" {
		t.Fatalf("summary version wrong: %v", m["version"])
	}
	assertNoSecretLeak(t, m, "authpw", "privpw", "public-secret")
}

// TestSnmpTrapProfileOverlaySameVersionReplacesReceivers pins that supplying a
// receiver list for the profile's already-active version replaces the list in
// place without switching branches, and that a supplied receiver sharing a
// stored name merges by name: an omitted community keeps the stored value.
// Sabotage: not replacing e.Version.V2c.Server in applySnmpTrapProfile leaves
// the old receivers and fails the replace assertion; neutralizing
// indexByName's seed in snmpV2cServers (an empty prev map) drops the
// preserved community and fails the merge assertion.
func TestSnmpTrapProfileOverlaySameVersionReplacesReceivers(t *testing.T) {
	e := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V2c: &snmptrap.VersionV2c{
		Server: []snmptrap.VersionV2cServer{
			{Name: "s1", Community: new("old")},
			{Name: "gone", Community: new("gone-secret")},
		},
	}}}
	if err := overlaySnmpTrapProfile(e, SnmpTrapProfileInput{
		Name: "snmp", Version: "v2c",
		V2cServers: []SnmpV2cServerInput{
			{Name: "s1", Manager: new("10.0.0.9")},
			{Name: "s2", Manager: new("10.0.0.10"), Community: new("new")},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if e.Version.V3 != nil {
		t.Fatalf("a same-version update must not create the other branch: %+v", e.Version)
	}
	if len(e.Version.V2c.Server) != 2 || e.Version.V2c.Server[0].Name != "s1" || e.Version.V2c.Server[1].Name != "s2" {
		t.Fatalf("v2c receivers must be replaced in place with exactly the supplied set: %+v", e.Version.V2c.Server)
	}
	mustStrPtr(t, e.Version.V2c.Server[0].Community, "old", "s1 omitted community must be preserved by name")
	mustStrPtr(t, e.Version.V2c.Server[1].Community, "new", "s2 supplied community")
}

// --- Email --------------------------------------------------------------------

// TestEmailProfileBuildAndSummary pins the SMTP server password as write-only.
func TestEmailProfileBuildAndSummary(t *testing.T) {
	e, err := buildEmailProfile(EmailProfileInput{
		Name:    "mail",
		Servers: []EmailServerInput{{Name: "s1", Gateway: new("smtp.example"), From: new("a@example"), To: new("b@example"), Password: new("smtppw")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Password == nil || *e.Server[0].Password != "smtppw" {
		t.Fatalf("email password not mapped: %+v", e.Server)
	}
	m := asMap(t, emailProfileSummary(&email.Entry{
		Name:   "mail",
		Server: []email.Server{{Name: "s1", Gateway: new("smtp.example"), Password: new("smtppw")}},
	}))
	assertNoSecretLeak(t, m, "smtppw")
	servers, ok := m["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers projection wrong: %v", m["servers"])
	}
	sm, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("server entry is not a map: %T", servers[0])
	}
	if sm["has_password"] != true {
		t.Fatalf("has_password must be true: %v", sm)
	}
}

// --- wire-level create xpath: server-profile vs log-settings nodes ------------

// TestServerProfileCreateXpath drives the create tool for an authentication
// profile (ldap -> server-profile/ldap) and a log-forwarding profile (syslog ->
// log-settings/syslog) on a firewall, asserting the set reaches the right config
// node. The node substrings are the sabotage anchors for location drift.
func TestServerProfileCreateXpath(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="p"/></result></response>`
	cases := []struct {
		name     string
		register func(*mcp.Server, *Deps)
		tool     string
		args     map[string]any
		want     []string
	}{
		{"ldap firewall vsys", RegisterLdapProfileTools, "panos_ldap_profile_create",
			map[string]any{"name": "p"}, []string{"server-profile", "ldap", "vsys"}},
		{"ldap panorama shared", RegisterLdapProfileTools, "panos_ldap_profile_create",
			map[string]any{"name": "p", "shared": true}, []string{"server-profile", "ldap", "shared"}},
		{"syslog firewall vsys", RegisterSyslogProfileTools, "panos_syslog_profile_create",
			map[string]any{"name": "p"}, []string{"log-settings", "syslog", "vsys"}},
		// The shared node measured on a live PA-VM (PAN-OS 11.2.6): an XML API get
		// of /config/shared/log-settings/syslog served a pre-existing profile. This
		// pins that this server now writes to that same node.
		{"syslog firewall shared", RegisterSyslogProfileTools, "panos_syslog_profile_create",
			map[string]any{"name": "p", "shared": true}, []string{"log-settings", "syslog", "shared"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			model := "PA-VM"
			if strings.Contains(c.name, "panorama") {
				model = "Panorama"
			}
			d, f := newTestDeps(t, model,
				fakeRoute{Match: configAction("set"), Body: configSuccessBody},
				fakeRoute{Match: configAction("get"), Body: entryBody},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			c.register(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
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

// --- device-scope gating through the registered handlers ----------------------

// TestServerProfileDeviceScopeGating pins resolveDeviceScope's routing through
// the registered handlers: a template on a firewall is rejected, a bare Panorama
// connection is rejected, and a shared request against a no-shared profile
// (email) is rejected on a firewall.
func TestServerProfileDeviceScopeGating(t *testing.T) {
	call := func(t *testing.T, model, register string, tool string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		d, f := newTestDeps(t, model)
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		switch register {
		case "ldap":
			RegisterLdapProfileTools(srv, d)
		case "syslog":
			RegisterSyslogProfileTools(srv, d)
		case "email":
			RegisterEmailProfileTools(srv, d)
		}
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

	t.Run("template on a firewall", func(t *testing.T) {
		res := call(t, "PA-VM", "ldap", "panos_ldap_profile_create", map[string]any{"name": "p", "template": "t1"})
		mustErr(t, res, "Panorama connection")
	})
	t.Run("panorama without scope", func(t *testing.T) {
		res := call(t, "Panorama", "ldap", "panos_ldap_profile_list", map[string]any{})
		mustErr(t, res, "template, template_stack, or shared")
	})
	t.Run("shared on a no-shared profile", func(t *testing.T) {
		// email, not syslog: pango models no shared location for email, while
		// syslog has one this server now exposes (see noSharedScopeProfiles).
		res := call(t, "PA-VM", "email", "panos_email_profile_create", map[string]any{"name": "p", "shared": true})
		mustErr(t, res, "shared scope is not available")
	})
}

// --- no-op update preserves the stored secret ---------------------------------

// TestLdapProfileNoOpUpdate proves an update supplying only the name issues no
// config write: the overlay leaves the read entry untouched, so pango's
// SpecMatches short-circuits. In particular an omitted bind_password is kept and
// an omitted servers list is not replaced. Sabotage: replacing e.Server
// unconditionally in applyLdapProfile forces a write and trips assertNoConfigWrite.
func TestLdapProfileNoOpUpdate(t *testing.T) {
	current := `<response status="success"><result><entry name="ad">` +
		`<server><entry name="s1"><address>10.0.0.1</address></entry></server></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_update", Arguments: map[string]any{"name": "ad"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

// --- single-wrap guard --------------------------------------------------------

// TestLdapProfileSingleWrappedGet proves the nameFixAdapter wraps the get name
// into an entry xpath exactly once, guarding against a double-wrap on a pango
// upgrade.
func TestLdapProfileSingleWrappedGet(t *testing.T) {
	entryBody := `<response status="success"><result><entry name="ad"/></result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: entryBody})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_get", Arguments: map[string]any{"name": "ad"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("get failed: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "ad")
}

// --- read-only gating ---------------------------------------------------------

func TestServerProfileReadOnlyGating(t *testing.T) {
	for _, c := range []struct {
		base     string
		register func(*mcp.Server, *Deps)
	}{
		{"panos_ldap_profile", RegisterLdapProfileTools},
		{"panos_tacacs_profile", RegisterTacacsProfileTools},
		{"panos_radius_profile", RegisterRadiusProfileTools},
		{"panos_syslog_profile", RegisterSyslogProfileTools},
		{"panos_snmptrap_profile", RegisterSnmpTrapProfileTools},
		{"panos_email_profile", RegisterEmailProfileTools},
	} {
		t.Run(c.base, func(t *testing.T) {
			assertReadOnlyGating(t, c.register,
				[]string{c.base + "_list", c.base + "_get"},
				[]string{c.base + "_create", c.base + "_update", c.base + "_delete"})
		})
	}
}

// TestSnmpTrapProfileV2cSummaryNoLeak pins the v2c summary path specifically:
// snmpV2cServerSummaries must report has_community and NEVER the community value.
// (The sibling overlay test builds only a v3 entry, so this is the only test that
// exercises the v2c projection.) Sabotage: echoing s.Community in
// snmpV2cServerSummaries trips assertNoSecretLeak.
func TestSnmpTrapProfileV2cSummaryNoLeak(t *testing.T) {
	e := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V2c: &snmptrap.VersionV2c{
		Server: []snmptrap.VersionV2cServer{{Name: "s1", Manager: new("10.0.0.3"), Community: new("public-secret")}},
	}}}
	m := asMap(t, snmpTrapProfileSummary(e))
	if m["version"] != "v2c" {
		t.Fatalf("summary version wrong: %v", m["version"])
	}
	servers, ok := m["v2c_servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("v2c_servers projection wrong: %v", m["v2c_servers"])
	}
	sm, ok := servers[0].(map[string]any)
	if !ok || sm["has_community"] != true {
		t.Fatalf("has_community must be true: %v", servers[0])
	}
	assertNoSecretLeak(t, m, "public-secret")
}

// TestSyslogProfileBuildAndSummary pins the syslog server field mapping and its
// projection (no secret on a syslog server). Sabotage: dropping the setPtr for
// Server, Transport, or Facility in syslogServers fails a build subcheck.
func TestSyslogProfileBuildAndSummary(t *testing.T) {
	e, err := buildSyslogProfile(SyslogProfileInput{
		Name:    "sl",
		Servers: []SyslogServerInput{{Name: "s1", Server: new("10.0.0.9"), Transport: new("UDP"), Port: new(int64(514)), Format: new("BSD"), Facility: new("LOG_USER")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 {
		t.Fatalf("expected one server, got %+v", e.Server)
	}
	mustStrPtr(t, e.Server[0].Server, "10.0.0.9", "server -> Server.Server")
	mustStrPtr(t, e.Server[0].Transport, "UDP", "transport -> Server.Transport")
	mustStrPtr(t, e.Server[0].Facility, "LOG_USER", "facility -> Server.Facility")
	if _, err := buildSyslogProfile(SyslogProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}

	m := asMap(t, syslogProfileSummary(&syslog.Entry{
		Name:   "sl",
		Server: []syslog.Server{{Name: "s1", Server: new("10.0.0.9"), Transport: new("UDP"), Facility: new("LOG_USER")}},
	}))
	servers, ok := m["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers projection wrong: %v", m["servers"])
	}
	sm, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("server entry is not a map: %T", servers[0])
	}
	if sm["server"] != "10.0.0.9" || sm["transport"] != "UDP" || sm["facility"] != "LOG_USER" {
		t.Fatalf("syslog server summary wrong: %v", sm)
	}
}

// TestTacacsProfileOverlayReplaceAndPreserve pins the update contract for a
// secret-bearing family: an overlay providing nothing preserves the stored
// servers (and their secrets) and scalar fields; an overlay providing a servers
// list merges by name, so a server absent from the list is removed. Sabotage:
// replacing e.Server unconditionally in applyTacacsProfile fails the preserve
// case; not merging when provided fails the removal case.
func TestTacacsProfileOverlayReplaceAndPreserve(t *testing.T) {
	e := &tacacsplus.Entry{
		Name: "tac", Protocol: new("PAP"),
		Server: []tacacsplus.Server{{Name: "s1", Address: new("10.0.0.1"), Secret: new("stored")}},
	}
	if err := overlayTacacsProfile(e, TacacsProfileInput{Name: "tac"}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Secret == nil || *e.Server[0].Secret != "stored" || e.Protocol == nil || *e.Protocol != "PAP" {
		t.Fatalf("omitted fields must be preserved on overlay: %+v", e)
	}
	if err := overlayTacacsProfile(e, TacacsProfileInput{Name: "tac", Servers: []TacacsServerInput{{Name: "s2", Address: new("10.0.0.2"), Secret: new("fresh")}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s2" || e.Server[0].Secret == nil || *e.Server[0].Secret != "fresh" {
		t.Fatalf("a server absent from the provided list must be removed: %+v", e.Server)
	}
}

// TestTacacsProfileMergePreservesSecretAndMisc pins the #89 fix: re-supplying an
// existing server by name, with its write-only secret omitted, keeps the stored
// secret and any unmodeled per-server XML, and editing one server does not clear
// another's secret.
func TestTacacsProfileMergePreservesSecretAndMisc(t *testing.T) {
	e := &tacacsplus.Entry{
		Name: "tac",
		Server: []tacacsplus.Server{
			{Name: "s1", Address: new("10.0.0.1"), Secret: new("stored1"),
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "u1"}}},
			{Name: "s2", Address: new("10.0.0.2"), Secret: new("stored2")},
		},
	}
	// Re-supply both servers by name: edit s1's address, omit both secrets.
	in := TacacsProfileInput{Name: "tac", Servers: []TacacsServerInput{
		{Name: "s1", Address: new("10.0.0.9")},
		{Name: "s2"},
	}}
	if err := overlayTacacsProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 2 {
		t.Fatalf("both named servers should remain: %+v", e.Server)
	}
	s1 := e.Server[0]
	if s1.Name != "s1" || s1.Address == nil || *s1.Address != "10.0.0.9" {
		t.Fatalf("s1 address should update: %+v", s1)
	}
	if s1.Secret == nil || *s1.Secret != "stored1" {
		t.Fatalf("s1 omitted secret must be preserved: %+v", s1)
	}
	if len(s1.MiscAttributes) != 1 || s1.MiscAttributes[0].Value != "u1" {
		t.Fatalf("s1 unmodeled XML must be preserved: %+v", s1.MiscAttributes)
	}
	if e.Server[1].Secret == nil || *e.Server[1].Secret != "stored2" {
		t.Fatalf("s2 secret must survive editing s1: %+v", e.Server[1])
	}
}

// TestRadiusProfileMergePreservesSecret is the #89 replace-vs-preserve test for
// the RADIUS family (the tracker called out RADIUS and email as lacking one).
func TestRadiusProfileMergePreservesSecret(t *testing.T) {
	e := &radius.Entry{
		Name: "rad",
		Server: []radius.Server{
			{Name: "s1", IpAddress: new("10.0.0.1"), Secret: new("stored1"),
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "r1"}}},
			{Name: "s2", IpAddress: new("10.0.0.2"), Secret: new("stored2")},
		},
	}
	in := RadiusProfileInput{Name: "rad", Servers: []RadiusServerInput{
		{Name: "s1", IpAddress: new("10.9.9.9")},
		{Name: "s2"},
	}}
	if err := overlayRadiusProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Server[0].Secret == nil || *e.Server[0].Secret != "stored1" ||
		e.Server[1].Secret == nil || *e.Server[1].Secret != "stored2" {
		t.Fatalf("omitted per-server secrets must be preserved: %+v", e.Server)
	}
	if e.Server[0].IpAddress == nil || *e.Server[0].IpAddress != "10.9.9.9" {
		t.Fatalf("a provided field should still update: %+v", e.Server[0])
	}
	if len(e.Server[0].MiscAttributes) != 1 || e.Server[0].MiscAttributes[0].Value != "r1" {
		t.Fatalf("s1 unmodeled XML must be preserved: %+v", e.Server[0].MiscAttributes)
	}
}

// TestEmailProfileMergePreservesSecret is the #89 replace-vs-preserve test for
// the email family.
func TestEmailProfileMergePreservesSecret(t *testing.T) {
	e := &email.Entry{
		Name: "em",
		Server: []email.Server{
			{Name: "s1", From: new("a@example.com"), Password: new("stored1"),
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "e1"}}},
			{Name: "s2", From: new("b@example.com"), Password: new("stored2")},
		},
	}
	in := EmailProfileInput{Name: "em", Servers: []EmailServerInput{
		{Name: "s1", From: new("c@example.com")},
		{Name: "s2"},
	}}
	if err := overlayEmailProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Server[0].Password == nil || *e.Server[0].Password != "stored1" ||
		e.Server[1].Password == nil || *e.Server[1].Password != "stored2" {
		t.Fatalf("omitted SMTP passwords must be preserved: %+v", e.Server)
	}
	if len(e.Server[0].MiscAttributes) != 1 || e.Server[0].MiscAttributes[0].Value != "e1" {
		t.Fatalf("s1 unmodeled XML must be preserved: %+v", e.Server[0].MiscAttributes)
	}
}

// TestSnmpTrapProfileV3MergePreservesPasswords is the #89 merge-by-name test
// for the SNMPv3 receiver branch: re-supplying an existing receiver by name
// with both write-only passwords omitted keeps the stored Authpwd and
// Privpwd. Sabotage: neutralizing indexByName's seed in snmpV3Servers (an
// empty prev map) drops both passwords and fails.
func TestSnmpTrapProfileV3MergePreservesPasswords(t *testing.T) {
	e := &snmptrap.Entry{Name: "snmp", Version: &snmptrap.Version{V3: &snmptrap.VersionV3{
		Server: []snmptrap.VersionV3Server{
			{Name: "s1", Manager: new("10.0.0.3"), User: new("u1"), Authpwd: new("authpw1"), Privpwd: new("privpw1")},
		},
	}}}
	in := SnmpTrapProfileInput{Name: "snmp", V3Servers: []SnmpV3ServerInput{
		{Name: "s1", Manager: new("10.0.0.99")},
	}}
	if err := overlaySnmpTrapProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if len(e.Version.V3.Server) != 1 || e.Version.V3.Server[0].Name != "s1" {
		t.Fatalf("s1 must remain: %+v", e.Version.V3.Server)
	}
	s1 := e.Version.V3.Server[0]
	if s1.Manager == nil || *s1.Manager != "10.0.0.99" {
		t.Fatalf("s1 manager should update: %+v", s1)
	}
	mustStrPtr(t, s1.Authpwd, "authpw1", "s1 omitted auth password must be preserved")
	mustStrPtr(t, s1.Privpwd, "privpw1", "s1 omitted priv password must be preserved")
}

// TestLdapProfileMergePreservesServerFields is the merge-by-name test for
// LDAP servers. LDAP servers carry no per-server secret, so this pins the
// preserved port and the preserved unmodeled per-server XML instead.
// Sabotage: neutralizing indexByName's seed in ldapServers (an empty prev
// map) drops the preserved port and the MiscAttributes and fails.
func TestLdapProfileMergePreservesServerFields(t *testing.T) {
	e := &ldap.Entry{
		Name: "ad",
		Server: []ldap.Server{
			{Name: "s1", Address: new("10.0.0.1"), Port: new(int64(636)),
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "l1"}}},
		},
	}
	in := LdapProfileInput{Name: "ad", Servers: []LdapServerInput{
		{Name: "s1", Address: new("10.0.0.9")},
	}}
	if err := overlayLdapProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s1" {
		t.Fatalf("s1 must remain: %+v", e.Server)
	}
	s1 := e.Server[0]
	if s1.Address == nil || *s1.Address != "10.0.0.9" {
		t.Fatalf("s1 address should update: %+v", s1)
	}
	if s1.Port == nil || *s1.Port != 636 {
		t.Fatalf("s1 omitted port must be preserved: %+v", s1)
	}
	if len(s1.MiscAttributes) != 1 || s1.MiscAttributes[0].Value != "l1" {
		t.Fatalf("s1 unmodeled XML must be preserved: %+v", s1.MiscAttributes)
	}
}

// TestSyslogProfileMergePreservesServerFields is the merge-by-name test for
// syslog servers. Syslog servers carry no secret, so this pins the preserved
// facility and the preserved unmodeled per-server XML instead. Sabotage:
// neutralizing indexByName's seed in syslogServers (an empty prev map) drops
// the preserved facility and the MiscAttributes and fails.
func TestSyslogProfileMergePreservesServerFields(t *testing.T) {
	e := &syslog.Entry{
		Name: "sl",
		Server: []syslog.Server{
			{Name: "s1", Server: new("10.0.0.9"), Transport: new("UDP"), Facility: new("LOG_USER"),
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "y1"}}},
		},
	}
	in := SyslogProfileInput{Name: "sl", Servers: []SyslogServerInput{
		{Name: "s1", Transport: new("TCP")},
	}}
	if err := overlaySyslogProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s1" {
		t.Fatalf("s1 must remain: %+v", e.Server)
	}
	s1 := e.Server[0]
	if s1.Transport == nil || *s1.Transport != "TCP" {
		t.Fatalf("s1 transport should update: %+v", s1)
	}
	if s1.Facility == nil || *s1.Facility != "LOG_USER" {
		t.Fatalf("s1 omitted facility must be preserved: %+v", s1)
	}
	if len(s1.MiscAttributes) != 1 || s1.MiscAttributes[0].Value != "y1" {
		t.Fatalf("s1 unmodeled XML must be preserved: %+v", s1.MiscAttributes)
	}
}
