package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file pins the write-path secret seam (tools/redact.go) for the server
// profile families registered in tools/server_profile_tools.go: each
// secret-bearing family must keep withSecrets(<extractor>) on both its create
// and update registration, or a failed write starts echoing the submitted
// secret into the tool result and the logs (issue #103). Each test below
// drives the real registered handler through the fake API, so it proves the
// extractor is actually wired in, not just that redactSecrets works in
// isolation (that is covered by TestRedactSecrets in redact_test.go).
//
// syslog (RegisterSyslogProfileTools) is deliberately absent here: it
// registers no withSecrets option on either its create or update handler
// (tools/server_profile_tools.go), and tools/redact.go defines no
// syslogProfileSecrets extractor. The family carries no per-server secret
// field (SyslogServerInput has no password or community), so there is
// nothing for a redaction test to pin.
//
// tacacs is covered here on the update path only. Its create path is already
// pinned by TestServerProfileCreateRedactsSecretOnError in redact_test.go.

// TestLdapProfileCreateRedactsSecretOnError drives the LDAP create tool
// through the registered handler and the fake API: the device rejects the
// write with an error that echoes the submitted bind password, and the tool
// result must not carry it.
// Sabotage target: the withSecrets(ldapProfileSecrets) argument on the
// panos_ldap_profile_create registration in RegisterLdapProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestLdapProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "LDAP-BIND-SECRET-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for bind-password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_create", Arguments: map[string]any{
		"name":          "ldap1",
		"bind_password": fixture,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted bind password leaked into the create error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestLdapProfileUpdateRedactsSecretOnError drives the LDAP update tool
// (read-modify-write) through the registered handler and the fake API.
// Sabotage target: the withSecrets(ldapProfileSecrets) argument on the
// panos_ldap_profile_update registration in RegisterLdapProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestLdapProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "LDAP-BIND-SECRET-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ldap1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for bind-password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for bind-password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_update", Arguments: map[string]any{
		"name":          "ldap1",
		"bind_password": fixture,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted bind password leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestRadiusProfileCreateRedactsSecretOnError drives the RADIUS create tool
// through the registered handler and the fake API: the device rejects the
// write with an error that echoes the submitted per-server shared secret.
// Sabotage target: the withSecrets(radiusProfileSecrets) argument on the
// panos_radius_profile_create registration in RegisterRadiusProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestRadiusProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "RADIUS-SECRET-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterRadiusProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_radius_profile_create", Arguments: map[string]any{
		"name":    "rad1",
		"servers": []any{map[string]any{"name": "s1", "ip_address": "10.0.0.2", "secret": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted server secret leaked into the create error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestRadiusProfileUpdateRedactsSecretOnError drives the RADIUS update tool
// (read-modify-write) through the registered handler and the fake API.
// Sabotage target: the withSecrets(radiusProfileSecrets) argument on the
// panos_radius_profile_update registration in RegisterRadiusProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestRadiusProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "RADIUS-SECRET-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="rad1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterRadiusProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_radius_profile_update", Arguments: map[string]any{
		"name":    "rad1",
		"servers": []any{map[string]any{"name": "s1", "secret": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted server secret leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestSnmpTrapProfileCreateRedactsSecretOnError drives the SNMP-trap create
// tool through the registered handler and the fake API: the device rejects
// the write with an error that echoes the submitted v2c community string.
// Sabotage target: the withSecrets(snmpTrapProfileSecrets) argument on the
// panos_snmptrap_profile_create registration in RegisterSnmpTrapProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestSnmpTrapProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "SNMP-COMMUNITY-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for community ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterSnmpTrapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_snmptrap_profile_create", Arguments: map[string]any{
		"name":        "trap1",
		"version":     "v2c",
		"v2c_servers": []any{map[string]any{"name": "s1", "manager": "10.0.0.3", "community": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted community string leaked into the create error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestSnmpTrapProfileUpdateRedactsSecretOnError drives the SNMP-trap update
// tool (read-modify-write) with a v3 receiver, so it exercises both the
// auth_password and priv_password collectors snmpTrapProfileSecrets combines,
// not just the v2c community path already covered by the create test above.
// Sabotage target: the withSecrets(snmpTrapProfileSecrets) argument on the
// panos_snmptrap_profile_update registration in RegisterSnmpTrapProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestSnmpTrapProfileUpdateRedactsSecretOnError(t *testing.T) {
	const authFixture = "SNMP-AUTH-PW-002"
	const privFixture = "SNMP-PRIV-PW-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="trap1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for auth ` + authFixture + ` priv ` + privFixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for auth ` + authFixture + ` priv ` + privFixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterSnmpTrapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_snmptrap_profile_update", Arguments: map[string]any{
		"name":    "trap1",
		"version": "v3",
		"v3_servers": []any{map[string]any{
			"name":          "s1",
			"manager":       "10.0.0.4",
			"auth_password": authFixture,
			"priv_password": privFixture,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, authFixture) {
		t.Fatalf("submitted auth password leaked into the update error: %q", out)
	}
	if strings.Contains(out, privFixture) {
		t.Fatalf("submitted priv password leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestEmailProfileCreateRedactsSecretOnError drives the email create tool
// through the registered handler and the fake API: the device rejects the
// write with an error that echoes the submitted SMTP password.
// Sabotage target: the withSecrets(emailProfileSecrets) argument on the
// panos_email_profile_create registration in RegisterEmailProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestEmailProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "EMAIL-SMTP-PW-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEmailProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_email_profile_create", Arguments: map[string]any{
		"name": "email1",
		"servers": []any{map[string]any{
			"name":     "s1",
			"gateway":  "smtp.example.com",
			"username": "svc",
			"password": fixture,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted SMTP password leaked into the create error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestEmailProfileUpdateRedactsSecretOnError drives the email update tool
// (read-modify-write) through the registered handler and the fake API.
// Sabotage target: the withSecrets(emailProfileSecrets) argument on the
// panos_email_profile_update registration in RegisterEmailProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestEmailProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "EMAIL-SMTP-PW-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="email1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterEmailProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_email_profile_update", Arguments: map[string]any{
		"name":    "email1",
		"servers": []any{map[string]any{"name": "s1", "password": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted SMTP password leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestTacacsProfileUpdateRedactsSecretOnError drives the TACACS+ update tool
// (read-modify-write) through the registered handler and the fake API. The
// create path for this family is already pinned by
// TestServerProfileCreateRedactsSecretOnError in redact_test.go; this test
// covers the update registration, which is a separate call site.
// Sabotage target: the withSecrets(tacacsProfileSecrets) argument on the
// panos_tacacs_profile_update registration in RegisterTacacsProfileTools.
// Confirmed red when removed, confirmed green when restored (see report).
func TestTacacsProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "TACACS-SECRET-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="tac1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterTacacsProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_tacacs_profile_update", Arguments: map[string]any{
		"name":    "tac1",
		"servers": []any{map[string]any{"name": "s1", "secret": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted server secret leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}
