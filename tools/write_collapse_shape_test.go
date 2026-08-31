package tools

import (
	"bytes"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests pin issue #109's fixture-fidelity gap: every OTHER per-family
// redaction fixture in this package is single-nested (<msg><line>text</line>
// </msg>), which pango parses to a clean message, so those tests exercise only
// the literal-replacement arm of redactSecrets. A real PA-VM write validation
// failure comes back DOUBLE-nested (<msg><line><line>...</line></line></msg>),
// which pango models as a leaf so the parsed message is empty and the
// raw-response COLLAPSE arm fires instead (measured on PAN-OS 11.2.6; see
// TestPangoNestedLineErrorTakesRawFallback). The two tests below drive the real
// registered create handler with that measured shape, so they pin that the
// collapse arm defends the secret for the shape a device actually produces, not
// just the literal-replacement arm the other fixtures cover.
//
// The secret sits inside the nested line, so it is part of the raw body the
// collapse discards; the assertion is that the body (and thus the secret) never
// reaches the tool result. Removing withSecrets(...) from the registration makes
// isSecretBearing false, disarms the collapse, and lets the raw body through.

// assertCollapsedWriteError checks a secret-bearing write error surfaced with the
// raw-response body collapsed rather than echoed, so the secret the body carried
// did not leak. Unlike assertRedactsSecret, it expects the collapse marker rather
// than the literal placeholder, because the double-nested shape parses empty and
// takes the raw fallback. It checks BOTH sinks the write path writes (the tool
// result and the log), the same two-sink concern issue #105 raised for reads.
//
// It also pins that the device response code survives the write-path collapse
// (issue #109): once the body is discarded the code is the only diagnostic left, so
// a failed create must not yield strictly less than a failed read. The fixtures
// driving this helper carry code="12". Sabotage: drop the withDeviceCodeFromErr
// call from redactWriteError and the code assertion turns red (the secret-leak
// assertions stay green, isolating the two concerns).
func assertCollapsedWriteError(t *testing.T, res *mcp.CallToolResult, err error, logs *bytes.Buffer, secret string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	for name, out := range map[string]string{"tool result": textContent(t, res), "log sink": logs.String()} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked into the %s: %q", name, out)
		}
		if !strings.Contains(out, "(raw response: [redacted])") {
			t.Fatalf("expected the collapsed raw response in the %s: %q", name, out)
		}
		if !strings.Contains(out, "device response code 12") {
			t.Fatalf("the device response code must survive the write-path collapse in the %s: %q", name, out)
		}
	}
}

// Sabotage target: the withSecrets(ldapProfileSecrets) argument on the
// panos_ldap_profile_create registration in RegisterLdapProfileTools. Removing
// it disarms the collapse for the double-nested shape and the bind password
// reaches the tool result.
func TestLdapProfileCreateCollapsesDoubleNestedDeviceError(t *testing.T) {
	const fixture = "LDAP-BIND-SECRET-DN-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error" code="12"><msg><line><line>validation error for bind-password ` + fixture + `</line></line></msg></response>`},
	)
	logs := captureLogs(t, d)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ldap_profile_create", Arguments: map[string]any{
		"name":          "ldap1",
		"bind_password": fixture,
	}})
	assertCollapsedWriteError(t, res, err, logs, fixture)
}

// Sabotage target: the withSecrets(radiusProfileSecrets) argument on the
// panos_radius_profile_create registration in RegisterRadiusProfileTools.
func TestRadiusProfileCreateCollapsesDoubleNestedDeviceError(t *testing.T) {
	const fixture = "RADIUS-SECRET-DN-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error" code="12"><msg><line><line>validation error for secret ` + fixture + `</line></line></msg></response>`},
	)
	logs := captureLogs(t, d)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterRadiusProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_radius_profile_create", Arguments: map[string]any{
		"name":    "rad1",
		"servers": []any{map[string]any{"name": "s1", "ip_address": "10.0.0.2", "secret": fixture}},
	}})
	assertCollapsedWriteError(t, res, err, logs, fixture)
}
