package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/ssldecrypt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- scope mapping ------------------------------------------------------------

// TestSslDecryptPartsScope pins that sslDecryptParts maps a firewall to the
// device-wide shared location (pango exposes no system or vsys node for these
// settings) and a Panorama template to its template location. Sabotage:
// pointing the system constructor at a Template location, or dropping the
// shared node, moves the firewall scope off shared.
func TestSslDecryptPartsScope(t *testing.T) {
	fw, _ := newTestDeps(t, "PA-VM")
	loc, err := resolveSystemScope(fw, SystemScopeInput{}, sslDecryptParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc.Shared == nil {
		t.Fatalf("firewall scope must resolve to the shared location, got %+v", loc)
	}
	if loc.Template != nil || loc.TemplateStack != nil {
		t.Fatalf("firewall scope must set only the shared location, got %+v", loc)
	}

	pano, _ := newTestDeps(t, "Panorama")
	loc2, err := resolveSystemScope(pano, SystemScopeInput{Template: "tmpl-a"}, sslDecryptParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc2.Template == nil || loc2.Template.Template != "tmpl-a" {
		t.Fatalf("panorama template must resolve, got %+v", loc2)
	}

	loc3, err := resolveSystemScope(pano, SystemScopeInput{TemplateStack: "st-a"}, sslDecryptParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc3.TemplateStack == nil || loc3.TemplateStack.TemplateStack != "st-a" {
		t.Fatalf("panorama template_stack must resolve, got %+v", loc3)
	}
}

// --- overlay and summary ------------------------------------------------------

func TestSslDecryptOverlayAndSummary(t *testing.T) {
	c := &ssldecrypt.Config{
		SslExcludeCert: []ssldecrypt.SslExcludeCert{{Name: "*.example.com", Exclude: new(true), Description: new("skip decrypt")}},
	}
	// Set every input field so a mis-wired mapping (a cert ref pointed at the
	// wrong Config field, or a dropped list assignment) is caught, not just the
	// two happy-path fields.
	in := SslDecryptInput{
		ForwardTrustCertRsa:            new("ft-rsa"),
		ForwardTrustCertEcdsa:          new("ft-ecdsa"),
		ForwardUntrustCertRsa:          new("fu-rsa"),
		ForwardUntrustCertEcdsa:        new("fu-ecdsa"),
		TrustedRootCa:                  []string{"root-a", "root-b"},
		RootCaExcludeList:              []string{"excl-a"},
		DisabledPredefinedExcludeCerts: []string{"pre-a", "pre-b"},
	}
	if err := overlaySslDecrypt(c, in); err != nil {
		t.Fatal(err)
	}
	// Every cert ref must land on its OWN Config field.
	mustStrPtr(t, c.ForwardTrustCertificateRsa, "ft-rsa", "forward_trust_cert_rsa -> Config")
	mustStrPtr(t, c.ForwardTrustCertificateEcdsa, "ft-ecdsa", "forward_trust_cert_ecdsa -> Config")
	mustStrPtr(t, c.ForwardUntrustCertificateRsa, "fu-rsa", "forward_untrust_cert_rsa -> Config")
	mustStrPtr(t, c.ForwardUntrustCertificateEcdsa, "fu-ecdsa", "forward_untrust_cert_ecdsa -> Config")
	// Every list must map to its own Config field (not to a sibling's).
	for _, tc := range []struct {
		got, want []string
		label     string
	}{
		{c.TrustedRootCa, []string{"root-a", "root-b"}, "trusted_root_ca"},
		{c.RootCaExcludeList, []string{"excl-a"}, "root_ca_exclude_list"},
		{c.DisabledSslExcludeCertFromPredefined, []string{"pre-a", "pre-b"}, "disabled_predefined_exclude_certs"},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Fatalf("%s did not map to its own Config field: got %v want %v", tc.label, tc.got, tc.want)
		}
	}
	// A read-modify-write must preserve the unmodeled ssl-exclude-cert list.
	if len(c.SslExcludeCert) != 1 || c.SslExcludeCert[0].Name != "*.example.com" {
		t.Fatalf("ssl-exclude-cert list must be preserved, got %+v", c.SslExcludeCert)
	}
	assertSslDecryptSummaryFields(t, sslDecryptSummary(c))
}

// assertSslDecryptSummaryFields checks the summary emits every modeled field
// with the value overlaySslDecrypt wrote, so a summary mis-wire is caught too.
func assertSslDecryptSummaryFields(t *testing.T, summary any) {
	t.Helper()
	m := asMap(t, summary)
	for k, want := range map[string]string{
		"forward_trust_cert_rsa":     "ft-rsa",
		"forward_trust_cert_ecdsa":   "ft-ecdsa",
		"forward_untrust_cert_rsa":   "fu-rsa",
		"forward_untrust_cert_ecdsa": "fu-ecdsa",
	} {
		if m[k] != want {
			t.Fatalf("summary %s wrong: got %v want %q", k, m[k], want)
		}
	}
	for k, want := range map[string][]string{
		"trusted_root_ca":                   {"root-a", "root-b"},
		"root_ca_exclude_list":              {"excl-a"},
		"disabled_predefined_exclude_certs": {"pre-a", "pre-b"},
	} {
		if got := mustStrSlice(t, m[k]); !slices.Equal(got, want) {
			t.Fatalf("summary %s wrong: got %v want %v", k, got, want)
		}
	}
	excludes, ok := m["exclude_certs"].([]any)
	if !ok || len(excludes) != 1 {
		t.Fatalf("summary exclude_certs wrong: %v", m["exclude_certs"])
	}
	ex := asMap(t, excludes[0])
	if ex[tagNameKey] != "*.example.com" || ex["exclude"] != true || ex["description"] != "skip decrypt" {
		t.Fatalf("exclude cert summary wrong: %v", ex)
	}
}

// TestSslDecryptOverlayNilPreservesLists pins that a nil list in the input does
// not clear the existing list (the "only provided fields change" contract).
// Sabotage: assigning c.TrustedRootCa = in.TrustedRootCa unconditionally clears
// it on an empty input.
func TestSslDecryptOverlayNilPreservesLists(t *testing.T) {
	c := &ssldecrypt.Config{TrustedRootCa: []string{"keep"}, ForwardTrustCertificateRsa: new("keep-rsa")}
	if err := overlaySslDecrypt(c, SslDecryptInput{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.TrustedRootCa, []string{"keep"}) {
		t.Fatalf("nil trusted_root_ca must preserve existing list, got %v", c.TrustedRootCa)
	}
	mustStrPtr(t, c.ForwardTrustCertificateRsa, "keep-rsa", "unset forward_trust_cert_rsa must be preserved")
}

// --- upsert arms --------------------------------------------------------------

// TestSslDecryptUpdateCreatesWhenAbsent pins the absent arm of the upsert: when
// the seed read finds no ssl-decrypt node, the write goes through Create (a
// "set"), not Update (an "edit" whose internal read would fail on the absent
// node). Sabotage: forcing the handler to always call svc.Update turns this red.
func TestSslDecryptUpdateCreatesWhenAbsent(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>CREATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterSslDecryptTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_ssl_decrypt_settings_update", Arguments: map[string]any{"forward_trust_cert_rsa": "ft-rsa"},
	})
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

// TestSslDecryptUpdateUsesUpdateWhenPresent is the present arm: when the seed
// read finds an existing ssl-decrypt node, the write goes through Update (an
// "edit"/"multi-config"), not Create (a "set"). Sabotage: forcing the handler
// to always call svc.Create turns this red with the CREATE-PATH-MARKER.
func TestSslDecryptUpdateUsesUpdateWhenPresent(t *testing.T) {
	present := `<response status="success"><result><ssl-decrypt><trusted-root-CA><member>root-a</member></trusted-root-CA></ssl-decrypt></result></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: present},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>CREATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>UPDATE-PATH-MARKER</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterSslDecryptTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_ssl_decrypt_settings_update", Arguments: map[string]any{"forward_trust_cert_rsa": "ft-rsa"},
	})
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

// --- read-only gating ---------------------------------------------------------

func TestSslDecryptReadOnlyGating(t *testing.T) {
	assertReadOnlyGating(t, RegisterSslDecryptTools,
		[]string{"panos_ssl_decrypt_settings_get"},
		[]string{"panos_ssl_decrypt_settings_update"})
}
