package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/certificate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertSawGet fails unless the fake recorded a config get whose xpath contains
// every fragment in want. Local to the certificate tests, which pin the
// read-only scope resolution end to end.
func assertSawGet(t *testing.T, f *fakeAPI, want []string) {
	t.Helper()
	for _, req := range f.Requests() {
		if req.Get("type") != "config" || req.Get("action") != "get" {
			continue
		}
		xp := req.Get("xpath")
		ok := true
		for _, w := range want {
			if !strings.Contains(xp, w) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no config get whose xpath contains all of %v; requests: %v", want, f.Requests())
}

// --- scope resolution ---------------------------------------------------------

func TestResolveCertScope(t *testing.T) {
	fw, _ := newTestDeps(t, "PA-VM")
	pano, _ := newTestDeps(t, "Panorama")
	// For a success case exactly one of wantVsys/wantTmpl/wantStack is set; the
	// resolver must set the matching pango sub-location to that value.
	cases := []struct {
		name      string
		d         *Deps
		in        CertScopeInput
		wantErr   string
		wantVsys  string
		wantTmpl  string
		wantStack string
	}{
		{name: "firewall default vsys1", d: fw, in: CertScopeInput{}, wantVsys: "vsys1"},
		{name: "firewall explicit vsys", d: fw, in: CertScopeInput{Vsys: "vsys3"}, wantVsys: "vsys3"},
		{name: "firewall template errors", d: fw, in: CertScopeInput{Template: "tmpl-a"}, wantErr: "template requires a Panorama connection"},
		{name: "firewall template_stack errors", d: fw, in: CertScopeInput{TemplateStack: "st-a"}, wantErr: "template_stack requires a Panorama connection"},
		{name: "panorama template", d: pano, in: CertScopeInput{Template: "tmpl-a"}, wantTmpl: "tmpl-a"},
		{name: "panorama stack", d: pano, in: CertScopeInput{TemplateStack: "st-a"}, wantStack: "st-a"},
		{name: "both template and stack errors", d: pano, in: CertScopeInput{Template: "t", TemplateStack: "s"}, wantErr: "set only one of template or template_stack"},
		{name: "vsys on panorama errors", d: pano, in: CertScopeInput{Vsys: "vsys1"}, wantErr: "vsys requires a firewall connection"},
		{name: "vsys with template errors (firewall)", d: fw, in: CertScopeInput{Vsys: "vsys1", Template: "tmpl-a"}, wantErr: "set only one of vsys (firewall) or template/template_stack"},
		{name: "vsys with template_stack errors (panorama)", d: pano, in: CertScopeInput{Vsys: "vsys1", TemplateStack: "st-a"}, wantErr: "set only one of vsys (firewall) or template/template_stack"},
		{name: "panorama needs a template", d: pano, in: CertScopeInput{}, wantErr: "template or template_stack is required on Panorama"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc, err := resolveCertScope(c.d, c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error containing %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertCertLoc(t, loc, c.wantVsys, c.wantTmpl, c.wantStack)
		})
	}
}

// assertCertLoc checks that loc set exactly the pango sub-location named by the
// single non-empty want*, to that value.
func assertCertLoc(t *testing.T, loc certificate.Location, wantVsys, wantTmpl, wantStack string) {
	t.Helper()
	switch {
	case wantVsys != "":
		if loc.Vsys == nil || loc.Vsys.Vsys != wantVsys {
			t.Fatalf("want vsys %q, got %+v", wantVsys, loc)
		}
	case wantTmpl != "":
		if loc.Template == nil || loc.Template.Template != wantTmpl {
			t.Fatalf("want template %q, got %+v", wantTmpl, loc)
		}
	case wantStack != "":
		if loc.TemplateStack == nil || loc.TemplateStack.TemplateStack != wantStack {
			t.Fatalf("want template_stack %q, got %+v", wantStack, loc)
		}
	}
}

// --- summary must not leak key material ---------------------------------------

// TestCertificateSummaryOmitsKeyMaterial is the security pin: the read-only
// certificate summary carries inventory and expiry metadata but never the
// private key, CSR, or public-key PEM. Sabotage: adding any of PrivateKey, Csr,
// or PublicKey to certificateSummary turns this red.
func TestCertificateSummaryOmitsKeyMaterial(t *testing.T) {
	e := &certificate.Entry{
		Name:           "cert1",
		Subject:        new("CN=vpn.example.com"),
		Issuer:         new("CN=Example CA"),
		CommonName:     new("vpn.example.com"),
		Algorithm:      new("RSA"),
		Status:         new("valid"),
		NotValidBefore: new("Jan 1 00:00:00 2026 GMT"),
		NotValidAfter:  new("Jan 1 00:00:00 2027 GMT"),
		ExpiryEpoch:    new("1798761600"),
		Ca:             new(true),
		PrivateKey:     new("PRIVATE-KEY-SENTINEL"),
		Csr:            new("CSR-SENTINEL"),
		PublicKey:      new("PUBLIC-KEY-SENTINEL"),
		// Cloud-HSM key references are secret material too; the summary must not
		// reach them either.
		CloudResourceId: &certificate.CloudResourceId{
			Aws:   &certificate.CloudResourceIdAws{Secret: new("AWS-SECRET-SENTINEL")},
			Azure: &certificate.CloudResourceIdAzure{Secret: new("AZURE-SECRET-SENTINEL"), KeyVaultUri: new("VAULT-URI-SENTINEL")},
		},
	}
	m := asMap(t, certificateSummary(e))
	if m[tagNameKey] != "cert1" || m["subject"] != "CN=vpn.example.com" {
		t.Fatalf("inventory metadata must be summarized, got %v", m)
	}
	if m["not_valid_after"] != "Jan 1 00:00:00 2027 GMT" {
		t.Fatalf("expiry metadata must be present, got %v", m["not_valid_after"])
	}
	if m["ca"] != true {
		t.Fatalf("ca flag must be present, got %v", m["ca"])
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{
		"PRIVATE-KEY-SENTINEL", "CSR-SENTINEL", "PUBLIC-KEY-SENTINEL",
		"AWS-SECRET-SENTINEL", "AZURE-SECRET-SENTINEL", "VAULT-URI-SENTINEL",
	} {
		if strings.Contains(string(b), sentinel) {
			t.Fatalf("certificate summary leaked key material %q: %s", sentinel, b)
		}
	}
}

// TestCertificateSummaryUnsetFields pins that unset optional fields render as
// empty strings and the ca flag is omitted when nil (tri-state, issue #67).
func TestCertificateSummaryUnsetFields(t *testing.T) {
	m := asMap(t, certificateSummary(&certificate.Entry{Name: "bare"}))
	if m["subject"] != "" || m["issuer"] != "" || m["not_valid_after"] != "" {
		t.Fatalf("unset metadata must render as empty strings: %v", m)
	}
	if _, ok := m["ca"]; ok {
		t.Fatalf("a nil ca flag must be omitted, got %v", m["ca"])
	}
}

// --- read-only registration ---------------------------------------------------

// TestCertificateToolsReadOnlyOnly pins that the family exposes only list and
// get, in BOTH write and read-only server modes: there is no create, update, or
// delete because installing a certificate needs the import operation. Sabotage:
// registering any write tool turns this red.
func TestCertificateToolsReadOnlyOnly(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		d, _ := newTestDeps(t, "PA-VM")
		d.ReadOnly = readOnly
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterCertificateTools(srv, d)
		names := serverToolNames(t, srv)
		for _, want := range []string{"panos_certificate_list", "panos_certificate_get"} {
			if !names[want] {
				t.Fatalf("readOnly=%v: expected %q to be registered", readOnly, want)
			}
		}
		for _, unwant := range []string{"panos_certificate_create", "panos_certificate_update", "panos_certificate_delete"} {
			if names[unwant] {
				t.Fatalf("readOnly=%v: %q must not be registered (the family is read-only)", readOnly, unwant)
			}
		}
	}
}

// --- wire-level list xpath ----------------------------------------------------

// TestCertificateListXpath pins that the list resolves to the per-vsys node on a
// firewall and the template node on Panorama. Sabotage: pointing resolveCertScope
// at a different location shifts the get xpath off the certificate node.
func TestCertificateListXpath(t *testing.T) {
	cases := []struct {
		name  string
		model string
		args  map[string]any
		want  []string
	}{
		{"firewall vsys", "PA-VM", map[string]any{}, []string{"certificate", "vsys1"}},
		{"panorama template", "Panorama", map[string]any{"template": "tmpl-a"}, []string{"certificate", "template", "tmpl-a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, c.model,
				fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
			)
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterCertificateTools(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_certificate_list", Arguments: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("list failed: %s", textContent(t, res))
			}
			assertSawGet(t, f, c.want)
		})
	}
}

// TestCertificateGetXpath drives panos_certificate_get and pins that the get
// reaches the named certificate under the resolved vsys node. It asserts on the
// request xpath (recorded regardless of the response), so it exercises
// CertNameInput.entryName() and the get registration closure. Sabotage:
// dropping the name from the input, or pointing resolveCertScope elsewhere,
// removes "my-cert" or "vsys1" from the xpath.
func TestCertificateGetXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterCertificateTools(srv, d)
	cs := connectInMemory(t, srv)
	// The empty result surfaces as not-found; we only pin that the get request
	// reached the right node by name, which the fake records either way.
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "panos_certificate_get", Arguments: map[string]any{"name": "my-cert"},
	}); err != nil {
		t.Fatal(err)
	}
	assertSawGet(t, f, []string{"certificate", "my-cert", "vsys1"})
}
