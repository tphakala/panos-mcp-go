package tools

import (
	"encoding/xml"
	"strings"
	"testing"

	certprof "github.com/PaloAltoNetworks/pango/device/profile/certificate"
	"github.com/PaloAltoNetworks/pango/generic"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Read-back bodies for the create path: pango's Create issues a config set and
// then reads the entry back with a config get, so each create test registers
// both routes.
const sslTlsCreatedBody = `<response status="success"><result>` +
	`<entry name="p1"><certificate>my-cert</certificate>` +
	`<protocol-settings><min-version>tls1-2</min-version></protocol-settings></entry>` +
	`</result></response>`

// --- SSL/TLS service profile --------------------------------------------------

// TestBuildSslTlsProfile pins that the modeled scalars and a couple of protocol
// toggles land in the matching Entry / ProtocolSettings fields, that min_version
// maps to MinVersion (not MaxVersion), and that an unset toggle stays nil.
// Sabotage: mapping in.MinVersion to ps.MaxVersion in applySslTlsProfile leaves
// MinVersion nil and turns this red.
func TestBuildSslTlsProfile(t *testing.T) {
	e, err := buildSslTlsProfile(SslTlsProfileInput{
		Name:                    "p1",
		Certificate:             new("my-cert"),
		MinVersion:              new("tls1-2"),
		AllowAlgorithm3des:      new(false),
		AllowAuthenticationSha1: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "p1" {
		t.Fatalf("name: %q", e.Name)
	}
	if e.Certificate == nil || *e.Certificate != "my-cert" {
		t.Fatalf("certificate must be set: %v", e.Certificate)
	}
	if e.ProtocolSettings == nil {
		t.Fatal("protocol settings must be allocated when a version/toggle is provided")
	}
	ps := e.ProtocolSettings
	if ps.MinVersion == nil || *ps.MinVersion != "tls1-2" {
		t.Fatalf("min_version must map to MinVersion: %v", ps.MinVersion)
	}
	if ps.MaxVersion != nil {
		t.Fatalf("max_version was not provided, must stay nil: %v", ps.MaxVersion)
	}
	if ps.AllowAlgorithm3des == nil || *ps.AllowAlgorithm3des != false {
		t.Fatalf("allow_algorithm_3des must be present-false: %v", ps.AllowAlgorithm3des)
	}
	if ps.AllowAuthenticationSha1 == nil || *ps.AllowAuthenticationSha1 != true {
		t.Fatalf("allow_authentication_sha1 must be present-true: %v", ps.AllowAuthenticationSha1)
	}
	// An unprovided toggle stays nil (tri-state absent).
	if ps.AllowAlgorithmRc4 != nil {
		t.Fatalf("unset toggle must stay nil: %v", ps.AllowAlgorithmRc4)
	}
}

// TestBuildSslTlsProfileCertOnly pins that a certificate-only create omits
// ProtocolSettings entirely, so a bare profile does not write an empty
// protocol-settings node.
func TestBuildSslTlsProfileCertOnly(t *testing.T) {
	e, err := buildSslTlsProfile(SslTlsProfileInput{Name: "p1", Certificate: new("c")})
	if err != nil {
		t.Fatal(err)
	}
	if e.ProtocolSettings != nil {
		t.Fatalf("protocol settings must stay nil when no version/toggle is provided: %+v", e.ProtocolSettings)
	}
}

// TestSslTlsProfileCreateFirewallSharedXpath drives the registered create tool on
// a firewall with the default (shared) scope and pins that the set reaches the
// shared xpath under ssl-tls-service-profile. Sabotage: pointing the firewall
// branch of resolveProfileScope at p.panorama() shifts the xpath from
// /config/shared to /config/panorama and fails the shared assertion.
func TestSslTlsProfileCreateFirewallSharedXpath(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: sslTlsCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterSslTlsProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_ssl_tls_profile_create",
		Arguments: map[string]any{"name": "p1", "certificate": "my-cert"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if joined == "" {
		t.Fatal("no config set request recorded")
	}
	if !strings.Contains(joined, "/shared/") {
		t.Fatalf("firewall create must target the shared xpath: %s", joined)
	}
	if !strings.Contains(joined, "ssl-tls-service-profile") {
		t.Fatalf("create did not target the ssl-tls-service-profile subtree: %s", joined)
	}
}

// TestSslTlsProfileCreatePanoramaTemplateXpath drives the registered create tool
// on Panorama under a template and pins that the set reaches the template's
// ssl-tls-service-profile subtree carrying the template name. Sabotage: routing
// the template branch to p.templateStack() drops "template/" and fails.
func TestSslTlsProfileCreatePanoramaTemplateXpath(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: sslTlsCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterSslTlsProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_ssl_tls_profile_create",
		Arguments: map[string]any{"name": "p1", "template": "tmpl-a", "certificate": "my-cert"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if joined == "" {
		t.Fatal("no config set request recorded")
	}
	// Require the "/template/" segment specifically: a template-stack xpath also
	// contains the substring "template", so a bare Contains would not catch a
	// template->template_stack mis-route.
	if !strings.Contains(joined, "/template/") || !strings.Contains(joined, "tmpl-a") {
		t.Fatalf("Panorama template create must target the template xpath: %s", joined)
	}
	if strings.Contains(joined, "template-stack") {
		t.Fatalf("template create must not target a template-stack xpath: %s", joined)
	}
	if !strings.Contains(joined, "ssl-tls-service-profile") {
		t.Fatalf("create did not target the ssl-tls-service-profile subtree: %s", joined)
	}
}

// TestSslTlsProfileNoOpUpdateNoWrite proves an update that changes nothing issues
// no config write: overlaySslTlsProfile leaves the read entry untouched, so
// pango's SpecMatches short-circuits and no multi-config reaches the API.
// Sabotage: if overlaySslTlsProfile forced a toggle or replaced certificate
// unconditionally, the entry would differ from the read-back and a write fires.
func TestSslTlsProfileNoOpUpdateNoWrite(t *testing.T) {
	current := `<response status="success"><result><entry name="p1"><certificate>c1</certificate>` +
		`<protocol-settings><min-version>tls1-2</min-version></protocol-settings></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterSslTlsProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ssl_tls_profile_update", Arguments: map[string]any{"name": "p1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("no-op update failed: %s", textContent(t, res))
	}
	assertNoConfigWrite(t, f)
}

func TestSslTlsProfileReadOnlyGating(t *testing.T) {
	base := "panos_ssl_tls_profile"
	assertReadOnlyGating(t, RegisterSslTlsProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// --- certificate profile ------------------------------------------------------

// wantBoolPtr fails when b is nil and otherwise returns its value, keeping the
// tri-state nil check out of the caller's cyclomatic budget.
func wantBoolPtr(t *testing.T, b *bool) bool {
	t.Helper()
	if b == nil {
		t.Fatalf("expected a present bool, got nil")
	}
	return *b
}

// TestBuildCertificateProfileCAList pins that a provided certificate_authorities
// list maps in order to e.Certificate with its per-CA fields, and that the
// block-* toggles map to the matching Entry fields. Sabotage: dropping the
// CertificateAuthorities mapping in applyCertificateProfile leaves e.Certificate
// nil and fails the ordered-list assertion.
func TestBuildCertificateProfileCAList(t *testing.T) {
	e, err := buildCertificateProfile(CertificateProfileInput{
		Name:                    "cp1",
		Domain:                  new("example.com"),
		BlockExpiredCertificate: new(true),
		BlockUnknownCertificate: new(false),
		UsernameFieldSubject:    new("common-name"),
		CertificateAuthorities: []CertificateAuthorityInput{
			{Name: "ca-a", DefaultOcspUrl: new("http://ocsp-a")},
			{Name: "ca-b", TemplateName: new("tmpl-b")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Domain == nil || *e.Domain != "example.com" {
		t.Fatalf("domain: %v", e.Domain)
	}
	if got := wantBoolPtr(t, e.BlockExpiredCertificate); got != true {
		t.Fatalf("block_expired_certificate must be present-true: %v", got)
	}
	if got := wantBoolPtr(t, e.BlockUnknownCertificate); got != false {
		t.Fatalf("block_unknown_certificate must be present-false: %v", got)
	}
	if e.UsernameField == nil || strVal(e.UsernameField.Subject) != "common-name" {
		t.Fatalf("username_field_subject must be set: %+v", e.UsernameField)
	}
	if len(e.Certificate) != 2 {
		t.Fatalf("CA list must have two entries in order: %+v", e.Certificate)
	}
	if got := e.Certificate[0].Name; got != "ca-a" {
		t.Fatalf("first CA out of order: %q", got)
	}
	if got := strVal(e.Certificate[0].DefaultOcspUrl); got != "http://ocsp-a" {
		t.Fatalf("first CA default_ocsp_url: %q", got)
	}
	if got := e.Certificate[1].Name; got != "ca-b" {
		t.Fatalf("second CA out of order: %q", got)
	}
	if got := strVal(e.Certificate[1].TemplateName); got != "tmpl-b" {
		t.Fatalf("second CA template_name: %q", got)
	}
}

// TestCertificateProfilePreservesUnmanaged pins the read-modify-write contract:
// overlaying only use_crl must leave the untouched managed siblings (domain and
// the existing CA list) and the unmodeled MiscAttributes intact, because
// overlayCertificateProfile applies onto the read-back entry and never rebuilds
// it. Sabotage: rebuilding e in overlayCertificateProfile (e.g.
// *e = certprof.Entry{Name: e.Name}) drops all three and turns this red.
func TestCertificateProfilePreservesUnmanaged(t *testing.T) {
	e := &certprof.Entry{
		Name:           "cp1",
		Domain:         new("example.com"),
		Certificate:    []certprof.Certificate{{Name: "ca-a"}},
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}
	if err := overlayCertificateProfile(e, CertificateProfileInput{Name: "cp1", UseCrl: new(true)}); err != nil {
		t.Fatal(err)
	}
	if e.UseCrl == nil || *e.UseCrl != true {
		t.Fatalf("provided use_crl must be set: %v", e.UseCrl)
	}
	if e.Domain == nil || *e.Domain != "example.com" {
		t.Fatalf("untouched domain must be preserved: %v", e.Domain)
	}
	if len(e.Certificate) != 1 || e.Certificate[0].Name != "ca-a" {
		t.Fatalf("an omitted CA list must leave the existing one untouched: %+v", e.Certificate)
	}
	if len(e.MiscAttributes) != 1 || e.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("unmanaged MiscAttributes must survive the overlay: %+v", e.MiscAttributes)
	}
}

// TestCertificateProfileSummary pins the read projection: certificateProfileSummary
// maps the scalars (name, domain, use_crl, certificate_status_timeout) and
// certificateAuthoritySummaries maps the CA list in order with its per-CA fields.
// Sabotage: dropping the "domain" mapping in certificateProfileSummary, or the
// "default_ocsp_url"/"template_name" mapping in certificateAuthoritySummaries,
// turns the matching assertion red.
func TestCertificateProfileSummary(t *testing.T) {
	e := &certprof.Entry{
		Name:                     "cp1",
		Domain:                   new("example.com"),
		UseCrl:                   new(true),
		CertificateStatusTimeout: new(int64(5)),
		Certificate: []certprof.Certificate{
			{Name: "ca-a", DefaultOcspUrl: new("http://ocsp-a")},
			{Name: "ca-b", TemplateName: new("tmpl-b")},
		},
	}
	m := asMap(t, certificateProfileSummary(e))
	if m[tagNameKey] != "cp1" {
		t.Fatalf("name: %v", m[tagNameKey])
	}
	if m["domain"] != "example.com" {
		t.Fatalf("domain: %v", m["domain"])
	}
	if m["use_crl"] != true {
		t.Fatalf("use_crl: %v", m["use_crl"])
	}
	if m["certificate_status_timeout"] != int64(5) {
		t.Fatalf("certificate_status_timeout: %v", m["certificate_status_timeout"])
	}
	cas, ok := m["certificate_authorities"].([]any)
	if !ok || len(cas) != 2 {
		t.Fatalf("certificate_authorities shape: %v", m["certificate_authorities"])
	}
	ca0, ok := cas[0].(map[string]any)
	if !ok || ca0[tagNameKey] != "ca-a" || ca0["default_ocsp_url"] != "http://ocsp-a" {
		t.Fatalf("first CA out of order or unmapped: %v", cas[0])
	}
	ca1, ok := cas[1].(map[string]any)
	if !ok || ca1[tagNameKey] != "ca-b" || ca1["template_name"] != "tmpl-b" {
		t.Fatalf("second CA out of order or unmapped: %v", cas[1])
	}
}

func TestCertificateProfileReadOnlyGating(t *testing.T) {
	base := "panos_certificate_profile"
	assertReadOnlyGating(t, RegisterCertificateProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// storedCertificateProfile returns a certificate profile whose first CA carries
// XML this server does not model, so a merge that rebuilds the CA from scratch
// is visibly different from one that seeds it from the stored entry.
func storedCertificateProfile() *certprof.Entry {
	return &certprof.Entry{
		Name: "cp1",
		Certificate: []certprof.Certificate{
			{
				Name:           "ca-a",
				DefaultOcspUrl: new("http://old-a"),
				TemplateName:   new("tmpl-a"),
				Misc:           []generic.Xml{{}},
				MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "ca-a-uuid"}},
			},
			{Name: "ca-b", DefaultOcspUrl: new("http://old-b")},
		},
	}
}

// TestCertificateProfileCASurvivorKeepsUnmodeledXML pins the half of the
// merge-by-name contract that the old fresh-build implementation got wrong: a CA
// the caller keeps must retain the XML this server does not model, exactly as
// the server profile builders preserve a per-server secret.
func TestCertificateProfileCASurvivorKeepsUnmodeledXML(t *testing.T) {
	e := storedCertificateProfile()
	if err := overlayCertificateProfile(e, CertificateProfileInput{
		Name:                   "cp1",
		CertificateAuthorities: []CertificateAuthorityInput{{Name: "ca-a", DefaultOcspUrl: new("http://new-a")}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.Certificate) != 1 {
		t.Fatalf("a CA absent from the provided list must be removed, got %+v", e.Certificate)
	}
	ca := e.Certificate[0]
	if strVal(ca.DefaultOcspUrl) != "http://new-a" {
		t.Errorf("default_ocsp_url must take the provided value, got %q", strVal(ca.DefaultOcspUrl))
	}
	if strVal(ca.TemplateName) != "tmpl-a" {
		t.Errorf("a field the caller did not provide must be preserved, got %q", strVal(ca.TemplateName))
	}
	if len(ca.Misc) != 1 {
		t.Errorf("per-CA Misc must survive the merge, got %+v", ca.Misc)
	}
	if len(ca.MiscAttributes) != 1 || ca.MiscAttributes[0].Value != "ca-a-uuid" {
		t.Errorf("per-CA MiscAttributes must survive the merge, got %+v", ca.MiscAttributes)
	}
}

// TestCertificateProfileCAListRemovesAndAdds pins the other half: the provided
// list is authoritative about membership and ordering, and a CA with no stored
// counterpart starts empty.
func TestCertificateProfileCAListRemovesAndAdds(t *testing.T) {
	e := storedCertificateProfile()
	if err := overlayCertificateProfile(e, CertificateProfileInput{
		Name: "cp1",
		CertificateAuthorities: []CertificateAuthorityInput{
			{Name: "ca-b"},
			{Name: "ca-c", DefaultOcspUrl: new("http://new-c")},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.Certificate) != 2 {
		t.Fatalf("expected exactly the two provided CAs, got %+v", e.Certificate)
	}
	if e.Certificate[0].Name != "ca-b" || e.Certificate[1].Name != "ca-c" {
		t.Fatalf("the caller's ordering must be preserved, got %q then %q", e.Certificate[0].Name, e.Certificate[1].Name)
	}
	if strVal(e.Certificate[0].DefaultOcspUrl) != "http://old-b" {
		t.Errorf("a stored value the caller did not provide must survive, got %q", strVal(e.Certificate[0].DefaultOcspUrl))
	}
	if e.Certificate[1].Misc != nil || e.Certificate[1].MiscAttributes != nil {
		t.Errorf("a CA with no stored entry must start empty, got %+v", e.Certificate[1])
	}
}

// TestCertificateProfileOmittedCAListPreserved pins that omitting the list is
// distinct from providing an empty one: the stored CA list is left alone.
func TestCertificateProfileOmittedCAListPreserved(t *testing.T) {
	e := storedCertificateProfile()
	if err := overlayCertificateProfile(e, CertificateProfileInput{Name: "cp1"}); err != nil {
		t.Fatal(err)
	}
	if len(e.Certificate) != 2 {
		t.Fatalf("an omitted CA list must preserve the stored list, got %+v", e.Certificate)
	}
}
