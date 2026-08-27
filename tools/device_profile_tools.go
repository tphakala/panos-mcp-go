package tools

import (
	"errors"

	certprof "github.com/PaloAltoNetworks/pango/device/profile/certificate"
	ssltls "github.com/PaloAltoNetworks/pango/device/profile/ssltls"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// SSL/TLS service profile (device/profile/ssltls)
// ---------------------------------------------------------------------------

func newSslTlsProfileService(d *Deps) nameFixAdapter[ssltls.Location, ssltls.Entry] {
	return nameFixAdapter[ssltls.Location, ssltls.Entry]{
		svc:    ssltls.NewService(d.Client),
		client: d.Client,
		name:   func(e *ssltls.Entry) string { return e.Name },
	}
}

func sslTlsProfileParts() profileScopeParts[ssltls.Location] {
	return profileScopeParts[ssltls.Location]{
		shared:   func() ssltls.Location { return ssltls.Location{Shared: &ssltls.SharedLocation{}} },
		panorama: func() ssltls.Location { return ssltls.Location{Panorama: &ssltls.PanoramaLocation{}} },
		template: func(pano, tmpl string) ssltls.Location {
			return ssltls.Location{Template: &ssltls.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) ssltls.Location {
			return ssltls.Location{TemplateVsys: &ssltls.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) ssltls.Location {
			return ssltls.Location{TemplateStack: &ssltls.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) ssltls.Location {
			return ssltls.Location{TemplateStackVsys: &ssltls.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// SslTlsProfileInput is the input for the SSL/TLS service profile create and
// update tools. certificate names an existing server certificate (a reference),
// not a secret blob. The min/max TLS version and the algorithm/authentication
// toggles live under pango's ProtocolSettings; an omitted toggle is left
// untouched (tri-state present-true / present-false / absent).
type SslTlsProfileInput struct {
	ProfileScopeInput
	Name        string  `json:"name" jsonschema:"SSL/TLS service profile name"`
	Certificate *string `json:"certificate,omitzero" jsonschema:"Name of the server certificate to present"`
	MinVersion  *string `json:"min_version,omitzero" jsonschema:"Minimum TLS version (tls1-0|tls1-1|tls1-2|tls1-3)"`
	MaxVersion  *string `json:"max_version,omitzero" jsonschema:"Maximum TLS version (tls1-0|tls1-1|tls1-2|tls1-3|max)"`

	AllowAlgorithm3des        *bool `json:"allow_algorithm_3des,omitzero" jsonschema:"Allow the 3DES encryption algorithm"`
	AllowAlgorithmRc4         *bool `json:"allow_algorithm_rc4,omitzero" jsonschema:"Allow the RC4 encryption algorithm"`
	AllowAlgorithmAes128Cbc   *bool `json:"allow_algorithm_aes_128_cbc,omitzero" jsonschema:"Allow the AES-128-CBC encryption algorithm"`
	AllowAlgorithmAes128Gcm   *bool `json:"allow_algorithm_aes_128_gcm,omitzero" jsonschema:"Allow the AES-128-GCM encryption algorithm"`
	AllowAlgorithmAes256Cbc   *bool `json:"allow_algorithm_aes_256_cbc,omitzero" jsonschema:"Allow the AES-256-CBC encryption algorithm"`
	AllowAlgorithmAes256Gcm   *bool `json:"allow_algorithm_aes_256_gcm,omitzero" jsonschema:"Allow the AES-256-GCM encryption algorithm"`
	AllowAlgorithmDhe         *bool `json:"allow_algorithm_dhe,omitzero" jsonschema:"Allow the DHE key-exchange algorithm"`
	AllowAlgorithmEcdhe       *bool `json:"allow_algorithm_ecdhe,omitzero" jsonschema:"Allow the ECDHE key-exchange algorithm"`
	AllowAlgorithmRsa         *bool `json:"allow_algorithm_rsa,omitzero" jsonschema:"Allow the RSA key-exchange algorithm"`
	AllowAuthenticationSha1   *bool `json:"allow_authentication_sha1,omitzero" jsonschema:"Allow the SHA1 authentication algorithm"`
	AllowAuthenticationSha256 *bool `json:"allow_authentication_sha256,omitzero" jsonschema:"Allow the SHA256 authentication algorithm"`
	AllowAuthenticationSha384 *bool `json:"allow_authentication_sha384,omitzero" jsonschema:"Allow the SHA384 authentication algorithm"`
}

// sslTlsHasProtocolSettings reports whether the caller provided any field that
// lives under pango's ProtocolSettings, so applySslTlsProfile allocates that
// sub-struct only on demand and a bare certificate-only create omits it.
func sslTlsHasProtocolSettings(in *SslTlsProfileInput) bool {
	return in.MinVersion != nil || in.MaxVersion != nil ||
		in.AllowAlgorithm3des != nil || in.AllowAlgorithmRc4 != nil ||
		in.AllowAlgorithmAes128Cbc != nil || in.AllowAlgorithmAes128Gcm != nil ||
		in.AllowAlgorithmAes256Cbc != nil || in.AllowAlgorithmAes256Gcm != nil ||
		in.AllowAlgorithmDhe != nil || in.AllowAlgorithmEcdhe != nil ||
		in.AllowAlgorithmRsa != nil ||
		in.AllowAuthenticationSha1 != nil || in.AllowAuthenticationSha256 != nil ||
		in.AllowAuthenticationSha384 != nil
}

// applySslTlsProfile overlays the managed fields onto e, applying only what the
// caller provided. Shared by build and overlay; it never rebuilds e, so an
// unmodeled Misc / MiscAttributes and any protocol-settings sibling the caller
// did not touch round-trip untouched.
func applySslTlsProfile(e *ssltls.Entry, in *SslTlsProfileInput) {
	setPtr(&e.Certificate, in.Certificate)
	if !sslTlsHasProtocolSettings(in) {
		return
	}
	if e.ProtocolSettings == nil {
		e.ProtocolSettings = &ssltls.ProtocolSettings{}
	}
	ps := e.ProtocolSettings
	setPtr(&ps.MinVersion, in.MinVersion)
	setPtr(&ps.MaxVersion, in.MaxVersion)
	setPtr(&ps.AllowAlgorithm3des, in.AllowAlgorithm3des)
	setPtr(&ps.AllowAlgorithmRc4, in.AllowAlgorithmRc4)
	setPtr(&ps.AllowAlgorithmAes128Cbc, in.AllowAlgorithmAes128Cbc)
	setPtr(&ps.AllowAlgorithmAes128Gcm, in.AllowAlgorithmAes128Gcm)
	setPtr(&ps.AllowAlgorithmAes256Cbc, in.AllowAlgorithmAes256Cbc)
	setPtr(&ps.AllowAlgorithmAes256Gcm, in.AllowAlgorithmAes256Gcm)
	setPtr(&ps.AllowAlgorithmDhe, in.AllowAlgorithmDhe)
	setPtr(&ps.AllowAlgorithmEcdhe, in.AllowAlgorithmEcdhe)
	setPtr(&ps.AllowAlgorithmRsa, in.AllowAlgorithmRsa)
	setPtr(&ps.AllowAuthenticationSha1, in.AllowAuthenticationSha1)
	setPtr(&ps.AllowAuthenticationSha256, in.AllowAuthenticationSha256)
	setPtr(&ps.AllowAuthenticationSha384, in.AllowAuthenticationSha384)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildSslTlsProfile(in SslTlsProfileInput) (*ssltls.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ssltls.Entry{Name: in.Name}
	applySslTlsProfile(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlaySslTlsProfile(e *ssltls.Entry, in SslTlsProfileInput) error {
	applySslTlsProfile(e, &in)
	return nil
}

func sslTlsProfileSummary(e *ssltls.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["certificate"] = strVal(e.Certificate)
	if ps := e.ProtocolSettings; ps != nil {
		m["min_version"] = strVal(ps.MinVersion)
		m["max_version"] = strVal(ps.MaxVersion)
		putBool(m, "allow_algorithm_3des", ps.AllowAlgorithm3des)
		putBool(m, "allow_algorithm_rc4", ps.AllowAlgorithmRc4)
		putBool(m, "allow_algorithm_aes_128_cbc", ps.AllowAlgorithmAes128Cbc)
		putBool(m, "allow_algorithm_aes_128_gcm", ps.AllowAlgorithmAes128Gcm)
		putBool(m, "allow_algorithm_aes_256_cbc", ps.AllowAlgorithmAes256Cbc)
		putBool(m, "allow_algorithm_aes_256_gcm", ps.AllowAlgorithmAes256Gcm)
		putBool(m, "allow_algorithm_dhe", ps.AllowAlgorithmDhe)
		putBool(m, "allow_algorithm_ecdhe", ps.AllowAlgorithmEcdhe)
		putBool(m, "allow_algorithm_rsa", ps.AllowAlgorithmRsa)
		putBool(m, "allow_authentication_sha1", ps.AllowAuthenticationSha1)
		putBool(m, "allow_authentication_sha256", ps.AllowAuthenticationSha256)
		putBool(m, "allow_authentication_sha384", ps.AllowAuthenticationSha384)
	}
	return m
}

// RegisterSslTlsProfileTools registers the SSL/TLS service profile tools on both
// firewall and Panorama.
func RegisterSslTlsProfileTools(s *mcp.Server, d *Deps) {
	svc := newSslTlsProfileService(d)
	parts := sslTlsProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_tls_profile_list",
		Description: "List SSL/TLS service profiles. Firewall: shared; Panorama: shared, panorama, template or template_stack. Read-only.",
		Annotations: readOnlyTool("List SSL/TLS service profiles"),
	}, profileListHandler(d, "panos_ssl_tls_profile_list", svc, parts, svc.name, sslTlsProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_tls_profile_get",
		Description: "Get one SSL/TLS service profile (certificate, min/max TLS version, allowed algorithms). Read-only.",
		Annotations: readOnlyTool("Get SSL/TLS service profile"),
	}, profileGetHandler(d, "panos_ssl_tls_profile_get", svc, parts, sslTlsProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_tls_profile_create",
		Description: "Create an SSL/TLS service profile in the candidate config. certificate names an existing server certificate. Run panos_commit to apply.",
		Annotations: createTool("Create SSL/TLS service profile"),
	}, profileCreateHandler(d, "panos_ssl_tls_profile_create", svc, parts, buildSslTlsProfile, sslTlsProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_tls_profile_update",
		Description: "Update an SSL/TLS service profile: read-modify-write, only provided fields change. Run panos_commit to apply.",
		Annotations: updateTool("Update SSL/TLS service profile"),
	}, profileUpdateHandler(d, "panos_ssl_tls_profile_update", svc, parts,
		func(in SslTlsProfileInput) string { return in.Name }, overlaySslTlsProfile, sslTlsProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_tls_profile_delete",
		Description: "Delete an SSL/TLS service profile from the candidate config. Fails while other config still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete SSL/TLS service profile"),
	}, profileDeleteHandler(d, "panos_ssl_tls_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// Certificate profile (device/profile/certificate)
// ---------------------------------------------------------------------------

func newCertificateProfileService(d *Deps) nameFixAdapter[certprof.Location, certprof.Entry] {
	return nameFixAdapter[certprof.Location, certprof.Entry]{
		svc:    certprof.NewService(d.Client),
		client: d.Client,
		name:   func(e *certprof.Entry) string { return e.Name },
	}
}

func certificateProfileParts() profileScopeParts[certprof.Location] {
	return profileScopeParts[certprof.Location]{
		shared:   func() certprof.Location { return certprof.Location{Shared: &certprof.SharedLocation{}} },
		panorama: func() certprof.Location { return certprof.Location{Panorama: &certprof.PanoramaLocation{}} },
		template: func(pano, tmpl string) certprof.Location {
			return certprof.Location{Template: &certprof.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) certprof.Location {
			return certprof.Location{TemplateVsys: &certprof.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) certprof.Location {
			return certprof.Location{TemplateStack: &certprof.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) certprof.Location {
			return certprof.Location{TemplateStackVsys: &certprof.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// CertificateAuthorityInput is one CA entry in a certificate profile's CA list.
type CertificateAuthorityInput struct {
	Name                  string  `json:"name" jsonschema:"Name of the CA certificate (a reference to an imported certificate)"`
	DefaultOcspUrl        *string `json:"default_ocsp_url,omitzero" jsonschema:"Default OCSP responder URL for this CA"`
	OcspVerifyCertificate *string `json:"ocsp_verify_certificate,omitzero" jsonschema:"Name of the certificate used to verify OCSP responses"`
	TemplateName          *string `json:"template_name,omitzero" jsonschema:"Certificate template name"`
}

// CertificateProfileInput is the input for the certificate profile create and
// update tools. The CA list, when provided, is merged onto the stored list by
// name and a CA absent from it is removed; a CA that stays keeps any field the
// caller did not provide, so a field cannot be cleared in place. When the list
// is omitted it is left untouched. All certificate references are names, not
// secret blobs.
type CertificateProfileInput struct {
	ProfileScopeInput
	Name                    string  `json:"name" jsonschema:"Certificate profile name"`
	Domain                  *string `json:"domain,omitzero" jsonschema:"Domain to prepend to the username extracted from the certificate"`
	UsernameFieldSubject    *string `json:"username_field_subject,omitzero" jsonschema:"Certificate subject field to use as the username (e.g. common-name)"`
	UsernameFieldSubjectAlt *string `json:"username_field_subject_alt,omitzero" jsonschema:"Certificate subject-alt field to use as the username (e.g. email, principal-name)"`

	UseCrl           *bool `json:"use_crl,omitzero" jsonschema:"Use a certificate revocation list (CRL)"`
	UseOcsp          *bool `json:"use_ocsp,omitzero" jsonschema:"Use OCSP for revocation checks"`
	OcspExcludeNonce *bool `json:"ocsp_exclude_nonce,omitzero" jsonschema:"Exclude the nonce extension from OCSP requests"`

	BlockExpiredCertificate         *bool `json:"block_expired_certificate,omitzero" jsonschema:"Block sessions with an expired certificate"`
	BlockTimeoutCertificate         *bool `json:"block_timeout_certificate,omitzero" jsonschema:"Block sessions when the revocation status times out"`
	BlockUnknownCertificate         *bool `json:"block_unknown_certificate,omitzero" jsonschema:"Block sessions with an unknown revocation status"`
	BlockUnauthenticatedCertificate *bool `json:"block_unauthenticated_certificate,omitzero" jsonschema:"Block sessions with an unauthenticated certificate"`

	CertificateStatusTimeout *int64 `json:"certificate_status_timeout,omitzero" jsonschema:"Certificate status query timeout in seconds"`
	CrlReceiveTimeout        *int64 `json:"crl_receive_timeout,omitzero" jsonschema:"CRL receive timeout in seconds"`
	OcspReceiveTimeout       *int64 `json:"ocsp_receive_timeout,omitzero" jsonschema:"OCSP receive timeout in seconds"`

	CertificateAuthorities []CertificateAuthorityInput `json:"certificate_authorities,omitzero" jsonschema:"CA certificate list, merged by name; a CA absent from a provided list is removed, a CA that stays keeps any field you do not provide, and an omitted list leaves the CA list unchanged"`
}

// certificateAuthorities maps the input CA list to pango's CA slice in order,
// preserving the caller's ordering and merging each entry by name onto the
// stored one. Seeding from the existing entry keeps whatever this server does
// not model on a CA (its Misc and MiscAttributes XML) instead of dropping it,
// matching the server-list builders in server_profile_tools.go. A CA absent
// from the input is removed.
func certificateAuthorities(in []CertificateAuthorityInput, existing []certprof.Certificate) []certprof.Certificate {
	prev := indexByName(existing, func(c certprof.Certificate) string { return c.Name })
	cas := make([]certprof.Certificate, 0, len(in))
	for i := range in {
		ca := &in[i]
		c := prev[ca.Name]
		c.Name = ca.Name
		setPtr(&c.DefaultOcspUrl, ca.DefaultOcspUrl)
		setPtr(&c.OcspVerifyCertificate, ca.OcspVerifyCertificate)
		setPtr(&c.TemplateName, ca.TemplateName)
		cas = append(cas, c)
	}
	return cas
}

// applyCertificateProfile overlays the managed fields onto e, applying only what
// the caller provided. Shared by build and overlay; it never rebuilds e, so an
// unmodeled Misc / MiscAttributes and any scalar the caller did not touch
// round-trip untouched. A non-nil CertificateAuthorities is merged onto
// e.Certificate by name, so a CA absent from the list is removed while a CA that
// stays keeps its unmodeled XML; a nil one preserves the existing CA list.
// UsernameField is allocated on demand.
func applyCertificateProfile(e *certprof.Entry, in *CertificateProfileInput) {
	setPtr(&e.Domain, in.Domain)
	setPtr(&e.UseCrl, in.UseCrl)
	setPtr(&e.UseOcsp, in.UseOcsp)
	setPtr(&e.OcspExcludeNonce, in.OcspExcludeNonce)
	setPtr(&e.BlockExpiredCertificate, in.BlockExpiredCertificate)
	setPtr(&e.BlockTimeoutCertificate, in.BlockTimeoutCertificate)
	setPtr(&e.BlockUnknownCertificate, in.BlockUnknownCertificate)
	setPtr(&e.BlockUnauthenticatedCertificate, in.BlockUnauthenticatedCertificate)
	setPtr(&e.CertificateStatusTimeout, in.CertificateStatusTimeout)
	setPtr(&e.CrlReceiveTimeout, in.CrlReceiveTimeout)
	setPtr(&e.OcspReceiveTimeout, in.OcspReceiveTimeout)
	if in.UsernameFieldSubject != nil || in.UsernameFieldSubjectAlt != nil {
		if e.UsernameField == nil {
			e.UsernameField = &certprof.UsernameField{}
		}
		setPtr(&e.UsernameField.Subject, in.UsernameFieldSubject)
		setPtr(&e.UsernameField.SubjectAlt, in.UsernameFieldSubjectAlt)
	}
	if in.CertificateAuthorities != nil {
		e.Certificate = certificateAuthorities(in.CertificateAuthorities, e.Certificate)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildCertificateProfile(in CertificateProfileInput) (*certprof.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &certprof.Entry{Name: in.Name}
	applyCertificateProfile(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayCertificateProfile(e *certprof.Entry, in CertificateProfileInput) error {
	applyCertificateProfile(e, &in)
	return nil
}

func certificateAuthoritySummaries(cas []certprof.Certificate) []any {
	out := make([]any, 0, len(cas))
	for i := range cas {
		ca := &cas[i]
		out = append(out, map[string]any{
			tagNameKey:                ca.Name,
			"default_ocsp_url":        strVal(ca.DefaultOcspUrl),
			"ocsp_verify_certificate": strVal(ca.OcspVerifyCertificate),
			"template_name":           strVal(ca.TemplateName),
		})
	}
	return out
}

func certificateProfileSummary(e *certprof.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["domain"] = strVal(e.Domain)
	putBool(m, "use_crl", e.UseCrl)
	putBool(m, "use_ocsp", e.UseOcsp)
	putBool(m, "ocsp_exclude_nonce", e.OcspExcludeNonce)
	putBool(m, "block_expired_certificate", e.BlockExpiredCertificate)
	putBool(m, "block_timeout_certificate", e.BlockTimeoutCertificate)
	putBool(m, "block_unknown_certificate", e.BlockUnknownCertificate)
	putBool(m, "block_unauthenticated_certificate", e.BlockUnauthenticatedCertificate)
	putInt(m, "certificate_status_timeout", e.CertificateStatusTimeout)
	putInt(m, "crl_receive_timeout", e.CrlReceiveTimeout)
	putInt(m, "ocsp_receive_timeout", e.OcspReceiveTimeout)
	if uf := e.UsernameField; uf != nil {
		m["username_field_subject"] = strVal(uf.Subject)
		m["username_field_subject_alt"] = strVal(uf.SubjectAlt)
	}
	m["certificate_authorities"] = certificateAuthoritySummaries(e.Certificate)
	return m
}

// RegisterCertificateProfileTools registers the certificate profile tools on both
// firewall and Panorama.
func RegisterCertificateProfileTools(s *mcp.Server, d *Deps) {
	svc := newCertificateProfileService(d)
	parts := certificateProfileParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_profile_list",
		Description: "List certificate profiles. Firewall: shared; Panorama: shared, panorama, template or template_stack. Read-only.",
		Annotations: readOnlyTool("List certificate profiles"),
	}, profileListHandler(d, "panos_certificate_profile_list", svc, parts, svc.name, certificateProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_profile_get",
		Description: "Get one certificate profile (domain, username fields, revocation settings, CA list). Read-only.",
		Annotations: readOnlyTool("Get certificate profile"),
	}, profileGetHandler(d, "panos_certificate_profile_get", svc, parts, certificateProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_profile_create",
		Description: "Create a certificate profile in the candidate config. All certificate references are names of imported certificates. Run panos_commit to apply.",
		Annotations: createTool("Create certificate profile"),
	}, profileCreateHandler(d, "panos_certificate_profile_create", svc, parts, buildCertificateProfile, certificateProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_profile_update",
		Description: "Update a certificate profile: read-modify-write, only provided fields change. A provided certificate_authorities list is merged by name: a CA absent from it is removed, and a CA that stays keeps any field you do not provide. Run panos_commit to apply.",
		Annotations: updateTool("Update certificate profile"),
	}, profileUpdateHandler(d, "panos_certificate_profile_update", svc, parts,
		func(in CertificateProfileInput) string { return in.Name }, overlayCertificateProfile, certificateProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_profile_delete",
		Description: "Delete a certificate profile from the candidate config. Fails while other config still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete certificate profile"),
	}, profileDeleteHandler(d, "panos_certificate_profile_delete", svc, parts))
}
