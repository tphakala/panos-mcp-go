package tools

import (
	"github.com/PaloAltoNetworks/pango/device/ssldecrypt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SSL decrypt trust settings (device/ssldecrypt)
// ---------------------------------------------------------------------------
//
// The device's SSL forward-proxy trust settings (the forward trust/untrust
// signing certificates, the trusted root CA list, and the decryption exclude
// lists) are a singleton config, not a named-entry list. pango models them as a
// Config value read and written whole, so this family reuses the system-scope
// singleton get/update handlers.
//
// The location differs from the other system singletons in one way: on a
// firewall these settings are device-wide and live at the shared node (pango
// exposes no per-vsys or system location for them), so the firewall scope
// resolves to Shared here rather than to a System location. The Panorama
// template and template-stack tiers are the same as the other singletons.
//
// The ssl-exclude-cert list is shown by the get summary but is not settable
// through the update tool; a read-modify-write preserves it (and any other
// unmodeled subtree) across updates.

func newSslDecryptService(d *Deps) *ssldecrypt.Service {
	return ssldecrypt.NewService(d.Client)
}

func sslDecryptParts() systemScopeParts[ssldecrypt.Location] {
	return systemScopeParts[ssldecrypt.Location]{
		system: func() ssldecrypt.Location {
			return ssldecrypt.Location{Shared: &ssldecrypt.SharedLocation{}}
		},
		template: func(tmpl string) ssldecrypt.Location {
			return ssldecrypt.Location{Template: &ssldecrypt.TemplateLocation{
				PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ssldecrypt.Location {
			return ssldecrypt.Location{TemplateStack: &ssldecrypt.TemplateStackLocation{
				PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// SslDecryptInput updates the SSL forward-proxy trust settings. Every field is
// optional; only provided fields change, and a provided list replaces the whole
// list. Each certificate reference is the name of an imported certificate.
type SslDecryptInput struct {
	SystemScopeInput
	ForwardTrustCertRsa            *string  `json:"forward_trust_cert_rsa,omitzero" jsonschema:"Name of the RSA certificate that signs trusted forward-proxy sessions"`
	ForwardTrustCertEcdsa          *string  `json:"forward_trust_cert_ecdsa,omitzero" jsonschema:"Name of the ECDSA certificate that signs trusted forward-proxy sessions"`
	ForwardUntrustCertRsa          *string  `json:"forward_untrust_cert_rsa,omitzero" jsonschema:"Name of the RSA certificate that signs untrusted forward-proxy sessions"`
	ForwardUntrustCertEcdsa        *string  `json:"forward_untrust_cert_ecdsa,omitzero" jsonschema:"Name of the ECDSA certificate that signs untrusted forward-proxy sessions"`
	TrustedRootCa                  []string `json:"trusted_root_ca,omitzero" jsonschema:"Trusted root CA certificate names; replaces the whole list when provided"`
	RootCaExcludeList              []string `json:"root_ca_exclude_list,omitzero" jsonschema:"Root CA names excluded from decryption; replaces the whole list when provided"`
	DisabledPredefinedExcludeCerts []string `json:"disabled_predefined_exclude_certs,omitzero" jsonschema:"Predefined SSL-exclude certificate names to disable; replaces the whole list when provided"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlaySslDecrypt(c *ssldecrypt.Config, in SslDecryptInput) error {
	setPtr(&c.ForwardTrustCertificateRsa, in.ForwardTrustCertRsa)
	setPtr(&c.ForwardTrustCertificateEcdsa, in.ForwardTrustCertEcdsa)
	setPtr(&c.ForwardUntrustCertificateRsa, in.ForwardUntrustCertRsa)
	setPtr(&c.ForwardUntrustCertificateEcdsa, in.ForwardUntrustCertEcdsa)
	if in.TrustedRootCa != nil {
		c.TrustedRootCa = in.TrustedRootCa
	}
	if in.RootCaExcludeList != nil {
		c.RootCaExcludeList = in.RootCaExcludeList
	}
	if in.DisabledPredefinedExcludeCerts != nil {
		c.DisabledSslExcludeCertFromPredefined = in.DisabledPredefinedExcludeCerts
	}
	return nil
}

func sslExcludeCertSummaries(certs []ssldecrypt.SslExcludeCert) []any {
	out := make([]any, 0, len(certs))
	for i := range certs {
		c := &certs[i]
		m := map[string]any{
			tagNameKey:     c.Name,
			descriptionKey: strVal(c.Description),
		}
		putBool(m, "exclude", c.Exclude)
		out = append(out, m)
	}
	return out
}

func sslDecryptSummary(c *ssldecrypt.Config) any {
	return map[string]any{
		"forward_trust_cert_rsa":            strVal(c.ForwardTrustCertificateRsa),
		"forward_trust_cert_ecdsa":          strVal(c.ForwardTrustCertificateEcdsa),
		"forward_untrust_cert_rsa":          strVal(c.ForwardUntrustCertificateRsa),
		"forward_untrust_cert_ecdsa":        strVal(c.ForwardUntrustCertificateEcdsa),
		"trusted_root_ca":                   strList(c.TrustedRootCa),
		"root_ca_exclude_list":              strList(c.RootCaExcludeList),
		"disabled_predefined_exclude_certs": strList(c.DisabledSslExcludeCertFromPredefined),
		"exclude_certs":                     sslExcludeCertSummaries(c.SslExcludeCert),
	}
}

// RegisterSslDecryptTools registers the SSL decrypt trust settings tools. The
// update tool is skipped in read-only mode.
func RegisterSslDecryptTools(s *mcp.Server, d *Deps) {
	svc := newSslDecryptService(d)
	parts := sslDecryptParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_decrypt_settings_get",
		Description: "Get the device SSL decrypt trust settings (forward trust/untrust signing certificate names, trusted root CA list, root CA exclude list, disabled predefined exclude-certs, and the SSL exclude-cert list). Firewall: device-wide (shared) scope; Panorama requires template or template_stack. Read-only.",
		Annotations: readOnlyTool("Get SSL decrypt settings"),
	}, systemGetHandler(d, "panos_ssl_decrypt_settings_get", svc, parts, sslDecryptSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ssl_decrypt_settings_update",
		Description: "Update the device SSL decrypt trust settings: read-modify-write, only provided fields change; a provided list replaces the whole list. All certificate references are names of imported certificates. The SSL exclude-cert list is preserved and is not settable here. Run panos_commit to apply.",
		Annotations: updateTool("Update SSL decrypt settings"),
	}, systemUpdateHandler(d, "panos_ssl_decrypt_settings_update", svc, parts, overlaySslDecrypt, sslDecryptSummary))
}
