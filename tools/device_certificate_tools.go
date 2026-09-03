package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/certificate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Certificate inventory (device/certificate)
// ---------------------------------------------------------------------------
//
// This family exposes the device certificate store read-only: a list and a get
// for inventory and expiry auditing. There is deliberately no create, update or
// delete. Installing a certificate with its key material needs the import
// operation (a multipart upload through the client, not a config set), which is
// outside the CRUD config surface pango models here; a config-set create would
// appear to work and produce an inert certificate. The read-only pair is the
// safe, useful subset.
//
// A certificate entry carries key material (private key, CSR, and the public
// key PEM). certificateSummary never emits any of it: this family is for
// auditing certificates, not exporting keys.
//
// The scope is its own small resolver rather than a shared one, because pango
// models the certificate node at a different set of locations than the object,
// device, profile or system scopes: on a firewall it is per-vsys (there is no
// shared or device-group node for it), and on Panorama it is a template or
// template-stack.

// CertScopeInput selects where certificates live. On a firewall they are
// per-vsys (defaults to vsys1); on Panorama they live in a template or
// template-stack.
type CertScopeInput struct {
	Vsys          string `json:"vsys,omitempty" jsonschema:"Firewall vsys (firewall only; defaults to vsys1)"`
	Template      string `json:"template,omitempty" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitempty" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
}

// resolveCertScope maps a CertScopeInput onto a pango certificate location for
// the connected device type. Firewall resolves to a vsys scope (vsys1 by
// default); Panorama requires exactly one of template or template_stack. Every
// ambiguous cross-tier request is rejected rather than silently resolved: a
// vsys combined with a template tier, a vsys on a Panorama connection, and a
// template on a firewall all error (matching the device-scope resolver, issue
// #117).
func resolveCertScope(d *Deps, in CertScopeInput) (certificate.Location, error) {
	var zero certificate.Location
	switch {
	case in.Template != "" && in.TemplateStack != "":
		return zero, errors.New("set only one of template or template_stack, not both")
	case in.Vsys != "" && (in.Template != "" || in.TemplateStack != ""):
		return zero, errors.New("set only one of vsys (firewall) or template/template_stack (Panorama), not both")
	case in.TemplateStack != "":
		if !d.IsPanorama {
			return zero, errors.New("template_stack requires a Panorama connection")
		}
		return certificate.Location{TemplateStack: &certificate.TemplateStackLocation{
			PanoramaDevice: defaultPanoramaDevice, TemplateStack: in.TemplateStack,
		}}, nil
	case in.Template != "":
		if !d.IsPanorama {
			return zero, errors.New("template requires a Panorama connection")
		}
		return certificate.Location{Template: &certificate.TemplateLocation{
			PanoramaDevice: defaultPanoramaDevice, Template: in.Template,
		}}, nil
	case in.Vsys != "":
		if d.IsPanorama {
			return zero, errors.New("vsys requires a firewall connection; use template or template_stack")
		}
		return certificate.Location{Vsys: &certificate.VsysLocation{
			NgfwDevice: defaultNgfwDevice, Vsys: in.Vsys,
		}}, nil
	case d.IsPanorama:
		return zero, errors.New("template or template_stack is required on Panorama; list templates with panos_template_list")
	default:
		return certificate.Location{Vsys: &certificate.VsysLocation{
			NgfwDevice: defaultNgfwDevice, Vsys: defaultVsys,
		}}, nil
	}
}

// CertListInput lists certificates in one scope.
type CertListInput struct {
	CertScopeInput
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// page exposes the paging triplet to the shared list handler.
//
//nolint:gocritic // hugeParam: the receiver is by value to satisfy the listInput constraint.
func (in CertListInput) page() (limit, offset int, filter string) {
	return in.Limit, in.Offset, in.Filter
}

// CertNameInput names one certificate, for get.
type CertNameInput struct {
	CertScopeInput
	Name string `json:"name" jsonschema:"Certificate name"`
}

// entryName exposes the entry name to the shared get handler.
func (in CertNameInput) entryName() string { return in.Name }

// certificateSummary projects a certificate to its inventory and expiry
// metadata. Key material (the private key, CSR, and public-key PEM) is
// deliberately omitted: this family audits certificates, it does not export
// keys.
func certificateSummary(e *certificate.Entry) any {
	m := map[string]any{
		tagNameKey:         e.Name,
		"subject":          strVal(e.Subject),
		"issuer":           strVal(e.Issuer),
		"common_name":      strVal(e.CommonName),
		"algorithm":        strVal(e.Algorithm),
		statusKey:          strVal(e.Status),
		"not_valid_before": strVal(e.NotValidBefore),
		"not_valid_after":  strVal(e.NotValidAfter),
		"expiry_epoch":     strVal(e.ExpiryEpoch),
	}
	putBool(m, "ca", e.Ca)
	return m
}

// newCertificateService wraps the pango certificate service in nameFixAdapter:
// its name-based Read passes the name straight into XpathWithComponents, which
// rejects a raw (unwrapped) name, so a plain service would fail every get. The
// adapter pre-wraps the name into an entry xpath, exactly as the object
// families do.
func newCertificateService(d *Deps) nameFixAdapter[certificate.Location, certificate.Entry] {
	return nameFixAdapter[certificate.Location, certificate.Entry]{
		svc:    certificate.NewService(d.Client),
		client: d.Client,
		name:   func(e *certificate.Entry) string { return e.Name },
	}
}

// RegisterCertificateTools registers the read-only certificate inventory tools.
// There is no create/update/delete (see the file comment), so the family is
// read-only regardless of the server mode.
func RegisterCertificateTools(s *mcp.Server, d *Deps) {
	svc := newCertificateService(d)
	resolveList := func(in CertListInput) (certificate.Location, error) { return resolveCertScope(d, in.CertScopeInput) }
	resolveGet := func(in CertNameInput) (certificate.Location, error) { return resolveCertScope(d, in.CertScopeInput) }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_list",
		Description: "List certificates (subject, issuer, validity window, expiry epoch, status, CA flag) for inventory and expiry auditing. Firewall: per-vsys (defaults to vsys1); Panorama requires template or template_stack. This is the certificate store, distinct from certificate profiles (panos_certificate_profile_list). Read-only.",
		Annotations: readOnlyTool("List certificates"),
	}, scopedListHandler(d, "panos_certificate_list", svc, resolveList,
		func(e *certificate.Entry) string { return e.Name }, certificateSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_certificate_get",
		Description: "Get one certificate's inventory and expiry metadata (subject, issuer, common name, algorithm, validity window, expiry epoch, CA flag, status). Key material (private key, CSR, public key) is never returned. Read-only.",
		Annotations: readOnlyTool("Get certificate"),
	}, scopedGetHandler(d, "panos_certificate_get", svc, resolveGet, certificateSummary))
}
