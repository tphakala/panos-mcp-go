package tools

import (
	"strings"
	"testing"
)

// TestResolveProfileScopeFirewallShared pins the firewall branch of
// resolveProfileScope: both the default (nothing set) and an explicit shared
// resolve to the shared location, since these profiles have no firewall vsys
// scope; a template on a firewall is rejected. Sabotage: deleting the firewall
// template/template_stack/panorama rejection makes the template case fall through
// to p.shared() and fail the error assertion.
func TestResolveProfileScopeFirewallShared(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	parts := sslTlsProfileParts()

	loc, err := resolveProfileScope(d, ProfileScopeInput{}, parts)
	if err != nil {
		t.Fatalf("default firewall scope: %v", err)
	}
	if loc.Shared == nil {
		t.Fatalf("default must resolve to the shared location on a firewall: %+v", loc)
	}

	loc, err = resolveProfileScope(d, ProfileScopeInput{Shared: true}, parts)
	if err != nil {
		t.Fatalf("firewall shared: %v", err)
	}
	if loc.Shared == nil {
		t.Fatalf("shared must resolve to the shared location: %+v", loc)
	}

	if _, err := resolveProfileScope(d, ProfileScopeInput{Template: "t1"}, parts); err == nil ||
		!strings.Contains(err.Error(), "Panorama connection") {
		t.Fatalf("template on a firewall must be rejected, got %v", err)
	}
}

// TestResolveProfileScopePanoramaRequiresSelection pins that a bare Panorama
// connection with no scope selected is rejected, naming the valid choices.
// Sabotage: replacing the default-branch error with a returned location (e.g.
// p.shared()) makes err nil and fails.
func TestResolveProfileScopePanoramaRequiresSelection(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := sslTlsProfileParts()

	if _, err := resolveProfileScope(d, ProfileScopeInput{}, parts); err == nil ||
		!strings.Contains(err.Error(), "shared, panorama, template, or template_stack") {
		t.Fatalf("a bare Panorama connection must require an explicit scope, got %v", err)
	}

	// The panorama and shared scopes both resolve normally on Panorama.
	if loc, err := resolveProfileScope(d, ProfileScopeInput{Panorama: true}, parts); err != nil || loc.Panorama == nil {
		t.Fatalf("panorama scope must resolve: loc=%+v err=%v", loc, err)
	}
	if loc, err := resolveProfileScope(d, ProfileScopeInput{Shared: true}, parts); err != nil || loc.Shared == nil {
		t.Fatalf("shared scope must resolve on Panorama: loc=%+v err=%v", loc, err)
	}
}

// TestResolveProfileScopeRejectsCrossTier pins the "exactly one scope" contract:
// a template (or template_stack) combined with shared or panorama is rejected
// rather than silently resolving to the template scope. Sabotage: deleting the
// cross-tier guard in resolveProfileScope lets template+shared fall through to
// the template branch and return no error.
func TestResolveProfileScopeRejectsCrossTier(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := sslTlsProfileParts()

	if _, err := resolveProfileScope(d, ProfileScopeInput{Template: "t1", Shared: true}, parts); err == nil ||
		!strings.Contains(err.Error(), "exactly one scope") {
		t.Fatalf("template + shared must be rejected, got %v", err)
	}
	if _, err := resolveProfileScope(d, ProfileScopeInput{TemplateStack: "s1", Panorama: true}, parts); err == nil ||
		!strings.Contains(err.Error(), "exactly one scope") {
		t.Fatalf("template_stack + panorama must be rejected, got %v", err)
	}
}

// TestResolveProfileScopeTemplateVsys pins that a template narrowed to a
// template_vsys routes to the TemplateVsys constructor carrying both the template
// and the vsys. Sabotage: routing the template_vsys case to the plain template
// constructor drops the vsys and leaves loc.TemplateVsys nil, failing this.
func TestResolveProfileScopeTemplateVsys(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := sslTlsProfileParts()

	loc, err := resolveProfileScope(d, ProfileScopeInput{Template: "tmpl-a", TemplateVsys: "vsys3"}, parts)
	if err != nil {
		t.Fatalf("template_vsys: %v", err)
	}
	if loc.TemplateVsys == nil || loc.TemplateVsys.Template != "tmpl-a" || loc.TemplateVsys.Vsys != "vsys3" {
		t.Fatalf("template+template_vsys must resolve to the template-vsys location: %+v", loc.TemplateVsys)
	}

	// A template_stack narrowed to a vsys routes to the template-stack-vsys form.
	loc, err = resolveProfileScope(d, ProfileScopeInput{TemplateStack: "stk-a", TemplateVsys: "vsys3"}, parts)
	if err != nil {
		t.Fatalf("template_stack_vsys: %v", err)
	}
	if loc.TemplateStackVsys == nil || loc.TemplateStackVsys.TemplateStack != "stk-a" || loc.TemplateStackVsys.Vsys != "vsys3" {
		t.Fatalf("template_stack+template_vsys must resolve to the template-stack-vsys location: %+v", loc.TemplateStackVsys)
	}
}
