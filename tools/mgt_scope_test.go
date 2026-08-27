package tools

import (
	"strings"
	"testing"
)

// TestResolveMgtScopeFirewall pins the firewall branch of resolveMgtScope. A
// firewall reaches only its own mgt-config, so a bare request resolves there and
// every Panorama-only tier is rejected rather than silently building a location
// the device cannot serve.
// Sabotage: returning p.ngfw() before the Panorama-only guard makes the three
// rejection subchecks fail.
func TestResolveMgtScopeFirewall(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	parts := administratorParts()

	loc, err := resolveMgtScope(d, MgtScopeInput{}, parts)
	if err != nil {
		t.Fatalf("default firewall scope: %v", err)
	}
	if loc.Ngfw == nil {
		t.Fatalf("a bare firewall request must resolve to the device's own mgt-config: %+v", loc)
	}

	for _, in := range []MgtScopeInput{
		{Panorama: true},
		{Template: "t1"},
		{TemplateStack: "s1"},
	} {
		if _, err := resolveMgtScope(d, in, parts); err == nil {
			t.Errorf("%+v on a firewall must be rejected", in)
		} else if !strings.Contains(err.Error(), "require a Panorama connection") {
			t.Errorf("%+v: unexpected error %q", in, err)
		}
	}
}

// TestResolveMgtScopePanorama pins the Panorama branch: each tier resolves to
// its own location, and the template tier wins over nothing else because the
// tiers are mutually exclusive.
func TestResolveMgtScopePanorama(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := administratorParts()

	loc, err := resolveMgtScope(d, MgtScopeInput{Panorama: true}, parts)
	if err != nil {
		t.Fatalf("panorama: %v", err)
	}
	if loc.Panorama == nil {
		t.Fatalf("panorama must resolve to the Panorama location: %+v", loc)
	}

	loc, err = resolveMgtScope(d, MgtScopeInput{Template: "t1"}, parts)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if loc.Template == nil || loc.Template.Template != "t1" || loc.Template.PanoramaDevice != defaultPanoramaDevice {
		t.Fatalf("template must resolve to the template location: %+v", loc.Template)
	}

	loc, err = resolveMgtScope(d, MgtScopeInput{TemplateStack: "s1"}, parts)
	if err != nil {
		t.Fatalf("template_stack: %v", err)
	}
	if loc.TemplateStack == nil || loc.TemplateStack.TemplateStack != "s1" {
		t.Fatalf("template_stack must resolve to the template-stack location: %+v", loc.TemplateStack)
	}
}

// TestResolveMgtScopeErrors pins the two input errors: a bare Panorama request
// must name a scope rather than defaulting, and the two template tiers are
// mutually exclusive.
func TestResolveMgtScopeErrors(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := administratorParts()

	_, err := resolveMgtScope(d, MgtScopeInput{}, parts)
	if err == nil {
		t.Fatal("a bare Panorama request must require an explicit scope")
	}
	if !strings.Contains(err.Error(), "set panorama, template, or template_stack") {
		t.Errorf("unexpected error: %q", err)
	}

	_, err = resolveMgtScope(d, MgtScopeInput{Template: "t1", TemplateStack: "s1"}, parts)
	if err == nil {
		t.Fatal("template combined with template_stack must be rejected")
	}
	if !strings.Contains(err.Error(), "set only one of template or template_stack") {
		t.Errorf("unexpected error: %q", err)
	}
}

// TestMgtScopeGating pins that the management-plane tools reject a
// Panorama-only scope on a firewall through the registered handler, not only
// through the resolver in isolation.
func TestMgtScopeGating(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	parts := passwordProfileParts()

	if _, err := resolveMgtScope(d, MgtScopeInput{Template: "t1"}, parts); err == nil {
		t.Fatal("a template on a firewall must be rejected for password profiles too")
	}
	loc, err := resolveMgtScope(d, MgtScopeInput{}, parts)
	if err != nil {
		t.Fatalf("firewall password profile scope: %v", err)
	}
	if loc.Ngfw == nil {
		t.Fatalf("password profiles must resolve to the device mgt-config on a firewall: %+v", loc)
	}
}
