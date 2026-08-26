package tools

import (
	"strings"
	"testing"
)

// TestResolveDeviceScopeFirewall pins the firewall branch of resolveDeviceScope
// using ldap parts (which supply a shared constructor). Default resolves to the
// vsys scope with the default ngfw device and vsys1; an explicit vsys is honored;
// shared resolves to the shared location; a template on a firewall is rejected.
// Sabotage: dropping the cmp.Or default makes the default-vsys subcheck fail.
func TestResolveDeviceScopeFirewall(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	parts := ldapProfileParts()

	loc, err := resolveDeviceScope(d, DeviceScopeInput{}, parts)
	if err != nil {
		t.Fatalf("default firewall scope: %v", err)
	}
	if loc.Vsys == nil || loc.Vsys.Vsys != "vsys1" || loc.Vsys.NgfwDevice != defaultNgfwDevice {
		t.Fatalf("default must resolve to vsys1 on the default device: %+v", loc.Vsys)
	}

	loc, err = resolveDeviceScope(d, DeviceScopeInput{Vsys: "vsys2"}, parts)
	if err != nil {
		t.Fatalf("explicit vsys: %v", err)
	}
	if loc.Vsys == nil || loc.Vsys.Vsys != "vsys2" {
		t.Fatalf("explicit vsys must be honored: %+v", loc.Vsys)
	}

	loc, err = resolveDeviceScope(d, DeviceScopeInput{Shared: true}, parts)
	if err != nil {
		t.Fatalf("firewall shared: %v", err)
	}
	if loc.Shared == nil {
		t.Fatalf("shared must resolve to the shared location: %+v", loc)
	}

	if _, err := resolveDeviceScope(d, DeviceScopeInput{Template: "t1"}, parts); err == nil ||
		!strings.Contains(err.Error(), "Panorama connection") {
		t.Fatalf("template on a firewall must be rejected, got %v", err)
	}
}

// TestResolveDeviceScopePanorama pins the Panorama branch of resolveDeviceScope
// using ldap parts: template, template+template_vsys, template_stack,
// template_stack+template_vsys, and shared each resolve to the matching location,
// and a bare Panorama connection with no scope is rejected.
// TestResolveDeviceScopePanoramaTemplate pins the Panorama template branches of
// resolveDeviceScope: a template, and a template narrowed to a vsys.
func TestResolveDeviceScopePanoramaTemplate(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := ldapProfileParts()

	loc, err := resolveDeviceScope(d, DeviceScopeInput{Template: "t1"}, parts)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if loc.Template == nil || loc.Template.Template != "t1" || loc.Template.PanoramaDevice != defaultPanoramaDevice {
		t.Fatalf("template must resolve to the template location: %+v", loc.Template)
	}

	loc, err = resolveDeviceScope(d, DeviceScopeInput{Template: "t1", TemplateVsys: "vsys3"}, parts)
	if err != nil {
		t.Fatalf("template_vsys: %v", err)
	}
	if loc.TemplateVsys == nil || loc.TemplateVsys.Template != "t1" || loc.TemplateVsys.Vsys != "vsys3" {
		t.Fatalf("template+template_vsys must resolve to the template-vsys location: %+v", loc.TemplateVsys)
	}
}

// TestResolveDeviceScopePanoramaStackAndShared pins the Panorama template-stack
// and shared branches of resolveDeviceScope, and that a bare Panorama connection
// with no scope is rejected.
func TestResolveDeviceScopePanoramaStackAndShared(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := ldapProfileParts()

	loc, err := resolveDeviceScope(d, DeviceScopeInput{TemplateStack: "s1"}, parts)
	if err != nil {
		t.Fatalf("template_stack: %v", err)
	}
	if loc.TemplateStack == nil || loc.TemplateStack.TemplateStack != "s1" {
		t.Fatalf("template_stack must resolve to the template-stack location: %+v", loc.TemplateStack)
	}

	loc, err = resolveDeviceScope(d, DeviceScopeInput{TemplateStack: "s1", TemplateVsys: "vsys3"}, parts)
	if err != nil {
		t.Fatalf("template_stack_vsys: %v", err)
	}
	if loc.TemplateStackVsys == nil || loc.TemplateStackVsys.TemplateStack != "s1" || loc.TemplateStackVsys.Vsys != "vsys3" {
		t.Fatalf("template_stack+template_vsys must resolve to the template-stack-vsys location: %+v", loc.TemplateStackVsys)
	}

	loc, err = resolveDeviceScope(d, DeviceScopeInput{Shared: true}, parts)
	if err != nil {
		t.Fatalf("panorama shared: %v", err)
	}
	if loc.Shared == nil {
		t.Fatalf("shared must resolve to the shared location on Panorama: %+v", loc)
	}

	if _, err := resolveDeviceScope(d, DeviceScopeInput{}, parts); err == nil ||
		!strings.Contains(err.Error(), "template, template_stack, or shared") {
		t.Fatalf("a bare Panorama connection must require an explicit scope, got %v", err)
	}
}

// TestResolveDeviceScopeErrors pins the input-validation errors shared by both
// device types, and the log-settings profiles' lack of a shared scope: syslog
// parts supply no shared constructor, so a shared request is rejected on both a
// firewall and Panorama. Sabotage: making the shared field non-nil in
// syslogProfileParts turns the two "no shared" subchecks green.
func TestResolveDeviceScopeErrors(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	fw, _ := newTestDeps(t, "PA-VM")
	ldapParts := ldapProfileParts()
	syslogParts := syslogProfileParts()

	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "t1", TemplateStack: "s1"}, ldapParts); err == nil ||
		!strings.Contains(err.Error(), "only one of template or template_stack") {
		t.Fatalf("template and template_stack together must be rejected, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{TemplateVsys: "vsys3"}, ldapParts); err == nil ||
		!strings.Contains(err.Error(), "template_vsys requires") {
		t.Fatalf("template_vsys without template/template_stack must be rejected, got %v", err)
	}

	// syslog (log-settings) has no shared scope on either device type.
	if _, err := resolveDeviceScope(fw, DeviceScopeInput{Shared: true}, syslogParts); err == nil ||
		!strings.Contains(err.Error(), "shared scope is not available") {
		t.Fatalf("shared on a firewall must be rejected for a log-settings profile, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Shared: true}, syslogParts); err == nil ||
		!strings.Contains(err.Error(), "shared scope is not available") {
		t.Fatalf("shared on Panorama must be rejected for a log-settings profile, got %v", err)
	}

	// syslog still resolves to a firewall vsys and a Panorama template normally.
	if loc, err := resolveDeviceScope(fw, DeviceScopeInput{}, syslogParts); err != nil || loc.Vsys == nil {
		t.Fatalf("syslog default firewall scope must resolve to vsys: loc=%+v err=%v", loc, err)
	}
	if loc, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "t1"}, syslogParts); err != nil || loc.Template == nil {
		t.Fatalf("syslog template scope must resolve: loc=%+v err=%v", loc, err)
	}
}
