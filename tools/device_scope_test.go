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

	// The device scope resolves a template combined with shared to the template,
	// where the profile scope rejects the same combination. That difference is
	// why the two resolvers share only their template tier and not their
	// cross-tier rules, so it is pinned here rather than left to inference.
	loc, err = resolveDeviceScope(d, DeviceScopeInput{Template: "t1", Shared: true}, parts)
	if err != nil {
		t.Fatalf("template combined with shared must resolve, not error: %v", err)
	}
	if loc.Template == nil || loc.Template.Template != "t1" {
		t.Fatalf("template must win over shared in the device scope: %+v", loc)
	}
	if loc.Shared != nil {
		t.Fatalf("template must win over shared in the device scope, got the shared location: %+v", loc)
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
// device types, and a no-shared family's lack of a shared scope: email parts
// supply no shared constructor, so a shared request is rejected on both a
// firewall and Panorama. The exemplar is email rather than syslog because pango
// models no shared location for email at all, while syslog has one and this
// server now exposes it (see noSharedScopeProfiles and
// TestResolveDeviceScopeSyslogShared). Sabotage: making the shared field non-nil
// in emailProfileParts turns the two "no shared" subchecks green.
func TestResolveDeviceScopeErrors(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	fw, _ := newTestDeps(t, "PA-VM")
	ldapParts := ldapProfileParts()
	emailParts := emailProfileParts()

	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "t1", TemplateStack: "s1"}, ldapParts); err == nil ||
		!strings.Contains(err.Error(), "only one of template or template_stack") {
		t.Fatalf("template and template_stack together must be rejected, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{TemplateVsys: "vsys3"}, ldapParts); err == nil ||
		!strings.Contains(err.Error(), "template_vsys requires") {
		t.Fatalf("template_vsys without template/template_stack must be rejected, got %v", err)
	}

	// email (log-settings) has no shared scope on either device type.
	if _, err := resolveDeviceScope(fw, DeviceScopeInput{Shared: true}, emailParts); err == nil ||
		!strings.Contains(err.Error(), "shared scope is not available") {
		t.Fatalf("shared on a firewall must be rejected for a no-shared profile, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Shared: true}, emailParts); err == nil ||
		!strings.Contains(err.Error(), "shared scope is not available") {
		t.Fatalf("shared on Panorama must be rejected for a no-shared profile, got %v", err)
	}

	// email still resolves to a firewall vsys and a Panorama template normally.
	if loc, err := resolveDeviceScope(fw, DeviceScopeInput{}, emailParts); err != nil || loc.Vsys == nil {
		t.Fatalf("email default firewall scope must resolve to vsys: loc=%+v err=%v", loc, err)
	}
	if loc, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "t1"}, emailParts); err != nil || loc.Template == nil {
		t.Fatalf("email template scope must resolve: loc=%+v err=%v", loc, err)
	}
}

// TestResolveDeviceScopeSyslogShared pins the shared scope this server now
// exposes for syslog on both device types. syslog was grouped with the other
// log-settings profiles as having no shared scope until it was measured: pango
// models one (device/profiles/syslog/location.go:14, XpathPrefix at :187 emitting
// config/shared), and one PA-VM on PAN-OS 11.2.6 answered an XML API get of
// /config/shared/log-settings/syslog with status="success" code="19"
// total-count="1" holding a pre-existing operator-created profile. Scope of that
// evidence: one firewall, one PAN-OS version; the Panorama half is exposed
// because pango addresses it the same way, NOT because it was measured.
//
// Sabotage: delete the shared constructor from syslogProfileParts and both
// subchecks fail with "shared scope is not available".
func TestResolveDeviceScopeSyslogShared(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	fw, _ := newTestDeps(t, "PA-VM")
	parts := syslogProfileParts()

	loc, err := resolveDeviceScope(fw, DeviceScopeInput{Shared: true}, parts)
	if err != nil || loc.Shared == nil {
		t.Fatalf("shared syslog on a firewall must resolve to the shared location: loc=%+v err=%v", loc, err)
	}
	loc, err = resolveDeviceScope(pano, DeviceScopeInput{Shared: true}, parts)
	if err != nil || loc.Shared == nil {
		t.Fatalf("shared syslog on Panorama must resolve to the shared location: loc=%+v err=%v", loc, err)
	}
}
