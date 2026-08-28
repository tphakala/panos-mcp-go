package tools

import (
	"encoding/json"
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
		!strings.Contains(err.Error(), "template, template_stack, shared, or panorama") {
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

// TestResolveDeviceScopePanorama pins the Panorama management-plane tier, which
// is what makes Panorama's OWN appliance-level configuration reachable rather
// than only a firewall's or a template's. The tier is Panorama-only: /config/panorama
// exists on a firewall but holds nothing these families live under (MEASURED on a
// PA-VM running PAN-OS 11.2.6: it contained only an empty vsys element), so a
// firewall request is rejected rather than silently retargeted to its vsys.
//
// Sabotage: delete "in.Panorama ||" from the firewall guard in resolveDeviceScope
// and the firewall subcheck goes green by falling through to the vsys scope.
func TestResolveDeviceScopePanorama(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	fw, _ := newTestDeps(t, "PA-VM")
	parts := ldapProfileParts()

	if _, err := resolveDeviceScope(fw, DeviceScopeInput{Panorama: true}, parts); err == nil ||
		!strings.Contains(err.Error(), "Panorama connection") {
		t.Fatalf("panorama on a firewall must be rejected, got %v", err)
	}

	loc, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true}, parts)
	if err != nil {
		t.Fatalf("panorama on Panorama: %v", err)
	}
	if loc.Panorama == nil {
		t.Fatalf("panorama must resolve to the panorama location: %+v", loc)
	}
	if loc.Shared != nil || loc.Template != nil || loc.Vsys != nil {
		t.Fatalf("panorama must not also set another tier: %+v", loc)
	}
}

// assertResolvesToPanorama resolves a panorama request against one family's
// parts and checks the pango location it produced has the Panorama branch set
// and no other branch set alongside it.
//
// It marshals the location rather than naming each family's own Location type,
// so the eight families share one assertion without this file importing eight
// pango packages. Every one of these Location structs tags Panorama as
// `json:"panorama"` with no omitempty, so the key is present either way and an
// unset branch is distinguishable as null. The "no other branch" half matters as
// much as the first: a constructor that filled two branches would build an xpath
// pango rejects, and pango does not enforce exactly-one itself.
func assertResolvesToPanorama[L any](t *testing.T, d *Deps, parts deviceScopeParts[L]) {
	t.Helper()
	loc, err := resolveDeviceScope(d, DeviceScopeInput{Panorama: true}, parts)
	if err != nil {
		t.Fatalf("panorama must resolve: %v", err)
	}
	raw, err := json.Marshal(loc)
	if err != nil {
		t.Fatalf("marshal location: %v", err)
	}
	var branches map[string]json.RawMessage
	if err := json.Unmarshal(raw, &branches); err != nil {
		t.Fatalf("unmarshal location: %v", err)
	}
	if b, ok := branches["panorama"]; !ok || string(b) == "null" {
		t.Fatalf("panorama must fill the Panorama branch: %s", raw)
	}
	for name, b := range branches {
		if name != "panorama" && string(b) != "null" {
			t.Fatalf("panorama must not also set the %q branch: %s", name, raw)
		}
	}
}

// TestResolveDeviceScopePanoramaConstructor pins that every family this server
// offers the tier for actually fills its own Panorama branch. A missing
// constructor is a nil func, so this fails loudly rather than resolving to a
// zero location that would write to the wrong node.
//
// The two families deliberately absent from this list, local users and MFA
// profiles, are covered by TestDevicePanoramaScopeUnavailable instead.
//
// Sabotage: delete the panorama constructor from any one of these parts
// functions and that subtest panics on the nil func.
func TestResolveDeviceScopePanoramaConstructor(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")

	t.Run("ldap", func(t *testing.T) { assertResolvesToPanorama(t, pano, ldapProfileParts()) })
	t.Run("tacacs", func(t *testing.T) { assertResolvesToPanorama(t, pano, tacacsProfileParts()) })
	t.Run("radius", func(t *testing.T) { assertResolvesToPanorama(t, pano, radiusProfileParts()) })
	t.Run("syslog", func(t *testing.T) { assertResolvesToPanorama(t, pano, syslogProfileParts()) })
	t.Run("snmptrap", func(t *testing.T) { assertResolvesToPanorama(t, pano, snmpTrapProfileParts()) })
	t.Run("email", func(t *testing.T) { assertResolvesToPanorama(t, pano, emailProfileParts()) })
	t.Run("samlidp", func(t *testing.T) { assertResolvesToPanorama(t, pano, samlIdpProfileParts()) })
	t.Run("authprofile", func(t *testing.T) { assertResolvesToPanorama(t, pano, authProfileParts()) })
}

// TestResolveDeviceScopePanoramaExclusivity pins that panorama cannot be combined
// with another tier, and that adding it did NOT change the pre-existing
// template+shared divergence.
//
// The asymmetry is deliberate. panorama with a template is rejected because
// resolving it to the template would push the write to every managed firewall
// while the caller believes it landed on the Panorama appliance. shared with a
// template keeps resolving to the template because that is shipped behaviour a
// test already pins; see TestResolveDeviceScopePanoramaTemplate and issue #98.
//
// Sabotage: delete the "in.Shared && in.Panorama" arm from
// validateDeviceScopeExclusivity and the first subcheck resolves with no error;
// delete the template arm and the second and third do.
func TestResolveDeviceScopePanoramaExclusivity(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")
	parts := ldapProfileParts()

	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true, Shared: true}, parts); err == nil ||
		!strings.Contains(err.Error(), "only one of shared or panorama") {
		t.Fatalf("panorama with shared must be rejected, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true, Template: "t1"}, parts); err == nil ||
		!strings.Contains(err.Error(), "cannot be combined with panorama") {
		t.Fatalf("panorama with template must be rejected, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true, TemplateStack: "s1"}, parts); err == nil ||
		!strings.Contains(err.Error(), "cannot be combined with panorama") {
		t.Fatalf("panorama with template_stack must be rejected, got %v", err)
	}

	// The divergence this change deliberately did not widen.
	loc, err := resolveDeviceScope(pano, DeviceScopeInput{Template: "t1", Shared: true}, parts)
	if err != nil || loc.Template == nil {
		t.Fatalf("template with shared must still resolve to the template: loc=%+v err=%v", loc, err)
	}
}

// TestDevicePanoramaScopeUnavailable pins the rejection for the two families
// pango models no Panorama location for. The list is named by
// noPanoramaScopeFamilies.
//
// The usual "add the constructor and watch it go green" sabotage does not compile
// here: device/localdb/user and device/profiles/mfa carry no PanoramaLocation type
// at pango v0.10.3-0.20260731153743, which is the very reason these two are on the
// list. Sabotage instead by deleting the "p.panorama == nil" guard from
// resolvePanoramaDeviceScope: both subchecks then panic on the nil func rather
// than returning the error.
func TestDevicePanoramaScopeUnavailable(t *testing.T) {
	pano, _ := newTestDeps(t, "Panorama")

	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true}, localUserParts()); err == nil ||
		!strings.Contains(err.Error(), "panorama scope is not available") {
		t.Fatalf("panorama on local users must be rejected, got %v", err)
	}
	if _, err := resolveDeviceScope(pano, DeviceScopeInput{Panorama: true}, mfaProfileParts()); err == nil ||
		!strings.Contains(err.Error(), "panorama scope is not available") {
		t.Fatalf("panorama on MFA profiles must be rejected, got %v", err)
	}
}
