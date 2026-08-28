package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/profiles/password"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

// TestResolveMgtScopeRejectsPanoramaWithTemplate pins that naming both panorama
// and a template tier is an error rather than a precedence question. Resolving
// it silently would write the entry into the template, which pushes it to every
// managed firewall using that template, while the caller believes it landed on
// Panorama. The profile scope rejects the same combination.
func TestResolveMgtScopeRejectsPanoramaWithTemplate(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := administratorParts()

	for _, in := range []MgtScopeInput{
		{Panorama: true, Template: "t1"},
		{Panorama: true, TemplateStack: "s1"},
	} {
		if _, err := resolveMgtScope(d, in, parts); err == nil {
			t.Errorf("%+v must be rejected, not silently resolved to the template", in)
		} else if !strings.Contains(err.Error(), "cannot be combined with panorama") {
			t.Errorf("%+v: unexpected error %q", in, err)
		}
	}
}

// TestPasswordProfileFirewallScope pins the password-profile family's own
// firewall wiring: its parts must build the device's mgt-config location, not a
// Panorama one. Only the administrator family's parts are exercised by the
// resolver tests, so without this a wrong constructor here is invisible.
func TestPasswordProfileFirewallScope(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	loc, err := resolveMgtScope(d, MgtScopeInput{}, passwordProfileParts())
	if err != nil {
		t.Fatalf("firewall password profile scope: %v", err)
	}
	if loc.Ngfw == nil {
		t.Fatalf("password profiles must resolve to the device mgt-config on a firewall: %+v", loc)
	}
	if loc.Panorama != nil || loc.Template != nil || loc.TemplateStack != nil {
		t.Fatalf("a bare firewall request must reach no Panorama location: %+v", loc)
	}
}

// TestPasswordProfilePanoramaScope pins the Panorama, template and
// template-stack constructors in passwordProfileParts. Only the administrator
// family's parts are exercised by the resolver tests, so without this a wrong
// constructor here would be invisible.
//
// Sabotage: returning a zero Location from any of the three Panorama
// constructors in passwordProfileParts turns the matching subtest red.
func TestPasswordProfilePanoramaScope(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	parts := passwordProfileParts()

	for _, tc := range []struct {
		name string
		in   MgtScopeInput
		// want reports whether the expected branch is set and carries the
		// expected values; each case checks only its own branch.
		want func(password.Location) bool
	}{
		{"panorama", MgtScopeInput{Panorama: true}, func(l password.Location) bool {
			return l.Panorama != nil
		}},
		{"template", MgtScopeInput{Template: "t1"}, func(l password.Location) bool {
			return l.Template != nil && l.Template.Template == "t1" &&
				l.Template.PanoramaDevice == defaultPanoramaDevice
		}},
		{"template stack", MgtScopeInput{TemplateStack: "s1"}, func(l password.Location) bool {
			return l.TemplateStack != nil && l.TemplateStack.TemplateStack == "s1" &&
				l.TemplateStack.PanoramaDevice == defaultPanoramaDevice
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := resolveMgtScope(d, tc.in, parts)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !tc.want(loc) {
				t.Fatalf("wrong or empty location: %+v", loc)
			}
			if n := mgtLocationBranches(loc); n != 1 {
				t.Fatalf("exactly one branch must be set, got %d: %+v", n, loc)
			}
		})
	}
}

// mgtLocationBranches counts the set branches of a password profile location, so
// a test can assert that resolving one scope did not also populate another.
func mgtLocationBranches(l password.Location) int {
	return countSet(l.Ngfw != nil, l.Panorama != nil, l.Template != nil, l.TemplateStack != nil)
}

// TestMgtScopeGatingThroughTool pins that a registered management-plane tool
// actually reaches the resolver, so its rejection surfaces as a tool error
// rather than being lost on the way in.
func TestMgtScopeGatingThroughTool(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterPasswordProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_password_profile_list",
		Arguments: map[string]any{"template": "t1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a template on a firewall must surface as a tool error")
	}
	if out := textContent(t, res); !strings.Contains(out, "require a Panorama connection") {
		t.Errorf("unexpected error text: %q", out)
	}
}
