package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/profiles/ikecrypto"
)

// ikeCryptoScopeParts is the net-scope parts used across the resolver tests. It
// exercises the common {Ngfw | Template | TemplateStack} shape.
func ikeCryptoScopeParts() netScopeParts[ikecrypto.Location] { return ikeCryptoProfileParts() }

func TestResolveNetScopeFirewall(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	loc, err := resolveNetScope(d, NetScopeInput{}, ikeCryptoScopeParts())
	if err != nil {
		t.Fatal(err)
	}
	// A firewall with no template must resolve to the Ngfw (device) scope. This
	// is the branch every VPN create/get/list on a firewall depends on.
	if loc.Ngfw == nil || loc.Template != nil || loc.TemplateStack != nil {
		t.Fatalf("firewall must resolve to the Ngfw scope, got %+v", loc)
	}
	if loc.Ngfw.NgfwDevice != defaultNgfwDevice {
		t.Fatalf("Ngfw device wrong: %q", loc.Ngfw.NgfwDevice)
	}
}

func TestResolveNetScopePanoramaTemplate(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	loc, err := resolveNetScope(d, NetScopeInput{Template: "edge"}, ikeCryptoScopeParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc.Template == nil || loc.Template.Template != "edge" {
		t.Fatalf("Panorama template scope wrong: %+v", loc)
	}
	if loc.Ngfw != nil || loc.TemplateStack != nil {
		t.Fatalf("only the Template branch must be set: %+v", loc)
	}
}

func TestResolveNetScopePanoramaTemplateStack(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama")
	loc, err := resolveNetScope(d, NetScopeInput{TemplateStack: "stack1"}, ikeCryptoScopeParts())
	if err != nil {
		t.Fatal(err)
	}
	if loc.TemplateStack == nil || loc.TemplateStack.TemplateStack != "stack1" {
		t.Fatalf("Panorama template-stack scope wrong: %+v", loc)
	}
}

func TestResolveNetScopeErrors(t *testing.T) {
	cases := []struct {
		name    string
		model   string
		in      NetScopeInput
		wantErr string
	}{
		{"panorama needs a scope", "Panorama", NetScopeInput{}, "template or template_stack is required on Panorama"},
		{"template on a firewall", "PA-VM", NetScopeInput{Template: "edge"}, "template requires a Panorama connection"},
		{"template_stack on a firewall", "PA-VM", NetScopeInput{TemplateStack: "s"}, "template_stack requires a Panorama connection"},
		{"both set", "Panorama", NetScopeInput{Template: "e", TemplateStack: "s"}, "set only one of template or template_stack"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newTestDeps(t, c.model)
			if _, err := resolveNetScope(d, c.in, ikeCryptoScopeParts()); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

// TestResolveNetScopeNilNgfw pins the template-only resource (the template
// variable): with a nil ngfw part, a bare firewall request must error rather
// than build an invalid location.
func TestResolveNetScopeNilNgfw(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	parts := templateVariableParts()
	if _, err := resolveNetScope(d, NetScopeInput{}, parts); err == nil || !strings.Contains(err.Error(), "template or template_stack is required") {
		t.Fatalf("a template-only resource on a firewall must error: %v", err)
	}
}
