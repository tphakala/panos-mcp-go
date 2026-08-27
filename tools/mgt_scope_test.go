package tools

import (
	"strings"
	"testing"

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

// TestMgtScopeGatingThroughTool pins the firewall rejection through a REGISTERED
// tool rather than the resolver alone, so a miswired handler (a family wired to
// the wrong resolver, or a scope never reaching it) turns this red.
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
