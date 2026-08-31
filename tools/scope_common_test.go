package tools

import "testing"

// TestResolveTemplateTierGuardsNilVsysConstructors pins the nil guard added for
// issue #109: templateScopeParts leaves the two vsys-narrowed constructors nil
// for a scope with no vsys level (the management scope is one such). No
// registered family both leaves them nil and exposes a template_vsys field, so
// this path is unreachable through any tool today; the guard turns that latent
// nil-call panic for the next family into a clear error, and this test exercises
// it directly.
//
// Sabotage: delete either "if p.templateVsys == nil" / "if p.templateStackVsys
// == nil" guard from resolveTemplateTier; the matching sub-test then panics with
// a nil function call instead of returning an error.
func TestResolveTemplateTierGuardsNilVsysConstructors(t *testing.T) {
	// Only the non-vsys constructors are populated, mirroring a scope with no
	// vsys level. The vsys-narrowed ones are deliberately nil.
	p := templateScopeParts[string]{
		template:      func(_, tmpl string) string { return "tmpl:" + tmpl },
		templateStack: func(_, stack string) string { return "stack:" + stack },
	}

	t.Run("template with vsys and nil constructor errors", func(t *testing.T) {
		if _, ok, err := resolveTemplateTier("t1", "", "vsys2", p); err == nil || ok {
			t.Fatalf("want an error and ok=false, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("template_stack with vsys and nil constructor errors", func(t *testing.T) {
		if _, ok, err := resolveTemplateTier("", "st1", "vsys2", p); err == nil || ok {
			t.Fatalf("want an error and ok=false, got ok=%v err=%v", ok, err)
		}
	})

	// The non-vsys paths still resolve through the populated constructors, and a
	// request naming neither tier reports ok=false with no error.
	t.Run("template without vsys resolves", func(t *testing.T) {
		if loc, ok, err := resolveTemplateTier("t1", "", "", p); err != nil || !ok || loc != "tmpl:t1" {
			t.Fatalf("want (tmpl:t1, true, nil), got (%q, %v, %v)", loc, ok, err)
		}
	})
	t.Run("template_stack without vsys resolves", func(t *testing.T) {
		if loc, ok, err := resolveTemplateTier("", "st1", "", p); err != nil || !ok || loc != "stack:st1" {
			t.Fatalf("want (stack:st1, true, nil), got (%q, %v, %v)", loc, ok, err)
		}
	})
	t.Run("neither tier reports ok false", func(t *testing.T) {
		if loc, ok, err := resolveTemplateTier("", "", "", p); err != nil || ok || loc != "" {
			t.Fatalf("want (\"\", false, nil), got (%q, %v, %v)", loc, ok, err)
		}
	})
}
