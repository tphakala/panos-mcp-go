package tools

import (
	"net/url"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/movement"
	"github.com/PaloAltoNetworks/pango/policies/rules/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ruleEntryXML renders one canned security rule entry in the standard
// any/any allow shape the rule tests expect.
func ruleEntryXML(name string) string {
	return `<entry name="` + name + `"><action>allow</action>` +
		`<from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<application><member>any</member></application><service><member>application-default</member></service>` +
		`<description>` + name + ` desc</description><tag><member>t1</member></tag></entry>`
}

// ruleGetBody answers a single-entry read (pango requires exactly one entry).
func ruleGetBody(name string) string {
	return `<response status="success"><result>` + ruleEntryXML(name) + `</result></response>`
}

// securityRuleListBody lists three rules in rulebase order; the list xpath
// ends at .../security/rules/entry, so <entry> children sit directly under
// <result>.
var securityRuleListBody = `<response status="success"><result>` +
	ruleEntryXML("rule-a") + ruleEntryXML("rule-b") + ruleEntryXML("rule-c") +
	`</result></response>`

// createMoveListBody is the rulebase as MoveGroup lists it right after a
// create: the new rule sits at the bottom, so moving it to the top requires
// a real move operation.
var createMoveListBody = `<response status="success"><result>` +
	ruleEntryXML("rule-a") + ruleEntryXML("rule-b") + ruleEntryXML("allow-web") +
	`</result></response>`

// getEntryXpath matches a config get whose xpath targets one named entry, so
// a test can serve the single-entry read distinctly from the rulebase list
// read (both are type=config action=get; the fake serves the first match, so
// register this BEFORE a generic configAction("get") route).
func getEntryXpath(name string) func(url.Values) bool {
	return func(v url.Values) bool {
		return v.Get("type") == "config" && v.Get("action") == "get" &&
			strings.Contains(v.Get("xpath"), "entry[@name='"+name+"']")
	}
}

func securityResolve(d *Deps) func(LocationInput) (security.Location, error) {
	return func(in LocationInput) (security.Location, error) {
		return resolveLocation(d, in, securityParts())
	}
}

func securityRuleName(e *security.Entry) string { return e.Name }

func TestMovePosition(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if p, err := movePosition("top", ""); err != nil {
			t.Fatal(err)
		} else if _, ok := p.(movement.PositionFirst); !ok {
			t.Fatalf("top => %T, want PositionFirst", p)
		}
		if p, err := movePosition("bottom", ""); err != nil {
			t.Fatal(err)
		} else if _, ok := p.(movement.PositionLast); !ok {
			t.Fatalf("bottom => %T, want PositionLast", p)
		}
		if p, err := movePosition("before", "rule-a"); err != nil {
			t.Fatal(err)
		} else if b, ok := p.(movement.PositionBefore); !ok || b.Pivot != "rule-a" || !b.Directly {
			t.Fatalf("before => %#v, want directly-before rule-a", p)
		}
		if p, err := movePosition("after", "rule-a"); err != nil {
			t.Fatal(err)
		} else if a, ok := p.(movement.PositionAfter); !ok || a.Pivot != "rule-a" || !a.Directly {
			t.Fatalf("after => %#v, want directly-after rule-a", p)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		for _, c := range []struct{ pos, rel string }{
			{"before", ""}, {"after", ""}, // pivot required
			{"top", "rule-a"}, {"bottom", "rule-a"}, // pivot rejected
			{"sideways", ""}, {"", ""}, // unknown and empty position
		} {
			if _, err := movePosition(c.pos, c.rel); err == nil {
				t.Errorf("movePosition(%q, %q) must error", c.pos, c.rel)
			}
		}
	})
}

//nolint:gocyclo // exhaustive field-by-field assertions on the built entry; each || is one field check.
func TestBuildSecurityRuleEntry(t *testing.T) {
	e, err := buildSecurityRuleEntry(SecurityRuleInput{Name: "r1", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]string{
		"from": e.From, "to": e.To, "source": e.Source, "destination": e.Destination, "application": e.Application,
	} {
		if len(got) != 1 || got[0] != "any" {
			t.Errorf("%s must default to [any], got %v", name, got)
		}
	}
	if len(e.Service) != 1 || e.Service[0] != "application-default" {
		t.Errorf("service must default to [application-default], got %v", e.Service)
	}
	if strVal(e.Action) != "deny" {
		t.Errorf("action = %v, want deny", e.Action)
	}
	if e.Description != nil || e.Disabled != nil || e.Tag != nil {
		t.Errorf("unset optional fields must stay unset: %v %v %v", e.Description, e.Disabled, e.Tag)
	}

	// Explicit values must suppress every default.
	e, err = buildSecurityRuleEntry(SecurityRuleInput{
		Name: "r2", Action: "allow",
		From: []string{"dmz"}, To: []string{"trust"},
		Source: []string{"10.0.0.0/8"}, Destination: []string{"web-srv"},
		Application: []string{"ssl"}, Service: []string{"tcp-8443"},
		Description: "d", Tags: []string{"t"}, Disabled: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.From[0] != "dmz" || e.To[0] != "trust" || e.Source[0] != "10.0.0.0/8" ||
		e.Destination[0] != "web-srv" || e.Application[0] != "ssl" || e.Service[0] != "tcp-8443" {
		t.Errorf("explicit fields must not be defaulted: %+v", e)
	}
	if strVal(e.Description) != "d" || len(e.Tag) != 1 || e.Disabled == nil || !*e.Disabled {
		t.Errorf("optional fields not carried: %+v", e)
	}
}

func TestBuildSecurityRuleEntryRejects(t *testing.T) {
	for _, c := range []struct {
		name, wantErr string
		in            SecurityRuleInput
	}{
		{"no name", "name", SecurityRuleInput{Action: "allow"}},
		{"no action", "action", SecurityRuleInput{Name: "r1"}},
		{"invalid action", "action", SecurityRuleInput{Name: "r1", Action: "permit"}},
	} {
		_, err := buildSecurityRuleEntry(c.in)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		// Assert the error is about the field it should be, so the action
		// cases cannot pass on an unrelated error (a same-error collapse).
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q must mention %q", c.name, err, c.wantErr)
		}
	}
}

//nolint:gocyclo // exhaustive overlay field assertions across the empty, replace and reject scenarios.
func TestOverlaySecurityRuleFields(t *testing.T) {
	base := func() *security.Entry {
		return &security.Entry{
			Name: "r1", Action: ptr("allow"),
			From: []string{"any"}, To: []string{"any"},
			Source: []string{"any"}, Destination: []string{"any"},
			Application: []string{"any"}, Service: []string{"application-default"},
			Description: ptr("old"), Tag: []string{"t1"}, Disabled: ptr(false),
		}
	}

	// An empty input changes nothing.
	e := base()
	if err := overlaySecurityRule(e, SecurityRuleInput{Name: "r1"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Action) != "allow" || e.From[0] != "any" || strVal(e.Description) != "old" || len(e.Tag) != 1 || *e.Disabled {
		t.Fatalf("empty overlay must not change the entry: %+v", e)
	}

	// All six match lists replace when provided non-empty. Every one is
	// exercised so that dropping any single "e.X = in.X" line fails here.
	e = base()
	err := overlaySecurityRule(e, SecurityRuleInput{
		Name: "r1", Action: "deny",
		From: []string{"dmz"}, To: []string{"untrust"},
		Source: []string{"10.0.0.0/8"}, Destination: []string{"192.0.2.0/24"},
		Application: []string{"ssl"}, Service: []string{"tcp-8443"},
		Description: "new", Tags: []string{}, Disabled: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.From[0] != "dmz" || e.To[0] != "untrust" || e.Source[0] != "10.0.0.0/8" ||
		e.Destination[0] != "192.0.2.0/24" || e.Application[0] != "ssl" || e.Service[0] != "tcp-8443" {
		t.Fatalf("all six match lists must replace when non-empty: %+v", e)
	}
	if strVal(e.Action) != "deny" || strVal(e.Description) != "new" || len(e.Tag) != 0 || !*e.Disabled {
		t.Fatalf("action/description/tags/disabled overlay wrong: %+v", e)
	}

	// An EMPTY match list leaves the field unchanged (a rule cannot have zero
	// zones; reset is expressed as ["any"]).
	e = base()
	if err := overlaySecurityRule(e, SecurityRuleInput{Name: "r1", To: []string{}}); err != nil {
		t.Fatal(err)
	}
	if len(e.To) != 1 || e.To[0] != "any" {
		t.Fatalf("empty to list must leave the zones unchanged: %v", e.To)
	}

	// An invalid action is rejected.
	e = base()
	if err := overlaySecurityRule(e, SecurityRuleInput{Name: "r1", Action: "permit"}); err == nil {
		t.Fatal("invalid action must be rejected")
	}
}

func TestSecurityRuleCreateDefaults(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the rule back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: ruleGetBody("allow-web")},
	)
	h := securityRuleCreateHandler(d, security.NewService(d.Client))

	res, _, err := h(t.Context(), nil, SecurityRuleInput{Name: "allow-web", Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			sawSet = true
			el := req.Get("element")
			// Assert the action verdict via its own element, not the bare word
			// "allow": the rule is named "allow-web", so a bare Contains(el,
			// "allow") would pass on the name even if the action were dropped.
			for _, want := range []string{"any", "application-default", "<action>allow</action>"} {
				if !strings.Contains(el, want) {
					t.Fatalf("set element missing %q: %s", want, el)
				}
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "rulebase/security/rules") {
				t.Fatalf("set xpath must target the vsys rulebase: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
}

func TestSecurityRuleCreateRequiresAction(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := securityRuleCreateHandler(d, security.NewService(d.Client))
	res, _, err := h(t.Context(), nil, SecurityRuleInput{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("missing action must be an error")
	}
	// Validation must reject before any API call: only the bootstrap
	// system-info request may exist.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestSecurityRuleCreateWithPosition(t *testing.T) {
	t.Run("positions after create", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM",
			// Order matters: the entry-specific get answers Create's read-back;
			// the generic get answers MoveGroup's rulebase listing.
			fakeRoute{Match: getEntryXpath("allow-web"), Body: ruleGetBody("allow-web")},
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: createMoveListBody},
			fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
		)
		h := securityRuleCreateHandler(d, security.NewService(d.Client))
		res, _, err := h(t.Context(), nil, SecurityRuleInput{Name: "allow-web", Action: "allow", Position: "top"})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("create failed: %s", textContent(t, res))
		}
		el := multiConfigElement(t, f)
		if !strings.Contains(el, "<move") || !strings.Contains(el, "allow-web") || !strings.Contains(el, `where="top"`) {
			t.Fatalf("expected a move-to-top after create: %s", el)
		}
	})

	t.Run("invalid position rejected before create", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		h := securityRuleCreateHandler(d, security.NewService(d.Client))
		res, _, err := h(t.Context(), nil, SecurityRuleInput{Name: "x", Action: "allow", Position: "before"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("position before without relative_to must be an error")
		}
		for _, req := range f.Requests() {
			if req.Get("action") == "set" {
				t.Fatal("invalid position must be rejected before the rule is created")
			}
		}
	})
}

func TestSecurityRuleAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid rule</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[security.Location, security.Entry](d, "panos_security_rule_get",
		newSecurityRuleService(d), securityResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("API error must surface as IsError result")
	}
	if body := textContent(t, res); !strings.Contains(body, "invalid rule") {
		t.Fatalf("error text must carry the PAN-OS message, got: %s", body)
	}
	// Single-wrap parity: the get must reach the API wrapped exactly once; a
	// raw-service wiring would fail client-side and record no such request,
	// and a double wrap would flag a pango upgrade that started wrapping.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

func TestSecurityRuleUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: ruleGetBody("allow-web")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[security.Location, security.Entry, SecurityRuleInput](d, "panos_security_rule_update",
		newSecurityRuleService(d), securityResolve(d),
		func(in SecurityRuleInput) LocationInput { return in.Location },
		func(in SecurityRuleInput) string { return in.Name }, overlaySecurityRule)

	// The overlay must CHANGE something: pango skips the edit entirely when
	// the overlaid entry SpecMatches the current one.
	res, _, err := h(t.Context(), nil, SecurityRuleInput{Name: "allow-web", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "deny") || !strings.Contains(el, "allow-web") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing the new action or the entry xpath: %s", el)
	}
	// Read-modify-write: the edit must carry fields the caller did not send.
	if !strings.Contains(el, "allow-web desc") {
		t.Fatalf("edit element must preserve the existing description: %s", el)
	}
}

func TestSecurityRuleDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[security.Location, security.Entry](d, "panos_security_rule_delete",
		newSecurityRuleService(d), securityResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "allow-web"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Bare-name matching: the element XML escapes the xpath apostrophes.
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "allow-web") || !strings.Contains(el, "security/rules") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete element missing the rule xpath: %s", el)
	}
}

func TestSecurityRuleList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: securityRuleListBody})
	h := listHandler[security.Location, security.Entry](d, "panos_security_rule_list",
		newSecurityRuleService(d), securityResolve(d), securityRuleName, securityRuleSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, `"total": 3`) || !strings.Contains(body, "rule-a") || !strings.Contains(body, "rule-c") {
		t.Fatalf("missing entries: %s", body)
	}
	if !strings.Contains(body, `"action": "allow"`) {
		t.Fatalf("summary missing the action key: %s", body)
	}
	// summaryBase supplies description (and tags) for rule summaries.
	if !strings.Contains(body, "rule-a desc") {
		t.Fatalf("summary missing the description from summaryBase: %s", body)
	}
}

//nolint:gocognit // three independent Panorama and firewall rulebase subtests kept in one place.
func TestSecurityRulePanoramaRulebase(t *testing.T) {
	t.Run("device group post create", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama",
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: ruleGetBody("allow-web")},
		)
		h := securityRuleCreateHandler(d, security.NewService(d.Client))
		res, _, err := h(t.Context(), nil, SecurityRuleInput{
			Name: "allow-web", Action: "allow",
			Location: LocationInput{DeviceGroup: "dg1", Rulebase: "post"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("create failed: %s", textContent(t, res))
		}
		var sawXpath bool
		for _, req := range f.Requests() {
			if req.Get("action") == "set" && strings.Contains(req.Get("xpath"), "post-rulebase") &&
				strings.Contains(req.Get("xpath"), "dg1") {
				sawXpath = true
			}
		}
		if !sawXpath {
			t.Fatal("set xpath must target the dg1 post-rulebase")
		}
	})

	t.Run("shared list defaults to pre", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: securityRuleListBody})
		h := listHandler[security.Location, security.Entry](d, "panos_security_rule_list",
			newSecurityRuleService(d), securityResolve(d), securityRuleName, securityRuleSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("list failed: %s", textContent(t, res))
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared/pre-rulebase/security/rules") {
			t.Fatalf("Panorama default must be the shared pre-rulebase, got: %s", joined)
		}
	})

	t.Run("firewall ignores rulebase", func(t *testing.T) {
		// resolveLocation threads the rulebase only into shared and
		// device-group locations; a firewall vsys has a single rulebase
		// (Task 3 design), so a stray rulebase input is accepted and ignored.
		d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: securityRuleListBody})
		h := listHandler[security.Location, security.Entry](d, "panos_security_rule_list",
			newSecurityRuleService(d), securityResolve(d), securityRuleName, securityRuleSummary)
		res, _, err := h(t.Context(), nil, ListInput{Location: LocationInput{Rulebase: "post"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("list failed: %s", textContent(t, res))
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "vsys1") || strings.Contains(joined, "post-rulebase") {
			t.Fatalf("firewall list must target the vsys rulebase, got: %s", joined)
		}
	})
}

//nolint:gocognit // table-driven positional cases plus the relative_to and missing-rule edge subtests.
func TestSecurityRuleMove(t *testing.T) {
	cases := []struct {
		name     string
		in       MoveInput
		wantElem []string
	}{
		// securityRuleListBody order is rule-a, rule-b, rule-c, so each case
		// requires a real move (MoveGroup issues nothing for a rule already
		// in position). The before case pivots on rule-b, NOT the first
		// rule: pango normalizes a move whose expected slot is index 0 into
		// a where="top" operation (movement.go GenerateMovements), so
		// "before rule-a" would be asserted as top, not before.
		{"top", MoveInput{Name: "rule-c", Position: "top"}, []string{"<move", "rule-c", `where="top"`}},
		{"bottom", MoveInput{Name: "rule-a", Position: "bottom"}, []string{"<move", "rule-a", `where="bottom"`}},
		{"before", MoveInput{Name: "rule-c", Position: "before", RelativeTo: "rule-b"}, []string{"<move", "rule-c", `where="before"`, `dst="rule-b"`}},
		{"after", MoveInput{Name: "rule-a", Position: "after", RelativeTo: "rule-b"}, []string{"<move", "rule-a", `where="after"`, `dst="rule-b"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM",
				// Entry-specific get first: it answers the existence read;
				// the generic get answers MoveGroup's rulebase listing.
				fakeRoute{Match: getEntryXpath(c.in.Name), Body: ruleGetBody(c.in.Name)},
				fakeRoute{Match: configAction("get"), Body: securityRuleListBody},
				fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
			)
			h := moveHandler[security.Location, security.Entry](d, "panos_security_rule_move",
				newSecurityRuleService(d), security.NewService(d.Client), securityResolve(d))
			res, _, err := h(t.Context(), nil, c.in)
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("move failed: %s", textContent(t, res))
			}
			el := multiConfigElement(t, f)
			for _, want := range c.wantElem {
				if !strings.Contains(el, want) {
					t.Fatalf("move element missing %q: %s", want, el)
				}
			}
		})
	}

	t.Run("before requires relative_to", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		h := moveHandler[security.Location, security.Entry](d, "panos_security_rule_move",
			newSecurityRuleService(d), security.NewService(d.Client), securityResolve(d))
		res, _, err := h(t.Context(), nil, MoveInput{Name: "rule-a", Position: "before"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("before without relative_to must be an error")
		}
		// Validation must reject before any API call beyond the bootstrap.
		if got := len(f.Requests()); got != 1 {
			t.Fatalf("expected no API traffic, recorded %d requests", got)
		}
	})

	t.Run("missing rule", func(t *testing.T) {
		// No get route: the existence read hits the fake's fail-loud
		// unmatched-request error and must stop the move.
		d, f := newTestDeps(t, "PA-VM")
		h := moveHandler[security.Location, security.Entry](d, "panos_security_rule_move",
			newSecurityRuleService(d), security.NewService(d.Client), securityResolve(d))
		res, _, err := h(t.Context(), nil, MoveInput{Name: "ghost", Position: "top"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("moving a missing rule must be an error")
		}
		if body := textContent(t, res); !strings.Contains(body, `read "ghost"`) {
			t.Fatalf("the error must come from the existence read, got: %s", body)
		}
		for _, req := range f.Requests() {
			if req.Get("action") == "multi-config" {
				t.Fatal("a missing rule must not issue a move")
			}
		}
	})
}

// TestRegisterSecurityRuleToolsReadOnly pins the write-safety gate: all four
// mutating tools, including move, are registered only when writes are
// enabled, while the read tools are always present. This is the sole
// enforcement point, so dropping the d.ReadOnly gate must fail here.
func TestRegisterSecurityRuleToolsReadOnly(t *testing.T) {
	reads := []string{"panos_security_rule_list", "panos_security_rule_get"}
	writes := []string{"panos_security_rule_create", "panos_security_rule_update", "panos_security_rule_delete", "panos_security_rule_move"}

	dRO, _ := newTestDeps(t, "PA-VM")
	dRO.ReadOnly = true
	ro := registeredToolNames(t, dRO)
	for _, n := range reads {
		if !ro[n] {
			t.Errorf("read-only: %q must be registered", n)
		}
	}
	for _, n := range writes {
		if ro[n] {
			t.Errorf("read-only: %q must NOT be registered", n)
		}
	}

	dRW, _ := newTestDeps(t, "PA-VM")
	dRW.ReadOnly = false
	rw := registeredToolNames(t, dRW)
	for _, n := range append(reads, writes...) {
		if !rw[n] {
			t.Errorf("writes enabled: %q must be registered", n)
		}
	}
}

func TestSecurityRuleGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: ruleGetBody("allow-web")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterSecurityRuleTools(srv, d)

	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cli := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0"}, nil)
	cs, err := cli.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_security_rule_get", Arguments: map[string]any{"name": "allow-web"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and
	// target the rulebase; a raw-service wiring (which also satisfies
	// crudService) would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='allow-web']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "security/rules") {
		t.Fatalf("registered get did not target the security rulebase: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_security_rule_update", Arguments: map[string]any{"name": "allow-web", "action": "deny"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "deny") || !strings.Contains(el, "allow-web") {
		t.Fatalf("registered update did not reach the API with the new action: %s", el)
	}
}
