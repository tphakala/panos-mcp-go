package tools

import (
	"net/url"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/movement"
	"github.com/PaloAltoNetworks/pango/policies/rules/nat"
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
		newSecurityRuleService(d), securityResolve(d), securityRuleSummary)

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
		func(in SecurityRuleInput) string { return in.Name }, overlaySecurityRule, securityRuleSummary)

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

	cs := connectInMemory(t, srv)

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

//nolint:gocyclo,gocognit // exhaustive field-by-field assertions on the built entry; each || is one field check.
func TestBuildNatRuleEntry(t *testing.T) {
	// Defaults: match fields any, service any, nothing else invented.
	e, err := buildNatRuleEntry(NatRuleInput{Name: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]string{
		"from": e.From, "to": e.To, "source": e.Source, "destination": e.Destination,
	} {
		if len(got) != 1 || got[0] != "any" {
			t.Errorf("%s must default to [any], got %v", name, got)
		}
	}
	if strVal(e.Service) != "any" {
		t.Errorf("service must default to any, got %v", e.Service)
	}
	if e.SourceTranslation != nil || e.DestinationTranslation != nil {
		t.Errorf("defaults must not invent translations: %+v %+v", e.SourceTranslation, e.DestinationTranslation)
	}
	if e.NatType != nil || e.ToInterface != nil || e.Description != nil || e.Disabled != nil || e.Tag != nil {
		t.Errorf("unset optional fields must stay unset: %+v", e)
	}

	// Explicit values suppress every default; SNAT pool and DNAT map to the
	// right nested pango fields.
	e, err = buildNatRuleEntry(NatRuleInput{
		Name: "n2", From: []string{"trust"}, To: []string{"untrust"},
		Source: []string{"10.0.0.0/8"}, Destination: []string{"192.0.2.1"},
		Service: "http-svc", NatType: "ipv4", ToInterface: "ethernet1/2",
		SNATAddresses: []string{"snat-pool"},
		DNATAddress:   "10.0.0.80", DNATPort: ptr(int64(8080)),
		Description: "d", Tags: []string{"t"}, Disabled: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.From[0] != "trust" || e.To[0] != "untrust" || e.Source[0] != "10.0.0.0/8" ||
		e.Destination[0] != "192.0.2.1" || strVal(e.Service) != "http-svc" {
		t.Errorf("explicit fields must not be defaulted: %+v", e)
	}
	if strVal(e.NatType) != "ipv4" || strVal(e.ToInterface) != "ethernet1/2" ||
		strVal(e.Description) != "d" || len(e.Tag) != 1 || e.Disabled == nil || !*e.Disabled {
		t.Errorf("optional fields not carried: %+v", e)
	}
	st := e.SourceTranslation
	if st == nil || st.DynamicIpAndPort == nil || len(st.DynamicIpAndPort.TranslatedAddress) != 1 ||
		st.DynamicIpAndPort.TranslatedAddress[0] != "snat-pool" || st.DynamicIpAndPort.InterfaceAddress != nil {
		t.Errorf("snat_addresses must map to DynamicIpAndPort.TranslatedAddress alone: %+v", st)
	}
	dt := e.DestinationTranslation
	if dt == nil || strVal(dt.TranslatedAddress) != "10.0.0.80" || dt.TranslatedPort == nil || *dt.TranslatedPort != 8080 {
		t.Errorf("dnat fields must map to DestinationTranslation: %+v", dt)
	}

	// SNAT via interface maps to InterfaceAddress.Interface, with no pool.
	e, err = buildNatRuleEntry(NatRuleInput{Name: "n3", SNATInterface: "ethernet1/1"})
	if err != nil {
		t.Fatal(err)
	}
	st = e.SourceTranslation
	if st == nil || st.DynamicIpAndPort == nil || st.DynamicIpAndPort.InterfaceAddress == nil ||
		strVal(st.DynamicIpAndPort.InterfaceAddress.Interface) != "ethernet1/1" ||
		st.DynamicIpAndPort.TranslatedAddress != nil {
		t.Errorf("snat_interface must map to DynamicIpAndPort.InterfaceAddress.Interface alone: %+v", st)
	}
	// DNAT address without port must not invent a port.
	e, err = buildNatRuleEntry(NatRuleInput{Name: "n4", DNATAddress: "10.0.0.80"})
	if err != nil {
		t.Fatal(err)
	}
	if e.DestinationTranslation == nil || e.DestinationTranslation.TranslatedPort != nil {
		t.Errorf("dnat without port must set the address only: %+v", e.DestinationTranslation)
	}
}

func TestBuildNatRuleEntryRejects(t *testing.T) {
	for _, c := range []struct {
		name, wantErr string
		in            NatRuleInput
	}{
		{"no name", "name", NatRuleInput{}},
		{"snat interface plus addresses", "not both", NatRuleInput{Name: "n", SNATInterface: "ethernet1/1", SNATAddresses: []string{"pool"}}},
		{"dnat port without address", "requires dnat_address", NatRuleInput{Name: "n", DNATPort: ptr(int64(8080))}},
		{"dnat port out of range", "between 1 and 65535", NatRuleInput{Name: "n", DNATAddress: "10.0.0.80", DNATPort: ptr(int64(70000))}},
		{"dnat port negative", "between 1 and 65535", NatRuleInput{Name: "n", DNATAddress: "10.0.0.80", DNATPort: ptr(int64(-1))}},
		{"dnat port zero", "between 1 and 65535", NatRuleInput{Name: "n", DNATAddress: "10.0.0.80", DNATPort: ptr(int64(0))}},
		{"bad nat_type", "nat_type", NatRuleInput{Name: "n", NatType: "ipv5"}},
	} {
		_, err := buildNatRuleEntry(c.in)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		// Assert the error names the offending field so distinct guards
		// cannot pass on one another's error (same-error collapse).
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q must mention %q", c.name, err, c.wantErr)
		}
	}
}

//nolint:gocyclo // exhaustive overlay field assertions across the empty, replace and reject scenarios.
func TestOverlayNatRuleFields(t *testing.T) {
	base := func() *nat.Entry {
		return &nat.Entry{
			Name: "n1",
			From: []string{"trust"}, To: []string{"untrust"},
			Source: []string{"any"}, Destination: []string{"any"},
			Service: ptr("any"), NatType: ptr("ipv4"), ToInterface: ptr("ethernet1/2"),
			SourceTranslation: &nat.SourceTranslation{
				DynamicIpAndPort: &nat.SourceTranslationDynamicIpAndPort{
					InterfaceAddress: &nat.SourceTranslationDynamicIpAndPortInterfaceAddress{Interface: ptr("ethernet1/1")},
				},
			},
			Description: ptr("old"), Tag: []string{"t1"}, Disabled: ptr(false),
		}
	}

	// An empty input changes nothing, including the existing translation.
	e := base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if e.From[0] != "trust" || strVal(e.Service) != "any" || strVal(e.NatType) != "ipv4" ||
		strVal(e.ToInterface) != "ethernet1/2" || strVal(e.Description) != "old" || len(e.Tag) != 1 || *e.Disabled {
		t.Fatalf("empty overlay must not change the entry: %+v", e)
	}
	if e.SourceTranslation == nil || e.SourceTranslation.DynamicIpAndPort.InterfaceAddress == nil {
		t.Fatalf("empty overlay must keep the existing source translation: %+v", e.SourceTranslation)
	}

	// Every replace branch exercised with a non-empty value, so dropping any
	// single "e.X = ..." line fails here (no mutation survivors).
	e = base()
	err := overlayNatRule(e, NatRuleInput{
		Name: "n1", From: []string{"dmz"}, To: []string{"guest"},
		Source: []string{"10.0.0.0/8"}, Destination: []string{"192.0.2.0/24"},
		Service: "http-svc", NatType: "nat64", ToInterface: "ethernet1/3",
		SNATAddresses: []string{"snat-pool"},
		DNATAddress:   "10.0.0.90", DNATPort: ptr(int64(9090)),
		Description: "new", Tags: []string{}, Disabled: ptr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.From[0] != "dmz" || e.To[0] != "guest" || e.Source[0] != "10.0.0.0/8" || e.Destination[0] != "192.0.2.0/24" {
		t.Fatalf("all four match lists must replace when non-empty: %+v", e)
	}
	if strVal(e.Service) != "http-svc" || strVal(e.NatType) != "nat64" || strVal(e.ToInterface) != "ethernet1/3" ||
		strVal(e.Description) != "new" || len(e.Tag) != 0 || !*e.Disabled {
		t.Fatalf("scalar overlays wrong: %+v", e)
	}
	// snat_addresses replaces the interface-form translation wholesale.
	st := e.SourceTranslation
	if st == nil || st.DynamicIpAndPort == nil || st.DynamicIpAndPort.InterfaceAddress != nil ||
		len(st.DynamicIpAndPort.TranslatedAddress) != 1 || st.DynamicIpAndPort.TranslatedAddress[0] != "snat-pool" {
		t.Fatalf("snat_addresses must replace the whole source translation: %+v", st)
	}
	dt := e.DestinationTranslation
	if dt == nil || strVal(dt.TranslatedAddress) != "10.0.0.90" || dt.TranslatedPort == nil || *dt.TranslatedPort != 9090 {
		t.Fatalf("dnat overlay wrong: %+v", dt)
	}

	// An EMPTY match list leaves the field unchanged (a rule cannot have
	// zero zones; reset is expressed as ["any"]).
	e = base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1", To: []string{}}); err != nil {
		t.Fatal(err)
	}
	if len(e.To) != 1 || e.To[0] != "untrust" {
		t.Fatalf("empty to list must leave the zones unchanged: %v", e.To)
	}

	// Validation still applies on update.
	e = base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1", NatType: "ipv5"}); err == nil {
		t.Fatal("invalid nat_type must be rejected")
	}
	e = base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1", SNATInterface: "ethernet1/1", SNATAddresses: []string{"p"}}); err == nil {
		t.Fatal("snat_interface plus snat_addresses must be rejected on update too")
	}
}

// TestOverlayNatRulePreservesDNATPort pins the issue #26 fix at the overlay
// level: an update changing only dnat_address must MERGE into the existing
// destination-translation, keeping the translated port (and any dns-rewrite)
// rather than rebuilding the subtree and silently widening the port-forward to
// a full-IP DNAT. A provided dnat_port still replaces the existing one.
func TestOverlayNatRulePreservesDNATPort(t *testing.T) {
	base := func() *nat.Entry {
		return &nat.Entry{
			Name: "n1",
			DestinationTranslation: &nat.DestinationTranslation{
				TranslatedAddress: ptr("10.0.0.80"),
				TranslatedPort:    ptr(int64(8080)),
				DnsRewrite:        &nat.DestinationTranslationDnsRewrite{Direction: ptr("reverse")},
			},
		}
	}

	// dnat_address alone: address changes, the existing port and dns-rewrite
	// survive the merge.
	e := base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1", DNATAddress: "10.0.0.99"}); err != nil {
		t.Fatal(err)
	}
	dt := e.DestinationTranslation
	if dt == nil || strVal(dt.TranslatedAddress) != "10.0.0.99" {
		t.Fatalf("dnat_address must be overwritten: %+v", dt)
	}
	if dt.TranslatedPort == nil || *dt.TranslatedPort != 8080 {
		t.Fatalf("omitted dnat_port must keep the existing translated port 8080: %+v", dt)
	}
	if dt.DnsRewrite == nil || strVal(dt.DnsRewrite.Direction) != "reverse" {
		t.Fatalf("merge must preserve an existing dns-rewrite: %+v", dt)
	}

	// A provided dnat_port replaces the existing one.
	e = base()
	if err := overlayNatRule(e, NatRuleInput{Name: "n1", DNATAddress: "10.0.0.99", DNATPort: ptr(int64(9090))}); err != nil {
		t.Fatal(err)
	}
	if dt := e.DestinationTranslation; dt.TranslatedPort == nil || *dt.TranslatedPort != 9090 {
		t.Fatalf("provided dnat_port must replace the existing port: %+v", dt)
	}
}

// natRuleEntryXML renders one canned NAT rule entry carrying both an
// interface-form source translation and a destination translation, so
// read-modify-write updates must preserve them. Element order follows
// pango's entryXml struct order, though unmarshaling does not depend on it.
func natRuleEntryXML(name string) string {
	return `<entry name="` + name + `">` +
		`<description>` + name + ` desc</description>` +
		`<destination><member>any</member></destination>` +
		`<from><member>trust</member></from>` +
		`<service>any</service>` +
		`<source><member>any</member></source>` +
		`<source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>` +
		`<tag><member>t1</member></tag>` +
		`<to><member>untrust</member></to>` +
		`<destination-translation><translated-address>10.0.0.80</translated-address><translated-port>8080</translated-port></destination-translation>` +
		`</entry>`
}

// natRuleGetBody answers a single-entry read (pango requires exactly one entry).
func natRuleGetBody(name string) string {
	return `<response status="success"><result>` + natRuleEntryXML(name) + `</result></response>`
}

// natRuleListBody lists three NAT rules in rulebase order.
var natRuleListBody = `<response status="success"><result>` +
	natRuleEntryXML("nat-a") + natRuleEntryXML("nat-b") + natRuleEntryXML("nat-c") +
	`</result></response>`

// natCreateMoveListBody is the rulebase as MoveGroup lists it right after a
// create: the new rule sits at the bottom.
var natCreateMoveListBody = `<response status="success"><result>` +
	natRuleEntryXML("nat-a") + natRuleEntryXML("nat-b") + natRuleEntryXML("out-snat") +
	`</result></response>`

func natResolve(d *Deps) func(LocationInput) (nat.Location, error) {
	return func(in LocationInput) (nat.Location, error) {
		return resolveLocation(d, in, natParts())
	}
}

func natRuleName(e *nat.Entry) string { return e.Name }

// TestNatRuleGetReturnsTranslationDetails pins issue #48 for NAT: get returns
// the flattened translation fields that create and update accept, not the
// compact has_*_translation booleans the list view uses, and never the raw
// pango struct.
func TestNatRuleGetReturnsTranslationDetails(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: natRuleGetBody("port-fwd")})
	h := getHandler[nat.Location, nat.Entry](d, "panos_nat_rule_get", newNatRuleService(d), natResolve(d), natRuleDetail)

	res, _, err := h(t.Context(), nil, NameInput{Name: "port-fwd"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	out := textContent(t, res)
	for _, want := range []string{`"snat_interface": "ethernet1/1"`, `"dnat_address": "10.0.0.80"`, `"dnat_port": 8080`} {
		if !strings.Contains(out, want) {
			t.Fatalf("nat get must include %s, got: %s", want, out)
		}
	}
	for _, leak := range []string{"has_source_translation", "has_destination_translation", "SourceTranslation", "DestinationTranslation", "MiscAttributes"} {
		if strings.Contains(out, leak) {
			t.Fatalf("nat get leaked %q: %s", leak, out)
		}
	}
}

// setElements returns the element bodies of all recorded config set requests.
func setElements(f *fakeAPI) []string {
	var els []string
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			els = append(els, req.Get("element"))
		}
	}
	return els
}

//nolint:gocognit // four independent translation wire-shape subtests kept in one place.
func TestNatRuleCreateTranslations(t *testing.T) {
	// The nested chains below are the exact shapes pango marshals (verified
	// against nat/entry.go entryXml struct order); asserting the full chain
	// rather than a bare "ethernet1/1" keeps a rule name or a zone from
	// satisfying the assertion by accident.
	const snatIfaceXML = `<source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>`
	const snatPoolXML = `<source-translation><dynamic-ip-and-port><translated-address><member>snat-pool</member></translated-address></dynamic-ip-and-port></source-translation>`
	const dnatXML = `<destination-translation><translated-address>10.0.0.80</translated-address><translated-port>8080</translated-port></destination-translation>`

	create := func(t *testing.T, name string) (func(NatRuleInput) *mcp.CallToolResult, *fakeAPI) {
		t.Helper()
		d, f := newTestDeps(t, "PA-VM",
			fakeRoute{Match: getEntryXpath(name), Body: natRuleGetBody(name)},
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		)
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		return func(in NatRuleInput) *mcp.CallToolResult {
			t.Helper()
			res, _, err := h(t.Context(), nil, in)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}, f
	}

	t.Run("snat interface", func(t *testing.T) {
		do, f := create(t, "out-snat")
		res := do(NatRuleInput{Name: "out-snat", From: []string{"trust"}, To: []string{"untrust"}, SNATInterface: "ethernet1/1"})
		if res.IsError {
			t.Fatalf("snat interface create failed: %s", textContent(t, res))
		}
		els := strings.Join(setElements(f), " ")
		if !strings.Contains(els, snatIfaceXML) {
			t.Fatalf("set element missing the interface source translation chain: %s", els)
		}
	})

	t.Run("snat address pool", func(t *testing.T) {
		do, f := create(t, "out-pool")
		res := do(NatRuleInput{Name: "out-pool", From: []string{"trust"}, To: []string{"untrust"}, SNATAddresses: []string{"snat-pool"}})
		if res.IsError {
			t.Fatalf("snat pool create failed: %s", textContent(t, res))
		}
		els := strings.Join(setElements(f), " ")
		if !strings.Contains(els, snatPoolXML) {
			t.Fatalf("set element missing the pool source translation chain: %s", els)
		}
	})

	t.Run("dnat address and port", func(t *testing.T) {
		do, f := create(t, "in-dnat")
		res := do(NatRuleInput{Name: "in-dnat", From: []string{"untrust"}, To: []string{"untrust"}, DNATAddress: "10.0.0.80", DNATPort: ptr(int64(8080))})
		if res.IsError {
			t.Fatalf("dnat create failed: %s", textContent(t, res))
		}
		els := strings.Join(setElements(f), " ")
		if !strings.Contains(els, dnatXML) {
			t.Fatalf("set element missing the destination translation chain: %s", els)
		}
	})

	t.Run("snat interface plus addresses rejected before create", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		res, _, err := h(t.Context(), nil, NatRuleInput{Name: "bad", SNATInterface: "ethernet1/1", SNATAddresses: []string{"pool"}})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("snat_interface plus snat_addresses must be an error")
		}
		// Validation must reject before any API call: only the bootstrap
		// system-info request may exist.
		if got := len(f.Requests()); got != 1 {
			t.Fatalf("validation must fail before any API call; recorded %d requests", got)
		}
	})
}

func TestNatRuleCreateDefaults(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the rule back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: natRuleGetBody("out-snat")},
	)
	h := natRuleCreateHandler(d, nat.NewService(d.Client))

	res, _, err := h(t.Context(), nil, NatRuleInput{Name: "out-snat"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	els := setElements(f)
	if len(els) != 1 {
		t.Fatalf("expected exactly one config set, got %d", len(els))
	}
	el := els[0]
	// Assert each defaulted field via its own full element so the assertions
	// cannot be satisfied by the rule name or one another.
	for _, want := range []string{
		"<from><member>any</member></from>", "<to><member>any</member></to>",
		"<source><member>any</member></source>", "<destination><member>any</member></destination>",
		"<service>any</service>",
	} {
		if !strings.Contains(el, want) {
			t.Fatalf("set element missing default %q: %s", want, el)
		}
	}
	// Defaults must not invent translations or a nat-type.
	for _, banned := range []string{"<source-translation>", "<destination-translation>", "<nat-type>"} {
		if strings.Contains(el, banned) {
			t.Fatalf("set element must not contain %q for a defaults-only create: %s", banned, el)
		}
	}
	var sawXpath bool
	for _, req := range f.Requests() {
		if req.Get("action") == "set" && strings.Contains(req.Get("xpath"), "vsys1") &&
			strings.Contains(req.Get("xpath"), "rulebase/nat/rules") {
			sawXpath = true
		}
	}
	if !sawXpath {
		t.Fatal("set xpath must target the vsys1 NAT rulebase")
	}
}

//nolint:gocognit,gocyclo // three independent create-positioning subtests kept in one place.
func TestNatRuleCreateWithPosition(t *testing.T) {
	t.Run("positions after create", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM",
			// Order matters: the entry-specific get answers Create's read-back;
			// the generic get answers MoveGroup's rulebase listing.
			fakeRoute{Match: getEntryXpath("out-snat"), Body: natRuleGetBody("out-snat")},
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: natCreateMoveListBody},
			fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
		)
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		res, _, err := h(t.Context(), nil, NatRuleInput{Name: "out-snat", Position: "top"})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("create failed: %s", textContent(t, res))
		}
		el := multiConfigElement(t, f)
		if !strings.Contains(el, "<move") || !strings.Contains(el, "out-snat") || !strings.Contains(el, `where="top"`) {
			t.Fatalf("expected a move-to-top after create: %s", el)
		}
	})

	t.Run("invalid position rejected before create", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM")
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		res, _, err := h(t.Context(), nil, NatRuleInput{Name: "x", Position: "before"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("position before without relative_to must be an error")
		}
		if len(setElements(f)) != 0 {
			t.Fatal("invalid position must be rejected before the rule is created")
		}
	})

	t.Run("relative_to names a missing rule", func(t *testing.T) {
		// The position is syntactically valid, so the rule IS created; the
		// move then fails inside MoveGroup (the pivot is not in the listing)
		// and the result must report the created-but-not-positioned state.
		// This is the only test pinning ruleCreateHandler's partial-failure
		// branch for BOTH security and NAT (see plan D1).
		d, f := newTestDeps(t, "PA-VM",
			fakeRoute{Match: getEntryXpath("out-snat"), Body: natRuleGetBody("out-snat")},
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: natCreateMoveListBody},
		)
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		res, _, err := h(t.Context(), nil, NatRuleInput{Name: "out-snat", Position: "before", RelativeTo: "ghost"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("a missing relative_to rule must surface as an error")
		}
		body := textContent(t, res)
		if !strings.Contains(body, "was created but positioning failed") || !strings.Contains(body, "rulebase bottom") {
			t.Fatalf("the error must report the created-but-unpositioned state, got: %s", body)
		}
		if len(setElements(f)) != 1 {
			t.Fatal("the rule itself must have been created")
		}
		for _, req := range f.Requests() {
			if req.Get("action") == "multi-config" {
				t.Fatal("a failed pivot lookup must not issue a move")
			}
		}
	})
}

func TestNatRuleAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid nat rule</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[nat.Location, nat.Entry](d, "panos_nat_rule_get",
		newNatRuleService(d), natResolve(d), natRuleSummary)

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("API error must surface as IsError result")
	}
	if body := textContent(t, res); !strings.Contains(body, "invalid nat rule") {
		t.Fatalf("error text must carry the PAN-OS message, got: %s", body)
	}
	// Single-wrap parity: the get must reach the API wrapped exactly once; a
	// raw-service wiring would fail client-side and record no such request,
	// and a double wrap would flag a pango upgrade that started wrapping.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

func TestNatRuleUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: natRuleGetBody("out-snat")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[nat.Location, nat.Entry, NatRuleInput](d, "panos_nat_rule_update",
		newNatRuleService(d), natResolve(d),
		func(in NatRuleInput) LocationInput { return in.Location },
		func(in NatRuleInput) string { return in.Name }, overlayNatRule, natRuleSummary)

	// The overlay must CHANGE something: pango skips the edit entirely when
	// the overlaid entry SpecMatches the current one.
	res, _, err := h(t.Context(), nil, NatRuleInput{Name: "out-snat", Service: "http-svc"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<service>http-svc</service>") || !strings.Contains(el, "out-snat") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing the new service or the entry xpath: %s", el)
	}
	// Read-modify-write: the edit must carry fields the caller did not send,
	// including BOTH translation subtrees from the canned entry.
	if !strings.Contains(el, "out-snat desc") {
		t.Fatalf("edit element must preserve the existing description: %s", el)
	}
	if !strings.Contains(el, "<interface>ethernet1/1</interface>") ||
		!strings.Contains(el, "<translated-address>10.0.0.80</translated-address>") {
		t.Fatalf("edit element must preserve the existing translations: %s", el)
	}
}

// TestNatRuleUpdatePreservesDNATPort is the end-to-end proof of the issue #26
// fix: updating only dnat_address must emit an edit carrying BOTH the new
// translated-address and the rule's existing translated-port, not a
// port-stripped full-IP DNAT. The canned entry forwards port 8080 to 10.0.0.80.
func TestNatRuleUpdatePreservesDNATPort(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: natRuleGetBody("out-snat")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[nat.Location, nat.Entry, NatRuleInput](d, "panos_nat_rule_update",
		newNatRuleService(d), natResolve(d),
		func(in NatRuleInput) LocationInput { return in.Location },
		func(in NatRuleInput) string { return in.Name }, overlayNatRule, natRuleSummary)

	// Change only the translated address; the port must ride along unchanged.
	res, _, err := h(t.Context(), nil, NatRuleInput{Name: "out-snat", DNATAddress: "10.0.0.99"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<translated-address>10.0.0.99</translated-address>") {
		t.Fatalf("edit must carry the new dnat address: %s", el)
	}
	if !strings.Contains(el, "<translated-port>8080</translated-port>") {
		t.Fatalf("edit must preserve the existing translated port 8080, not widen to full-IP DNAT: %s", el)
	}
}

func TestNatRuleDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[nat.Location, nat.Entry](d, "panos_nat_rule_delete",
		newNatRuleService(d), natResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "out-snat"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "out-snat") || !strings.Contains(el, "nat/rules") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete element missing the rule xpath: %s", el)
	}
}

func TestNatRuleList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: natRuleListBody})
	h := listHandler[nat.Location, nat.Entry](d, "panos_nat_rule_list",
		newNatRuleService(d), natResolve(d), natRuleName, natRuleSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, `"total": 3`) || !strings.Contains(body, "nat-a") || !strings.Contains(body, "nat-c") {
		t.Fatalf("missing entries: %s", body)
	}
	if !strings.Contains(body, `"service": "any"`) {
		t.Fatalf("summary missing the service key: %s", body)
	}
	if !strings.Contains(body, `"has_source_translation": true`) || !strings.Contains(body, `"has_destination_translation": true`) {
		t.Fatalf("summary missing the translation flags: %s", body)
	}
	// summaryBase supplies description (and tags) for rule summaries.
	if !strings.Contains(body, "nat-a desc") {
		t.Fatalf("summary missing the description from summaryBase: %s", body)
	}
}

//nolint:gocognit // three independent Panorama and firewall rulebase subtests kept in one place.
func TestNatRulePanoramaRulebase(t *testing.T) {
	t.Run("device group post create", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama",
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: natRuleGetBody("out-snat")},
		)
		h := natRuleCreateHandler(d, nat.NewService(d.Client))
		res, _, err := h(t.Context(), nil, NatRuleInput{
			Name:     "out-snat",
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
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: natRuleListBody})
		h := listHandler[nat.Location, nat.Entry](d, "panos_nat_rule_list",
			newNatRuleService(d), natResolve(d), natRuleName, natRuleSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("list failed: %s", textContent(t, res))
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared/pre-rulebase/nat/rules") {
			t.Fatalf("Panorama default must be the shared pre-rulebase, got: %s", joined)
		}
	})

	t.Run("firewall ignores rulebase", func(t *testing.T) {
		// resolveLocation threads the rulebase only into shared and
		// device-group locations; a firewall vsys has a single rulebase.
		d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: natRuleListBody})
		h := listHandler[nat.Location, nat.Entry](d, "panos_nat_rule_list",
			newNatRuleService(d), natResolve(d), natRuleName, natRuleSummary)
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
func TestNatRuleMove(t *testing.T) {
	cases := []struct {
		name     string
		in       MoveInput
		wantElem []string
	}{
		// natRuleListBody order is nat-a, nat-b, nat-c, so each case requires
		// a real move (MoveGroup issues nothing for a rule already in
		// position). The before case pivots on nat-b, NOT the first rule:
		// pango normalizes a move whose expected slot is index 0 into a
		// where="top" operation (movement.go GenerateMovements), so
		// "before nat-a" would be asserted as top, not before.
		{"top", MoveInput{Name: "nat-c", Position: "top"}, []string{"<move", "nat-c", `where="top"`}},
		{"bottom", MoveInput{Name: "nat-a", Position: "bottom"}, []string{"<move", "nat-a", `where="bottom"`}},
		{"before", MoveInput{Name: "nat-c", Position: "before", RelativeTo: "nat-b"}, []string{"<move", "nat-c", `where="before"`, `dst="nat-b"`}},
		{"after", MoveInput{Name: "nat-a", Position: "after", RelativeTo: "nat-b"}, []string{"<move", "nat-a", `where="after"`, `dst="nat-b"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM",
				// Entry-specific get first: it answers the existence read;
				// the generic get answers MoveGroup's rulebase listing.
				fakeRoute{Match: getEntryXpath(c.in.Name), Body: natRuleGetBody(c.in.Name)},
				fakeRoute{Match: configAction("get"), Body: natRuleListBody},
				fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
			)
			h := moveHandler[nat.Location, nat.Entry](d, "panos_nat_rule_move",
				newNatRuleService(d), nat.NewService(d.Client), natResolve(d))
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
		h := moveHandler[nat.Location, nat.Entry](d, "panos_nat_rule_move",
			newNatRuleService(d), nat.NewService(d.Client), natResolve(d))
		res, _, err := h(t.Context(), nil, MoveInput{Name: "nat-a", Position: "before"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("before without relative_to must be an error")
		}
		if got := len(f.Requests()); got != 1 {
			t.Fatalf("expected no API traffic beyond bootstrap, recorded %d requests", got)
		}
	})

	t.Run("missing rule", func(t *testing.T) {
		// No get route: the existence read hits the fake's fail-loud
		// unmatched-request error and must stop the move.
		d, f := newTestDeps(t, "PA-VM")
		h := moveHandler[nat.Location, nat.Entry](d, "panos_nat_rule_move",
			newNatRuleService(d), nat.NewService(d.Client), natResolve(d))
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

// TestRegisterNatRuleToolsReadOnly pins the write-safety gate: all four
// mutating tools, including move, are registered only when writes are
// enabled, while the read tools are always present. This is the sole
// enforcement point, so dropping the d.ReadOnly gate must fail here.
func TestRegisterNatRuleToolsReadOnly(t *testing.T) {
	reads := []string{"panos_nat_rule_list", "panos_nat_rule_get"}
	writes := []string{"panos_nat_rule_create", "panos_nat_rule_update", "panos_nat_rule_delete", "panos_nat_rule_move"}

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

func TestNatRuleGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: natRuleGetBody("out-snat")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterNatRuleTools(srv, d)

	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_nat_rule_get", Arguments: map[string]any{"name": "out-snat"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and
	// target the NAT rulebase; a raw-service wiring (which also satisfies
	// crudService) would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='out-snat']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "nat/rules") {
		t.Fatalf("registered get did not target the NAT rulebase: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_nat_rule_update", Arguments: map[string]any{"name": "out-snat", "service": "http-svc"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "<service>http-svc</service>") || !strings.Contains(el, "out-snat") {
		t.Fatalf("registered update did not reach the API with the new service: %s", el)
	}
}
