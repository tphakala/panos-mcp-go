package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/policies/rules/authentication"
	"github.com/PaloAltoNetworks/pango/policies/rules/decryption"
	"github.com/PaloAltoNetworks/pango/policies/rules/pbf"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Fixtures ---------------------------------------------------------------

// decryptionRuleEntryXML renders a canned no-decrypt / ssl-forward-proxy rule.
// The <type><ssl-forward-proxy/></type> shape is the pango wire form (see
// decryption/entry.go typeXml tags).
func decryptionRuleEntryXML(name string) string {
	return `<entry name="` + name + `"><action>no-decrypt</action>` +
		`<from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service><member>any</member></service>` +
		`<type><ssl-forward-proxy/></type>` +
		`<description>` + name + ` desc</description><tag><member>t1</member></tag></entry>`
}

func decryptionRuleGetBody(name string) string {
	return `<response status="success"><result>` + decryptionRuleEntryXML(name) + `</result></response>`
}

// decryptionInboundEntryXML renders a decrypt / ssl-inbound-inspection rule
// carrying a certificate, for the get-detail projection test.
func decryptionInboundEntryXML(name string) string {
	return `<entry name="` + name + `"><action>decrypt</action>` +
		`<from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service><member>any</member></service>` +
		`<type><ssl-inbound-inspection><certificates><member>cert1</member></certificates></ssl-inbound-inspection></type>` +
		`</entry>`
}

func decryptionInboundGetBody(name string) string {
	return `<response status="success"><result>` + decryptionInboundEntryXML(name) + `</result></response>`
}

var decryptionRuleListBody = `<response status="success"><result>` +
	decryptionRuleEntryXML("dec-a") + decryptionRuleEntryXML("dec-b") + decryptionRuleEntryXML("dec-c") +
	`</result></response>`

func decryptionResolve(d *Deps) func(LocationInput) (decryption.Location, error) {
	return func(in LocationInput) (decryption.Location, error) {
		return resolveLocation(d, in, decryptionParts())
	}
}

func decryptionRuleName(e *decryption.Entry) string { return e.Name }

// authRuleEntryXML renders a canned authentication rule with an enforcement
// object and a timeout.
func authRuleEntryXML(name string) string {
	return `<entry name="` + name + `">` +
		`<authentication-enforcement>default-web-form</authentication-enforcement>` +
		`<timeout>60</timeout>` +
		`<from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service><member>any</member></service>` +
		`<description>` + name + ` desc</description><tag><member>t1</member></tag></entry>`
}

func authRuleGetBody(name string) string {
	return `<response status="success"><result>` + authRuleEntryXML(name) + `</result></response>`
}

var authRuleListBody = `<response status="success"><result>` +
	authRuleEntryXML("auth-a") + authRuleEntryXML("auth-b") + authRuleEntryXML("auth-c") +
	`</result></response>`

func authenticationResolve(d *Deps) func(LocationInput) (authentication.Location, error) {
	return func(in LocationInput) (authentication.Location, error) {
		return resolveLocation(d, in, authenticationParts())
	}
}

func authenticationRuleName(e *authentication.Entry) string { return e.Name }

// pbfRuleEntryXML renders a canned forward PBF rule (egress interface plus a
// next-hop IP, zone-based from). The nested action chain is the pango wire form
// (see pbf/entry.go actionXml/fromXml tags).
func pbfRuleEntryXML(name string) string {
	return `<entry name="` + name + `">` +
		`<action><forward><egress-interface>ethernet1/3</egress-interface>` +
		`<nexthop><ip-address>10.0.0.1</ip-address></nexthop></forward></action>` +
		`<from><zone><member>trust</member></zone></from>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service><member>any</member></service><application><member>any</member></application>` +
		`<description>` + name + ` desc</description><tag><member>t1</member></tag></entry>`
}

func pbfRuleGetBody(name string) string {
	return `<response status="success"><result>` + pbfRuleEntryXML(name) + `</result></response>`
}

var pbfRuleListBody = `<response status="success"><result>` +
	pbfRuleEntryXML("pbf-a") + pbfRuleEntryXML("pbf-b") + pbfRuleEntryXML("pbf-c") +
	`</result></response>`

func pbfResolve(d *Deps) func(LocationInput) (pbf.Location, error) {
	return func(in LocationInput) (pbf.Location, error) {
		return resolveLocation(d, in, pbfParts())
	}
}

func pbfRuleName(e *pbf.Entry) string { return e.Name }

// --- Decryption: unit tests -------------------------------------------------

func TestBuildDecryptionRuleEntry(t *testing.T) {
	e, err := buildDecryptionRuleEntry(DecryptionRuleInput{
		Name: "dec", Action: "no-decrypt", Description: "d",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Match fields default to any (a rule with an empty member list fails
	// commit); action is set verbatim; type stays unset when not requested.
	if e.Action == nil || *e.Action != "no-decrypt" {
		t.Errorf("action = %v, want no-decrypt", e.Action)
	}
	for name, got := range map[string][]string{"from": e.From, "to": e.To, "source": e.Source, "destination": e.Destination, "service": e.Service} {
		if len(got) != 1 || got[0] != "any" {
			t.Errorf("%s default = %v, want [any]", name, got)
		}
	}
	if e.Type != nil {
		t.Errorf("type must stay unset when decryption_type omitted, got %+v", e.Type)
	}
}

func TestBuildDecryptionRuleEntryType(t *testing.T) {
	fwd, err := buildDecryptionRuleEntry(DecryptionRuleInput{Name: "d", Action: "decrypt", DecryptionType: "ssl-forward-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if fwd.Type == nil || fwd.Type.SslForwardProxy == nil {
		t.Fatalf("ssl-forward-proxy type not built: %+v", fwd.Type)
	}
	inb, err := buildDecryptionRuleEntry(DecryptionRuleInput{Name: "d", Action: "decrypt", DecryptionType: "ssl-inbound-inspection", Certificates: []string{"cert1"}})
	if err != nil {
		t.Fatal(err)
	}
	if inb.Type == nil || inb.Type.SslInboundInspection == nil || len(inb.Type.SslInboundInspection.Certificates) != 1 || inb.Type.SslInboundInspection.Certificates[0] != "cert1" {
		t.Fatalf("ssl-inbound-inspection certificates not built: %+v", inb.Type)
	}
}

func TestBuildDecryptionRuleEntryRejects(t *testing.T) {
	cases := []struct {
		name    string
		in      DecryptionRuleInput
		wantErr string
	}{
		{"no name", DecryptionRuleInput{Action: "decrypt"}, "name is required"},
		{"no action", DecryptionRuleInput{Name: "d"}, "action is required"},
		{"bad action", DecryptionRuleInput{Name: "d", Action: "permit"}, "action must be one of"},
		{"bad type", DecryptionRuleInput{Name: "d", Action: "decrypt", DecryptionType: "bogus"}, "decryption_type must be one of"},
		{"certs wrong type", DecryptionRuleInput{Name: "d", Action: "decrypt", DecryptionType: "ssl-forward-proxy", Certificates: []string{"c"}}, "certificates require decryption_type ssl-inbound-inspection"},
		{"certs no type", DecryptionRuleInput{Name: "d", Action: "decrypt", Certificates: []string{"c"}}, "certificates require decryption_type ssl-inbound-inspection"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildDecryptionRuleEntry(c.in)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func decryptionOverlayBase(t *testing.T) *decryption.Entry {
	t.Helper()
	e, err := buildDecryptionRuleEntry(DecryptionRuleInput{Name: "d", Action: "no-decrypt", DecryptionType: "ssl-forward-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOverlayDecryptionRuleFields(t *testing.T) {
	// Empty input leaves everything, including the type oneof, untouched.
	e := decryptionOverlayBase(t)
	if err := overlayDecryptionRule(e, DecryptionRuleInput{Name: "d"}); err != nil {
		t.Fatal(err)
	}
	if *e.Action != "no-decrypt" || e.Type == nil || e.Type.SslForwardProxy == nil {
		t.Fatalf("empty overlay mutated action/type: action=%v type=%+v", e.Action, e.Type)
	}
	if len(e.Source) != 1 || e.Source[0] != "any" {
		t.Fatalf("empty overlay mutated source: %v", e.Source)
	}

	// action replaces.
	e = decryptionOverlayBase(t)
	if err := overlayDecryptionRule(e, DecryptionRuleInput{Action: "decrypt"}); err != nil {
		t.Fatal(err)
	}
	if *e.Action != "decrypt" {
		t.Errorf("action overlay = %v, want decrypt", *e.Action)
	}

	// a non-empty match list replaces fully.
	e = decryptionOverlayBase(t)
	if err := overlayDecryptionRule(e, DecryptionRuleInput{Source: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Source) != 1 || e.Source[0] != "10.0.0.0/8" {
		t.Errorf("source overlay = %v", e.Source)
	}
}

func TestOverlayDecryptionRuleType(t *testing.T) {
	// type replacement swaps the whole oneof, clearing the previous member.
	e := decryptionOverlayBase(t)
	if err := overlayDecryptionRule(e, DecryptionRuleInput{DecryptionType: "ssh-proxy"}); err != nil {
		t.Fatal(err)
	}
	if e.Type == nil || e.Type.SshProxy == nil || e.Type.SslForwardProxy != nil {
		t.Fatalf("type replacement did not clear the old member: %+v", e.Type)
	}

	// invalid action and certs-without-inbound are rejected on update too.
	if err := overlayDecryptionRule(decryptionOverlayBase(t), DecryptionRuleInput{Action: "bogus"}); err == nil {
		t.Error("invalid action must be rejected on update")
	}
	if err := overlayDecryptionRule(decryptionOverlayBase(t), DecryptionRuleInput{Certificates: []string{"c"}}); err == nil {
		t.Error("certificates without ssl-inbound-inspection must be rejected on update")
	}
}

// --- Authentication: unit tests ---------------------------------------------

func TestBuildAuthenticationRuleEntry(t *testing.T) {
	e, err := buildAuthenticationRuleEntry(AuthenticationRuleInput{
		Name: "auth", AuthenticationEnforcement: "default-web-form", Timeout: ptr(int64(60)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.AuthenticationEnforcement == nil || *e.AuthenticationEnforcement != "default-web-form" {
		t.Errorf("authentication_enforcement = %v", e.AuthenticationEnforcement)
	}
	if e.Timeout == nil || *e.Timeout != 60 {
		t.Errorf("timeout = %v, want 60", e.Timeout)
	}
	for name, got := range map[string][]string{"from": e.From, "to": e.To, "source": e.Source, "destination": e.Destination, "service": e.Service} {
		if len(got) != 1 || got[0] != "any" {
			t.Errorf("%s default = %v, want [any]", name, got)
		}
	}
}

func TestBuildAuthenticationRuleEntryRejects(t *testing.T) {
	cases := []struct {
		name    string
		in      AuthenticationRuleInput
		wantErr string
	}{
		{"no name", AuthenticationRuleInput{}, "name is required"},
		{"timeout zero", AuthenticationRuleInput{Name: "a", Timeout: ptr(int64(0))}, "timeout must be at least 1"},
		{"timeout negative", AuthenticationRuleInput{Name: "a", Timeout: ptr(int64(-5))}, "timeout must be at least 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildAuthenticationRuleEntry(c.in)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestOverlayAuthenticationRuleFields(t *testing.T) {
	base := func() *authentication.Entry {
		e, err := buildAuthenticationRuleEntry(AuthenticationRuleInput{Name: "a", AuthenticationEnforcement: "default-web-form", Timeout: ptr(int64(60))})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	e := base()
	if err := overlayAuthenticationRule(e, AuthenticationRuleInput{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if *e.AuthenticationEnforcement != "default-web-form" || *e.Timeout != 60 {
		t.Fatalf("empty overlay mutated enforcement/timeout: %v %v", e.AuthenticationEnforcement, e.Timeout)
	}

	e = base()
	if err := overlayAuthenticationRule(e, AuthenticationRuleInput{AuthenticationEnforcement: "cert-auth", Timeout: ptr(int64(30))}); err != nil {
		t.Fatal(err)
	}
	if *e.AuthenticationEnforcement != "cert-auth" || *e.Timeout != 30 {
		t.Errorf("overlay = %v %v, want cert-auth 30", *e.AuthenticationEnforcement, *e.Timeout)
	}

	e = base()
	if err := overlayAuthenticationRule(e, AuthenticationRuleInput{Source: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Source) != 1 || e.Source[0] != "10.0.0.0/8" {
		t.Errorf("source overlay = %v", e.Source)
	}

	if err := overlayAuthenticationRule(base(), AuthenticationRuleInput{Timeout: ptr(int64(0))}); err == nil {
		t.Error("timeout 0 must be rejected on update")
	}
}

// --- PBF: unit tests --------------------------------------------------------

func TestBuildPbfRuleEntry(t *testing.T) {
	e, err := buildPbfRuleEntry(PbfRuleInput{
		Name: "pbf", Action: "forward", EgressInterface: "ethernet1/3", NexthopIP: "10.0.0.1", From: []string{"trust"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Action == nil || e.Action.Forward == nil || e.Action.Forward.EgressInterface == nil || *e.Action.Forward.EgressInterface != "ethernet1/3" {
		t.Fatalf("forward egress not built: %+v", e.Action)
	}
	if nh := e.Action.Forward.Nexthop; nh == nil || nh.IpAddress == nil || *nh.IpAddress != "10.0.0.1" {
		t.Fatalf("forward nexthop ip not built: %+v", e.Action.Forward.Nexthop)
	}
	if e.From == nil || len(e.From.Zone) != 1 || e.From.Zone[0] != "trust" {
		t.Fatalf("from zone not built: %+v", e.From)
	}
	for name, got := range map[string][]string{"source": e.Source, "destination": e.Destination, "service": e.Service, "application": e.Application} {
		if len(got) != 1 || got[0] != "any" {
			t.Errorf("%s default = %v, want [any]", name, got)
		}
	}
}

func TestBuildPbfRuleEntryActions(t *testing.T) {
	cases := []struct {
		name  string
		in    PbfRuleInput
		check func(*pbf.Entry) error
	}{
		{"discard", PbfRuleInput{Name: "p", Action: "discard", From: []string{"trust"}}, func(e *pbf.Entry) error {
			if e.Action == nil || e.Action.Discard == nil {
				return fmt.Errorf("discard action not built: %+v", e.Action)
			}
			return nil
		}},
		{"forward-to-vsys", PbfRuleInput{Name: "p", Action: "forward-to-vsys", ForwardVsys: "vsys2", From: []string{"trust"}}, func(e *pbf.Entry) error {
			if e.Action == nil || e.Action.ForwardToVsys == nil || *e.Action.ForwardToVsys != "vsys2" {
				return fmt.Errorf("forward-to-vsys action not built: %+v", e.Action)
			}
			return nil
		}},
		{"no-pbf", PbfRuleInput{Name: "p", Action: "no-pbf", From: []string{"trust"}}, func(e *pbf.Entry) error {
			if e.Action == nil || e.Action.NoPbf == nil {
				return fmt.Errorf("no-pbf action not built: %+v", e.Action)
			}
			return nil
		}},
		{"forward nexthop fqdn", PbfRuleInput{Name: "p", Action: "forward", EgressInterface: "e1", NexthopFQDN: "gw.example", From: []string{"trust"}}, func(e *pbf.Entry) error {
			nh := e.Action.Forward.Nexthop
			if nh == nil || nh.Fqdn == nil || *nh.Fqdn != "gw.example" || nh.IpAddress != nil {
				return fmt.Errorf("forward nexthop fqdn not built (or ip set): %+v", nh)
			}
			return nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := buildPbfRuleEntry(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.check(e); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// asMap checked-asserts a summary's any return to its concrete map shape.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("summary is not a map[string]any: %T", v)
	}
	return m
}

// TestPbfRuleSummaryActions pins pbfActionString and pbfRuleSummary across all
// four action members and the fields only some carry, so a mis-mapped action
// (e.g. a discard rule summarized as forward) cannot slip through the way it
// would if only the forward member were tested.
func TestPbfRuleSummaryActions(t *testing.T) {
	build := func(in PbfRuleInput) map[string]any {
		e, err := buildPbfRuleEntry(in)
		if err != nil {
			t.Fatal(err)
		}
		return asMap(t, pbfRuleSummary(e))
	}

	vsys := build(PbfRuleInput{Name: "v", Action: "forward-to-vsys", ForwardVsys: "vsys2", From: []string{"trust"}})
	if vsys["action"] != "forward-to-vsys" || vsys["forward_vsys"] != "vsys2" {
		t.Fatalf("forward-to-vsys summary = %v", vsys)
	}
	if build(PbfRuleInput{Name: "d", Action: "discard", From: []string{"trust"}})["action"] != "discard" {
		t.Fatal("discard action not summarized")
	}
	if build(PbfRuleInput{Name: "n", Action: "no-pbf", From: []string{"trust"}})["action"] != "no-pbf" {
		t.Fatal("no-pbf action not summarized")
	}
	fqdn := build(PbfRuleInput{Name: "f", Action: "forward", EgressInterface: "e1", NexthopFQDN: "gw.example", From: []string{"trust"}})
	if fqdn["nexthop_fqdn"] != "gw.example" {
		t.Fatalf("nexthop_fqdn not summarized: %v", fqdn)
	}

	// An interface-based from is SDK-only (create/update model zones), but the
	// summary must read it faithfully.
	iface := &pbf.Entry{Name: "i", Action: &pbf.Action{Discard: &pbf.ActionDiscard{}}, From: &pbf.From{Interface: []string{"ethernet1/5"}}}
	m := asMap(t, pbfRuleSummary(iface))
	if fi, ok := m["from_interfaces"].([]string); !ok || len(fi) != 1 || fi[0] != "ethernet1/5" {
		t.Fatalf("from_interfaces not summarized: %v", m)
	}
}

// TestDecryptionRuleSummaryTypes pins decryptionTypeString across the ssh-proxy
// member and a typeless entry, which the list and get-detail fixtures (both
// ssl-forward-proxy / ssl-inbound-inspection) never exercise.
func TestDecryptionRuleSummaryTypes(t *testing.T) {
	e, err := buildDecryptionRuleEntry(DecryptionRuleInput{Name: "s", Action: "decrypt", DecryptionType: "ssh-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if got := asMap(t, decryptionRuleSummary(e))["decryption_type"]; got != "ssh-proxy" {
		t.Fatalf("ssh-proxy summary = %v", got)
	}
	// A typeless rule reports an empty decryption_type, not a panic.
	e, err = buildDecryptionRuleEntry(DecryptionRuleInput{Name: "n", Action: "no-decrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if got := asMap(t, decryptionRuleSummary(e))["decryption_type"]; got != "" {
		t.Fatalf("typeless summary decryption_type = %v, want empty", got)
	}
}

func TestBuildPbfRuleEntryRejects(t *testing.T) {
	cases := []struct {
		name    string
		in      PbfRuleInput
		wantErr string
	}{
		{"no name", PbfRuleInput{Action: "discard", From: []string{"trust"}}, "name is required"},
		{"no action", PbfRuleInput{Name: "p", From: []string{"trust"}}, "action is required"},
		{"no from", PbfRuleInput{Name: "p", Action: "forward", EgressInterface: "e1"}, "from is required"},
		{"bad action", PbfRuleInput{Name: "p", Action: "bogus", From: []string{"trust"}}, "action must be one of"},
		{"forward no egress", PbfRuleInput{Name: "p", Action: "forward", From: []string{"trust"}}, "requires egress_interface"},
		{"forward both nexthops", PbfRuleInput{Name: "p", Action: "forward", EgressInterface: "e1", NexthopIP: "1.1.1.1", NexthopFQDN: "gw.example", From: []string{"trust"}}, "not both"},
		{"discard with egress", PbfRuleInput{Name: "p", Action: "discard", EgressInterface: "e1", From: []string{"trust"}}, "apply only to action forward"},
		{"vsys no target", PbfRuleInput{Name: "p", Action: "forward-to-vsys", From: []string{"trust"}}, "requires forward_vsys"},
		{"vsys param on forward", PbfRuleInput{Name: "p", Action: "forward", EgressInterface: "e1", ForwardVsys: "vsys2", From: []string{"trust"}}, "forward_vsys applies only to action forward-to-vsys"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildPbfRuleEntry(c.in)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func pbfOverlayBase(t *testing.T) *pbf.Entry {
	t.Helper()
	e, err := buildPbfRuleEntry(PbfRuleInput{Name: "p", Action: "forward", EgressInterface: "ethernet1/3", NexthopIP: "10.0.0.1", From: []string{"trust"}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOverlayPbfRuleFields(t *testing.T) {
	// Empty input leaves the action and from oneofs untouched.
	e := pbfOverlayBase(t)
	if err := overlayPbfRule(e, PbfRuleInput{Name: "p"}); err != nil {
		t.Fatal(err)
	}
	if e.Action == nil || e.Action.Forward == nil {
		t.Fatalf("empty overlay mutated action: %+v", e.Action)
	}
	if e.From == nil || len(e.From.Zone) != 1 || e.From.Zone[0] != "trust" {
		t.Fatalf("empty overlay mutated from: %+v", e.From)
	}

	// from replacement swaps the zone list.
	e = pbfOverlayBase(t)
	if err := overlayPbfRule(e, PbfRuleInput{From: []string{"dmz"}}); err != nil {
		t.Fatal(err)
	}
	if e.From == nil || len(e.From.Zone) != 1 || e.From.Zone[0] != "dmz" {
		t.Fatalf("from overlay = %+v", e.From)
	}

	// application list replaces fully.
	e = pbfOverlayBase(t)
	if err := overlayPbfRule(e, PbfRuleInput{Application: []string{"web-browsing"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Application) != 1 || e.Application[0] != "web-browsing" {
		t.Errorf("application overlay = %v", e.Application)
	}
}

func TestOverlayPbfRuleAction(t *testing.T) {
	// switching action to discard clears the forward subtree.
	e := pbfOverlayBase(t)
	if err := overlayPbfRule(e, PbfRuleInput{Action: "discard"}); err != nil {
		t.Fatal(err)
	}
	if e.Action == nil || e.Action.Discard == nil || e.Action.Forward != nil {
		t.Fatalf("action switch did not clear forward: %+v", e.Action)
	}

	// an action parameter without an action is rejected on update.
	if err := overlayPbfRule(pbfOverlayBase(t), PbfRuleInput{EgressInterface: "ethernet1/4"}); err == nil {
		t.Error("egress_interface without action must be rejected on update")
	}
}

// --- Decryption: wire-level tests -------------------------------------------

func TestDecryptionRuleCreateDefaults(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: decryptionRuleGetBody("dec-new")},
	)
	h := decryptionRuleCreateHandler(d, decryption.NewService(d.Client))
	res, _, err := h(ctx, nil, DecryptionRuleInput{Name: "dec-new", Action: "no-decrypt", DecryptionType: "ssl-forward-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{"<action>no-decrypt</action>", "<from><member>any</member></from>", "<service><member>any</member></service>", "<type><ssl-forward-proxy", "dec-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "decryption/rules") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall decryption rulebase: %s", xs)
	}
}

func TestDecryptionRuleCreateRequiresAction(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := decryptionRuleCreateHandler(d, decryption.NewService(d.Client))
	res, _, err := h(t.Context(), nil, DecryptionRuleInput{Name: "dec"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("create without action must fail")
	}
	assertNoConfigWrite(t, f)
}

func TestDecryptionRuleList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: decryptionRuleListBody})
	h := listHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_list", newDecryptionRuleService(d), decryptionResolve(d), decryptionRuleName, decryptionRuleSummary)
	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"total": 3`, `"dec-a"`, `"dec-c"`, `"decryption_type": "ssl-forward-proxy"`, `"dec-a desc"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("list missing %q: %s", want, out)
		}
	}
}

func TestDecryptionRuleGetReturnsTypeDetails(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: decryptionInboundGetBody("inbound")})
	h := getHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_get", newDecryptionRuleService(d), decryptionResolve(d), decryptionRuleSummary)
	res, _, err := h(t.Context(), nil, NameInput{Name: "inbound"})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"decryption_type": "ssl-inbound-inspection"`, `"certificates"`, "cert1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("get missing %q: %s", want, out)
		}
	}
	for _, leak := range []string{"SslInboundInspection", "MiscAttributes", `"Type"`} {
		if strings.Contains(out, leak) {
			t.Fatalf("get leaked %q: %s", leak, out)
		}
	}
}

func TestDecryptionRuleUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: decryptionRuleGetBody("dec-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[decryption.Location, decryption.Entry, DecryptionRuleInput](d, "panos_decryption_rule_update", newDecryptionRuleService(d), decryptionResolve(d),
		func(in DecryptionRuleInput) LocationInput { return in.Location },
		func(in DecryptionRuleInput) string { return in.Name }, overlayDecryptionRule, decryptionRuleSummary)
	res, _, err := h(t.Context(), nil, DecryptionRuleInput{Name: "dec-a", Action: "decrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("update failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<action>decrypt</action>") || !strings.Contains(el, "dec-a") {
		t.Fatalf("update element missing new action: %s", el)
	}
	// read-modify-write preserves the existing type and description.
	if !strings.Contains(el, "ssl-forward-proxy") || !strings.Contains(el, "dec-a desc") {
		t.Fatalf("update dropped preserved fields: %s", el)
	}
}

func TestDecryptionRuleDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_delete", newDecryptionRuleService(d), decryptionResolve(d))
	res, _, err := h(t.Context(), nil, NameInput{Name: "dec-a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "dec-a") || !strings.Contains(el, "decryption/rules") {
		t.Fatalf("delete element wrong: %s", el)
	}
}

func TestDecryptionRuleMove(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: getEntryXpath("dec-b"), Body: decryptionRuleGetBody("dec-b")},
		fakeRoute{Match: configAction("get"), Body: decryptionRuleListBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := moveHandler[decryption.Location, decryption.Entry](d, "panos_decryption_rule_move", newDecryptionRuleService(d), decryption.NewService(d.Client), decryptionResolve(d))
	res, _, err := h(t.Context(), nil, MoveInput{Name: "dec-b", Position: "top"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("move failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<move") || !strings.Contains(el, `where="top"`) || !strings.Contains(el, "dec-b") {
		t.Fatalf("move element wrong: %s", el)
	}

	// before without relative_to is rejected before any request.
	d2, f2 := newTestDeps(t, "PA-VM")
	h2 := moveHandler[decryption.Location, decryption.Entry](d2, "panos_decryption_rule_move", newDecryptionRuleService(d2), decryption.NewService(d2.Client), decryptionResolve(d2))
	res2, _, err := h2(t.Context(), nil, MoveInput{Name: "dec-b", Position: "before"})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.IsError {
		t.Fatal("before without relative_to must fail")
	}
	assertNoConfigWrite(t, f2)
}

func TestDecryptionRulePanoramaRulebase(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: decryptionRuleGetBody("dec-new")},
	)
	h := decryptionRuleCreateHandler(d, decryption.NewService(d.Client))
	res, _, err := h(t.Context(), nil, DecryptionRuleInput{
		Name: "dec-new", Action: "no-decrypt",
		Location: LocationInput{DeviceGroup: "dg1", Rulebase: "post"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "post-rulebase") || !strings.Contains(xs, "dg1") {
		t.Fatalf("panorama create did not target the device-group post rulebase: %s", xs)
	}
}

func TestRegisterDecryptionRuleToolsReadOnly(t *testing.T) {
	reads := []string{"panos_decryption_rule_list", "panos_decryption_rule_get"}
	writes := []string{"panos_decryption_rule_create", "panos_decryption_rule_update", "panos_decryption_rule_delete", "panos_decryption_rule_move"}
	assertReadOnlyGate(t, reads, writes)
}

func TestDecryptionRuleGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: decryptionRuleGetBody("dec-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterDecryptionRuleTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_decryption_rule_get", Arguments: map[string]any{"name": "dec-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='dec-a']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "decryption/rules") {
		t.Fatalf("registered get did not target the decryption rulebase: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_decryption_rule_update", Arguments: map[string]any{"name": "dec-a", "action": "decrypt"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "decrypt") || !strings.Contains(el, "dec-a") {
		t.Fatalf("registered update did not reach the API: %s", el)
	}
}

// --- Authentication: wire-level tests ---------------------------------------

func TestAuthenticationRuleCreateDefaults(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: authRuleGetBody("auth-new")},
	)
	h := authenticationRuleCreateHandler(d, authentication.NewService(d.Client))
	res, _, err := h(t.Context(), nil, AuthenticationRuleInput{Name: "auth-new"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{"<from><member>any</member></from>", "<service><member>any</member></service>", "auth-new"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	// nothing invented: a name-only create carries no enforcement or timeout.
	for _, unwanted := range []string{"authentication-enforcement", "<timeout>"} {
		if strings.Contains(set, unwanted) {
			t.Fatalf("create invented %q: %s", unwanted, set)
		}
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "authentication/rules") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall authentication rulebase: %s", xs)
	}
}

func TestAuthenticationRuleList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: authRuleListBody})
	h := listHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_list", newAuthenticationRuleService(d), authenticationResolve(d), authenticationRuleName, authenticationRuleSummary)
	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"total": 3`, `"auth-a"`, `"authentication_enforcement": "default-web-form"`, `"timeout": 60`} {
		if !strings.Contains(out, want) {
			t.Fatalf("list missing %q: %s", want, out)
		}
	}
}

func TestAuthenticationRuleUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: authRuleGetBody("auth-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[authentication.Location, authentication.Entry, AuthenticationRuleInput](d, "panos_authentication_rule_update", newAuthenticationRuleService(d), authenticationResolve(d),
		func(in AuthenticationRuleInput) LocationInput { return in.Location },
		func(in AuthenticationRuleInput) string { return in.Name }, overlayAuthenticationRule, authenticationRuleSummary)
	res, _, err := h(t.Context(), nil, AuthenticationRuleInput{Name: "auth-a", AuthenticationEnforcement: "cert-auth"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("update failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "cert-auth") || !strings.Contains(el, "auth-a") {
		t.Fatalf("update element missing new enforcement: %s", el)
	}
	if !strings.Contains(el, "auth-a desc") {
		t.Fatalf("update dropped the preserved description: %s", el)
	}
}

func TestAuthenticationRuleDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[authentication.Location, authentication.Entry](d, "panos_authentication_rule_delete", newAuthenticationRuleService(d), authenticationResolve(d))
	res, _, err := h(t.Context(), nil, NameInput{Name: "auth-a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "auth-a") || !strings.Contains(el, "authentication/rules") {
		t.Fatalf("delete element wrong: %s", el)
	}
}

func TestRegisterAuthenticationRuleToolsReadOnly(t *testing.T) {
	reads := []string{"panos_authentication_rule_list", "panos_authentication_rule_get"}
	writes := []string{"panos_authentication_rule_create", "panos_authentication_rule_update", "panos_authentication_rule_delete", "panos_authentication_rule_move"}
	assertReadOnlyGate(t, reads, writes)
}

func TestAuthenticationRuleGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: authRuleGetBody("auth-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAuthenticationRuleTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_authentication_rule_get", Arguments: map[string]any{"name": "auth-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='auth-a']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "authentication/rules") {
		t.Fatalf("registered get did not target the authentication rulebase: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_authentication_rule_update", Arguments: map[string]any{"name": "auth-a", "authentication_enforcement": "cert-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "cert-auth") {
		t.Fatalf("registered update did not reach the API: %s", el)
	}
}

// --- PBF: wire-level tests --------------------------------------------------

func TestPbfRuleCreateDefaults(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: pbfRuleGetBody("pbf-new")},
	)
	h := pbfRuleCreateHandler(d, pbf.NewService(d.Client))
	res, _, err := h(t.Context(), nil, PbfRuleInput{Name: "pbf-new", Action: "forward", EgressInterface: "ethernet1/3", From: []string{"trust"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	set := strings.Join(setElements(f), " ")
	for _, want := range []string{"<forward><egress-interface>ethernet1/3</egress-interface></forward>", "<from><zone><member>trust</member></zone></from>", "<source><member>any</member></source>", "<application><member>any</member></application>"} {
		if !strings.Contains(set, want) {
			t.Fatalf("create set element missing %q: %s", want, set)
		}
	}
	// no next-hop was supplied, so none is invented.
	if strings.Contains(set, "<nexthop>") {
		t.Fatalf("create invented a nexthop: %s", set)
	}
	if xs := strings.Join(getConfigXpaths(f), " "); !strings.Contains(xs, "pbf/rules") || !strings.Contains(xs, "vsys1") {
		t.Fatalf("create did not target the firewall pbf rulebase: %s", xs)
	}
}

func TestPbfRuleCreateRequiresActionAndFrom(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := pbfRuleCreateHandler(d, pbf.NewService(d.Client))
	// missing action
	res, _, err := h(t.Context(), nil, PbfRuleInput{Name: "p", From: []string{"trust"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("create without action must fail")
	}
	// missing from
	res2, _, err := h(t.Context(), nil, PbfRuleInput{Name: "p", Action: "discard"})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.IsError {
		t.Fatal("create without from must fail")
	}
	assertNoConfigWrite(t, f)
}

func TestPbfRuleList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: pbfRuleListBody})
	h := listHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_list", newPbfRuleService(d), pbfResolve(d), pbfRuleName, pbfRuleSummary)
	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"total": 3`, `"pbf-a"`, `"action": "forward"`, `"egress_interface": "ethernet1/3"`, `"nexthop_ip": "10.0.0.1"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("list missing %q: %s", want, out)
		}
	}
}

func TestPbfRuleGetReturnsActionDetails(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: pbfRuleGetBody("fwd")})
	h := getHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_get", newPbfRuleService(d), pbfResolve(d), pbfRuleSummary)
	res, _, err := h(t.Context(), nil, NameInput{Name: "fwd"})
	if err != nil {
		t.Fatal(err)
	}
	out := textContent(t, res)
	for _, want := range []string{`"action": "forward"`, `"egress_interface": "ethernet1/3"`, `"nexthop_ip": "10.0.0.1"`, `"trust"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("get missing %q: %s", want, out)
		}
	}
	for _, leak := range []string{"ActionForward", "MiscAttributes", "IpAddress"} {
		if strings.Contains(out, leak) {
			t.Fatalf("get leaked %q: %s", leak, out)
		}
	}
}

func TestPbfRuleUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: pbfRuleGetBody("pbf-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[pbf.Location, pbf.Entry, PbfRuleInput](d, "panos_pbf_rule_update", newPbfRuleService(d), pbfResolve(d),
		func(in PbfRuleInput) LocationInput { return in.Location },
		func(in PbfRuleInput) string { return in.Name }, overlayPbfRule, pbfRuleSummary)
	// change only the description; action and from must survive the RMW.
	res, _, err := h(t.Context(), nil, PbfRuleInput{Name: "pbf-a", Description: "changed"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("update failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "changed") || !strings.Contains(el, "pbf-a") {
		t.Fatalf("update element missing new description: %s", el)
	}
	for _, preserved := range []string{"<forward><egress-interface>ethernet1/3", "<from><zone><member>trust</member></zone></from>"} {
		if !strings.Contains(el, preserved) {
			t.Fatalf("update dropped preserved %q: %s", preserved, el)
		}
	}
}

func TestPbfRuleDelete(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_delete", newPbfRuleService(d), pbfResolve(d))
	res, _, err := h(t.Context(), nil, NameInput{Name: "pbf-a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("delete failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "pbf-a") || !strings.Contains(el, "pbf/rules") {
		t.Fatalf("delete element wrong: %s", el)
	}
}

func TestPbfRuleMove(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: getEntryXpath("pbf-b"), Body: pbfRuleGetBody("pbf-b")},
		fakeRoute{Match: configAction("get"), Body: pbfRuleListBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := moveHandler[pbf.Location, pbf.Entry](d, "panos_pbf_rule_move", newPbfRuleService(d), pbf.NewService(d.Client), pbfResolve(d))
	res, _, err := h(t.Context(), nil, MoveInput{Name: "pbf-b", Position: "top"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("move failed: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<move") || !strings.Contains(el, `where="top"`) || !strings.Contains(el, "pbf-b") {
		t.Fatalf("move element wrong: %s", el)
	}
}

func TestRegisterPbfRuleToolsReadOnly(t *testing.T) {
	reads := []string{"panos_pbf_rule_list", "panos_pbf_rule_get"}
	writes := []string{"panos_pbf_rule_create", "panos_pbf_rule_update", "panos_pbf_rule_delete", "panos_pbf_rule_move"}
	assertReadOnlyGate(t, reads, writes)
}

func TestPbfRuleGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: pbfRuleGetBody("pbf-a")},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterPbfRuleTools(srv, d)
	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_pbf_rule_get", Arguments: map[string]any{"name": "pbf-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	assertSingleWrappedGet(t, f, "entry[@name='pbf-a']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "pbf/rules") {
		t.Fatalf("registered get did not target the pbf rulebase: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_pbf_rule_update", Arguments: map[string]any{"name": "pbf-a", "description": "changed"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "changed") {
		t.Fatalf("registered update did not reach the API: %s", el)
	}
}

// TestDecryptionRuleCreateInboundCertificates pins the build-to-wire path for
// the ssl-inbound-inspection type: the certificates reach the set element,
// which TestDecryptionRuleCreateDefaults (ssl-forward-proxy) does not exercise.
func TestDecryptionRuleCreateInboundCertificates(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: decryptionInboundGetBody("inbound")},
	)
	h := decryptionRuleCreateHandler(d, decryption.NewService(d.Client))
	res, _, err := h(t.Context(), nil, DecryptionRuleInput{Name: "inbound", Action: "decrypt", DecryptionType: "ssl-inbound-inspection", Certificates: []string{"cert1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<ssl-inbound-inspection><certificates><member>cert1</member></certificates></ssl-inbound-inspection>") {
		t.Fatalf("create set element missing inbound certificates: %s", set)
	}
}

// TestPbfRuleCreateForwardToVsys pins the build-to-wire path for the
// forward-to-vsys action, which TestPbfRuleCreateDefaults (forward) does not
// exercise.
func TestPbfRuleCreateForwardToVsys(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: pbfRuleGetBody("vsys-fwd")},
	)
	h := pbfRuleCreateHandler(d, pbf.NewService(d.Client))
	res, _, err := h(t.Context(), nil, PbfRuleInput{Name: "vsys-fwd", Action: "forward-to-vsys", ForwardVsys: "vsys2", From: []string{"trust"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	if set := strings.Join(setElements(f), " "); !strings.Contains(set, "<action><forward-to-vsys>vsys2</forward-to-vsys></action>") {
		t.Fatalf("create set element missing forward-to-vsys: %s", set)
	}
}

// assertReadOnlyGate pins the write-safety gate for a rulebase: the read tools
// are always registered, the mutating tools only when writes are enabled.
// Dropping the d.ReadOnly return in a Register function fails here.
func assertReadOnlyGate(t *testing.T, reads, writes []string) {
	t.Helper()
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
