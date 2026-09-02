package tools

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP input schemas are this server's public API: a renamed field, a
// reworded description or a changed required-set breaks every client. They are
// inferred from the tool input structs by jsonschema-go, so a refactor of the
// shared scope machinery can move them without touching a single tag.
//
// These tests pin one representative tool per scope family against a literal:
// its exact top-level property set, its exact required set, and the wording of
// the scope-derived descriptions. They exist to make a scope refactor prove it
// changed nothing, so a diff here is either a deliberate, reviewed API change or
// a bug. Pinning the exact property SET is what makes an ADDED field fail too,
// not only a renamed or removed one.

// toolSchema is the part of a tool's inferred input schema these tests pin.
type toolSchema struct {
	Properties map[string]struct {
		Description string `json:"description"`
	} `json:"properties"`
	Required []string `json:"required"`
}

// inputSchema returns the inferred input schema of one registered tool. The
// go-sdk carries it as an any, so it is round-tripped through JSON, which is
// also exactly the form a client receives.
func inputSchema(t *testing.T, tool string) toolSchema {
	t.Helper()
	d, _ := newTestDeps(t, "Panorama")
	s := mcp.NewServer(&mcp.Implementation{Name: "schema-test", Version: "0"}, nil)
	RegisterAll(s, d)
	cs := connectInMemory(t, s)

	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name != tool {
			continue
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tool, err)
		}
		var got toolSchema
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s input schema: %v", tool, err)
		}
		return got
	}
	t.Fatalf("tool %q is not registered", tool)
	return toolSchema{}
}

// assertProperties fails unless the schema exposes exactly the named top-level
// properties and exactly the named required ones.
func assertProperties(t *testing.T, tool string, got toolSchema, wantProps, wantRequired []string) {
	t.Helper()
	names := slices.Sorted(maps.Keys(got.Properties))
	slices.Sort(wantProps)
	if !slices.Equal(names, wantProps) {
		t.Errorf("%s top-level properties changed:\n got  %v\n want %v", tool, names, wantProps)
	}
	required := slices.Clone(got.Required)
	slices.Sort(required)
	slices.Sort(wantRequired)
	if !slices.Equal(required, wantRequired) {
		t.Errorf("%s required set changed:\n got  %v\n want %v", tool, required, wantRequired)
	}
}

// assertDescriptions fails unless each named property carries exactly the given
// description. Only the scope-derived properties are pinned, since those are the
// ones a scope refactor can move.
func assertDescriptions(t *testing.T, tool string, got toolSchema, want map[string]string) {
	t.Helper()
	for prop, wantDesc := range want {
		p, ok := got.Properties[prop]
		if !ok {
			t.Errorf("%s lost the %q property", tool, prop)
			continue
		}
		if p.Description != wantDesc {
			t.Errorf("%s property %q description changed:\n got  %q\n want %q", tool, prop, p.Description, wantDesc)
		}
	}
}

func TestNetScopeSchemaUnchanged(t *testing.T) {
	const tool = "panos_bfd_profile_create"
	got := inputSchema(t, tool)
	assertProperties(t, tool, got,
		[]string{"name", "template", "template_stack", "mode", "min_rx_interval", "min_tx_interval", "detection_multiplier", "hold_time"},
		[]string{"name"})
	assertDescriptions(t, tool, got, map[string]string{
		"template":       "Panorama template name (Panorama only; mutually exclusive with template_stack)",
		"template_stack": "Panorama template-stack name (Panorama only; mutually exclusive with template)",
	})
	if _, ok := got.Properties["vsys"]; ok {
		t.Errorf("%s must not expose vsys: the net scope has no vsys tier", tool)
	}
	if _, ok := got.Properties["panorama"]; ok {
		t.Errorf("%s must not expose panorama: the net scope has no panorama tier", tool)
	}
}

func TestDeviceScopeSchemaUnchanged(t *testing.T) {
	const tool = "panos_ldap_profile_create"
	got := inputSchema(t, tool)
	assertProperties(t, tool, got,
		[]string{"name", "vsys", "shared", "panorama", "template", "template_stack", "template_vsys",
			"base", "bind_dn", "bind_password", "bind_timelimit", "disabled", "ldap_type",
			"retry_interval", "servers", "ssl", "timelimit", "verify_server_certificate"},
		[]string{"name"})
	assertDescriptions(t, tool, got, map[string]string{
		"vsys":           "Firewall vsys name (firewall only; default vsys1). On Panorama use template_vsys instead; a vsys here is rejected.",
		"shared":         "Use the shared scope (firewall shared, or Panorama shared pushed to all device groups). Not available for snmp-trap, email and authentication profiles.",
		"panorama":       "Use the Panorama management-plane scope (Panorama only). Not available for local database users and MFA server profiles.",
		"template":       "Panorama template name (Panorama only; mutually exclusive with template_stack)",
		"template_stack": "Panorama template-stack name (Panorama only; mutually exclusive with template)",
		"template_vsys":  "vsys within the chosen template or template-stack (Panorama only); omit for the template's shared scope",
	})
	// The shared description is now pinned literally above, because an edit to it
	// changes the published schema of 50 tools (ten device-scoped families times
	// five tools) and nothing used to fail when it did. TestProfileScopeSchemaUnchanged
	// already pins its equivalent; this closes the same gap on the device scope.
	//
	// The Contains check below is complementary, not redundant. The literal pin
	// catches an edit to the struct tag; this catches an edit to the const that
	// leaves the tag stale, which the literal pin alone would let through. A Go
	// struct tag cannot reference a const, so the tag restates noSharedScopeProfiles
	// in prose and only an assertion keeps the two copies honest.
	//
	// Sabotage: change a word in the DeviceScopeInput.Shared jsonschema tag and the
	// literal pin turns red; change a word in noSharedScopeProfiles instead and only
	// this Contains assertion turns red. The panorama property below is pinned the
	// same way against noPanoramaScopeFamilies.
	for _, prop := range []string{"vsys", "shared", "panorama"} {
		if _, ok := got.Properties[prop]; !ok {
			t.Errorf("%s lost the %q property: the device scope has that tier", tool, prop)
		}
	}
	if shared, ok := got.Properties["shared"]; ok {
		if d := shared.Description; !strings.Contains(d, noSharedScopeProfiles) {
			t.Errorf("%s: the shared description must restate noSharedScopeProfiles verbatim (a struct tag cannot reference a const); got %q, want it to contain %q", tool, d, noSharedScopeProfiles)
		}
	}
	if panorama, ok := got.Properties["panorama"]; ok {
		if d := panorama.Description; !strings.Contains(d, noPanoramaScopeFamilies) {
			t.Errorf("%s: the panorama description must restate noPanoramaScopeFamilies verbatim (a struct tag cannot reference a const); got %q, want it to contain %q", tool, d, noPanoramaScopeFamilies)
		}
	}
}

func TestProfileScopeSchemaUnchanged(t *testing.T) {
	const tool = "panos_certificate_profile_create"
	got := inputSchema(t, tool)
	assertProperties(t, tool, got,
		[]string{"name", "shared", "panorama", "template", "template_stack", "template_vsys",
			"block_expired_certificate", "block_timeout_certificate", "block_unauthenticated_certificate",
			"block_unknown_certificate", "certificate_authorities", "certificate_status_timeout",
			"crl_receive_timeout", "domain", "ocsp_exclude_nonce", "ocsp_receive_timeout",
			"use_crl", "use_ocsp", "username_field_subject", "username_field_subject_alt"},
		[]string{"name"})
	assertDescriptions(t, tool, got, map[string]string{
		"shared":        "Use the shared scope (the only scope on a firewall; on Panorama pushed to all device groups)",
		"panorama":      "Use the Panorama management-plane scope (Panorama only)",
		"template_vsys": "vsys within the chosen template or template_stack (Panorama only); omit for the template shared scope",
	})
	if _, ok := got.Properties["vsys"]; ok {
		t.Errorf("%s must not expose vsys: that tier belongs to the device scope", tool)
	}
}

func TestObjectScopeSchemaUnchanged(t *testing.T) {
	const tool = "panos_address_create"
	got := inputSchema(t, tool)
	assertProperties(t, tool, got,
		[]string{"name", "location", "description", "tags", "ip_netmask", "ip_range", "fqdn"},
		[]string{"name"})
	if _, ok := got.Properties["template"]; ok {
		t.Errorf("%s must not expose template: object scope nests its scope under location", tool)
	}
}

func TestMgtScopeSchemaUnchanged(t *testing.T) {
	const tool = "panos_administrator_create"
	got := inputSchema(t, tool)
	assertProperties(t, tool, got,
		[]string{"name", "panorama", "template", "template_stack",
			"authentication_profile", "client_certificate_only", "password_hash",
			"password_profile", "role", "role_profile", "role_vsys"},
		[]string{"name"})
	assertDescriptions(t, tool, got, map[string]string{
		"panorama":       "Use the Panorama management-plane scope (Panorama only)",
		"template":       "Panorama template name (Panorama only; mutually exclusive with template_stack)",
		"template_stack": "Panorama template-stack name (Panorama only; mutually exclusive with template)",
	})
	// mgt-config is device-wide, so neither vsys tier may appear: an
	// administrator cannot be narrowed to a vsys the way a server profile can.
	for _, prop := range []string{"vsys", "template_vsys", "shared"} {
		if _, ok := got.Properties[prop]; ok {
			t.Errorf("%s must not expose %q: mgt-config has no such tier", tool, prop)
		}
	}
	// The password hash is an input, never an output. Its presence here with the
	// documented write-only wording is what the summary projection is trusted
	// against.
	if p, ok := got.Properties["password_hash"]; !ok {
		t.Errorf("%s must accept password_hash", tool)
	} else if !strings.Contains(p.Description, "never returned") {
		t.Errorf("%s password_hash must document that it is never returned, got %q", tool, p.Description)
	}
}

// allInputSchemas returns the inferred input schema of every registered tool,
// keyed by tool name, from a single Panorama registration. inputSchema re-runs
// RegisterAll per tool, which is fine for the one-tool pins above but wasteful for
// a whole-surface sweep.
func allInputSchemas(t *testing.T) map[string]toolSchema {
	t.Helper()
	d, _ := newTestDeps(t, "Panorama")
	s := mcp.NewServer(&mcp.Implementation{Name: "schema-test", Version: "0"}, nil)
	RegisterAll(s, d)
	cs := connectInMemory(t, s)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]toolSchema, len(res.Tools))
	for _, tl := range res.Tools {
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tl.Name, err)
		}
		var got toolSchema
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s input schema: %v", tl.Name, err)
		}
		out[tl.Name] = got
	}
	return out
}

// hasAllProps reports whether the schema exposes every named top-level property.
func hasAllProps(sc toolSchema, props []string) bool {
	for _, p := range props {
		if _, ok := sc.Properties[p]; !ok {
			return false
		}
	}
	return true
}

// TestDeviceScopeSchemaUniformAcrossTools broadens TestDeviceScopeSchemaUnchanged
// from one representative tool to every device-scoped tool. They all embed the same
// DeviceScopeInput, so every one must expose the six scope properties with
// byte-identical descriptions; a scope refactor that skewed one family's scope
// schema, or a new family that embedded a divergent scope input, fails here.
//
// A device-scoped tool is identified by its scope signature: it exposes all six of
// vsys, shared, panorama, template, template_stack and template_vsys at top level.
// That set is unique to the device scope: the profile scope has no vsys, the net
// scope has neither vsys, shared nor panorama, the management scope has no shared,
// vsys or template_vsys, and the object and zone scopes expose no template_vsys at
// top level. The reference descriptions come from panos_ldap_profile_create, which
// TestDeviceScopeSchemaUnchanged pins against literals, so the two tests together
// cover all device-scoped tools: that one proves the reference wording, this one
// proves every other device-scoped tool matches it.
func TestDeviceScopeSchemaUniformAcrossTools(t *testing.T) {
	scopeProps := []string{"vsys", "shared", "panorama", "template", "template_stack", "template_vsys"}
	all := allInputSchemas(t)

	const ref = "panos_ldap_profile_create"
	refSchema, ok := all[ref]
	if !ok {
		t.Fatalf("reference tool %q is not registered", ref)
	}
	want := make(map[string]string, len(scopeProps))
	for _, p := range scopeProps {
		pv, ok := refSchema.Properties[p]
		if !ok {
			t.Fatalf("reference tool %q lost scope property %q", ref, p)
		}
		want[p] = pv.Description
	}

	var deviceTools []string
	for name, sc := range all {
		if hasAllProps(sc, scopeProps) {
			deviceTools = append(deviceTools, name)
		}
	}
	slices.Sort(deviceTools)

	// The device scope has ten families of five CRUD tools each. Asserting the exact
	// count guards against a signature change that silently narrowed the selection
	// (which would make the per-tool loop below vacuous) and makes an added family a
	// deliberate update here, matching the "prove a refactor changed nothing" intent
	// of the pins above.
	if len(deviceTools) != 50 {
		t.Errorf("expected 50 device-scoped tools (ten families x five CRUD tools), got %d: %v", len(deviceTools), deviceTools)
	}

	for _, name := range deviceTools {
		sc := all[name]
		for _, p := range scopeProps {
			pv, ok := sc.Properties[p]
			if !ok {
				t.Errorf("%s: device-scoped tool lost scope property %q", name, p)
				continue
			}
			if pv.Description != want[p] {
				t.Errorf("%s: scope property %q description diverges from %s:\n got  %q\n want %q", name, p, ref, pv.Description, want[p])
			}
		}
	}
}
