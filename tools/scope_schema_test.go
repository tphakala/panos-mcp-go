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
		[]string{"name", "vsys", "shared", "template", "template_stack", "template_vsys",
			"base", "bind_dn", "bind_password", "bind_timelimit", "disabled", "ldap_type",
			"retry_interval", "servers", "ssl", "timelimit", "verify_server_certificate"},
		[]string{"name"})
	assertDescriptions(t, tool, got, map[string]string{
		"template":       "Panorama template name (Panorama only; mutually exclusive with template_stack)",
		"template_stack": "Panorama template-stack name (Panorama only; mutually exclusive with template)",
	})
	for _, prop := range []string{"vsys", "shared"} {
		if _, ok := got.Properties[prop]; !ok {
			t.Errorf("%s lost the %q property: the device scope has that tier", tool, prop)
		}
	}
	if _, ok := got.Properties["panorama"]; ok {
		t.Errorf("%s must not expose panorama: that tier belongs to the profile scope", tool)
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
