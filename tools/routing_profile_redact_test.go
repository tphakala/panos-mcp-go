package tools

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file pins the write-path secret seam (tools/redact.go) for the
// secret-bearing advanced-routing profile families in routing_profile_tools.go
// and the update-proxy singleton in system_service_tools.go: each must keep
// withSecrets(<extractor>) on its write registrations, or a failed write starts
// echoing the submitted key material into the tool result and the logs. Each
// test drives the real registered handler through the fake API, so it proves
// the extractor is wired in, not just that redactSecrets works in isolation.

// TestBgpAuthProfileCreateRedactsSecretOnError drives the BGP auth profile
// create tool: the device rejects the write echoing the submitted MD5 key, and
// the tool result must not carry it.
// Sabotage target: withSecrets(bgpAuthProfileSecrets) on the
// panos_bgp_auth_profile_create registration in RegisterBgpAuthProfileTools.
func TestBgpAuthProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "BGP-AUTH-SECRET-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterBgpAuthProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_bgp_auth_profile_create", Arguments: map[string]any{
		"name":   "bgpauth1",
		"secret": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}

// TestBgpAuthProfileUpdateRedactsSecretOnError drives the BGP auth profile
// update tool (read-modify-write) through the fake API.
// Sabotage target: withSecrets(bgpAuthProfileSecrets) on the
// panos_bgp_auth_profile_update registration in RegisterBgpAuthProfileTools.
func TestBgpAuthProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "BGP-AUTH-SECRET-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="bgpauth1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for secret ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterBgpAuthProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_bgp_auth_profile_update", Arguments: map[string]any{
		"name":   "bgpauth1",
		"secret": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}

// TestOspfAuthProfileCreateRedactsSecretOnError drives the OSPF auth profile
// create tool with an MD5 key, exercising the collectSecrets arm of
// ospfAuthProfileSecrets: the device rejects the write echoing the submitted
// key material.
// Sabotage target: withSecrets(ospfAuthProfileSecrets) on the
// panos_ospf_auth_profile_create registration in RegisterOspfAuthProfileTools.
func TestOspfAuthProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "OSPF-MD5-KEY-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for key ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterOspfAuthProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ospf_auth_profile_create", Arguments: map[string]any{
		"name":     "ospfauth1",
		"md5_keys": []any{map[string]any{"key_id": "1", "key": fixture, "preferred": true}},
	}})
	assertRedactsSecret(t, res, err, fixture)
}

// TestOspfAuthProfileUpdateRedactsSecretOnError drives the OSPF auth profile
// update tool with a simple password, exercising the secretVals arm of
// ospfAuthProfileSecrets.
// Sabotage target: withSecrets(ospfAuthProfileSecrets) on the
// panos_ospf_auth_profile_update registration in RegisterOspfAuthProfileTools.
func TestOspfAuthProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "OSPF-PASSWORD-002"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ospfauth1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterOspfAuthProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ospf_auth_profile_update", Arguments: map[string]any{
		"name":     "ospfauth1",
		"password": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}

// TestProxySettingsUpdateRedactsPasswordOnError drives the update-proxy
// settings singleton update tool (read-modify-write) through the fake API. The
// family is update-only (a singleton has no create), so this is its sole
// redaction test.
// Sabotage target: withSecrets(proxySettingsSecrets) on the
// panos_proxy_settings_update registration in RegisterProxySettingsTools.
func TestProxySettingsUpdateRedactsPasswordOnError(t *testing.T) {
	const fixture = "PROXY-PASSWORD-001"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result/></response>`},
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for secure-proxy-password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for secure-proxy-password ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for secure-proxy-password ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterProxySettingsTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_proxy_settings_update", Arguments: map[string]any{
		"secure_proxy_password": fixture,
	}})
	assertRedactsSecret(t, res, err, fixture)
}
