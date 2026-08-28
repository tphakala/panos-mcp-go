package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file drives the local_user, mfa_profile, and ike_gateway create and
// update tools through their registered handlers and the fake API, the same
// way TestServerProfileCreateRedactsSecretOnError (redact_test.go) and
// TestAdministratorUpdateRedactsPasswordHashOnError (device_admin_tools_test.go)
// prove the tacacs and administrator families. Each test proves the
// withSecrets extractor is actually wired into the registration, not just
// that redactSecrets works in isolation (issue #103): deleting the
// withSecrets(...) argument from a registration leaves the rest of the suite
// green, so only a test that submits a real secret and inspects the error
// text catches the regression.

// TestLocalUserCreateRedactsPasswordHashOnError drives panos_local_user_create
// through the registered handler: the device rejects the write with an error
// that echoes the submitted password hash, and the tool result must not carry
// it. Sabotage: remove withSecrets(localUserSecrets) from the
// panos_local_user_create registration in RegisterLocalUserTools
// (tools/device_identity_tools.go); this test turns red.
func TestLocalUserCreateRedactsPasswordHashOnError(t *testing.T) {
	const phash = "$1$createsalt$CREATESECRETHASH"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLocalUserTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_local_user_create", Arguments: map[string]any{
		"name":          "user1",
		"password_hash": phash,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, phash) {
		t.Fatalf("submitted password hash leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestLocalUserUpdateRedactsPasswordHashOnError is the update-path twin of
// TestLocalUserCreateRedactsPasswordHashOnError. Sabotage: remove
// withSecrets(localUserSecrets) from the panos_local_user_update registration
// in RegisterLocalUserTools (tools/device_identity_tools.go); this test turns
// red.
func TestLocalUserUpdateRedactsPasswordHashOnError(t *testing.T) {
	const phash = "$1$updatesalt$UPDATESECRETHASH"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="user1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLocalUserTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_local_user_update", Arguments: map[string]any{
		"name":          "user1",
		"password_hash": phash,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, phash) {
		t.Fatalf("submitted password hash leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestMfaProfileCreateRedactsSecretOnError drives panos_mfa_profile_create
// through the registered handler. The secret lives on a repeated vendor-config
// element (MfaVendorConfigInput.Value), not a top-level field, so the request
// arguments nest it under config. Sabotage: remove
// withSecrets(mfaProfileSecrets) from the panos_mfa_profile_create
// registration in RegisterMfaProfileTools (tools/device_identity_tools.go);
// this test turns red.
func TestMfaProfileCreateRedactsSecretOnError(t *testing.T) {
	const fixture = "MFA-VENDOR-SECRET-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for value ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterMfaProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_mfa_profile_create", Arguments: map[string]any{
		"name":   "mfa1",
		"config": []any{map[string]any{"name": "api_key", "value": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted vendor config value leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestMfaProfileUpdateRedactsSecretOnError is the update-path twin of
// TestMfaProfileCreateRedactsSecretOnError. Sabotage: remove
// withSecrets(mfaProfileSecrets) from the panos_mfa_profile_update
// registration in RegisterMfaProfileTools (tools/device_identity_tools.go);
// this test turns red.
func TestMfaProfileUpdateRedactsSecretOnError(t *testing.T) {
	const fixture = "MFA-VENDOR-SECRET-def456"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="mfa1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for value ` + fixture + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for value ` + fixture + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterMfaProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_mfa_profile_update", Arguments: map[string]any{
		"name":   "mfa1",
		"config": []any{map[string]any{"name": "api_key", "value": fixture}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, fixture) {
		t.Fatalf("submitted vendor config value leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestIkeGatewayCreateRedactsPreSharedKeyOnError drives
// panos_ike_gateway_create through the registered handler. buildIkeGateway
// requires only a name; peer address, local address, and protocol version are
// all optional, so name plus pre_shared_key is a minimally valid create.
// Sabotage: remove withSecrets(ikeGatewaySecrets) from the
// panos_ike_gateway_create registration in RegisterIkeGatewayTools
// (tools/vpn_tools.go); this test turns red.
func TestIkeGatewayCreateRedactsPreSharedKeyOnError(t *testing.T) {
	const psk = "IKE-PRESHARED-KEY-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for key ` + psk + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterIkeGatewayTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ike_gateway_create", Arguments: map[string]any{
		"name":           "gw1",
		"pre_shared_key": psk,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, psk) {
		t.Fatalf("submitted pre-shared key leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestIkeGatewayUpdateRedactsPreSharedKeyOnError is the update-path twin of
// TestIkeGatewayCreateRedactsPreSharedKeyOnError. Sabotage: remove
// withSecrets(ikeGatewaySecrets) from the panos_ike_gateway_update
// registration in RegisterIkeGatewayTools (tools/vpn_tools.go); this test
// turns red.
func TestIkeGatewayUpdateRedactsPreSharedKeyOnError(t *testing.T) {
	const psk = "IKE-PRESHARED-KEY-def456"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="gw1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for key ` + psk + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for key ` + psk + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterIkeGatewayTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ike_gateway_update", Arguments: map[string]any{
		"name":           "gw1",
		"pre_shared_key": psk,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, psk) {
		t.Fatalf("submitted pre-shared key leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}
