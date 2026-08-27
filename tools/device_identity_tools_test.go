package tools

import (
	"encoding/xml"
	"strings"
	"testing"

	localdb "github.com/PaloAltoNetworks/pango/device/localdb/user"
	mfa "github.com/PaloAltoNetworks/pango/device/profiles/mfa"
	samlidp "github.com/PaloAltoNetworks/pango/device/profiles/samlidp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Read-back bodies for the create path: pango's Create issues a config set and
// then reads the entry back with a config get, so each create test registers
// both routes.
const localUserCreatedBody = `<response status="success"><result>` +
	`<entry name="alice"><disabled>no</disabled><phash>PHASHVAL</phash></entry>` +
	`</result></response>`

const samlIdpCreatedBody = `<response status="success"><result>` +
	`<entry name="idp1"><entity-id>urn:idp</entity-id><certificate>my-cert</certificate></entry>` +
	`</result></response>`

const mfaCreatedBody = `<response status="success"><result>` +
	`<entry name="mfa1"><mfa-vendor-type>PingID</mfa-vendor-type></entry>` +
	`</result></response>`

// setXpaths returns the xpath of every recorded type=config action=set request.
func setXpaths(f *fakeAPI) []string {
	var xs []string
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			xs = append(xs, req.Get("xpath"))
		}
	}
	return xs
}

// --- local database user ------------------------------------------------------

// TestLocalUserCreateXpath drives the registered create tool on a firewall with
// the default (vsys) scope and pins that the set reaches the vsys xpath carrying
// the entry name. Sabotage: dropping the vsys constructor in localUserParts (or
// the setPtr in applyLocalUser that writes the name-bearing entry) fails this.
func TestLocalUserCreateXpath(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: localUserCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterLocalUserTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_local_user_create",
		Arguments: map[string]any{"name": "alice", "disabled": true, "password_hash": "PHASHVAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	xs := setXpaths(f)
	if len(xs) == 0 {
		t.Fatal("no config set request recorded")
	}
	joined := strings.Join(xs, " ")
	if !strings.Contains(joined, "vsys1") {
		t.Fatalf("create did not target the default vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "local-user-database") {
		t.Fatalf("create did not target the local-user-database subtree: %s", joined)
	}
	if el := strings.Join(setElements(f), " "); !strings.Contains(el, `name="alice"`) {
		t.Fatalf("set element missing the entry name: %s", el)
	}
}

// TestLocalUserCreateSharedScope pins that the shared scope is accepted on a
// firewall (local_user is group A) and routes to the shared xpath, not a vsys.
// Sabotage: setting the shared field of localUserParts to nil makes the shared
// request an error result.
func TestLocalUserCreateSharedScope(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: localUserCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterLocalUserTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_local_user_create",
		Arguments: map[string]any{"name": "alice", "shared": true, "password_hash": "PHASHVAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("shared create must be accepted for a group A profile: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if joined == "" {
		t.Fatal("no config set request recorded")
	}
	if strings.Contains(joined, "/vsys/") {
		t.Fatalf("shared create must not target a vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "/shared/") {
		t.Fatalf("shared create must target the shared xpath: %s", joined)
	}
}

// TestLocalUserHasPasswordHashNoLeak drives create then get through the
// registered tools and pins that the summary reports has_password_hash true when
// a phash is stored, while the phash value itself never appears in the output.
// Sabotage: echoing e.Phash in localUserSummary (instead of the has_ boolean)
// fails the leak assertions.
func TestLocalUserHasPasswordHashNoLeak(t *testing.T) {
	ctx := t.Context()
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: localUserCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterLocalUserTools(srv, d)
	cs := connectInMemory(t, srv)

	createRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_local_user_create",
		Arguments: map[string]any{"name": "alice", "password_hash": "PHASHVAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if createRes.IsError {
		t.Fatalf("create failed: %s", textContent(t, createRes))
	}
	assertHasPasswordHashNoLeak(t, textContent(t, createRes))

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_local_user_get",
		Arguments: map[string]any{"name": "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("get failed: %s", textContent(t, getRes))
	}
	assertHasPasswordHashNoLeak(t, textContent(t, getRes))

	// The summary function itself must fail closed against the leak walker too.
	m := asMap(t, localUserSummary(&localdb.Entry{Name: "alice", Phash: new("PHASHVAL")}))
	if m["has_password_hash"] != true {
		t.Fatalf("has_password_hash must be true when a phash is set: %v", m["has_password_hash"])
	}
	assertNoSecretLeak(t, m, "PHASHVAL")
	// Absent phash reports false.
	m2 := asMap(t, localUserSummary(&localdb.Entry{Name: "alice"}))
	if m2["has_password_hash"] != false {
		t.Fatalf("has_password_hash must be false when unset: %v", m2["has_password_hash"])
	}
}

// TestBuildLocalUserRequiresPasswordHash pins that create rejects a local user
// with no password_hash. PAN-OS requires a phash for every local database user
// (verified live: validate full fails with "... user -> <name> is missing
// 'phash'" on 11.1.16-h1), so buildLocalUser guards it client-side with a clear
// message. Sabotage: removing the phash guard in buildLocalUser makes the
// no-hash and empty-hash cases return a nil error.
func TestBuildLocalUserRequiresPasswordHash(t *testing.T) {
	if _, err := buildLocalUser(LocalUserInput{Name: "alice"}); err == nil {
		t.Fatal("create without password_hash must be rejected")
	}
	empty := ""
	if _, err := buildLocalUser(LocalUserInput{Name: "alice", PasswordHash: &empty}); err == nil {
		t.Fatal("create with an empty password_hash must be rejected")
	}
	e, err := buildLocalUser(LocalUserInput{Name: "alice", PasswordHash: new("PHASHVAL")})
	if err != nil {
		t.Fatalf("create with a password_hash must succeed: %v", err)
	}
	if e.Phash == nil || *e.Phash != "PHASHVAL" {
		t.Fatalf("built entry must carry the phash: %v", e.Phash)
	}
}

// TestOverlayLocalUserAllowsOmittedPasswordHash pins that update (overlay) stays
// lenient: an omitted password_hash is neither rejected nor cleared, so an
// existing user can be edited without re-supplying its phash. Sabotage: moving
// the create-path phash guard into applyLocalUser/overlayLocalUser would make
// this return an error or nil out the stored phash.
func TestOverlayLocalUserAllowsOmittedPasswordHash(t *testing.T) {
	e := &localdb.Entry{Name: "alice", Phash: new("EXISTING")}
	if err := overlayLocalUser(e, LocalUserInput{Name: "alice", Disabled: new(true)}); err != nil {
		t.Fatalf("update with an omitted password_hash must succeed: %v", err)
	}
	if e.Phash == nil || *e.Phash != "EXISTING" {
		t.Fatalf("omitted password_hash must keep the stored value, got %v", e.Phash)
	}
}

func assertHasPasswordHashNoLeak(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "PHASHVAL") {
		t.Fatalf("phash leaked into the summary: %s", body)
	}
	if !strings.Contains(body, `"has_password_hash": true`) {
		t.Fatalf("summary must report has_password_hash true: %s", body)
	}
}

// TestMfaProfileSummaryHidesConfigValue pins that an MFA vendor-config value
// (which can be a vendor secret) is never echoed in a get/list summary; the
// summary reports only has_value. Sabotage: reverting mfaVendorConfigSummaries
// to emit "value": strVal(c.Value) surfaces the raw value and drops has_value.
func TestMfaProfileSummaryHidesConfigValue(t *testing.T) {
	e := &mfa.Entry{Name: "m", MfaConfig: []mfa.MfaConfig{{Name: "secret-key", Value: new("SECRETVAL")}}}
	m := asMap(t, mfaProfileSummary(e))
	cfg, ok := m["config"].([]any)
	if !ok || len(cfg) != 1 {
		t.Fatalf("config summary shape: %v", m["config"])
	}
	item, ok := cfg[0].(map[string]any)
	if !ok {
		t.Fatalf("config item shape: %v", cfg[0])
	}
	if v, present := item["value"]; present {
		t.Fatalf("vendor config value must not be echoed: %v", v)
	}
	if item["has_value"] != true {
		t.Fatalf("has_value must be true for a set config item: %v", item)
	}
}

// --- SAML IdP profile ---------------------------------------------------------

// TestSamlIdpProfileCreateXpath drives the registered create tool on a firewall
// with the default (vsys) scope and pins that the set reaches the vsys xpath
// carrying the entry name and mapped fields. Sabotage: dropping the vsys
// constructor in samlIdpProfileParts fails the xpath assertion.
func TestSamlIdpProfileCreateXpath(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: samlIdpCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterSamlIdpProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_saml_idp_profile_create",
		Arguments: map[string]any{"name": "idp1", "entity_id": "urn:idp", "certificate": "my-cert"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if joined == "" {
		t.Fatal("no config set request recorded")
	}
	if !strings.Contains(joined, "vsys1") {
		t.Fatalf("create did not target the default vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "saml-idp") {
		t.Fatalf("create did not target the saml-idp subtree: %s", joined)
	}
	if el := strings.Join(setElements(f), " "); !strings.Contains(el, `name="idp1"`) || !strings.Contains(el, "urn:idp") || !strings.Contains(el, "my-cert") {
		t.Fatalf("set element missing mapped fields: %s", el)
	}
}

// TestSamlIdpProfileCreateSharedScope pins that the shared scope is accepted on a
// firewall (samlidp is group A) and routes to the shared xpath, not a vsys.
// Sabotage: setting the shared field of samlIdpProfileParts to nil makes the
// shared request an error result.
func TestSamlIdpProfileCreateSharedScope(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: samlIdpCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterSamlIdpProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_saml_idp_profile_create",
		Arguments: map[string]any{"name": "idp1", "shared": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("shared create must be accepted for a group A profile: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if strings.Contains(joined, "/vsys/") {
		t.Fatalf("shared create must not target a vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "/shared/") {
		t.Fatalf("shared create must target the shared xpath: %s", joined)
	}
}

// --- MFA profile --------------------------------------------------------------

// TestMfaProfileCreateXpath drives the registered create tool on a firewall with
// the default (vsys) scope and pins that the set reaches the vsys xpath carrying
// the entry name and vendor config. Sabotage: dropping the vsys constructor in
// mfaProfileParts fails the xpath assertion; dropping the Config branch of
// applyMfaProfile fails the element field check.
func TestMfaProfileCreateXpath(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: mfaCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterMfaProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "panos_mfa_profile_create",
		Arguments: map[string]any{
			"name":                "mfa1",
			"vendor_type":         "PingID",
			"certificate_profile": "cp1",
			"config":              []any{map[string]any{"name": "idp-url", "value": "https://idp"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if joined == "" {
		t.Fatal("no config set request recorded")
	}
	if !strings.Contains(joined, "vsys1") {
		t.Fatalf("create did not target the default vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "mfa") {
		t.Fatalf("create did not target the mfa subtree: %s", joined)
	}
	el := strings.Join(setElements(f), " ")
	if !strings.Contains(el, `name="mfa1"`) || !strings.Contains(el, "PingID") || !strings.Contains(el, "idp-url") || !strings.Contains(el, "https://idp") {
		t.Fatalf("set element missing mapped fields: %s", el)
	}
}

// TestMfaProfileCreateSharedScope pins that the shared scope is accepted on a
// firewall (mfa is group A) and routes to the shared xpath, not a vsys.
// Sabotage: setting the shared field of mfaProfileParts to nil makes the shared
// request an error result.
func TestMfaProfileCreateSharedScope(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: mfaCreatedBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterMfaProfileTools(srv, d)
	cs := connectInMemory(t, srv)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "panos_mfa_profile_create",
		Arguments: map[string]any{"name": "mfa1", "shared": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("shared create must be accepted for a group A profile: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if strings.Contains(joined, "/vsys/") {
		t.Fatalf("shared create must not target a vsys xpath: %s", joined)
	}
	if !strings.Contains(joined, "/shared/") {
		t.Fatalf("shared create must target the shared xpath: %s", joined)
	}
}

// TestOverlaySamlIdpProfilePreserves pins the read-modify-write contract for the
// pure-setPtr SAML IdP overlay: overlaying only sso_url must leave the untouched
// managed sibling (entity_id) and the unmodeled MiscAttributes (which stand in
// for the access-domain and admin-role import fields the input does not model)
// intact, because overlaySamlIdpProfile applies onto the read-back entry and
// never rebuilds it. Sabotage: rebuilding e in overlaySamlIdpProfile (e.g.
// *e = samlidp.Entry{Name: e.Name}) drops both and turns this red.
func TestOverlaySamlIdpProfilePreserves(t *testing.T) {
	e := &samlidp.Entry{
		Name:           "idp1",
		EntityId:       new("urn:idp"),
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}
	if err := overlaySamlIdpProfile(e, SamlIdpProfileInput{Name: "idp1", SsoUrl: new("https://idp.example/sso")}); err != nil {
		t.Fatal(err)
	}
	if e.EntityId == nil || *e.EntityId != "urn:idp" {
		t.Fatalf("untouched entity_id must be preserved: %v", e.EntityId)
	}
	if e.SsoUrl == nil || *e.SsoUrl != "https://idp.example/sso" {
		t.Fatalf("provided sso_url must be set: %v", e.SsoUrl)
	}
	if len(e.MiscAttributes) != 1 || e.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("unmanaged MiscAttributes must survive the overlay: %+v", e.MiscAttributes)
	}
}

// TestOverlayMfaProfilePreserves pins the read-modify-write contract for the
// MFA server profile overlay; see TestOverlaySamlIdpProfilePreserves. Overlaying
// only certificate_profile must leave the untouched managed sibling
// (vendor_type) and the unmodeled MiscAttributes intact, because
// overlayMfaProfile applies onto the read-back entry and never rebuilds it.
// Sabotage: rebuilding e in overlayMfaProfile (e.g. *e = mfa.Entry{Name: e.Name})
// drops both and turns this red.
func TestOverlayMfaProfilePreserves(t *testing.T) {
	e := &mfa.Entry{
		Name:           "mfa1",
		MfaVendorType:  new("PingID"),
		MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}
	if err := overlayMfaProfile(e, MfaProfileInput{Name: "mfa1", CertificateProfile: new("cp1")}); err != nil {
		t.Fatal(err)
	}
	if e.MfaVendorType == nil || *e.MfaVendorType != "PingID" {
		t.Fatalf("untouched vendor_type must be preserved: %v", e.MfaVendorType)
	}
	if e.MfaCertProfile == nil || *e.MfaCertProfile != "cp1" {
		t.Fatalf("provided certificate_profile must be set: %v", e.MfaCertProfile)
	}
	if len(e.MiscAttributes) != 1 || e.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("unmanaged MiscAttributes must survive the overlay: %+v", e.MiscAttributes)
	}
}
