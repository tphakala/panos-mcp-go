package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/authprofile"
	"github.com/PaloAltoNetworks/pango/generic"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// storedLdapProfile returns an entry whose method is LDAP, with a Misc element on
// the branch and another on the method container, so a test can prove what a
// method switch preserves and what it clears.
func storedLdapProfile() *authprofile.Entry {
	return &authprofile.Entry{
		Name: "ap1",
		Method: &authprofile.Method{
			Ldap: &authprofile.MethodLdap{
				ServerProfile: new("ldap1"),
				Misc:          []generic.Xml{{}},
			},
			Misc: []generic.Xml{{}},
		},
	}
}

// TestAuthProfileMethodSwitchClearsSiblings is the primary safety pin for this
// family: PAN-OS allows exactly one child under <method> and pango enforces
// nothing, so the overlay must clear every sibling when it sets a branch.
//
// Sabotage: delete the first clearing assignment in applyAuthProfileMethod (the
// one setting m.Cloud, m.Kerberos, m.Ldap and m.LocalDatabase to nil) and the
// stored LDAP branch survives beside the new RADIUS branch, turning this red.
// The second clearing assignment is pinned separately by
// TestAuthProfileSwitchFromLateBranchClearsIt, because a switch away from LDAP
// never exercises it.
func TestAuthProfileMethodSwitchClearsSiblings(t *testing.T) {
	e := storedLdapProfile()
	in := AuthProfileInput{Name: "ap1", MethodRadius: &AuthMethodRadiusInput{ServerProfile: new("rad1")}}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Method.Ldap != nil {
		t.Fatalf("the stored ldap branch must be cleared when radius is selected, got %+v", e.Method.Ldap)
	}
	if e.Method.Radius == nil || strVal(e.Method.Radius.ServerProfile) != "rad1" {
		t.Fatalf("radius branch not set: %+v", e.Method.Radius)
	}
	if got := authProfileMethodString(e.Method); got != "radius" {
		t.Fatalf("method = %q, want radius", got)
	}
}

// TestAuthProfileSwitchAwayFromCloudClearsIt covers the branch this server can
// report but never set. A profile using the cloud method must not keep it when
// the caller selects a modeled branch, or the device receives two children.
//
// Sabotage: drop m.Cloud from the first clearing assignment in
// applyAuthProfileMethod and this test goes red while every other method test
// stays green, which is exactly why it is a separate test.
func TestAuthProfileSwitchAwayFromCloudClearsIt(t *testing.T) {
	e := &authprofile.Entry{
		Name:   "ap1",
		Method: &authprofile.Method{Cloud: &authprofile.MethodCloud{ClockSkew: new(int64(60))}},
	}
	in := AuthProfileInput{Name: "ap1", MethodLdap: &AuthMethodLdapInput{ServerProfile: new("ldap1")}}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Method.Cloud != nil {
		t.Fatalf("the cloud branch must be cleared when another method is selected, got %+v", e.Method.Cloud)
	}
	if e.Method.Ldap == nil {
		t.Fatal("ldap branch not set")
	}
}

// TestAuthProfileSwitchFromLateBranchClearsIt covers the second of the two
// clearing assignments. Every other switch test starts from LDAP, which the
// first assignment clears, so without this the line nilling m.None, m.Radius,
// m.SamlIdp and m.Tacplus is not pinned by anything and could be deleted with
// the suite still green.
//
// Sabotage: delete the assignment setting m.None, m.Radius, m.SamlIdp and
// m.Tacplus to nil in applyAuthProfileMethod and each subtest goes red.
func TestAuthProfileSwitchFromLateBranchClearsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored *authprofile.Method
		check  func(*authprofile.Method) bool
	}{
		{"radius", &authprofile.Method{Radius: &authprofile.MethodRadius{ServerProfile: new("rad1")}},
			func(m *authprofile.Method) bool { return m.Radius == nil }},
		{"tacplus", &authprofile.Method{Tacplus: &authprofile.MethodTacplus{ServerProfile: new("tac1")}},
			func(m *authprofile.Method) bool { return m.Tacplus == nil }},
		{"saml idp", &authprofile.Method{SamlIdp: &authprofile.MethodSamlIdp{ServerProfile: new("idp1")}},
			func(m *authprofile.Method) bool { return m.SamlIdp == nil }},
		{"none", &authprofile.Method{None: &authprofile.MethodNone{}},
			func(m *authprofile.Method) bool { return m.None == nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &authprofile.Entry{Name: "ap1", Method: tc.stored}
			in := AuthProfileInput{Name: "ap1", MethodLdap: &AuthMethodLdapInput{ServerProfile: new("ldap1")}}
			if err := overlayAuthProfile(e, in); err != nil {
				t.Fatal(err)
			}
			if !tc.check(e.Method) {
				t.Fatalf("the stored %s branch must be cleared when ldap is selected: %+v", tc.name, e.Method)
			}
			if e.Method.Ldap == nil {
				t.Fatal("the ldap branch must be set")
			}
		})
	}
}

// TestAuthProfileOmittedMethodPreserved pins the other direction: an update that
// touches only an unrelated field must leave the stored method exactly as it was,
// including a cloud method this server cannot rebuild.
//
// Sabotage: delete the "if n == 0 { return nil }" early return in
// applyAuthProfileMethod and the stored cloud branch is cleared, turning this red.
func TestAuthProfileOmittedMethodPreserved(t *testing.T) {
	cloud := &authprofile.MethodCloud{ClockSkew: new(int64(60))}
	e := &authprofile.Entry{Name: "ap1", Method: &authprofile.Method{Cloud: cloud}}
	in := AuthProfileInput{Name: "ap1", UserDomain: new("example.com")}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Method == nil || e.Method.Cloud != cloud {
		t.Fatalf("an update providing no method must leave the stored method untouched, got %+v", e.Method)
	}
	if strVal(e.UserDomain) != "example.com" {
		t.Fatalf("user_domain not applied: %q", strVal(e.UserDomain))
	}
}

// TestAuthProfileSameBranchRebuildKeepsMisc pins the capture-before-clear step:
// re-selecting the branch the profile already uses must keep the XML this server
// does not model, rather than starting from a fresh struct.
//
// Sabotage: replace "b := seedBranch(oldLdap)" with "b := &authprofile.MethodLdap{}"
// in applyAuthProfileMethod and the branch Misc is lost, turning this red.
func TestAuthProfileSameBranchRebuildKeepsMisc(t *testing.T) {
	e := storedLdapProfile()
	in := AuthProfileInput{Name: "ap1", MethodLdap: &AuthMethodLdapInput{LoginAttribute: new("sAMAccountName")}}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Method.Ldap == nil || len(e.Method.Ldap.Misc) != 1 {
		t.Fatalf("the ldap branch must keep its unmodeled Misc, got %+v", e.Method.Ldap)
	}
	// The field the caller did not provide must also survive.
	if strVal(e.Method.Ldap.ServerProfile) != "ldap1" {
		t.Fatalf("an omitted branch field must be preserved, got %q", strVal(e.Method.Ldap.ServerProfile))
	}
	if strVal(e.Method.Ldap.LoginAttribute) != "sAMAccountName" {
		t.Fatalf("login_attribute not applied: %q", strVal(e.Method.Ldap.LoginAttribute))
	}
}

// TestAuthProfileMethodContainerMiscSurvivesSwitch pins that the <method>
// container itself is reused rather than replaced, so unmodeled XML that sits on
// the container (not on a branch) survives a switch between branches.
//
// Sabotage: replace the "if e.Method == nil { e.Method = ... }" guard in
// applyAuthProfileMethod with an unconditional assignment and the container Misc
// is dropped, turning this red.
func TestAuthProfileMethodContainerMiscSurvivesSwitch(t *testing.T) {
	e := storedLdapProfile()
	in := AuthProfileInput{Name: "ap1", MethodTacplus: &AuthMethodTacplusInput{ServerProfile: new("tac1")}}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if len(e.Method.Misc) != 1 {
		t.Fatalf("the method container must keep its unmodeled Misc across a switch, got %+v", e.Method.Misc)
	}
}

// TestAuthProfileRejectsTwoMethods pins the exactly-one rule. pango's marshaller
// writes every non-nil branch independently, so without this the device receives
// a document it rejects.
//
// Sabotage: delete the "if n > 1" error return in applyAuthProfileMethod and
// this goes red.
func TestAuthProfileRejectsTwoMethods(t *testing.T) {
	e := &authprofile.Entry{Name: "ap1"}
	in := AuthProfileInput{
		Name:         "ap1",
		MethodLdap:   &AuthMethodLdapInput{ServerProfile: new("ldap1")},
		MethodRadius: &AuthMethodRadiusInput{ServerProfile: new("rad1")},
	}
	err := overlayAuthProfile(e, in)
	if err == nil || !strings.Contains(err.Error(), "at most one of method_") {
		t.Fatalf("two method branches must be rejected, got %v", err)
	}
}

// TestAuthProfileFieldFreeBranchSelectable pins that the two branches carrying no
// fields at all can still be chosen. They are why selection is keyed on pointer
// presence rather than on a non-empty string: a string discriminator could never
// reach them.
//
// Sabotage: delete the "case in.MethodNone != nil" arm in applyAuthProfileMethod
// and this goes red (the default arm would set tacplus instead).
func TestAuthProfileFieldFreeBranchSelectable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   AuthProfileInput
		want string
	}{
		{"none", AuthProfileInput{Name: "ap1", MethodNone: &AuthMethodNoneInput{}}, "none"},
		{"local database", AuthProfileInput{Name: "ap1", MethodLocalDatabase: &AuthMethodLocalDatabaseInput{}}, "local-database"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := storedLdapProfile()
			if err := overlayAuthProfile(e, tc.in); err != nil {
				t.Fatal(err)
			}
			if got := authProfileMethodString(e.Method); got != tc.want {
				t.Fatalf("method = %q, want %q", got, tc.want)
			}
			if e.Method.Ldap != nil {
				t.Fatal("the stored ldap branch must be cleared")
			}
		})
	}
}

// TestAuthProfileCheckgroupTriState pins that an omitted PAN-OS boolean stays
// absent rather than becoming an explicit no. Coercing it would silently turn
// group retrieval off on every update that did not mention it.
//
// Sabotage: replace "setPtr(&b.Checkgroup, in.MethodRadius.Checkgroup)" in
// applyAuthProfileMethod with "b.Checkgroup = new(boolVal(in.MethodRadius.Checkgroup))"
// and this goes red.
func TestAuthProfileCheckgroupTriState(t *testing.T) {
	e := &authprofile.Entry{Name: "ap1"}
	in := AuthProfileInput{Name: "ap1", MethodRadius: &AuthMethodRadiusInput{ServerProfile: new("rad1")}}
	if err := overlayAuthProfile(e, in); err != nil {
		t.Fatal(err)
	}
	if e.Method.Radius.Checkgroup != nil {
		t.Fatalf("an omitted checkgroup must stay absent, got %v", *e.Method.Radius.Checkgroup)
	}

	// A stored true must also survive an update that does not mention it.
	e.Method.Radius.Checkgroup = new(true)
	if err := overlayAuthProfile(e, AuthProfileInput{Name: "ap1", UserDomain: new("d")}); err != nil {
		t.Fatal(err)
	}
	if e.Method.Radius.Checkgroup == nil || !*e.Method.Radius.Checkgroup {
		t.Fatal("a stored checkgroup must survive an update that omits it")
	}
}

// TestAuthProfileSummaryHidesKeytab pins that the Kerberos keytab, which is key
// material equivalent to the principal's password, never reaches a caller.
//
// Sabotage: change the has_kerberos_keytab line in authProfileSummary to echo the
// value (m["sso_kerberos_keytab"] = strVal(...)) and this goes red.
func TestAuthProfileSummaryHidesKeytab(t *testing.T) {
	const keytab = "BQIAAABTAAIAC0VYQU1QTEUuQ09N"
	e := &authprofile.Entry{
		Name: "ap1",
		SingleSignOn: &authprofile.SingleSignOn{
			Realm:            new("EXAMPLE.COM"),
			ServicePrincipal: new("HTTP/fw.example.com"),
			KerberosKeytab:   new(keytab),
		},
	}
	m, ok := authProfileSummary(e).(map[string]any)
	if !ok {
		t.Fatalf("summary is not a map: %T", authProfileSummary(e))
	}
	assertNoSecretLeak(t, m, keytab)
	if m["has_kerberos_keytab"] != true {
		t.Fatalf("has_kerberos_keytab = %v, want true", m["has_kerberos_keytab"])
	}
	if m["sso_realm"] != "EXAMPLE.COM" {
		t.Fatalf("sso_realm = %v", m["sso_realm"])
	}
}

// TestAuthProfileCreateRedactsKeytabOnError proves the withSecrets extractor is
// actually wired into the registered create handler, not merely that
// redactSecrets works: the device rejects the write with an error echoing the
// submitted keytab, and neither the tool result nor the logs may carry it.
//
// Sabotage: drop withSecrets(authProfileSecrets) from the
// panos_auth_profile_create registration and this goes red.
func TestAuthProfileCreateRedactsKeytabOnError(t *testing.T) {
	const keytab = "KEYTAB-SECRET-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>bad keytab ` + keytab + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAuthProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_auth_profile_create", Arguments: map[string]any{
		"name":                "ap1",
		"sso_kerberos_keytab": keytab,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, keytab) {
		t.Fatalf("the submitted keytab leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestAuthProfileSharedScopeRejected pins that the authentication profile joins
// the no-shared group: authprofile.Location has no shared scope, so a shared
// request must be an error rather than a silently retargeted write.
//
// Sabotage: add a shared constructor to authProfileParts and this goes red. A
// deletion sabotage does not apply here, because the load-bearing thing is the
// ABSENCE of a shared key in that literal.
func TestAuthProfileSharedScopeRejected(t *testing.T) {
	parts := authProfileParts()
	for _, model := range []string{"PA-VM", "Panorama"} {
		t.Run(model, func(t *testing.T) {
			d, _ := newTestDeps(t, model)
			if _, err := resolveDeviceScope(d, DeviceScopeInput{Shared: true}, parts); err == nil ||
				!strings.Contains(err.Error(), "shared scope is not available") {
				t.Fatalf("shared must be rejected for the authentication profile, got %v", err)
			}
		})
	}
}

// TestAuthProfileScopeResolves pins the four location constructors this family
// supplies, so a copy-paste error in any of them is visible.
//
// Sabotage: delete any one constructor from authProfileParts and its subtest
// panics on the nil func; change a constructor to fill the wrong Location branch
// and its subtest fails instead.
func TestAuthProfileScopeResolves(t *testing.T) {
	parts := authProfileParts()
	fw, _ := newTestDeps(t, "PA-VM")
	pano, _ := newTestDeps(t, "Panorama")

	for _, tc := range []struct {
		name string
		d    *Deps
		in   DeviceScopeInput
		want func(authprofile.Location) bool
	}{
		{"firewall vsys", fw, DeviceScopeInput{}, func(l authprofile.Location) bool {
			return l.Vsys != nil && l.Vsys.Vsys == defaultVsys
		}},
		{"template", pano, DeviceScopeInput{Template: "t1"}, func(l authprofile.Location) bool {
			return l.Template != nil && l.Template.Template == "t1"
		}},
		{"template vsys", pano, DeviceScopeInput{Template: "t1", TemplateVsys: "vsys2"}, func(l authprofile.Location) bool {
			return l.TemplateVsys != nil && l.TemplateVsys.Template == "t1" && l.TemplateVsys.Vsys == "vsys2"
		}},
		{"template stack", pano, DeviceScopeInput{TemplateStack: "s1"}, func(l authprofile.Location) bool {
			return l.TemplateStack != nil && l.TemplateStack.TemplateStack == "s1"
		}},
		{"template stack vsys", pano, DeviceScopeInput{TemplateStack: "s1", TemplateVsys: "vsys2"}, func(l authprofile.Location) bool {
			return l.TemplateStackVsys != nil && l.TemplateStackVsys.TemplateStack == "s1" &&
				l.TemplateStackVsys.Vsys == "vsys2"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := resolveDeviceScope(tc.d, tc.in, parts)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !tc.want(loc) {
				t.Fatalf("wrong or empty location: %+v", loc)
			}
		})
	}
}

// TestAuthProfileBuildRequiresName pins the create guard.
//
// Sabotage: delete the name check in buildAuthProfile and this goes red.
func TestAuthProfileBuildRequiresName(t *testing.T) {
	if _, err := buildAuthProfile(AuthProfileInput{}); err == nil {
		t.Fatal("a create without a name must be rejected")
	}
}

// TestAuthProfileListsReplace pins that allow_list and mfa_factors replace the
// stored lists when provided and are left alone when omitted.
//
// Sabotage: delete the "if in.AllowList != nil" guard in applyAuthProfile so the
// assignment becomes unconditional, and the preserve subtest goes red.
func TestAuthProfileListsReplace(t *testing.T) {
	e := &authprofile.Entry{
		Name:            "ap1",
		AllowList:       []string{"old"},
		MultiFactorAuth: &authprofile.MultiFactorAuth{Factors: []string{"f-old"}},
	}
	if err := overlayAuthProfile(e, AuthProfileInput{Name: "ap1", UserDomain: new("d")}); err != nil {
		t.Fatal(err)
	}
	if len(e.AllowList) != 1 || e.AllowList[0] != "old" {
		t.Fatalf("an omitted allow_list must be preserved, got %v", e.AllowList)
	}
	if len(e.MultiFactorAuth.Factors) != 1 {
		t.Fatalf("omitted mfa_factors must be preserved, got %v", e.MultiFactorAuth.Factors)
	}

	if err := overlayAuthProfile(e, AuthProfileInput{
		Name: "ap1", AllowList: []string{"a", "b"}, MfaFactors: []string{"f1"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.AllowList) != 2 {
		t.Fatalf("a provided allow_list must replace the stored one, got %v", e.AllowList)
	}
	if len(e.MultiFactorAuth.Factors) != 1 || e.MultiFactorAuth.Factors[0] != "f1" {
		t.Fatalf("a provided mfa_factors must replace the stored one, got %v", e.MultiFactorAuth.Factors)
	}
}

// TestAuthProfileReadOnlyGating pins that the three write tools disappear in
// read-only mode.
//
// Sabotage: delete the "if d.ReadOnly { return }" guard in
// RegisterAuthProfileTools and this goes red.
func TestAuthProfileReadOnlyGating(t *testing.T) {
	assertReadOnlyGating(t, RegisterAuthProfileTools,
		[]string{"panos_auth_profile_list", "panos_auth_profile_get"},
		[]string{"panos_auth_profile_create", "panos_auth_profile_update", "panos_auth_profile_delete"})
}
