package tools

import (
	"encoding/xml"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/device/administrator"
	"github.com/PaloAltoNetworks/pango/device/profiles/password"
	"github.com/PaloAltoNetworks/pango/generic"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Password profile
// ---------------------------------------------------------------------------

// TestBuildPasswordProfileOmitsEmptyChangeBlock pins that a name-only create
// emits no password-change block at all. Allocating one unconditionally would
// send an empty <password-change/> that carries no setting.
func TestBuildPasswordProfileOmitsEmptyChangeBlock(t *testing.T) {
	e, err := buildPasswordProfile(PasswordProfileInput{Name: "pp1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.PasswordChange != nil {
		t.Fatalf("a name-only create must not allocate a password-change block: %+v", e.PasswordChange)
	}
}

// TestBuildPasswordProfileSetsProvidedSettings pins that a provided setting
// allocates the block and lands in it, and that a zero is carried through rather
// than treated as absent (0 disables expiry, which is a real setting).
func TestBuildPasswordProfileSetsProvidedSettings(t *testing.T) {
	e, err := buildPasswordProfile(PasswordProfileInput{
		Name:             "pp1",
		ExpirationPeriod: new(int64(0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.PasswordChange == nil {
		t.Fatal("a provided setting must allocate the password-change block")
	}
	if e.PasswordChange.ExpirationPeriod == nil || *e.PasswordChange.ExpirationPeriod != 0 {
		t.Fatalf("expiration_period 0 must be carried through, got %v", e.PasswordChange.ExpirationPeriod)
	}
	if e.PasswordChange.PostExpirationGracePeriod != nil {
		t.Errorf("a setting the caller did not provide must stay absent, got %v", e.PasswordChange.PostExpirationGracePeriod)
	}
}

// TestOverlayPasswordProfilePreservesStored pins the read-modify-write contract:
// an omitted setting keeps its stored value and unmodeled XML survives.
func TestOverlayPasswordProfilePreservesStored(t *testing.T) {
	e := &password.Entry{
		Name: "pp1",
		PasswordChange: &password.PasswordChange{
			ExpirationPeriod:          new(int64(90)),
			PostExpirationGracePeriod: new(int64(7)),
			Misc:                      []generic.Xml{{}},
		},
	}
	if err := overlayPasswordProfile(e, PasswordProfileInput{Name: "pp1", ExpirationPeriod: new(int64(30))}); err != nil {
		t.Fatal(err)
	}
	if e.PasswordChange.ExpirationPeriod == nil || *e.PasswordChange.ExpirationPeriod != 30 {
		t.Errorf("a provided setting must be applied, got %v", e.PasswordChange.ExpirationPeriod)
	}
	if e.PasswordChange.PostExpirationGracePeriod == nil || *e.PasswordChange.PostExpirationGracePeriod != 7 {
		t.Errorf("an omitted setting must keep its stored value, got %v", e.PasswordChange.PostExpirationGracePeriod)
	}
	if len(e.PasswordChange.Misc) != 1 {
		t.Errorf("unmodeled XML must survive the overlay, got %+v", e.PasswordChange.Misc)
	}
}

// TestPasswordProfileSummaryOmitsAbsentSettings pins the tri-state convention:
// an unset setting is absent from the summary rather than reported as 0.
func TestPasswordProfileSummaryOmitsAbsentSettings(t *testing.T) {
	m, ok := passwordProfileSummary(&password.Entry{Name: "pp1"}).(map[string]any)
	if !ok {
		t.Fatal("summary must be a map")
	}
	if _, present := m["expiration_period"]; present {
		t.Errorf("an absent setting must be omitted, not coerced: %+v", m)
	}

	// The absence check above passes just as happily if the projection were
	// deleted outright, so pin that a populated setting IS reported.
	set, ok := passwordProfileSummary(&password.Entry{
		Name:           "pp1",
		PasswordChange: &password.PasswordChange{ExpirationPeriod: new(int64(90))},
	}).(map[string]any)
	if !ok {
		t.Fatal("summary must be a map")
	}
	if set["expiration_period"] != int64(90) {
		t.Errorf("a set value must be reported, got %v", set["expiration_period"])
	}
}

// TestPasswordProfileReadOnlyGating pins read-only tool gating for password profiles.
// Sabotage: deleting the if d.ReadOnly guard in RegisterPasswordProfileTools exposes write tools in read-only mode and fails this test.
func TestPasswordProfileReadOnlyGating(t *testing.T) {
	base := "panos_password_profile"
	assertReadOnlyGating(t, RegisterPasswordProfileTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// ---------------------------------------------------------------------------
// Administrator
// ---------------------------------------------------------------------------

// TestAdministratorRoleOverlayExclusive pins the exactly-one contract on the
// role-based permissions. PAN-OS rejects an administrator carrying two role
// branches, so setting one must clear the others. This is deliberately not the
// usual "apply only what the caller provided" rule, and it must hold in BOTH
// directions: a built-in role clears a custom profile, and a custom profile
// clears a built-in role.
func TestAdministratorRoleOverlayExclusive(t *testing.T) {
	e := &administrator.Entry{Name: "admin1"}

	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", Role: new(adminRoleSuperuser)}); err != nil {
		t.Fatal(err)
	}
	rb := e.Permissions.RoleBased
	if rb.Superuser == nil {
		t.Fatal("superuser must be set")
	}

	// built-in -> custom must clear the built-in branch
	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleProfile: new("custom-role")}); err != nil {
		t.Fatal(err)
	}
	rb = e.Permissions.RoleBased
	if rb.Superuser != nil {
		t.Error("switching to a custom role must clear superuser")
	}
	if rb.Custom == nil || strVal(rb.Custom.Profile) != "custom-role" {
		t.Fatalf("custom role must be set: %+v", rb.Custom)
	}

	// custom -> built-in must clear the custom branch
	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", Role: new(adminRoleSuperreader)}); err != nil {
		t.Fatal(err)
	}
	rb = e.Permissions.RoleBased
	if rb.Custom != nil {
		t.Error("switching to a built-in role must clear the custom role")
	}
	if rb.Superreader == nil {
		t.Error("superreader must be set")
	}
	if rb.Superuser != nil {
		t.Error("the previous built-in role must not survive")
	}
}

// TestAdministratorRoleVsysAloneRequiresAProfile pins that role_vsys on its own
// is rejected when nothing supplies a profile name. The profile IS the custom
// role, so accepting this would clear the administrator's existing role and
// write a custom branch naming no profile, which PAN-OS rejects at commit.
//
// The rejection must also leave the entry untouched: a failed request that has
// already cleared the stored role is worse than one that changes nothing.
func TestAdministratorRoleVsysAloneRequiresAProfile(t *testing.T) {
	e := storedRoleBranch(adminRoleDeviceAdmin)
	err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleVsys: []string{"vsys1"}})
	if err == nil {
		t.Fatal("role_vsys with no profile name must be rejected")
	}
	if !strings.Contains(err.Error(), "custom role needs a non-empty role_profile") {
		t.Errorf("unexpected error: %q", err)
	}
	if got := setRoleBranches(e); len(got) != 1 || got[0] != adminRoleDeviceAdmin {
		t.Errorf("a rejected request must leave the stored role untouched, got %v", got)
	}

	// An explicit empty role_profile is non-nil, so a guard keyed on presence
	// rather than on the effective name would let this one through.
	e = storedRoleBranch(adminRoleDeviceAdmin)
	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleProfile: new("")}); err == nil {
		t.Error("an explicit empty role_profile must be rejected")
	}
	if got := setRoleBranches(e); len(got) != 1 || got[0] != adminRoleDeviceAdmin {
		t.Errorf("a rejected request must leave the stored role untouched, got %v", got)
	}
}

// TestAdministratorRoleVsysAloneSwitchesAStoredCustomRole pins the case that IS
// valid: an administrator already holding a custom role can be rescoped by
// naming only role_vsys, because the stored profile supplies the name.
func TestAdministratorRoleVsysAloneSwitchesAStoredCustomRole(t *testing.T) {
	e := storedRoleBranch("custom")
	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleVsys: []string{"vsys1"}}); err != nil {
		t.Fatal(err)
	}
	rb := e.Permissions.RoleBased
	if rb.Custom == nil || len(rb.Custom.Vsys) != 1 || rb.Custom.Vsys[0] != "vsys1" {
		t.Fatalf("role_vsys must be applied to the custom branch: %+v", rb.Custom)
	}
	if strVal(rb.Custom.Profile) != "stale-role" {
		t.Errorf("the stored profile name must survive, got %q", strVal(rb.Custom.Profile))
	}
}

// TestAdministratorRoleEmptyStringRejected pins that an empty role is a rejected
// value, not a silently ignored one. Detecting the transition by non-empty value
// instead of by presence would mask it and leave the stored role untouched while
// reporting success.
func TestAdministratorRoleEmptyStringRejected(t *testing.T) {
	e := &administrator.Entry{Name: "admin1"}
	err := overlayAdministrator(e, AdministratorInput{Name: "admin1", Role: new("")})
	if err == nil {
		t.Fatal("an empty role must be rejected, not ignored")
	}
	if !strings.Contains(err.Error(), "role must be one of") {
		t.Errorf("unexpected error: %q", err)
	}
}

// TestAdministratorRoleAndProfileConflict pins that naming both branches is a
// client error rather than a silent precedence rule.
func TestAdministratorRoleAndProfileConflict(t *testing.T) {
	_, err := buildAdministrator(AdministratorInput{
		Name: "admin1", Role: new(adminRoleSuperuser), RoleProfile: new("custom-role"),
	})
	if err == nil {
		t.Fatal("role combined with role_profile must be rejected")
	}
	if !strings.Contains(err.Error(), "set only one of role or role_profile") {
		t.Errorf("unexpected error: %q", err)
	}
}

// TestAdministratorOverlayLeavesPermissionsAlone pins that an update naming no
// role at all does not touch the stored permissions, including their unmodeled
// XML. The exclusivity logic must not run when there is nothing to switch to.
func TestAdministratorOverlayLeavesPermissionsAlone(t *testing.T) {
	e := &administrator.Entry{
		Name: "admin1",
		Permissions: &administrator.Permissions{
			RoleBased: &administrator.PermissionsRoleBased{Superuser: new("yes")},
			Misc:      []generic.Xml{{}},
		},
	}
	if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", PasswordProfile: new("pp1")}); err != nil {
		t.Fatal(err)
	}
	if e.Permissions.RoleBased == nil || e.Permissions.RoleBased.Superuser == nil {
		t.Error("an update naming no role must leave the stored role alone")
	}
	if len(e.Permissions.Misc) != 1 {
		t.Error("unmodeled permissions XML must survive an update")
	}
	if strVal(e.PasswordProfile) != "pp1" {
		t.Errorf("the provided field must be applied, got %q", strVal(e.PasswordProfile))
	}
}

// TestAdministratorSummaryHidesSecrets pins that neither the password hash nor
// the public key is echoed, and that both are reported as presence only.
func TestAdministratorSummaryHidesSecrets(t *testing.T) {
	const phash = "$1$abcdefgh$SECRETHASHVALUE"
	e := &administrator.Entry{
		Name:      "admin1",
		Phash:     new(phash),
		PublicKey: new("ssh-rsa AAAAB3NzaC1yc2E"),
		Permissions: &administrator.Permissions{
			RoleBased: &administrator.PermissionsRoleBased{Superuser: new("yes")},
		},
	}
	m, ok := administratorSummary(e).(map[string]any)
	if !ok {
		t.Fatal("summary must be a map")
	}
	for k, v := range m {
		if s, isStr := v.(string); isStr && strings.Contains(s, "SECRETHASHVALUE") {
			t.Fatalf("the password hash leaked into the summary at %q: %q", k, s)
		}
	}
	if m["has_password_hash"] != true {
		t.Error("has_password_hash must report presence")
	}
	if m["has_public_key"] != true {
		t.Error("has_public_key must report presence")
	}
	if m["role"] != adminRoleSuperuser {
		t.Errorf("role must be derived from the role-based branch, got %v", m["role"])
	}
}

// TestAdministratorSummaryOmitsAbsentToggle pins the tri-state convention on
// client_certificate_only: absent stays absent rather than becoming false.
func TestAdministratorSummaryOmitsAbsentToggle(t *testing.T) {
	m, ok := administratorSummary(&administrator.Entry{Name: "admin1"}).(map[string]any)
	if !ok {
		t.Fatal("summary must be a map")
	}
	if _, present := m["client_certificate_only"]; present {
		t.Errorf("an absent toggle must be omitted, not coerced to false: %+v", m)
	}
	if m["has_password_hash"] != false {
		t.Error("has_password_hash must be false when no hash is stored")
	}

	// Same reasoning as the password profile: an absence assertion alone would
	// survive deleting the projection, so pin the present-false and present-true
	// readings that make this field tri-state rather than boolean.
	for _, tc := range []struct{ stored, want bool }{{stored: false}, {stored: true, want: true}} {
		set, ok := administratorSummary(&administrator.Entry{
			Name: "admin1", ClientCertificateOnly: new(tc.stored),
		}).(map[string]any)
		if !ok {
			t.Fatal("summary must be a map")
		}
		if set["client_certificate_only"] != tc.want {
			t.Errorf("a stored %v must be reported as %v, got %v", tc.stored, tc.want, set["client_certificate_only"])
		}
	}
}

// TestAdministratorCreateRedactsPasswordHashOnError drives the create tool
// through the registered handler and the fake API: the device rejects the write
// with an error echoing the submitted hash, and neither the tool result nor the
// logs may carry it. This proves withSecrets(administratorSecrets) is actually
// wired into the handler, not merely defined.
func TestAdministratorCreateRedactsPasswordHashOnError(t *testing.T) {
	const phash = "$1$secretsalt$SUPERSECRETHASH"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAdministratorTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_administrator_create", Arguments: map[string]any{
		"name":          "admin1",
		"password_hash": phash,
		"role":          adminRoleSuperuser,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, phash) {
		t.Fatalf("the submitted password hash leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestAdministratorCustomRolePartialUpdatePreserves pins the read-modify-write
// contract INSIDE the custom role branch. The branch has two fields and either
// one alone triggers it, so building it fresh silently dropped whichever the
// caller did not name, along with the branch's own unmodeled XML. That
// contradicted the tool's "only provided fields change" description in the one
// place a caller could not see it.
func TestAdministratorCustomRolePartialUpdatePreserves(t *testing.T) {
	stored := func() *administrator.Entry {
		return &administrator.Entry{
			Name: "admin1",
			Permissions: &administrator.Permissions{
				RoleBased: &administrator.PermissionsRoleBased{
					Custom: &administrator.PermissionsRoleBasedCustom{
						Profile:        new("ReadOnlyRole"),
						Vsys:           []string{"vsys1", "vsys2"},
						Misc:           []generic.Xml{{}},
						MiscAttributes: []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "custom-uuid"}},
					},
				},
			},
		}
	}

	t.Run("naming only role_vsys keeps the role profile", func(t *testing.T) {
		e := stored()
		if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleVsys: []string{"vsys1", "vsys2", "vsys3"}}); err != nil {
			t.Fatal(err)
		}
		c := e.Permissions.RoleBased.Custom
		if strVal(c.Profile) != "ReadOnlyRole" {
			t.Errorf("the stored role profile must survive, got %q", strVal(c.Profile))
		}
		if len(c.Vsys) != 3 {
			t.Errorf("the provided vsys list must be applied, got %v", c.Vsys)
		}
		if len(c.Misc) != 1 || len(c.MiscAttributes) != 1 {
			t.Errorf("the custom branch's unmodeled XML must survive, got %+v", c)
		}
	})

	t.Run("naming only role_profile keeps the vsys scoping", func(t *testing.T) {
		e := stored()
		if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleProfile: new("ReadWriteRole")}); err != nil {
			t.Fatal(err)
		}
		c := e.Permissions.RoleBased.Custom
		if strVal(c.Profile) != "ReadWriteRole" {
			t.Errorf("the provided role profile must be applied, got %q", strVal(c.Profile))
		}
		if len(c.Vsys) != 2 {
			t.Errorf("the stored vsys scoping must survive, got %v", c.Vsys)
		}
		if len(c.Misc) != 1 {
			t.Errorf("the custom branch's unmodeled XML must survive, got %+v", c.Misc)
		}
	})
}

// TestAdministratorRoleSwitchClearsPerVsysBranches pins that BOTH role branches
// this server does not offer as inputs are cleared on a switch. They are
// siblings of the rest, so leaving one set beside a newly chosen role is exactly
// the two-branch config the clear exists to prevent. Naming only one of them
// here would leave the other's clear line dead to the suite.
func TestAdministratorRoleSwitchClearsPerVsysBranches(t *testing.T) {
	for _, role := range []string{adminRoleVsysAdmin, adminRoleVsysReader} {
		t.Run(role, func(t *testing.T) {
			e := storedRoleBranch(role)
			if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", Role: new(adminRoleSuperuser)}); err != nil {
				t.Fatal(err)
			}
			if got := setRoleBranches(e); len(got) != 1 || got[0] != adminRoleSuperuser {
				t.Fatalf("switching from %s must leave only the chosen role, got %v", role, got)
			}
		})
	}
}

// TestAdministratorSummaryReportsPerVsysRole pins that an administrator
// configured with a per-vsys role elsewhere does not read back as having no role
// at all. Reporting nothing would present a privileged account as unprivileged.
func TestAdministratorSummaryReportsPerVsysRole(t *testing.T) {
	m, ok := administratorSummary(&administrator.Entry{
		Name: "admin1",
		Permissions: &administrator.Permissions{
			RoleBased: &administrator.PermissionsRoleBased{
				Vsysadmin: []administrator.PermissionsRoleBasedVsysadmin{{Name: "d", Vsys: []string{"vsys1"}}},
			},
		},
	}).(map[string]any)
	if !ok {
		t.Fatal("summary must be a map")
	}
	if m["role"] != adminRoleVsysAdmin {
		t.Errorf("a per-vsys administrator must report its role, got %v", m["role"])
	}
}

// TestAdministratorUpdateRedactsPasswordHashOnError is the update-path twin of
// the create redaction test. Without it, deleting withSecrets from the update
// registration leaves the whole suite green, so the seam is registered but
// unproven on the verb that carries a read-modify-write.
func TestAdministratorUpdateRedactsPasswordHashOnError(t *testing.T) {
	const phash = "$1$updatesalt$UPDATESECRETHASH"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="admin1"/></result></response>`},
		fakeRoute{Match: configAction("multi-config"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
		fakeRoute{Match: configAction("edit"), Body: `<response status="error"><msg><line>validation error for phash ` + phash + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterAdministratorTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_administrator_update", Arguments: map[string]any{
		"name":          "admin1",
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
		t.Fatalf("the submitted password hash leaked into the update error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestAdministratorReadOnlyGating pins read-only tool gating for administrators.
// Sabotage: deleting the if d.ReadOnly guard in RegisterAdministratorTools exposes write tools in read-only mode and fails this test.
func TestAdministratorReadOnlyGating(t *testing.T) {
	base := "panos_administrator"
	assertReadOnlyGating(t, RegisterAdministratorTools,
		[]string{base + "_list", base + "_get"},
		[]string{base + "_create", base + "_update", base + "_delete"})
}

// storedRoleBranch returns an entry carrying exactly one role branch, named by
// role. It covers all seven branches pango models, including the two per-vsys
// ones this server never accepts as input but must still clear and report.
func storedRoleBranch(role string) *administrator.Entry {
	rb := &administrator.PermissionsRoleBased{}
	const yes = "yes"
	switch role {
	case adminRoleSuperuser:
		rb.Superuser = new(yes)
	case adminRoleSuperreader:
		rb.Superreader = new(yes)
	case adminRolePanoramaAdmin:
		rb.PanoramaAdmin = new(yes)
	case adminRoleDeviceAdmin:
		rb.Deviceadmin = []string{yes}
	case adminRoleDeviceReader:
		rb.Devicereader = []string{yes}
	case adminRoleVsysAdmin:
		rb.Vsysadmin = []administrator.PermissionsRoleBasedVsysadmin{{Name: "d", Vsys: []string{"vsys1"}}}
	case adminRoleVsysReader:
		rb.Vsysreader = []administrator.PermissionsRoleBasedVsysreader{{Name: "d", Vsys: []string{"vsys1"}}}
	case "custom":
		rb.Custom = &administrator.PermissionsRoleBasedCustom{Profile: new("stale-role")}
	}
	return &administrator.Entry{
		Name:        "admin1",
		Permissions: &administrator.Permissions{RoleBased: rb},
	}
}

// setRoleBranches reports every role branch currently set on an entry. Exactly
// one may ever be set: PAN-OS rejects a role-based block carrying two.
func setRoleBranches(e *administrator.Entry) []string {
	rb := e.Permissions.RoleBased
	var out []string
	for _, c := range []struct {
		name string
		set  bool
	}{
		{adminRoleSuperuser, rb.Superuser != nil},
		{adminRoleSuperreader, rb.Superreader != nil},
		{adminRolePanoramaAdmin, rb.PanoramaAdmin != nil},
		{adminRoleDeviceAdmin, len(rb.Deviceadmin) > 0},
		{adminRoleDeviceReader, len(rb.Devicereader) > 0},
		{adminRoleVsysAdmin, len(rb.Vsysadmin) > 0},
		{adminRoleVsysReader, len(rb.Vsysreader) > 0},
		{"custom", rb.Custom != nil},
	} {
		if c.set {
			out = append(out, c.name)
		}
	}
	return out
}

// assertExactlyOneRole fails unless the entry carries exactly the one named role
// branch. Two branches set is the config PAN-OS rejects.
func assertExactlyOneRole(t *testing.T, e *administrator.Entry, from, want string) {
	t.Helper()
	got := setRoleBranches(e)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("switching from %s to %s must leave exactly one branch set, got %v", from, want, got)
	}
}

// allStoredRoleBranches is every branch an entry can already carry, and
// settableRoles is every branch these tools can switch it to.
var (
	allStoredRoleBranches = []string{
		adminRoleSuperuser, adminRoleSuperreader, adminRolePanoramaAdmin,
		adminRoleDeviceAdmin, adminRoleDeviceReader,
		adminRoleVsysAdmin, adminRoleVsysReader, "custom",
	}
	settableRoles = []string{
		adminRoleSuperuser, adminRoleSuperreader, adminRolePanoramaAdmin,
		adminRoleDeviceAdmin, adminRoleDeviceReader,
	}
)

// TestAdministratorRoleExclusiveToBuiltin drives every stored role branch to
// every settable built-in role and asserts exactly one branch survives.
//
// A single linear walk leaves most clear lines dead: deleting any of them keeps
// such a suite green while a stale sibling survives, which is exactly the config
// PAN-OS rejects. Only a stored x target table reaches all of them.
func TestAdministratorRoleExclusiveToBuiltin(t *testing.T) {
	for _, from := range allStoredRoleBranches {
		for _, to := range settableRoles {
			t.Run(from+"_to_"+to, func(t *testing.T) {
				e := storedRoleBranch(from)
				if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", Role: new(to)}); err != nil {
					t.Fatal(err)
				}
				assertExactlyOneRole(t, e, from, to)
				m, _ := administratorSummary(e).(map[string]any)
				if m["role"] != to {
					t.Errorf("the summary must report %s, got %v", to, m["role"])
				}
			})
		}
	}
}

// TestAdministratorRoleExclusiveToCustom is the same sweep for the custom
// branch, which is reached through role_profile rather than role.
func TestAdministratorRoleExclusiveToCustom(t *testing.T) {
	for _, from := range allStoredRoleBranches {
		t.Run(from+"_to_custom", func(t *testing.T) {
			e := storedRoleBranch(from)
			if err := overlayAdministrator(e, AdministratorInput{Name: "admin1", RoleProfile: new("ReadOnlyRole")}); err != nil {
				t.Fatal(err)
			}
			assertExactlyOneRole(t, e, from, "custom")
			m, _ := administratorSummary(e).(map[string]any)
			if m["role_profile"] != "ReadOnlyRole" {
				t.Errorf("the summary must report the custom profile, got %v", m["role_profile"])
			}
			if _, present := m["role"]; present {
				t.Errorf("a custom role must not also report a built-in role: %+v", m)
			}
		})
	}
}

// TestAdministratorSummaryReportsEveryStoredBranch pins the read projection for
// all seven role branches, not just the one a single test happened to use.
func TestAdministratorSummaryReportsEveryStoredBranch(t *testing.T) {
	for _, role := range []string{
		adminRoleSuperuser, adminRoleSuperreader, adminRolePanoramaAdmin,
		adminRoleDeviceAdmin, adminRoleDeviceReader,
		adminRoleVsysAdmin, adminRoleVsysReader,
	} {
		t.Run(role, func(t *testing.T) {
			m, ok := administratorSummary(storedRoleBranch(role)).(map[string]any)
			if !ok {
				t.Fatal("summary must be a map")
			}
			if m["role"] != role {
				t.Errorf("a stored %s must be reported as %s, got %v", role, role, m["role"])
			}
		})
	}
}

// TestSetBuiltinRoleCoversBuiltinAdminRoles pins that every role accepted by
// builtinAdminRoles is mapped to a role branch in setBuiltinRole.
// Sabotage: deleting any case in setBuiltinRole leaves that role unset and fails this test.
func TestSetBuiltinRoleCoversBuiltinAdminRoles(t *testing.T) {
	for _, role := range slices.Sorted(maps.Keys(builtinAdminRoles)) {
		t.Run(role, func(t *testing.T) {
			rb := &administrator.PermissionsRoleBased{}
			setBuiltinRole(rb, role)
			e := &administrator.Entry{
				Permissions: &administrator.Permissions{RoleBased: rb},
			}
			assertExactlyOneRole(t, e, "fresh", role)
		})
	}
}
