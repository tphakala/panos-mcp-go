package tools

import (
	"go/ast"
	"go/token"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// existingEntryBody answers a config get for an entry that exists.
const existingEntryBody = `<response status="success"><result total-count="1" count="1"><entry name="dup"/></result></response>`

// TestCreateRejectsExistingEntry drives one create tool per handler kind through
// the registered server against a device whose every config get finds the entry,
// and expects the tool to fail naming the entry and its update tool, with no
// config write. PAN-OS merges a set into an existing entry, so a create path that
// skipped the pre-read would send the set (and, with no set route here, would see
// the fake's unmatched error instead of "already exists").
//
// Sabotage: delete the rejectExisting call in createCore (rows object through
// system-entry), in zoneCreateHandler (zone) or in ruleCreateHandler (rule); or
// pass the raw rule service as the rule reader.
func TestCreateRejectsExistingEntry(t *testing.T) {
	rows := []struct {
		kind, tool string
		args       map[string]any
	}{
		{"object", "panos_address_create", map[string]any{"name": "dup", "ip_netmask": "10.0.0.1/32"}},
		{"mgt", "panos_password_profile_create", map[string]any{"name": "dup"}},
		{"device", "panos_saml_idp_profile_create", map[string]any{"name": "dup"}},
		{"net", "panos_ike_crypto_profile_create", map[string]any{"name": "dup"}},
		{"parent", "panos_static_route_create", map[string]any{"name": "dup", "virtual_router": "default", "destination": "10.9.0.0/16"}},
		{"profile", "panos_ssl_tls_profile_create", map[string]any{"name": "dup"}},
		{"system-entry", "panos_log_export_schedule_create", map[string]any{"name": "dup"}},
		{"zone", "panos_zone_create", map[string]any{"name": "dup", "network_type": "layer3"}},
		{"rule", "panos_security_rule_create", map[string]any{"name": "dup", "action": "allow"}},
	}
	for _, r := range rows {
		t.Run(r.kind, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: existingEntryBody})
			srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			RegisterAll(srv, d)
			cs := connectInMemory(t, srv)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: r.tool, Arguments: r.args})
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsError {
				t.Fatalf("%s on an existing entry must be an error", r.tool)
			}
			body := textContent(t, res)
			updateTool := strings.TrimSuffix(r.tool, "_create") + "_update"
			for _, want := range []string{`"dup" already exists`, updateTool} {
				if !strings.Contains(body, want) {
					t.Fatalf("error must contain %q, got: %s", want, body)
				}
			}
			assertNoConfigWrite(t, f)
		})
	}
}

// TestCreatePreReadErrorAbortsAndRedacts pins that a pre-read failing for any
// reason other than not-found stops the create (a flaky read must not be taken
// as "absent" and merge into an entry) and that the read error carries none of
// the secret values the call submitted.
//
// Sabotage: make rejectExisting's default branch return nil (a set is recorded),
// or drop gatherSecrets(&in, opts)... from the createCore call (the secret shows
// in the body).
func TestCreatePreReadErrorAbortsAndRedacts(t *testing.T) {
	const secret = "FIXTURE-bind-secret"
	d, f := newTestDeps(t, "PA-VM", fakeRoute{
		Match: configAction("get"),
		Body:  `<response status="error" code="12"><msg><line>bad bind-password ` + secret + `</line></msg></response>`,
	})
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterLdapProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_ldap_profile_create",
		Arguments: map[string]any{"name": "ldap1", "bind_password": secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a failed pre-read must be an error result")
	}
	body := textContent(t, res)
	if !strings.Contains(body, `read "ldap1"`) {
		t.Fatalf("error must name the failed pre-read, got: %s", body)
	}
	if strings.Contains(body, secret) {
		t.Fatalf("the submitted secret reached the pre-read error: %s", body)
	}
	assertNoConfigWrite(t, f)
}

// TestCreateToolsHaveUpdateSibling pins the hint in the "already exists" error:
// it names <tool minus _create>_update, so every registered create must have that
// update tool unless it is listed in createsWithoutUpdate, and every listed tool
// must really be a create without an update in at least one model.
//
// Sabotage: remove a member from createsWithoutUpdate, or add a name that is not a
// create without an update.
func TestCreateToolsHaveUpdateSibling(t *testing.T) {
	listedSeen := map[string]bool{}
	for _, model := range []string{"PA-VM", "Panorama"} {
		names := allRegisteredNames(t, model, false)
		for name := range names {
			base, ok := strings.CutSuffix(name, "_create")
			if !ok {
				continue
			}
			if names[base+"_update"] {
				continue
			}
			if !createsWithoutUpdate[name] {
				t.Errorf("%s: %s has no %s_update tool and is not in createsWithoutUpdate", model, name, base)
				continue
			}
			listedSeen[name] = true
		}
	}
	for name := range createsWithoutUpdate {
		if !listedSeen[name] {
			t.Errorf("createsWithoutUpdate lists %s, which is not a registered create without an update tool in either model", name)
		}
	}
}

// TestEveryCreateCallSitePreReads is a structural tripwire over the tools
// package source: the only functions that call a pango Create or CreateWithXpath
// are the three create cores (which must call rejectExisting before it), the
// singleton seed in systemUpdateHandler (an intended upsert) and the two adapters'
// pass-through Create methods. A new bespoke create handler that writes without
// the pre-read fails here, which no behavioural test would catch until someone
// wrote one for that family.
//
// Sabotage: move the rejectExisting call after Create in createCore, or add a
// function that calls svc.Create or svc.CreateWithXpath.
func TestEveryCreateCallSitePreReads(t *testing.T) {
	type site struct{ create, pre token.Pos }
	sites := map[string]*site{}
	for _, f := range parseToolsPackage(t) {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				name = recvTypeName(fd.Recv.List[0].Type) + "." + name
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fn.Sel.Name == "Create" || fn.Sel.Name == "CreateWithXpath" {
						s := sites[name]
						if s == nil {
							s = &site{}
							sites[name] = s
						}
						if s.create == token.NoPos || call.Pos() < s.create {
							s.create = call.Pos()
						}
					}
				case *ast.Ident:
					if fn.Name == "rejectExisting" {
						s := sites[name]
						if s == nil {
							s = &site{}
							sites[name] = s
						}
						if s.pre == token.NoPos || call.Pos() < s.pre {
							s.pre = call.Pos()
						}
					}
				}
				return true
			})
		}
	}
	var got []string
	for name, s := range sites {
		if s.create != token.NoPos {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	want := []string{
		"createCore", "nameFixAdapter.Create", "parentFixAdapter.Create",
		"ruleCreateHandler", "systemUpdateHandler", "zoneCreateHandler",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("functions calling Create or CreateWithXpath changed:\n got  %v\n want %v\n"+
			"a new create path must call rejectExisting before it writes; add it here only if it is a deliberate upsert", got, want)
	}
	for _, name := range []string{"createCore", "ruleCreateHandler", "zoneCreateHandler"} {
		s := sites[name]
		if s.pre == token.NoPos || s.pre > s.create {
			t.Errorf("%s must call rejectExisting before Create", name)
		}
	}
}

// recvTypeName returns the base type name of a method receiver, looking through
// a pointer and type arguments.
func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.IndexExpr:
		return recvTypeName(t.X)
	case *ast.IndexListExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}
