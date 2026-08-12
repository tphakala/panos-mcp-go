package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/address"
	address_group "github.com/PaloAltoNetworks/pango/objects/address/group"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addressListBody is what pango's list parser expects: the client strips only
// the outer <response> tag, leaving <result> whose direct <entry> children bind
// to the entry container. The list xpath already ends at .../address/entry, so
// there is no <address> wrapper element in the response.
const addressListBody = `<response status="success"><result><entry name="web-1">` +
	`<ip-netmask>10.0.0.10/32</ip-netmask><description>web box</description></entry>` +
	`<entry name="db-1"><ip-netmask>10.0.0.20/32</ip-netmask></entry></result></response>`

// configSuccessBody answers a config set; code 20 is "command succeeded".
const configSuccessBody = `<response status="success" code="20"><msg>command succeeded</msg></response>`

// addressCreatedBody answers the read-back get that pango's Create issues after
// the set; the read-back requires exactly one entry.
const addressCreatedBody = `<response status="success"><result><entry name="web-1">` +
	`<ip-netmask>10.0.0.10/32</ip-netmask><tag><member>prod</member></tag></entry></result></response>`

// addressCurrentBody is the entry as it exists before an update or read; an
// update reads it, overlays the new value, and edits.
const addressCurrentBody = `<response status="success"><result><entry name="web-1">` +
	`<ip-netmask>10.0.0.10/32</ip-netmask></entry></result></response>`

func addressResolve(d *Deps) func(LocationInput) (address.Location, error) {
	return func(in LocationInput) (address.Location, error) {
		return resolveLocation(d, in, addressParts())
	}
}

func addressName(e *address.Entry) string { return e.Name }

func TestAddressList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: addressListBody})
	h := listHandler[address.Location, address.Entry](d, "panos_address_list",
		newAddressService(d), addressResolve(d), addressName, addressSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, `"total": 2`) || !strings.Contains(body, "web-1") || !strings.Contains(body, "db-1") {
		t.Fatalf("missing entries: %s", body)
	}

	res, _, err = h(t.Context(), nil, ListInput{Filter: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	if body = textContent(t, res); strings.Contains(body, "db-1") || !strings.Contains(body, "web-1") {
		t.Fatalf("filter failed: %s", body)
	}
}

func TestAddressCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the object back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: addressCreatedBody},
	)
	h := createHandler[address.Location, address.Entry, AddressInput](d, "panos_address_create",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location }, buildAddressEntry)

	res, _, err := h(t.Context(), nil, AddressInput{Name: "web-1", IPNetmask: "10.0.0.10/32", Description: "web box", Tags: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			sawSet = true
			el := req.Get("element")
			if !strings.Contains(el, `name="web-1"`) || !strings.Contains(el, "10.0.0.10/32") ||
				!strings.Contains(el, "<member>prod</member>") || !strings.Contains(el, "web box") {
				t.Fatalf("element missing fields: %s", el)
			}
			if !strings.Contains(req.Get("xpath"), "vsys1") {
				t.Fatalf("xpath missing default vsys: %s", req.Get("xpath"))
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
}

func TestAddressCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[address.Location, address.Entry, AddressInput](d, "panos_address_create",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location }, buildAddressEntry)

	for name, in := range map[string]AddressInput{
		"no name":        {IPNetmask: "10.0.0.1"},
		"no value":       {Name: "x"},
		"two values":     {Name: "x", IPNetmask: "10.0.0.1", FQDN: "a.example.com"},
		"dg on firewall": {Name: "x", IPNetmask: "10.0.0.1", Location: LocationInput{DeviceGroup: "dg1"}},
	} {
		res, _, err := h(t.Context(), nil, in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", name)
		}
	}
	// Validation must reject before any API call: only the bootstrap system-info
	// request may exist. Without this, a broken validator would still "pass" via
	// the fake's fail-loud error on the unexpected request.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestAddressAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[address.Location, address.Entry](d, "panos_address_get",
		newAddressService(d), addressResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("API error must surface as IsError result")
	}
	if body := textContent(t, res); !strings.Contains(body, "invalid object") {
		t.Fatalf("error text must carry the PAN-OS message, got: %s", body)
	}
	// The request must reach the API with the wrapped entry xpath, not a raw name;
	// asserting the entry[@name='...'] shape (not just the "nope" substring) pins
	// that the adapter wrapped the name. A client-side xpath rejection would also
	// produce IsError but vacuously, never consulting the canned route.
	var sawGet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "get" && strings.Contains(req.Get("xpath"), "entry[@name='nope']") {
			sawGet = true
		}
	}
	if !sawGet {
		t.Fatal("get never reached the API: the service must wrap the name into an entry xpath")
	}
}

func TestAddressUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressCurrentBody},
		// pango Update edits through a multi-config request, not a plain set.
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[address.Location, address.Entry, AddressInput](d, "panos_address_update",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location },
		func(in AddressInput) string { return in.Name }, overlayAddress)

	res, _, err := h(t.Context(), nil, AddressInput{Name: "web-1", IPNetmask: "10.9.9.9/32"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// The edit must reach the API as a multi-config carrying the new value and the
	// entry xpath (default vsys). A client-side xpath rejection (the raw-name bug
	// the adapter fixes for Update) would never record a multi-config request.
	var sawEdit bool
	for _, req := range f.Requests() {
		if req.Get("action") == "multi-config" {
			sawEdit = true
			el := req.Get("element")
			if !strings.Contains(el, "10.9.9.9/32") {
				t.Fatalf("edit element missing new value: %s", el)
			}
			if !strings.Contains(el, "vsys1") || !strings.Contains(el, "web-1") {
				t.Fatalf("edit element missing entry xpath: %s", el)
			}
		}
	}
	if !sawEdit {
		t.Fatal("update never issued a multi-config edit; adapter must wrap the name into an entry xpath")
	}
}

func TestAddressUpdateRejectsRename(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	svc := newAddressService(d)
	// The guard fires before the location is used, so a zero Location is fine.
	if _, err := svc.Update(t.Context(), address.Location{}, &address.Entry{Name: "web-1"}, "web-2"); err == nil {
		t.Fatal("Update must reject a name that differs from entry.Name (rename)")
	} else if !strings.Contains(err.Error(), "renaming") {
		t.Fatalf("expected a rename-not-supported error, got: %v", err)
	}
}

func TestAddressUpdateRejectsConflict(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	h := updateHandler[address.Location, address.Entry, AddressInput](d, "panos_address_update",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location },
		func(in AddressInput) string { return in.Name }, overlayAddress)

	res, _, err := h(t.Context(), nil, AddressInput{Name: "web-1", IPNetmask: "10.9.9.9/32", FQDN: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("update with two value types must be an error result")
	}
	// A rejected overlay must never edit the device.
	for _, req := range f.Requests() {
		if req.Get("action") == "multi-config" {
			t.Fatal("rejected update must not issue a multi-config edit")
		}
	}
}

func TestAddressDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[address.Location, address.Entry](d, "panos_address_delete",
		newAddressService(d), addressResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Delete must reach the API with the entry xpath carrying the name and the
	// default vsys, proving addressParts wires the location end-to-end.
	var sawDelete bool
	for _, req := range f.Requests() {
		if req.Get("action") == "multi-config" && strings.Contains(req.Get("element"), "web-1") &&
			strings.Contains(req.Get("element"), "vsys1") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatal("delete never reached the API with the entry xpath")
	}
}

// TestOverlayAddressValueTypes pins that providing one value type sets it and
// clears the other two, and that providing more than one is rejected.
func TestOverlayAddressValueTypes(t *testing.T) {
	cases := []struct {
		name                             string
		in                               AddressInput
		wantErr                          bool
		wantNetmask, wantRange, wantFqdn string
	}{
		{"ip_netmask", AddressInput{IPNetmask: "10.1.1.1/32"}, false, "10.1.1.1/32", "", ""},
		{"ip_range replaces and clears", AddressInput{IPRange: "10.0.0.1-10.0.0.9"}, false, "", "10.0.0.1-10.0.0.9", ""},
		{"fqdn replaces and clears", AddressInput{FQDN: "a.example.com"}, false, "", "", "a.example.com"},
		{"rejects two value types", AddressInput{IPNetmask: "10.0.0.1", FQDN: "a.example.com"}, true, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Seed both a tool-settable value type (ip_netmask) and a pre-existing
			// ip-wildcard (settable only outside this tool). The netmask proves the
			// range and fqdn branches clear a stale sibling type; the wildcard proves
			// they clear it too. Otherwise the read-modify-write emits a dual-valued
			// (invalid) entry.
			e := &address.Entry{Name: "web-1", IpNetmask: ptr("10.0.0.10/32"), IpWildcard: ptr("10.0.0.0/0.0.0.255")}
			err := overlayAddress(e, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error for multiple value types")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strVal(e.IpNetmask) != tc.wantNetmask || strVal(e.IpRange) != tc.wantRange ||
				strVal(e.Fqdn) != tc.wantFqdn || e.IpWildcard != nil {
				t.Fatalf("got netmask=%q range=%q fqdn=%q wildcard=%v",
					strVal(e.IpNetmask), strVal(e.IpRange), strVal(e.Fqdn), e.IpWildcard)
			}
		})
	}
}

// TestBuildAddressEntry pins that a create entry is built from exactly one value
// type (covering all three build branches) and rejects missing or duplicate ones.
func TestBuildAddressEntry(t *testing.T) {
	ok := []struct {
		name                             string
		in                               AddressInput
		wantNetmask, wantRange, wantFqdn string
	}{
		{"netmask", AddressInput{Name: "a", IPNetmask: "10.0.0.1/32"}, "10.0.0.1/32", "", ""},
		{"range", AddressInput{Name: "a", IPRange: "10.0.0.1-10.0.0.9"}, "", "10.0.0.1-10.0.0.9", ""},
		{"fqdn", AddressInput{Name: "a", FQDN: "a.example.com"}, "", "", "a.example.com"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			e, err := buildAddressEntry(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if strVal(e.IpNetmask) != tc.wantNetmask || strVal(e.IpRange) != tc.wantRange || strVal(e.Fqdn) != tc.wantFqdn {
				t.Fatalf("got netmask=%q range=%q fqdn=%q", strVal(e.IpNetmask), strVal(e.IpRange), strVal(e.Fqdn))
			}
		})
	}

	bad := map[string]AddressInput{
		"no name":    {IPNetmask: "10.0.0.1/32"},
		"no value":   {Name: "a"},
		"two values": {Name: "a", IPNetmask: "10.0.0.1/32", IPRange: "10.0.0.1-10.0.0.9"},
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := buildAddressEntry(in); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

// TestOverlayAddressDescriptionAndTags pins the partial-update semantics: an
// omitted description or nil tags leave the existing values unchanged, while a
// non-nil empty tags slice clears the tags.
func TestOverlayAddressDescriptionAndTags(t *testing.T) {
	e := &address.Entry{Name: "web-1", IpNetmask: ptr("10.0.0.10/32"), Description: ptr("old"), Tag: []string{"a"}}

	if err := overlayAddress(e, AddressInput{Description: "new"}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" {
		t.Fatalf("description not updated: %v", e.Description)
	}

	// Omitted description and nil tags must leave the existing values unchanged.
	if err := overlayAddress(e, AddressInput{}); err != nil {
		t.Fatal(err)
	}
	if strVal(e.Description) != "new" || len(e.Tag) != 1 {
		t.Fatalf("omitted fields must not change entry: desc=%v tags=%v", e.Description, e.Tag)
	}

	// A non-nil empty tags slice clears the tags.
	if err := overlayAddress(e, AddressInput{Tags: []string{}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Tag) != 0 {
		t.Fatalf("empty tags slice must clear tags: %v", e.Tag)
	}
}

// getConfigXpaths returns the xpath of every recorded type=config action=get
// request, so a test can assert which location a read or list targeted.
func getConfigXpaths(f *fakeAPI) []string {
	var xs []string
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "get" {
			xs = append(xs, req.Get("xpath"))
		}
	}
	return xs
}

// TestAddressPanoramaLocations exercises the Panorama location branches of
// addressParts: the shared default and an explicit device group. Each subtest
// asserts the request xpath so it pins the resolved location, not merely that a
// canned body came back.
func TestAddressPanoramaLocations(t *testing.T) {
	t.Run("shared list", func(t *testing.T) {
		// Panorama with no location resolves to the shared location.
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: addressListBody})
		h := listHandler[address.Location, address.Entry](d, "panos_address_list",
			newAddressService(d), addressResolve(d), addressName, addressSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if body := textContent(t, res); !strings.Contains(body, "web-1") {
			t.Fatalf("shared list missing entries: %s", body)
		}
		// Pin that the Panorama default actually resolves to shared, not a vsys.
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared") || strings.Contains(joined, "vsys") {
			t.Fatalf("shared list must target the shared xpath and not a vsys, got: %s", joined)
		}
	})

	t.Run("device group get", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: addressCurrentBody})
		h := getHandler[address.Location, address.Entry](d, "panos_address_get",
			newAddressService(d), addressResolve(d))
		res, _, err := h(t.Context(), nil, NameInput{Name: "web-1", Location: LocationInput{DeviceGroup: "dg1"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		// The xpath must target the device group, proving addressParts.deviceGroup
		// wiring end-to-end (not just the firewall vsys path).
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "dg1") {
			t.Fatalf("device_group get did not target the device group xpath, got: %s", joined)
		}
	})
}

// registeredToolNames registers the address and address group tools on a fresh
// in-memory MCP server/client pair and returns the set of tool names the server
// exposes.
func registeredToolNames(t *testing.T, d *Deps) map[string]bool {
	t.Helper()
	ctx := t.Context()
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAddressTools(srv, d)
	RegisterAddressGroupTools(srv, d)

	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	cli := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0"}, nil)
	cs, err := cli.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tl := range res.Tools {
		names[tl.Name] = true
	}
	return names
}

// TestRegisterAddressToolsReadOnly pins the write-safety gate: the mutating tools
// are registered only when writes are enabled (PANOS_ALLOW_WRITES), while the
// read tools are always present. This is the sole enforcement point for these
// tools, so a regression that drops the d.ReadOnly gate must fail here.
func TestRegisterAddressToolsReadOnly(t *testing.T) {
	reads := []string{"panos_address_list", "panos_address_get"}
	writes := []string{"panos_address_create", "panos_address_update", "panos_address_delete"}

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
	for _, n := range reads {
		if !rw[n] {
			t.Errorf("writes enabled: %q must be registered", n)
		}
	}
	for _, n := range writes {
		if !rw[n] {
			t.Errorf("writes enabled: %q must be registered", n)
		}
	}
}

// addressGroupListBody lists a static group and a dynamic group. Static members
// and tags marshal as <static>/<tag> member lists; a dynamic group carries a
// <dynamic><filter>. The list xpath ends at .../address-group/entry, so there is
// no <address-group> wrapper element in the response.
const addressGroupListBody = `<response status="success"><result>` +
	`<entry name="grp-static"><static><member>web-1</member><member>db-1</member></static><tag><member>t1</member></tag><description>static grp</description></entry>` +
	`<entry name="grp-dyn"><dynamic><filter>'prod' and 'web'</filter></dynamic></entry>` +
	`</result></response>`

// addressGroupCreatedBody answers the read-back get pango's Create issues after
// the set; the read-back requires exactly one entry.
const addressGroupCreatedBody = `<response status="success"><result><entry name="grp-1">` +
	`<static><member>web-1</member></static><tag><member>prod</member></tag></entry></result></response>`

// addressGroupCurrentBody is the entry as it exists before an update: one static
// member and a description. Every update input below must differ from it, or
// pango's UpdateWithXpath short-circuits on SpecMatches and issues no
// multi-config request, making the edit assertions vacuous.
const addressGroupCurrentBody = `<response status="success"><result><entry name="grp-1">` +
	`<static><member>web-1</member></static><description>old desc</description></entry></result></response>`

func addressGroupResolve(d *Deps) func(LocationInput) (address_group.Location, error) {
	return func(in LocationInput) (address_group.Location, error) {
		return resolveLocation(d, in, addressGroupParts())
	}
}

func addressGroupName(e *address_group.Entry) string { return e.Name }

// TestBuildAddressGroupEntry pins the create XOR: exactly one of static,
// dynamic_filter is required, and the chosen side plus description and tags map
// onto the entry.
func TestBuildAddressGroupEntry(t *testing.T) {
	t.Run("static only", func(t *testing.T) {
		e, err := buildAddressGroupEntry(AddressGroupInput{Name: "g", Static: []string{"web-1", "db-1"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Static) != 2 || e.Dynamic != nil {
			t.Fatalf("static build wrong: static=%v dynamic=%v", e.Static, e.Dynamic)
		}
	})
	t.Run("dynamic with description and tags", func(t *testing.T) {
		e, err := buildAddressGroupEntry(AddressGroupInput{Name: "g", DynamicFilter: "'prod'", Description: "d", Tags: []string{"t"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.Static != nil || e.Dynamic == nil || strVal(e.Dynamic.Filter) != "'prod'" {
			t.Fatalf("dynamic build wrong: static=%v dynamic=%v", e.Static, e.Dynamic)
		}
		if strVal(e.Description) != "d" || len(e.Tag) != 1 {
			t.Fatalf("dynamic build lost description or tags: desc=%v tags=%v", e.Description, e.Tag)
		}
	})
	bad := map[string]AddressGroupInput{
		"no name":      {Static: []string{"web-1"}},
		"neither":      {Name: "g"},
		"empty static": {Name: "g", Static: []string{}}, // an empty static list counts as absent
		"both":         {Name: "g", Static: []string{"web-1"}, DynamicFilter: "'prod'"},
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := buildAddressGroupEntry(in); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

// TestOverlayAddressGroupMembership pins that providing one membership side
// (static or dynamic_filter) rewrites both fields, clearing the other, and that
// providing both is rejected.
func TestOverlayAddressGroupMembership(t *testing.T) {
	t.Run("static replaces and clears dynamic", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}, Dynamic: &address_group.Dynamic{Filter: ptr("'old'")}}
		if err := overlayAddressGroup(e, AddressGroupInput{Static: []string{"app-1", "app-2"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Static) != 2 || e.Static[0] != "app-1" || e.Dynamic != nil {
			t.Fatalf("static overlay wrong: static=%v dynamic=%v", e.Static, e.Dynamic)
		}
	})
	t.Run("dynamic replaces and clears static", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}}
		if err := overlayAddressGroup(e, AddressGroupInput{DynamicFilter: "'prod'"}); err != nil {
			t.Fatal(err)
		}
		if e.Static != nil || e.Dynamic == nil || strVal(e.Dynamic.Filter) != "'prod'" {
			t.Fatalf("dynamic overlay wrong: static=%v dynamic=%v", e.Static, e.Dynamic)
		}
	})
	t.Run("both is an error", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}}
		if err := overlayAddressGroup(e, AddressGroupInput{Static: []string{"a"}, DynamicFilter: "'x'"}); err == nil {
			t.Fatal("providing both static and dynamic_filter must error")
		}
	})
	t.Run("empty static list is ignored", func(t *testing.T) {
		// An empty static list is treated as absent (a static group cannot be
		// emptied in place), so the existing members are left untouched.
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}}
		if err := overlayAddressGroup(e, AddressGroupInput{Static: []string{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Static) != 1 || e.Static[0] != "web-1" {
			t.Fatalf("empty static list must be ignored, got: %v", e.Static)
		}
	})
}

// TestOverlayAddressGroupFields pins the non-membership overlay semantics: tags
// replace when non-nil and clear when empty, an omitted description or nil tags
// leave the existing values unchanged, and a provided description updates.
func TestOverlayAddressGroupFields(t *testing.T) {
	t.Run("tags replace when non-nil and clear when empty", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}, Tag: []string{"a"}}
		if err := overlayAddressGroup(e, AddressGroupInput{Tags: []string{"b", "c"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 2 {
			t.Fatalf("tags not replaced: %v", e.Tag)
		}
		if err := overlayAddressGroup(e, AddressGroupInput{Tags: []string{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 0 {
			t.Fatalf("empty tags slice must clear tags: %v", e.Tag)
		}
	})
	t.Run("omitted fields unchanged", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}, Description: ptr("old"), Tag: []string{"a"}}
		if err := overlayAddressGroup(e, AddressGroupInput{}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Description) != "old" || len(e.Tag) != 1 || len(e.Static) != 1 {
			t.Fatalf("empty overlay changed entry: desc=%v tags=%v static=%v", e.Description, e.Tag, e.Static)
		}
	})
	t.Run("description updates when provided", func(t *testing.T) {
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}, Description: ptr("old")}
		if err := overlayAddressGroup(e, AddressGroupInput{Description: "new"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Description) != "new" {
			t.Fatalf("description not updated: %v", e.Description)
		}
	})
}

func TestAddressGroupCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the object back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: addressGroupCreatedBody},
	)
	h := createHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_create",
		newAddressGroupService(d), addressGroupResolve(d),
		func(in AddressGroupInput) LocationInput { return in.Location }, buildAddressGroupEntry)

	res, _, err := h(t.Context(), nil, AddressGroupInput{Name: "grp-1", Static: []string{"web-1"}, Description: "web tier", Tags: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "set" {
			sawSet = true
			el := req.Get("element")
			if !strings.Contains(el, `name="grp-1"`) || !strings.Contains(el, "<member>web-1</member>") ||
				!strings.Contains(el, "<member>prod</member>") || !strings.Contains(el, "web tier") {
				t.Fatalf("element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "address-group") {
				t.Fatalf("xpath missing default vsys or address-group endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
}

func TestAddressGroupCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_create",
		newAddressGroupService(d), addressGroupResolve(d),
		func(in AddressGroupInput) LocationInput { return in.Location }, buildAddressGroupEntry)

	for name, in := range map[string]AddressGroupInput{
		"no name":        {Static: []string{"web-1"}},
		"neither":        {Name: "g"},
		"both":           {Name: "g", Static: []string{"web-1"}, DynamicFilter: "'prod'"},
		"dg on firewall": {Name: "g", Static: []string{"web-1"}, Location: LocationInput{DeviceGroup: "dg1"}},
	} {
		res, _, err := h(t.Context(), nil, in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", name)
		}
	}
	// Validation must reject before any API call: only the bootstrap system-info
	// request may exist.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestAddressGroupAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[address_group.Location, address_group.Entry](d, "panos_address_group_get",
		newAddressGroupService(d), addressGroupResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("API error must surface as IsError result")
	}
	if body := textContent(t, res); !strings.Contains(body, "invalid object") {
		t.Fatalf("error text must carry the PAN-OS message, got: %s", body)
	}
	// Pin that the shared adapter wraps the name into an entry xpath for the group
	// instantiation too; a client-side raw-name rejection would set IsError
	// vacuously, never consulting the canned route.
	var sawGet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "get" && strings.Contains(req.Get("xpath"), "entry[@name='nope']") {
			sawGet = true
		}
	}
	if !sawGet {
		t.Fatal("get never reached the API: the adapter must wrap the name into an entry xpath")
	}
}

// multiConfigElement returns the element of the single recorded multi-config
// request, failing if none was issued. pango routes edits and deletes through
// multi-config, so an update or delete assertion inspects the wire here. A
// client-side raw-name rejection would record no multi-config request at all.
func multiConfigElement(t *testing.T, f *fakeAPI) string {
	t.Helper()
	for _, req := range f.Requests() {
		if req.Get("action") == "multi-config" {
			return req.Get("element")
		}
	}
	t.Fatal("no multi-config request recorded")
	return ""
}

// newAddressGroupUpdateHandler builds the update handler used by the update
// tests, keeping their setup to one line.
func newAddressGroupUpdateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, AddressGroupInput) (*mcp.CallToolResult, any, error) {
	return updateHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_update",
		newAddressGroupService(d), addressGroupResolve(d),
		func(in AddressGroupInput) LocationInput { return in.Location },
		func(in AddressGroupInput) string { return in.Name }, overlayAddressGroup)
}

func TestAddressGroupUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	res, _, err := newAddressGroupUpdateHandler(d)(t.Context(), nil, AddressGroupInput{Name: "grp-1", Static: []string{"app-1", "app-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// The edit must replace the member list, preserve the untouched description,
	// and carry the entry xpath (default vsys).
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<member>app-1</member>") || !strings.Contains(el, "<member>app-2</member>") {
		t.Fatalf("edit element missing new members: %s", el)
	}
	if strings.Contains(el, "<member>web-1</member>") {
		t.Fatalf("edit element must not keep the replaced member: %s", el)
	}
	if !strings.Contains(el, "old desc") {
		t.Fatalf("read-modify-write must preserve the untouched description: %s", el)
	}
	if !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing entry xpath: %s", el)
	}
}

func TestAddressGroupUpdateSwitchToDynamic(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	res, _, err := newAddressGroupUpdateHandler(d)(t.Context(), nil, AddressGroupInput{Name: "grp-1", DynamicFilter: "'prod'"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	// pango marshals the filter through encoding/xml, so single quotes are
	// escaped; match the bare word rather than the quoted form.
	if !strings.Contains(el, "<filter>") || !strings.Contains(el, "prod") {
		t.Fatalf("edit element missing dynamic filter: %s", el)
	}
	if strings.Contains(el, "<member>web-1</member>") {
		t.Fatalf("switching to dynamic must clear static members: %s", el)
	}
}

func TestAddressGroupUpdateAPIError(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>edit rejected</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: errBody},
	)
	res, _, err := newAddressGroupUpdateHandler(d)(t.Context(), nil, AddressGroupInput{Name: "grp-1", Static: []string{"app-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a device-rejected edit must surface as IsError")
	}
	if body := textContent(t, res); !strings.Contains(body, "edit rejected") {
		t.Fatalf("error text must carry the PAN-OS message, got: %s", body)
	}
}

func TestAddressGroupDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[address_group.Location, address_group.Entry](d, "panos_address_group_delete",
		newAddressGroupService(d), addressGroupResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "grp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Delete must reach the API with the entry xpath carrying the name and default
	// vsys, proving addressGroupParts wires the location end-to-end.
	if el := multiConfigElement(t, f); !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete did not reach the API with the entry xpath: %s", el)
	}
}

func TestAddressGroupList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: addressGroupListBody})
	h := listHandler[address_group.Location, address_group.Entry](d, "panos_address_group_list",
		newAddressGroupService(d), addressGroupResolve(d), addressGroupName, addressGroupSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, `"total": 2`) || !strings.Contains(body, "grp-static") || !strings.Contains(body, "grp-dyn") {
		t.Fatalf("missing entries: %s", body)
	}
	// The summary must expose both the static members and the dynamic filter.
	if !strings.Contains(body, "web-1") {
		t.Fatalf("summary missing static members: %s", body)
	}
	if !strings.Contains(body, "'prod' and 'web'") {
		t.Fatalf("summary missing dynamic filter: %s", body)
	}
	// The summary must also surface description and tags.
	if !strings.Contains(body, "static grp") || !strings.Contains(body, "t1") {
		t.Fatalf("summary missing description or tags: %s", body)
	}

	res, _, err = h(t.Context(), nil, ListInput{Filter: "dyn"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	if body = textContent(t, res); strings.Contains(body, "grp-static") || !strings.Contains(body, "grp-dyn") {
		t.Fatalf("name filter failed: %s", body)
	}
}

// TestAddressGroupPanoramaLocations exercises the Panorama location branches of
// addressGroupParts: the shared default and an explicit device group, asserting
// the request xpath so it pins the resolved location.
func TestAddressGroupPanoramaLocations(t *testing.T) {
	t.Run("shared list", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: addressGroupListBody})
		h := listHandler[address_group.Location, address_group.Entry](d, "panos_address_group_list",
			newAddressGroupService(d), addressGroupResolve(d), addressGroupName, addressGroupSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if body := textContent(t, res); !strings.Contains(body, "grp-static") {
			t.Fatalf("shared list missing entries: %s", body)
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared") || strings.Contains(joined, "vsys") {
			t.Fatalf("shared list must target the shared xpath and not a vsys, got: %s", joined)
		}
	})

	t.Run("device group get", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody})
		h := getHandler[address_group.Location, address_group.Entry](d, "panos_address_group_get",
			newAddressGroupService(d), addressGroupResolve(d))
		res, _, err := h(t.Context(), nil, NameInput{Name: "grp-1", Location: LocationInput{DeviceGroup: "dg1"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "dg1") {
			t.Fatalf("device_group get did not target the device group xpath, got: %s", joined)
		}
	})
}

func TestRegisterAddressGroupToolsReadOnly(t *testing.T) {
	reads := []string{"panos_address_group_list", "panos_address_group_get"}
	writes := []string{"panos_address_group_create", "panos_address_group_update", "panos_address_group_delete"}

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
