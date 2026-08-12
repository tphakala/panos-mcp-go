package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/address"
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

	res, _, _ = h(t.Context(), nil, ListInput{Filter: "web"})
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
	// The request must actually reach the API with an entry xpath carrying the
	// name; a client-side xpath rejection would also produce IsError but
	// vacuously, never consulting the canned route.
	var sawGet bool
	for _, req := range f.Requests() {
		if req.Get("type") == "config" && req.Get("action") == "get" && strings.Contains(req.Get("xpath"), "nope") {
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

// registeredToolNames registers the address tools on a fresh in-memory MCP
// server/client pair and returns the set of tool names the server exposes.
func registeredToolNames(t *testing.T, d *Deps) map[string]bool {
	t.Helper()
	ctx := t.Context()
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAddressTools(srv, d)

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
