package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/objects/address"
	address_group "github.com/PaloAltoNetworks/pango/objects/address/group"
	"github.com/PaloAltoNetworks/pango/objects/admintag"
	"github.com/PaloAltoNetworks/pango/objects/service"
	service_group "github.com/PaloAltoNetworks/pango/objects/service/group"
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

// objectNotFoundBody is what PAN-OS returns for a config get on an object node
// with no entries: status success but code 7, which pango surfaces as an
// "object not found" error. The list tools must treat it as an empty list, not
// a failure (issue #47).
const objectNotFoundBody = `<response status="success" code="7"><result/></response>`

func TestAddressListEmptyObjectSetReturnsEmpty(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: objectNotFoundBody})
	h := listHandler[address.Location, address.Entry](d, "panos_address_list",
		newAddressService(d), addressResolve(d), addressName, addressSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("empty object set must not be an error result: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 0`) || !strings.Contains(body, `"count": 0`) {
		t.Fatalf("expected an empty list, got: %s", body)
	}

	// A filter over an empty set must also yield an empty list, not an error.
	res, _, err = h(t.Context(), nil, ListInput{Filter: "anything"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("filtered empty set must not be an error result: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 0`) {
		t.Fatalf("expected an empty filtered list, got: %s", body)
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
		func(in AddressInput) LocationInput { return in.Location }, buildAddressEntry, addressSummary)

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
	// pango's Create reads the object back after the set; pin that read-back
	// actually reached the API.
	assertReadBackGet(t, f)
}

func TestAddressCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[address.Location, address.Entry, AddressInput](d, "panos_address_create",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location }, buildAddressEntry, addressSummary)

	// Assert each rejection's distinct message, not merely IsError, so the name,
	// value-count and location guards cannot pass on one another's error.
	bad := []struct {
		name, wantErr string
		in            AddressInput
	}{
		{"no name", "name is required", AddressInput{IPNetmask: "10.0.0.1"}},
		{"no value", "exactly one of ip_netmask, ip_range, fqdn", AddressInput{Name: "x"}},
		{"two values", "exactly one of ip_netmask, ip_range, fqdn", AddressInput{Name: "x", IPNetmask: "10.0.0.1", FQDN: "a.example.com"}},
		{"dg on firewall", "device_group requires a Panorama connection", AddressInput{Name: "x", IPNetmask: "10.0.0.1", Location: LocationInput{DeviceGroup: "dg1"}}},
	}
	for _, c := range bad {
		res, _, err := h(t.Context(), nil, c.in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", c.name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", c.name)
		}
		if body := textContent(t, res); !strings.Contains(body, c.wantErr) {
			t.Fatalf("%s: error %q must mention %q", c.name, body, c.wantErr)
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
		newAddressService(d), addressResolve(d), addressSummary)

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
	// The request must reach the API wrapped exactly once: a raw name is rejected
	// client-side, and a double-wrap would flag a pango upgrade that started
	// wrapping names internally.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// TestAddressGetReturnsCleanSchema pins issue #48: get returns the clean summary
// shape, not the raw pango Entry. A candidate-config get carries pango-internal
// attributes (dirtyId, admin, time) on the entry element, and the raw struct
// marshals with Go PascalCase field names; neither may leak into the tool output.
func TestAddressGetReturnsCleanSchema(t *testing.T) {
	body := `<response status="success"><result>` +
		`<entry name="web-1" admin="admin" dirtyId="7" time="2026/08/17 23:58:58">` +
		`<ip-netmask>10.0.0.10/32</ip-netmask></entry></result></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: body})
	h := getHandler[address.Location, address.Entry](d, "panos_address_get",
		newAddressService(d), addressResolve(d), addressSummary)

	res, _, err := h(t.Context(), nil, NameInput{Name: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	out := textContent(t, res)
	if !strings.Contains(out, `"name": "web-1"`) || !strings.Contains(out, `"ip_netmask": "10.0.0.10/32"`) {
		t.Fatalf("get must return the clean snake_case summary, got: %s", out)
	}
	// The raw pango struct would surface these; the clean summary must not.
	for _, leak := range []string{"MiscAttributes", "dirtyId", "IpNetmask", "DisableOverride"} {
		if strings.Contains(out, leak) {
			t.Fatalf("get output leaked internal/raw field %q: %s", leak, out)
		}
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
		func(in AddressInput) string { return in.Name }, overlayAddress, addressSummary)

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
	assertContainsAll(t, multiConfigElement(t, f), "10.9.9.9/32", "vsys1", "web-1")
}

// TestAddressUpdateNoopSpecMatches pins pango's UpdateWithXpath SpecMatches
// short-circuit: an overlay that changes nothing leaves the entry byte-identical
// to the one read back, so pango issues no edit. Only a get route is registered,
// so a broken short-circuit that did fire an edit would also trip the fake's
// fail-loud on the unmatched multi-config request.
func TestAddressUpdateNoopSpecMatches(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: addressCurrentBody})
	h := updateHandler[address.Location, address.Entry, AddressInput](d, "panos_address_update",
		newAddressService(d), addressResolve(d),
		func(in AddressInput) LocationInput { return in.Location },
		func(in AddressInput) string { return in.Name }, overlayAddress, addressSummary)

	// Only the name is set, and it matches the entry read back, so the overlay
	// leaves the spec unchanged.
	res, _, err := h(t.Context(), nil, AddressInput{Name: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// An identical overlay must issue no config write at all.
	assertNoConfigWrite(t, f)
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
		func(in AddressInput) string { return in.Name }, overlayAddress, addressSummary)

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
	if el := multiConfigElement(t, f); !strings.Contains(el, "web-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete did not reach the API with the entry xpath: %s", el)
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

	bad := []struct {
		name, wantErr string
		in            AddressInput
	}{
		{"no name", "name is required", AddressInput{IPNetmask: "10.0.0.1/32"}},
		{"no value", "exactly one of ip_netmask, ip_range, fqdn", AddressInput{Name: "a"}},
		{"two values", "exactly one of ip_netmask, ip_range, fqdn", AddressInput{Name: "a", IPNetmask: "10.0.0.1/32", IPRange: "10.0.0.1-10.0.0.9"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildAddressEntry(c.in)
			if err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
			// Assert the offending field is named so distinct guards cannot
			// pass on one another's error (same-error collapse).
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %q must mention %q", c.name, err, c.wantErr)
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

// assertReadBackGet fails unless some recorded request is a config get, proving
// pango's Create issued the read-back that follows the set. Without it a create
// test asserting only the set would still pass if the SDK stopped reading the
// object back (or the get route were dropped).
func assertReadBackGet(t *testing.T, f *fakeAPI) {
	t.Helper()
	if len(getConfigXpaths(f)) == 0 {
		t.Fatal("pango Create must read the object back with a config get")
	}
}

// assertSingleWrappedGet fails unless some recorded config get carries the
// singly-wrapped entry xpath in wrapped (e.g. entry[@name='nope']) and no get is
// double-wrapped. A double-wrapped entry[@name='entry[@name=...']' still CONTAINS
// the single-wrapped substring, so a plain Contains would pass vacuously if a
// pango upgrade started wrapping names internally; the negative check flags that
// regression (see nameFixAdapter's doc comment).
func assertSingleWrappedGet(t *testing.T, f *fakeAPI, wrapped string) {
	t.Helper()
	var sawGet bool
	for _, req := range f.Requests() {
		if req.Get("type") != "config" || req.Get("action") != "get" {
			continue
		}
		xpath := req.Get("xpath")
		if strings.Contains(xpath, "entry[@name='entry[") {
			t.Fatalf("name double-wrapped: adapter and SDK both wrapped it: %s", xpath)
		}
		if strings.Contains(xpath, wrapped) {
			sawGet = true
		}
	}
	if !sawGet {
		t.Fatalf("get never reached the API wrapped as %s: the adapter must wrap the name into an entry xpath", wrapped)
	}
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
			newAddressService(d), addressResolve(d), addressSummary)
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

// registeredToolNames registers every object and rule tool set (but not the
// device or op tools) on a fresh in-memory MCP server/client pair and returns
// the set of tool names the server exposes.
func registeredToolNames(t *testing.T, d *Deps) map[string]bool {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAddressTools(srv, d)
	RegisterAddressGroupTools(srv, d)
	RegisterServiceTools(srv, d)
	RegisterServiceGroupTools(srv, d)
	RegisterTagTools(srv, d)
	RegisterSecurityRuleTools(srv, d)
	RegisterNatRuleTools(srv, d)
	RegisterDecryptionRuleTools(srv, d)
	RegisterAuthenticationRuleTools(srv, d)
	RegisterPbfRuleTools(srv, d)
	return serverToolNames(t, srv)
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
	bad := []struct {
		name, wantErr string
		in            AddressGroupInput
	}{
		{"no name", "name is required", AddressGroupInput{Static: []string{"web-1"}}},
		{"neither", "exactly one of static, dynamic_filter", AddressGroupInput{Name: "g"}},
		// An empty static list counts as absent on create, so the XOR rejects it.
		{"empty static", "exactly one of static, dynamic_filter", AddressGroupInput{Name: "g", Static: []string{}}},
		{"both", "exactly one of static, dynamic_filter", AddressGroupInput{Name: "g", Static: []string{"web-1"}, DynamicFilter: "'prod'"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildAddressGroupEntry(c.in)
			if err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
			// Assert the offending field is named so distinct guards cannot
			// pass on one another's error (same-error collapse).
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %q must mention %q", c.name, err, c.wantErr)
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
	t.Run("empty static list is rejected", func(t *testing.T) {
		// A static group cannot be emptied in place, so an explicitly empty
		// static list is a client-side error rather than a silent no-op that
		// would report success while leaving the members untouched.
		e := &address_group.Entry{Name: "g", Static: []string{"web-1"}}
		err := overlayAddressGroup(e, AddressGroupInput{Static: []string{}})
		if err == nil {
			t.Fatal("an explicitly empty static list must be rejected")
		}
		if !strings.Contains(err.Error(), "cannot be emptied in place") {
			t.Fatalf("error must explain the empty-static rejection, got: %v", err)
		}
		// A rejected overlay must not have mutated the entry.
		if len(e.Static) != 1 || e.Static[0] != "web-1" {
			t.Fatalf("a rejected overlay must leave the members untouched, got: %v", e.Static)
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
		func(in AddressGroupInput) LocationInput { return in.Location }, buildAddressGroupEntry, addressGroupSummary)

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
	// pango's Create reads the object back after the set; pin that read-back
	// actually reached the API.
	assertReadBackGet(t, f)
}

func TestAddressGroupCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[address_group.Location, address_group.Entry, AddressGroupInput](d, "panos_address_group_create",
		newAddressGroupService(d), addressGroupResolve(d),
		func(in AddressGroupInput) LocationInput { return in.Location }, buildAddressGroupEntry, addressGroupSummary)

	// Assert each rejection's distinct message, not merely IsError, so the name,
	// XOR and location guards cannot pass on one another's error.
	bad := []struct {
		name, wantErr string
		in            AddressGroupInput
	}{
		{"no name", "name is required", AddressGroupInput{Static: []string{"web-1"}}},
		{"neither", "exactly one of static, dynamic_filter", AddressGroupInput{Name: "g"}},
		{"both", "exactly one of static, dynamic_filter", AddressGroupInput{Name: "g", Static: []string{"web-1"}, DynamicFilter: "'prod'"}},
		{"dg on firewall", "device_group requires a Panorama connection", AddressGroupInput{Name: "g", Static: []string{"web-1"}, Location: LocationInput{DeviceGroup: "dg1"}}},
	}
	for _, c := range bad {
		res, _, err := h(t.Context(), nil, c.in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", c.name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", c.name)
		}
		if body := textContent(t, res); !strings.Contains(body, c.wantErr) {
			t.Fatalf("%s: error %q must mention %q", c.name, body, c.wantErr)
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
		newAddressGroupService(d), addressGroupResolve(d), addressGroupSummary)

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
	// Pin that the shared adapter wraps the name into an entry xpath exactly once
	// for the group instantiation too; a raw-name rejection or a double-wrap would
	// both be caught here.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
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
		func(in AddressGroupInput) string { return in.Name }, overlayAddressGroup, addressGroupSummary)
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

// TestAddressGroupUpdateNoopSpecMatches mirrors TestAddressUpdateNoopSpecMatches
// for the address group resource: an overlay that changes nothing leaves the
// entry byte-identical to the one read back, so pango's UpdateWithXpath
// short-circuits on SpecMatches and issues no edit. Only a get route is
// registered, so an edit that did fire would trip the fake's fail-loud on the
// unmatched multi-config.
func TestAddressGroupUpdateNoopSpecMatches(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody})
	// Only the name is set, and it matches the entry read back, so the overlay
	// leaves the spec unchanged.
	res, _, err := newAddressGroupUpdateHandler(d)(t.Context(), nil, AddressGroupInput{Name: "grp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// An identical overlay must issue no config write at all.
	assertNoConfigWrite(t, f)
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
			newAddressGroupService(d), addressGroupResolve(d), addressGroupSummary)
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

// TestAddressGroupGetUpdateViaRegisteredTools drives panos_address_group_get
// and panos_address_group_update through a registered MCP server over the
// in-memory transport. It is the proof of the adapter wiring: the raw pango
// service also satisfies crudService, so wiring address_group.NewService
// directly would COMPILE and only fail here, where the calls must actually
// reach the fake API. A raw-name wiring is rejected client-side and records no
// request.
func TestAddressGroupGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: addressGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterAddressGroupTools(srv, d)

	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_address_group_get", Arguments: map[string]any{"name": "grp-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and target
	// the address-group endpoint; a raw-service wiring (which also satisfies
	// crudService) would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='grp-1']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "address-group") {
		t.Fatalf("registered get did not target the address-group endpoint: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_address_group_update", Arguments: map[string]any{"name": "grp-1", "static": []string{"app-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "app-1") || !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("registered update did not reach the API with the new member: %s", el)
	}
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

// serviceListBody lists a tcp service with a source port, description and tag,
// and a bare udp service. Ports marshal as <protocol><tcp|udp><port>; a source
// port as <source-port>. The list xpath ends at .../service/entry, so there is
// no <service> wrapper element in the response.
const serviceListBody = `<response status="success"><result>` +
	`<entry name="web-8080"><protocol><tcp><port>8080</port><source-port>1024-65535</source-port></tcp></protocol><description>web svc</description><tag><member>prod</member></tag></entry>` +
	`<entry name="dns-u"><protocol><udp><port>53</port></udp></protocol></entry>` +
	`</result></response>`

// serviceCreatedBody answers the read-back get pango's Create issues after the
// set; the read-back requires exactly one entry.
const serviceCreatedBody = `<response status="success"><result><entry name="web-8080">` +
	`<protocol><tcp><port>8080</port></tcp></protocol><tag><member>prod</member></tag></entry></result></response>`

// serviceCurrentBody is the entry as it exists before an update: tcp/8080 with a
// description. Every update input below must differ from it, or pango's
// UpdateWithXpath short-circuits on SpecMatches and issues no multi-config
// request, making the edit assertions vacuous.
const serviceCurrentBody = `<response status="success"><result><entry name="svc-1">` +
	`<protocol><tcp><port>8080</port></tcp></protocol><description>old desc</description></entry></result></response>`

func serviceResolve(d *Deps) func(LocationInput) (service.Location, error) {
	return func(in LocationInput) (service.Location, error) {
		return resolveLocation(d, in, serviceParts())
	}
}

func serviceName(e *service.Entry) string { return e.Name }

// TestBuildServiceEntry pins that a create entry is built from tcp or udp with a
// required destination port, that source_port, description and tags map onto the
// entry, and that a missing name, missing port, or unknown protocol is rejected.
func TestBuildServiceEntry(t *testing.T) {
	t.Run("tcp with source port", func(t *testing.T) {
		e, err := buildServiceEntry(ServiceInput{Name: "s", Protocol: "tcp", Port: "8080", SourcePort: "1024"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Protocol == nil || e.Protocol.Tcp == nil || e.Protocol.Udp != nil {
			t.Fatalf("tcp build wrong: %+v", e.Protocol)
		}
		if strVal(e.Protocol.Tcp.Port) != "8080" || strVal(e.Protocol.Tcp.SourcePort) != "1024" {
			t.Fatalf("tcp port/source wrong: %+v", e.Protocol.Tcp)
		}
	})
	t.Run("udp with description and tags", func(t *testing.T) {
		e, err := buildServiceEntry(ServiceInput{Name: "s", Protocol: "udp", Port: "53", Description: "d", Tags: []string{"t"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.Protocol == nil || e.Protocol.Udp == nil || e.Protocol.Tcp != nil || strVal(e.Protocol.Udp.Port) != "53" {
			t.Fatalf("udp build wrong: %+v", e.Protocol)
		}
		if strVal(e.Description) != "d" || len(e.Tag) != 1 {
			t.Fatalf("udp build lost description or tags: desc=%v tags=%v", e.Description, e.Tag)
		}
	})
}

// TestBuildServiceEntryRejects pins that a create entry requires a name, a port,
// and a known protocol.
func TestBuildServiceEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            ServiceInput
	}{
		{"no name", "name is required", ServiceInput{Protocol: "tcp", Port: "80"}},
		{"no port", "port is required", ServiceInput{Name: "s", Protocol: "tcp"}},
		{"bad protocol", `protocol must be "tcp" or "udp"`, ServiceInput{Name: "s", Protocol: "icmp", Port: "1"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildServiceEntry(c.in)
			if err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
			// Assert the offending field is named so distinct guards cannot
			// pass on one another's error (same-error collapse).
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %q must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

// TestOverlayServiceProtocol pins that touching the protocol side replaces the
// whole block: switching tcp to udp clears the tcp side, an omitted source_port
// clears a pre-existing one, and providing only one of protocol/port is rejected.
func TestOverlayServiceProtocol(t *testing.T) {
	t.Run("switch tcp to udp clears tcp", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("8080")}}}
		if err := overlayService(e, ServiceInput{Protocol: "udp", Port: "53"}); err != nil {
			t.Fatal(err)
		}
		if e.Protocol.Udp == nil || strVal(e.Protocol.Udp.Port) != "53" || e.Protocol.Tcp != nil {
			t.Fatalf("switch wrong: %+v", e.Protocol)
		}
	})
	t.Run("replacing tcp clears a pre-existing source port", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("8080"), SourcePort: ptr("1024")}}}
		if err := overlayService(e, ServiceInput{Protocol: "tcp", Port: "9090"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Protocol.Tcp.Port) != "9090" || e.Protocol.Tcp.SourcePort != nil {
			t.Fatalf("block replacement must drop the old source port: %+v", e.Protocol.Tcp)
		}
	})
	bad := map[string]ServiceInput{
		"port only":        {Port: "9090"},
		"protocol only":    {Protocol: "tcp"},
		"source port only": {SourcePort: "1024"},
		// protocol and port both set, but the protocol is unknown: this passes the
		// requires-both guard and must surface buildServiceProtocol's rejection.
		"invalid protocol": {Protocol: "icmp", Port: "80"},
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("8080")}}}
			if err := overlayService(e, in); err == nil {
				t.Fatalf("%s: changing ports requires protocol and port together", name)
			}
		})
	}
}

// TestOverlayServicePreservesOverride pins that a same-protocol port change
// carries the existing timeout override (a field this tool does not expose, so a
// rebuild would otherwise destroy it), while a protocol-type switch drops it with
// the old side.
func TestOverlayServicePreservesOverride(t *testing.T) {
	t.Run("same protocol keeps override", func(t *testing.T) {
		ov := &service.ProtocolTcpOverride{}
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("8080"), Override: ov}}}
		if err := overlayService(e, ServiceInput{Protocol: "tcp", Port: "9090"}); err != nil {
			t.Fatal(err)
		}
		if e.Protocol.Tcp == nil || e.Protocol.Tcp.Override != ov {
			t.Fatalf("same-protocol port change must preserve the timeout override: %+v", e.Protocol.Tcp)
		}
		if strVal(e.Protocol.Tcp.Port) != "9090" {
			t.Fatalf("port not updated: %+v", e.Protocol.Tcp)
		}
	})
	t.Run("protocol switch drops the old override", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("8080"), Override: &service.ProtocolTcpOverride{}}}}
		if err := overlayService(e, ServiceInput{Protocol: "udp", Port: "53"}); err != nil {
			t.Fatal(err)
		}
		if e.Protocol.Udp == nil || e.Protocol.Tcp != nil {
			t.Fatalf("switch must move to udp and clear tcp: %+v", e.Protocol)
		}
		if e.Protocol.Udp.Override != nil {
			t.Fatalf("protocol switch must not carry the tcp override onto udp: %+v", e.Protocol.Udp)
		}
	})
}

// TestOverlayServiceUDPKeepsOverride mirrors the tcp override-preservation case
// for the udp branch of carryServiceOverride, and also exercises the udp
// source_port build path. Pointer identity proves the override survived the
// block rebuild.
func TestOverlayServiceUDPKeepsOverride(t *testing.T) {
	ov := &service.ProtocolUdpOverride{}
	e := &service.Entry{Name: "s", Protocol: &service.Protocol{Udp: &service.ProtocolUdp{Port: ptr("53"), Override: ov}}}
	if err := overlayService(e, ServiceInput{Protocol: "udp", Port: "5353", SourcePort: "1024"}); err != nil {
		t.Fatal(err)
	}
	if e.Protocol.Udp == nil || e.Protocol.Udp.Override != ov {
		t.Fatalf("udp same-protocol change must preserve the timeout override: %+v", e.Protocol.Udp)
	}
	if strVal(e.Protocol.Udp.Port) != "5353" || strVal(e.Protocol.Udp.SourcePort) != "1024" {
		t.Fatalf("udp port/source_port not applied: %+v", e.Protocol.Udp)
	}
}

// TestOverlayServiceNilProtocol pins that overlaying protocol fields onto an entry
// with no existing protocol block builds the block without panicking (the update
// path always reads a block back, so this is the defensive carryServiceOverride
// nil-src path).
func TestOverlayServiceNilProtocol(t *testing.T) {
	e := &service.Entry{Name: "s"}
	if err := overlayService(e, ServiceInput{Protocol: "tcp", Port: "80"}); err != nil {
		t.Fatal(err)
	}
	if e.Protocol == nil || e.Protocol.Tcp == nil || strVal(e.Protocol.Tcp.Port) != "80" {
		t.Fatalf("overlay on a nil-protocol entry must build the block: %+v", e.Protocol)
	}
}

// TestOverlayServiceFields pins the non-protocol overlay semantics: a provided
// description updates, an omitted description or nil tags leave the existing
// values unchanged, and a non-nil empty tags slice clears the tags.
func TestOverlayServiceFields(t *testing.T) {
	t.Run("description updates when provided", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("80")}}, Description: ptr("old")}
		if err := overlayService(e, ServiceInput{Description: "new"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Description) != "new" {
			t.Fatalf("description not updated: %v", e.Description)
		}
	})
	t.Run("omitted fields unchanged", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("80")}}, Description: ptr("old"), Tag: []string{"a"}}
		if err := overlayService(e, ServiceInput{}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Description) != "old" || len(e.Tag) != 1 || e.Protocol.Tcp == nil {
			t.Fatalf("empty overlay changed entry: desc=%v tags=%v proto=%+v", e.Description, e.Tag, e.Protocol)
		}
	})
	t.Run("tags replace when non-nil and clear when empty", func(t *testing.T) {
		e := &service.Entry{Name: "s", Protocol: &service.Protocol{Tcp: &service.ProtocolTcp{Port: ptr("80")}}, Tag: []string{"a"}}
		if err := overlayService(e, ServiceInput{Tags: []string{"b", "c"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 2 {
			t.Fatalf("tags not replaced: %v", e.Tag)
		}
		if err := overlayService(e, ServiceInput{Tags: []string{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 0 {
			t.Fatalf("empty tags slice must clear tags: %v", e.Tag)
		}
	})
}

func TestServiceCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the object back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: serviceCreatedBody},
	)
	h := createHandler[service.Location, service.Entry, ServiceInput](d, "panos_service_create",
		newServiceService(d), serviceResolve(d),
		func(in ServiceInput) LocationInput { return in.Location }, buildServiceEntry, serviceSummary)

	res, _, err := h(t.Context(), nil, ServiceInput{Name: "web-8080", Protocol: "tcp", Port: "8080", Description: "web svc", Tags: []string{"prod"}})
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
			if !strings.Contains(el, `name="web-8080"`) || !strings.Contains(el, "<tcp>") ||
				!strings.Contains(el, "<port>8080</port>") || !strings.Contains(el, "<member>prod</member>") ||
				!strings.Contains(el, "web svc") {
				t.Fatalf("element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "service") {
				t.Fatalf("xpath missing default vsys or service endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
	// pango's Create reads the object back after the set; pin that read-back
	// actually reached the API.
	assertReadBackGet(t, f)
}

func TestServiceCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[service.Location, service.Entry, ServiceInput](d, "panos_service_create",
		newServiceService(d), serviceResolve(d),
		func(in ServiceInput) LocationInput { return in.Location }, buildServiceEntry, serviceSummary)

	// Assert each rejection's distinct message, not merely IsError, so the name,
	// port, protocol and location guards cannot pass on one another's error.
	bad := []struct {
		name, wantErr string
		in            ServiceInput
	}{
		{"no name", "name is required", ServiceInput{Protocol: "tcp", Port: "80"}},
		{"no port", "port is required", ServiceInput{Name: "x", Protocol: "tcp"}},
		{"bad protocol", `protocol must be "tcp" or "udp"`, ServiceInput{Name: "x", Protocol: "icmp", Port: "1"}},
		{"dg on firewall", "device_group requires a Panorama connection", ServiceInput{Name: "x", Protocol: "tcp", Port: "80", Location: LocationInput{DeviceGroup: "dg1"}}},
	}
	for _, c := range bad {
		res, _, err := h(t.Context(), nil, c.in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", c.name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", c.name)
		}
		if body := textContent(t, res); !strings.Contains(body, c.wantErr) {
			t.Fatalf("%s: error %q must mention %q", c.name, body, c.wantErr)
		}
	}
	// Validation must reject before any API call: only the bootstrap system-info
	// request may exist.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestServiceAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[service.Location, service.Entry](d, "panos_service_get",
		newServiceService(d), serviceResolve(d), serviceSummary)

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
	// Pin that the shared adapter wraps the name into an entry xpath exactly once
	// for the service instantiation too; a raw-name rejection or a double-wrap
	// would both be caught here.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// newServiceUpdateHandler builds the update handler used by the update tests,
// keeping their setup to one line.
func newServiceUpdateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ServiceInput) (*mcp.CallToolResult, any, error) {
	return updateHandler[service.Location, service.Entry, ServiceInput](d, "panos_service_update",
		newServiceService(d), serviceResolve(d),
		func(in ServiceInput) LocationInput { return in.Location },
		func(in ServiceInput) string { return in.Name }, overlayService, serviceSummary)
}

func TestServiceUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	// Switch tcp/8080 to udp/53; the input differs from the current entry, so
	// SpecMatches cannot short-circuit, and the protocol switch proves the block
	// replacement clears the tcp side end-to-end.
	res, _, err := newServiceUpdateHandler(d)(t.Context(), nil, ServiceInput{Name: "svc-1", Protocol: "udp", Port: "53"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<udp>") || !strings.Contains(el, "<port>53</port>") {
		t.Fatalf("edit element missing new udp port: %s", el)
	}
	if strings.Contains(el, "<tcp>") || strings.Contains(el, "8080") {
		t.Fatalf("switching protocol must clear the tcp side: %s", el)
	}
	if !strings.Contains(el, "old desc") {
		t.Fatalf("read-modify-write must preserve the untouched description: %s", el)
	}
	if !strings.Contains(el, "svc-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing entry xpath: %s", el)
	}
}

func TestServiceUpdateRequiresProtocolAndPort(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	for name, in := range map[string]ServiceInput{
		"port only":        {Name: "svc-1", Port: "9090"},
		"protocol only":    {Name: "svc-1", Protocol: "tcp"},
		"source port only": {Name: "svc-1", SourcePort: "1024"},
	} {
		res, _, err := newServiceUpdateHandler(d)(t.Context(), nil, in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: changing ports requires protocol and port together", name)
		}
		// Assert the guard's own message, not merely IsError: buildServiceProtocol
		// would also reject each of these inputs ("port is required" / "protocol
		// must be ..."), so without this the test passes even when the overlay
		// requires-both guard is deleted. The guard fires first and gives the
		// clearer message, and this pins it.
		if body := textContent(t, res); !strings.Contains(body, "protocol and port") {
			t.Fatalf("%s: error must name the requires-both guard, got: %s", name, body)
		}
	}
	// A rejected overlay must never edit the device.
	for _, req := range f.Requests() {
		if req.Get("action") == "multi-config" {
			t.Fatal("rejected update must not issue a multi-config edit")
		}
	}
}

// TestServiceUpdateNoopSpecMatches mirrors TestAddressUpdateNoopSpecMatches for
// the service resource: an overlay that changes nothing leaves the entry
// byte-identical to the one read back, so pango's UpdateWithXpath short-circuits
// on SpecMatches and issues no edit. Only a get route is registered, so an edit
// that did fire would trip the fake's fail-loud on the unmatched multi-config.
func TestServiceUpdateNoopSpecMatches(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: serviceCurrentBody})
	// Only the name is set, and it matches the entry read back, so the overlay
	// leaves the spec unchanged.
	res, _, err := newServiceUpdateHandler(d)(t.Context(), nil, ServiceInput{Name: "svc-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// An identical overlay must issue no config write at all.
	assertNoConfigWrite(t, f)
}

func TestServiceUpdateAPIError(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>edit rejected</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: errBody},
	)
	res, _, err := newServiceUpdateHandler(d)(t.Context(), nil, ServiceInput{Name: "svc-1", Protocol: "udp", Port: "53"})
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

func TestServiceUpdateRejectsRename(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	svc := newServiceService(d)
	// The guard fires before the location is used, so a zero Location is fine.
	if _, err := svc.Update(t.Context(), service.Location{}, &service.Entry{Name: "svc-1"}, "svc-2"); err == nil {
		t.Fatal("Update must reject a name that differs from entry.Name (rename)")
	} else if !strings.Contains(err.Error(), "renaming") {
		t.Fatalf("expected a rename-not-supported error, got: %v", err)
	}
}

func TestServiceDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[service.Location, service.Entry](d, "panos_service_delete",
		newServiceService(d), serviceResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "svc-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Delete must reach the API with the entry xpath carrying the name and default
	// vsys, proving serviceParts wires the location end-to-end.
	if el := multiConfigElement(t, f); !strings.Contains(el, "svc-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete did not reach the API with the entry xpath: %s", el)
	}
}

// assertContainsAll fails the test if body is missing any of subs. Collapsing a
// row of substring checks into one call keeps the calling test's cyclomatic
// complexity down.
func assertContainsAll(t *testing.T, body string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(body, s) {
			t.Fatalf("missing %q in: %s", s, body)
		}
	}
}

func TestServiceList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: serviceListBody})
	h := listHandler[service.Location, service.Entry](d, "panos_service_list",
		newServiceService(d), serviceResolve(d), serviceName, serviceSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	// Both entries appear, and the summary surfaces protocol, port and source_port
	// for the tcp entry, the udp side, and the description and tags.
	assertContainsAll(t, textContent(t, res),
		`"total": 2`, "web-8080", "dns-u",
		`"protocol": "tcp"`, `"port": "8080"`, `"source_port": "1024-65535"`,
		`"protocol": "udp"`, `"port": "53"`, "web svc", "prod")

	res, _, err = h(t.Context(), nil, ListInput{Filter: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	if body := textContent(t, res); strings.Contains(body, "web-8080") || !strings.Contains(body, "dns-u") {
		t.Fatalf("name filter failed: %s", body)
	}
}

// TestServicePanoramaLocations exercises the Panorama location branches of
// serviceParts: the shared default and an explicit device group, asserting the
// request xpath so it pins the resolved location.
func TestServicePanoramaLocations(t *testing.T) {
	t.Run("shared list", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: serviceListBody})
		h := listHandler[service.Location, service.Entry](d, "panos_service_list",
			newServiceService(d), serviceResolve(d), serviceName, serviceSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if body := textContent(t, res); !strings.Contains(body, "web-8080") {
			t.Fatalf("shared list missing entries: %s", body)
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared") || strings.Contains(joined, "vsys") {
			t.Fatalf("shared list must target the shared xpath and not a vsys, got: %s", joined)
		}
	})

	t.Run("device group get", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: serviceCurrentBody})
		h := getHandler[service.Location, service.Entry](d, "panos_service_get",
			newServiceService(d), serviceResolve(d), serviceSummary)
		res, _, err := h(t.Context(), nil, NameInput{Name: "svc-1", Location: LocationInput{DeviceGroup: "dg1"}})
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

// TestServiceGetUpdateViaRegisteredTools drives panos_service_get and
// panos_service_update through a registered MCP server over the in-memory
// transport. It is the proof of the adapter wiring: the raw pango service also
// satisfies crudService, so wiring service.NewService directly would COMPILE and
// only fail here, where the calls must actually reach the fake API. A raw-name
// wiring is rejected client-side and records no request.
func TestServiceGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterServiceTools(srv, d)

	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_service_get", Arguments: map[string]any{"name": "svc-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and target
	// the service endpoint; a raw-service wiring (which also satisfies crudService)
	// would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='svc-1']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "service") {
		t.Fatalf("registered get did not target the service endpoint: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_service_update", Arguments: map[string]any{"name": "svc-1", "protocol": "tcp", "port": "9090"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "9090") || !strings.Contains(el, "svc-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("registered update did not reach the API with the new port: %s", el)
	}
}

func TestRegisterServiceToolsReadOnly(t *testing.T) {
	reads := []string{"panos_service_list", "panos_service_get"}
	writes := []string{"panos_service_create", "panos_service_update", "panos_service_delete"}

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

// TestBuildServiceGroupEntry pins that a create entry carries the name, members
// and tags.
func TestBuildServiceGroupEntry(t *testing.T) {
	e, err := buildServiceGroupEntry(ServiceGroupInput{Name: "g", Members: []string{"a", "b"}, Tags: []string{"t"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "g" || len(e.Members) != 2 || e.Members[0] != "a" || len(e.Tag) != 1 {
		t.Fatalf("entry built wrong: %+v", e)
	}
}

// TestBuildServiceGroupEntryRejects pins that a create entry requires a name
// and at least one member.
func TestBuildServiceGroupEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            ServiceGroupInput
	}{
		{"no name", "name is required", ServiceGroupInput{Members: []string{"a"}}},
		{"no members", "at least one member is required", ServiceGroupInput{Name: "g"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildServiceGroupEntry(c.in)
			if err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
			// Assert the offending field is named so distinct guards cannot
			// pass on one another's error (same-error collapse).
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %q must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

// TestOverlayServiceGroupFields pins the overlay semantics: a non-empty members
// list replaces the membership, an explicitly empty one is rejected (a group
// cannot be emptied in place), a nil tags slice leaves tags unchanged, and a
// non-nil empty tags slice clears them.
//
//nolint:gocognit // exhaustive independent subtests for the overlay membership and tags semantics; each t.Run is one scenario.
func TestOverlayServiceGroupFields(t *testing.T) {
	t.Run("members replace when non-empty", func(t *testing.T) {
		e := &service_group.Entry{Name: "g", Members: []string{"a"}}
		if err := overlayServiceGroup(e, ServiceGroupInput{Members: []string{"b", "c"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Members) != 2 || e.Members[0] != "b" {
			t.Fatalf("members not replaced: %v", e.Members)
		}
	})
	t.Run("explicitly empty members list is rejected", func(t *testing.T) {
		// A service group cannot be emptied in place, so an explicit [] is a
		// client-side error, not a silent no-op that reports success.
		e := &service_group.Entry{Name: "g", Members: []string{"a"}}
		err := overlayServiceGroup(e, ServiceGroupInput{Members: []string{}})
		if err == nil {
			t.Fatal("an explicitly empty members list must be rejected")
		}
		if !strings.Contains(err.Error(), "cannot be emptied in place") {
			t.Fatalf("error must explain the empty-members rejection, got: %v", err)
		}
		// A rejected overlay must not have mutated the entry.
		if len(e.Members) != 1 || e.Members[0] != "a" {
			t.Fatalf("a rejected overlay must leave the members untouched, got: %v", e.Members)
		}
	})
	t.Run("empty overlay leaves entry unchanged", func(t *testing.T) {
		e := &service_group.Entry{Name: "g", Members: []string{"a"}, Tag: []string{"t"}}
		if err := overlayServiceGroup(e, ServiceGroupInput{}); err != nil {
			t.Fatal(err)
		}
		if len(e.Members) != 1 || len(e.Tag) != 1 {
			t.Fatalf("empty overlay changed entry: members=%v tags=%v", e.Members, e.Tag)
		}
	})
	t.Run("tags replace when non-nil and clear when empty", func(t *testing.T) {
		e := &service_group.Entry{Name: "g", Members: []string{"a"}, Tag: []string{"t"}}
		if err := overlayServiceGroup(e, ServiceGroupInput{Tags: []string{"x", "y"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 2 {
			t.Fatalf("tags not replaced: %v", e.Tag)
		}
		if err := overlayServiceGroup(e, ServiceGroupInput{Tags: []string{}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Tag) != 0 {
			t.Fatalf("empty tags slice must clear tags: %v", e.Tag)
		}
	})
}

// serviceGroupListBody lists a group with members and a tag, and a bare group.
// Members marshal as <members><member>. The list xpath ends at
// .../service-group/entry, so there is no wrapper element in the response.
const serviceGroupListBody = `<response status="success"><result>` +
	`<entry name="grp-web"><members><member>web-8080</member><member>web-8443</member></members><tag><member>prod</member></tag></entry>` +
	`<entry name="grp-dns"><members><member>dns-u</member></members></entry>` +
	`</result></response>`

// serviceGroupCreatedBody answers the read-back get pango's Create issues after
// the set; the read-back requires exactly one entry.
const serviceGroupCreatedBody = `<response status="success"><result><entry name="grp-web">` +
	`<members><member>web-8080</member></members><tag><member>prod</member></tag></entry></result></response>`

// serviceGroupCurrentBody is the entry as it exists before an update: one
// member and one tag. Every update input below must differ from it, or pango's
// UpdateWithXpath short-circuits on SpecMatches and issues no multi-config
// request, making the edit assertions vacuous.
const serviceGroupCurrentBody = `<response status="success"><result><entry name="grp-1">` +
	`<members><member>web-8080</member></members><tag><member>prod</member></tag></entry></result></response>`

func serviceGroupResolve(d *Deps) func(LocationInput) (service_group.Location, error) {
	return func(in LocationInput) (service_group.Location, error) {
		return resolveLocation(d, in, serviceGroupParts())
	}
}

func serviceGroupName(e *service_group.Entry) string { return e.Name }

func TestServiceGroupCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the object back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: serviceGroupCreatedBody},
	)
	h := createHandler[service_group.Location, service_group.Entry, ServiceGroupInput](d, "panos_service_group_create",
		newServiceGroupService(d), serviceGroupResolve(d),
		func(in ServiceGroupInput) LocationInput { return in.Location }, buildServiceGroupEntry, serviceGroupSummary)

	res, _, err := h(t.Context(), nil, ServiceGroupInput{Name: "grp-web", Members: []string{"web-8080"}, Tags: []string{"prod"}})
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
			if !strings.Contains(el, `name="grp-web"`) || !strings.Contains(el, "<members>") ||
				!strings.Contains(el, "<member>web-8080</member>") || !strings.Contains(el, "<member>prod</member>") {
				t.Fatalf("element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "service-group") {
				t.Fatalf("xpath missing default vsys or service-group endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
	// pango's Create reads the object back after the set; pin that read-back
	// actually reached the API.
	assertReadBackGet(t, f)
}

func TestServiceGroupCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[service_group.Location, service_group.Entry, ServiceGroupInput](d, "panos_service_group_create",
		newServiceGroupService(d), serviceGroupResolve(d),
		func(in ServiceGroupInput) LocationInput { return in.Location }, buildServiceGroupEntry, serviceGroupSummary)

	// Assert each rejection's distinct message, not merely IsError, so the name,
	// members and location guards cannot pass on one another's error.
	bad := []struct {
		name, wantErr string
		in            ServiceGroupInput
	}{
		{"no name", "name is required", ServiceGroupInput{Members: []string{"web-8080"}}},
		{"no members", "at least one member is required", ServiceGroupInput{Name: "g"}},
		{"dg on firewall", "device_group requires a Panorama connection", ServiceGroupInput{Name: "g", Members: []string{"web-8080"}, Location: LocationInput{DeviceGroup: "dg1"}}},
	}
	for _, c := range bad {
		res, _, err := h(t.Context(), nil, c.in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", c.name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", c.name)
		}
		if body := textContent(t, res); !strings.Contains(body, c.wantErr) {
			t.Fatalf("%s: error %q must mention %q", c.name, body, c.wantErr)
		}
	}
	// Validation must reject before any API call: only the bootstrap system-info
	// request may exist.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestServiceGroupAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[service_group.Location, service_group.Entry](d, "panos_service_group_get",
		newServiceGroupService(d), serviceGroupResolve(d), serviceGroupSummary)

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
	// Pin that the shared adapter wraps the name into an entry xpath exactly
	// once for the service group instantiation too; a raw-name rejection or a
	// double-wrap would both be caught here.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// newServiceGroupUpdateHandler builds the update handler used by the update
// tests, keeping their setup to one line.
func newServiceGroupUpdateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ServiceGroupInput) (*mcp.CallToolResult, any, error) {
	return updateHandler[service_group.Location, service_group.Entry, ServiceGroupInput](d, "panos_service_group_update",
		newServiceGroupService(d), serviceGroupResolve(d),
		func(in ServiceGroupInput) LocationInput { return in.Location },
		func(in ServiceGroupInput) string { return in.Name }, overlayServiceGroup, serviceGroupSummary)
}

func TestServiceGroupUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	// Replace the single member; the input differs from the current entry, so
	// SpecMatches cannot short-circuit.
	res, _, err := newServiceGroupUpdateHandler(d)(t.Context(), nil, ServiceGroupInput{Name: "grp-1", Members: []string{"db-5432"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<member>db-5432</member>") {
		t.Fatalf("edit element missing new member: %s", el)
	}
	if strings.Contains(el, "web-8080") {
		t.Fatalf("members must replace, not merge: %s", el)
	}
	if !strings.Contains(el, "prod") {
		t.Fatalf("read-modify-write must preserve the untouched tags: %s", el)
	}
	if !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing entry xpath: %s", el)
	}
}

// TestServiceGroupUpdateNoopSpecMatches mirrors TestAddressUpdateNoopSpecMatches
// for the service group resource: an overlay that changes nothing leaves the
// entry byte-identical to the one read back, so pango's UpdateWithXpath
// short-circuits on SpecMatches and issues no edit. Only a get route is
// registered, so an edit that did fire would trip the fake's fail-loud on the
// unmatched multi-config.
func TestServiceGroupUpdateNoopSpecMatches(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: serviceGroupCurrentBody})
	// Only the name is set, and it matches the entry read back, so the overlay
	// leaves the spec unchanged.
	res, _, err := newServiceGroupUpdateHandler(d)(t.Context(), nil, ServiceGroupInput{Name: "grp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// An identical overlay must issue no config write at all.
	assertNoConfigWrite(t, f)
}

func TestServiceGroupUpdateAPIError(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>edit rejected</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: errBody},
	)
	res, _, err := newServiceGroupUpdateHandler(d)(t.Context(), nil, ServiceGroupInput{Name: "grp-1", Members: []string{"db-5432"}})
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

func TestServiceGroupDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[service_group.Location, service_group.Entry](d, "panos_service_group_delete",
		newServiceGroupService(d), serviceGroupResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "grp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Delete must reach the API with the entry xpath carrying the name and
	// default vsys, proving serviceGroupParts wires the location end-to-end.
	if el := multiConfigElement(t, f); !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete did not reach the API with the entry xpath: %s", el)
	}
}

func TestServiceGroupList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: serviceGroupListBody})
	h := listHandler[service_group.Location, service_group.Entry](d, "panos_service_group_list",
		newServiceGroupService(d), serviceGroupResolve(d), serviceGroupName, serviceGroupSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	body := textContent(t, res)
	// Both entries appear, and the summary surfaces members and tags.
	assertContainsAll(t, body,
		`"total": 2`, "grp-web", "grp-dns",
		`"members"`, "web-8080", "web-8443", "dns-u", "prod")
	// Service groups have no description; the summary must not emit a bogus
	// empty description field.
	if strings.Contains(body, `"description"`) {
		t.Fatalf("service group summary must not contain a description field: %s", body)
	}

	res, _, err = h(t.Context(), nil, ListInput{Filter: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	if body := textContent(t, res); strings.Contains(body, "grp-web") || !strings.Contains(body, "grp-dns") {
		t.Fatalf("name filter failed: %s", body)
	}
}

// TestServiceGroupPanoramaLocations exercises the Panorama location branches of
// serviceGroupParts: the shared default and an explicit device group, asserting
// the request xpath so it pins the resolved location.
func TestServiceGroupPanoramaLocations(t *testing.T) {
	t.Run("shared list", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: serviceGroupListBody})
		h := listHandler[service_group.Location, service_group.Entry](d, "panos_service_group_list",
			newServiceGroupService(d), serviceGroupResolve(d), serviceGroupName, serviceGroupSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if body := textContent(t, res); !strings.Contains(body, "grp-web") {
			t.Fatalf("shared list missing entries: %s", body)
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared") || strings.Contains(joined, "vsys") {
			t.Fatalf("shared list must target the shared xpath and not a vsys, got: %s", joined)
		}
	})

	t.Run("device group get", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: serviceGroupCurrentBody})
		h := getHandler[service_group.Location, service_group.Entry](d, "panos_service_group_get",
			newServiceGroupService(d), serviceGroupResolve(d), serviceGroupSummary)
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

// TestServiceGroupGetUpdateViaRegisteredTools drives panos_service_group_get
// and panos_service_group_update through a registered MCP server over the
// in-memory transport. It is the proof of the adapter wiring: the raw pango
// service also satisfies crudService, so wiring service_group.NewService
// directly would COMPILE and only fail here, where the calls must actually
// reach the fake API. A raw-name wiring is rejected client-side and records no
// request.
func TestServiceGroupGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: serviceGroupCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterServiceGroupTools(srv, d)

	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_service_group_get", Arguments: map[string]any{"name": "grp-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and
	// target the service-group endpoint; a raw-service wiring (which also
	// satisfies crudService) would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='grp-1']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "service-group") {
		t.Fatalf("registered get did not target the service-group endpoint: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_service_group_update", Arguments: map[string]any{"name": "grp-1", "members": []string{"db-5432"}}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "db-5432") || !strings.Contains(el, "grp-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("registered update did not reach the API with the new member: %s", el)
	}
}

func TestRegisterServiceGroupToolsReadOnly(t *testing.T) {
	reads := []string{"panos_service_group_list", "panos_service_group_get"}
	writes := []string{"panos_service_group_create", "panos_service_group_update", "panos_service_group_delete"}

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

// TestBuildTagEntry pins that a create entry carries the name, color and
// comments, and that omitted optional fields stay nil so the XML omits them.
func TestBuildTagEntry(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		e, err := buildTagEntry(TagInput{Name: "prod", Color: "color13", Comments: "production workloads"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Name != "prod" || strVal(e.Color) != "color13" || strVal(e.Comments) != "production workloads" {
			t.Fatalf("entry built wrong: %+v", e)
		}
	})
	t.Run("bare", func(t *testing.T) {
		e, err := buildTagEntry(TagInput{Name: "lab"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Name != "lab" || e.Color != nil || e.Comments != nil {
			t.Fatalf("omitted fields must stay nil: %+v", e)
		}
	})
}

// TestBuildTagEntryRejects pins that a create entry requires a name.
func TestBuildTagEntryRejects(t *testing.T) {
	_, err := buildTagEntry(TagInput{Color: "color13"})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	// Assert the message, not merely that an error occurred, so the name guard
	// cannot pass on a future unrelated rejection.
	if !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("error must name the missing field, got: %v", err)
	}
}

// TestOverlayTagFields pins the overlay semantics: a non-empty color or
// comments replaces the current value, and an empty one leaves it unchanged.
// Consequently neither field can be cleared in place, matching how the
// sibling overlays treat their description fields.
func TestOverlayTagFields(t *testing.T) {
	t.Run("color replaces when non-empty", func(t *testing.T) {
		e := &admintag.Entry{Name: "t", Color: ptr("color13")}
		if err := overlayTag(e, TagInput{Color: "color20"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Color) != "color20" {
			t.Fatalf("color not replaced: %q", strVal(e.Color))
		}
	})
	t.Run("comments replace when non-empty", func(t *testing.T) {
		e := &admintag.Entry{Name: "t", Comments: ptr("old note")}
		if err := overlayTag(e, TagInput{Comments: "new note"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Comments) != "new note" {
			t.Fatalf("comments not replaced: %q", strVal(e.Comments))
		}
	})
	t.Run("empty overlay leaves entry unchanged", func(t *testing.T) {
		e := &admintag.Entry{Name: "t", Color: ptr("color13"), Comments: ptr("old note")}
		if err := overlayTag(e, TagInput{}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.Color) != "color13" || strVal(e.Comments) != "old note" {
			t.Fatalf("empty overlay changed entry: color=%q comments=%q", strVal(e.Color), strVal(e.Comments))
		}
	})
	t.Run("disable-override passes through untouched", func(t *testing.T) {
		e := &admintag.Entry{Name: "t", Color: ptr("color13"), DisableOverride: ptr("yes")}
		if err := overlayTag(e, TagInput{Color: "color20"}); err != nil {
			t.Fatal(err)
		}
		if strVal(e.DisableOverride) != "yes" {
			t.Fatalf("overlay must not touch DisableOverride: %q", strVal(e.DisableOverride))
		}
	})
}

// tagListBody lists a tag with a color and comments, and a bare tag. The list
// xpath ends at .../tag/entry, so there is no wrapper element in the response.
const tagListBody = `<response status="success"><result>` +
	`<entry name="prod"><color>color13</color><comments>production workloads</comments></entry>` +
	`<entry name="lab"></entry>` +
	`</result></response>`

// tagCreatedBody answers the read-back get pango's Create issues after the
// set; the read-back requires exactly one entry.
const tagCreatedBody = `<response status="success"><result><entry name="prod">` +
	`<color>color13</color><comments>production workloads</comments></entry></result></response>`

// tagCurrentBody is the entry as it exists before an update: a color and
// comments. Every update input below must differ from it, or pango's
// UpdateWithXpath short-circuits on SpecMatches and issues no multi-config
// request, making the edit assertions vacuous.
const tagCurrentBody = `<response status="success"><result><entry name="t-1">` +
	`<color>color13</color><comments>old note</comments></entry></result></response>`

func tagResolve(d *Deps) func(LocationInput) (admintag.Location, error) {
	return func(in LocationInput) (admintag.Location, error) {
		return resolveLocation(d, in, tagParts())
	}
}

func tagName(e *admintag.Entry) string { return e.Name }

func TestTagCreateBuildsEntry(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		// pango's Create reads the object back with a config get after the set.
		fakeRoute{Match: configAction("get"), Body: tagCreatedBody},
	)
	h := createHandler[admintag.Location, admintag.Entry, TagInput](d, "panos_tag_create",
		newTagService(d), tagResolve(d),
		func(in TagInput) LocationInput { return in.Location }, buildTagEntry, tagSummary)

	res, _, err := h(t.Context(), nil, TagInput{Name: "prod", Color: "color13", Comments: "production workloads"})
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
			if !strings.Contains(el, `name="prod"`) || !strings.Contains(el, "<color>color13</color>") ||
				!strings.Contains(el, "<comments>production workloads</comments>") {
				t.Fatalf("element missing fields: %s", el)
			}
			if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "/tag") {
				t.Fatalf("xpath missing default vsys or tag endpoint: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set request recorded")
	}
	// pango's Create reads the object back after the set; pin that read-back
	// actually reached the API.
	assertReadBackGet(t, f)
}

func TestTagCreateValidation(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	h := createHandler[admintag.Location, admintag.Entry, TagInput](d, "panos_tag_create",
		newTagService(d), tagResolve(d),
		func(in TagInput) LocationInput { return in.Location }, buildTagEntry, tagSummary)

	// Assert each rejection's distinct message, not merely IsError, so the name
	// and location guards cannot pass on one another's error.
	bad := []struct {
		name, wantErr string
		in            TagInput
	}{
		{"no name", "name is required", TagInput{Color: "color13"}},
		{"dg on firewall", "device_group requires a Panorama connection", TagInput{Name: "t", Location: LocationInput{DeviceGroup: "dg1"}}},
	}
	for _, c := range bad {
		res, _, err := h(t.Context(), nil, c.in)
		if err != nil {
			t.Fatalf("%s: handler must not return Go error: %v", c.name, err)
		}
		if !res.IsError {
			t.Fatalf("%s: expected IsError", c.name)
		}
		if body := textContent(t, res); !strings.Contains(body, c.wantErr) {
			t.Fatalf("%s: error %q must mention %q", c.name, body, c.wantErr)
		}
	}
	// Validation must reject before any API call: only the bootstrap system-info
	// request may exist.
	if got := len(f.Requests()); got != 1 {
		t.Fatalf("validation must fail before any API call; recorded %d requests", got)
	}
}

func TestTagAPIErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>invalid object</line></msg></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	h := getHandler[admintag.Location, admintag.Entry](d, "panos_tag_get",
		newTagService(d), tagResolve(d), tagSummary)

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
	// Pin that the shared adapter wraps the name into an entry xpath exactly
	// once for the tag instantiation too; a raw-name rejection or a double-wrap
	// would both be caught here.
	assertSingleWrappedGet(t, f, "entry[@name='nope']")
}

// newTagUpdateHandler builds the update handler used by the update tests,
// keeping their setup to one line.
func newTagUpdateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, TagInput) (*mcp.CallToolResult, any, error) {
	return updateHandler[admintag.Location, admintag.Entry, TagInput](d, "panos_tag_update",
		newTagService(d), tagResolve(d),
		func(in TagInput) LocationInput { return in.Location },
		func(in TagInput) string { return in.Name }, overlayTag, tagSummary)
}

func TestTagUpdate(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: tagCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	// Change the color; the input differs from the current entry, so
	// SpecMatches cannot short-circuit.
	res, _, err := newTagUpdateHandler(d)(t.Context(), nil, TagInput{Name: "t-1", Color: "color20"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "<color>color20</color>") {
		t.Fatalf("edit element missing new color: %s", el)
	}
	if strings.Contains(el, "color13") {
		t.Fatalf("color must replace, not keep the old value: %s", el)
	}
	if !strings.Contains(el, "old note") {
		t.Fatalf("read-modify-write must preserve the untouched comments: %s", el)
	}
	if !strings.Contains(el, "t-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("edit element missing entry xpath: %s", el)
	}
}

// TestTagUpdateNoopSpecMatches mirrors TestAddressUpdateNoopSpecMatches for the
// tag resource: an overlay that changes nothing leaves the entry byte-identical
// to the one read back, so pango's UpdateWithXpath short-circuits on SpecMatches
// and issues no edit. Only a get route is registered, so an edit that did fire
// would trip the fake's fail-loud on the unmatched multi-config.
func TestTagUpdateNoopSpecMatches(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: tagCurrentBody})
	// Only the name is set, and it matches the entry read back, so the overlay
	// leaves the spec unchanged.
	res, _, err := newTagUpdateHandler(d)(t.Context(), nil, TagInput{Name: "t-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// An identical overlay must issue no config write at all.
	assertNoConfigWrite(t, f)
}

func TestTagUpdateAPIError(t *testing.T) {
	errBody := `<response status="error" code="12"><msg><line>edit rejected</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: tagCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: errBody},
	)
	res, _, err := newTagUpdateHandler(d)(t.Context(), nil, TagInput{Name: "t-1", Color: "color20"})
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

func TestTagDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	h := deleteHandler[admintag.Location, admintag.Entry](d, "panos_tag_delete",
		newTagService(d), tagResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "t-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// Delete must reach the API with the entry xpath carrying the name and
	// default vsys, proving tagParts wires the location end-to-end.
	if el := multiConfigElement(t, f); !strings.Contains(el, "t-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("delete did not reach the API with the entry xpath: %s", el)
	}
}

func TestTagList(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: tagListBody})
	h := listHandler[admintag.Location, admintag.Entry](d, "panos_tag_list",
		newTagService(d), tagResolve(d), tagName, tagSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	body := textContent(t, res)
	// Both entries appear; the summary surfaces color and comments, and the
	// bare entry emits them as empty strings rather than dropping the keys.
	assertContainsAll(t, body,
		`"total": 2`, "prod", "lab",
		`"color": "color13"`, `"comments": "production workloads"`,
		`"color": ""`, `"comments": ""`)
	// Tags have neither a description nor tags of their own; the hand-rolled
	// summary must not emit bogus summaryBase fields.
	if strings.Contains(body, `"description"`) || strings.Contains(body, `"tags"`) {
		t.Fatalf("tag summary must contain only name, color and comments: %s", body)
	}

	res, _, err = h(t.Context(), nil, ListInput{Filter: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	if body := textContent(t, res); strings.Contains(body, "prod") || !strings.Contains(body, "lab") {
		t.Fatalf("name filter failed: %s", body)
	}
}

// TestTagPanoramaLocations exercises the Panorama location branches of
// tagParts: the shared default and an explicit device group, asserting the
// request xpath so it pins the resolved location.
func TestTagPanoramaLocations(t *testing.T) {
	t.Run("shared list", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: tagListBody})
		h := listHandler[admintag.Location, admintag.Entry](d, "panos_tag_list",
			newTagService(d), tagResolve(d), tagName, tagSummary)
		res, _, err := h(t.Context(), nil, ListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		if body := textContent(t, res); !strings.Contains(body, "prod") {
			t.Fatalf("shared list missing entries: %s", body)
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/config/shared") || strings.Contains(joined, "vsys") {
			t.Fatalf("shared list must target the shared xpath and not a vsys, got: %s", joined)
		}
	})

	t.Run("device group get", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: tagCurrentBody})
		h := getHandler[admintag.Location, admintag.Entry](d, "panos_tag_get",
			newTagService(d), tagResolve(d), tagSummary)
		res, _, err := h(t.Context(), nil, NameInput{Name: "t-1", Location: LocationInput{DeviceGroup: "dg1"}})
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

// TestTagGetUpdateViaRegisteredTools drives panos_tag_get and panos_tag_update
// through a registered MCP server over the in-memory transport. It is the
// proof of the adapter wiring: the raw pango service also satisfies
// crudService, so wiring admintag.NewService directly would COMPILE and only
// fail here, where the calls must actually reach the fake API. A raw-name
// wiring is rejected client-side and records no request.
func TestTagGetUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: tagCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterTagTools(srv, d)

	cs := connectInMemory(t, srv)

	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_tag_get", Arguments: map[string]any{"name": "t-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.IsError {
		t.Fatalf("registered get failed: %s", textContent(t, getRes))
	}
	// The registered get must reach the fake API wrapped exactly once and
	// target the tag endpoint; a raw-service wiring (which also satisfies
	// crudService) would compile but record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='t-1']")
	if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "/tag/entry") {
		t.Fatalf("registered get did not target the tag endpoint: %s", joined)
	}

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_tag_update", Arguments: map[string]any{"name": "t-1", "color": "color20"}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered update failed: %s", textContent(t, updRes))
	}
	if el := multiConfigElement(t, f); !strings.Contains(el, "color20") || !strings.Contains(el, "t-1") || !strings.Contains(el, "vsys1") {
		t.Fatalf("registered update did not reach the API with the new color: %s", el)
	}
}

func TestRegisterTagToolsReadOnly(t *testing.T) {
	reads := []string{"panos_tag_list", "panos_tag_get"}
	writes := []string{"panos_tag_create", "panos_tag_update", "panos_tag_delete"}

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
