package tools

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/network/zone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//nolint:gocognit,gocyclo // six independent zone-location scenarios kept in one place.
func TestResolveZoneLocation(t *testing.T) {
	t.Run("firewall default vsys", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		loc, err := resolveZoneLocation(d, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if loc.Vsys == nil || loc.Vsys.Vsys != "vsys1" {
			t.Fatalf("firewall must default to vsys1: %+v", loc.Vsys)
		}
	})
	t.Run("firewall explicit vsys", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		loc, err := resolveZoneLocation(d, "vsys3", "")
		if err != nil {
			t.Fatal(err)
		}
		if loc.Vsys == nil || loc.Vsys.Vsys != "vsys3" {
			t.Fatalf("firewall must honor the vsys parameter, not hardcode it: %+v", loc.Vsys)
		}
	})
	t.Run("firewall with template rejected", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		if _, err := resolveZoneLocation(d, "", "tmpl"); err == nil || !strings.Contains(err.Error(), "template requires a Panorama") {
			t.Fatalf("template on a firewall must be rejected: %v", err)
		}
	})
	t.Run("panorama without template rejected", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		if _, err := resolveZoneLocation(d, "", ""); err == nil || !strings.Contains(err.Error(), "template is required") {
			t.Fatalf("Panorama without a template must be rejected: %v", err)
		}
	})
	t.Run("panorama with template pins vsys1", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		loc, err := resolveZoneLocation(d, "", "edge")
		if err != nil {
			t.Fatal(err)
		}
		if loc.Template == nil || loc.Template.Template != "edge" || loc.Template.Vsys != "vsys1" {
			t.Fatalf("Panorama template location wrong: %+v", loc.Template)
		}
	})
	t.Run("panorama with vsys rejected", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		if _, err := resolveZoneLocation(d, "vsys1", "edge"); err == nil || !strings.Contains(err.Error(), "vsys applies to a firewall") {
			t.Fatalf("vsys on Panorama must be rejected: %v", err)
		}
	})
}

func TestBuildZoneEntry(t *testing.T) {
	t.Run("layer3 with interfaces and toggles", func(t *testing.T) {
		e, err := buildZoneEntry(&ZoneWriteInput{Name: "z", NetworkType: "layer3", Interfaces: []string{"ethernet1/1"},
			ZoneProtectionProfile: "zpp", EnableUserIdentification: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		if e.Network == nil || len(e.Network.Layer3) != 1 || e.Network.Layer3[0] != "ethernet1/1" {
			t.Fatalf("layer3 interfaces wrong: %+v", e.Network)
		}
		if strVal(e.Network.ZoneProtectionProfile) != "zpp" {
			t.Fatalf("zone protection profile not set: %v", strVal(e.Network.ZoneProtectionProfile))
		}
		if !boolVal(e.EnableUserIdentification) {
			t.Fatal("enable_user_identification must be set")
		}
	})
	t.Run("layer3 with no interfaces keeps a non-nil type marker", func(t *testing.T) {
		e, err := buildZoneEntry(&ZoneWriteInput{Name: "z", NetworkType: "layer3"})
		if err != nil {
			t.Fatal(err)
		}
		// The wire type marker requires a non-nil empty slice; a nil slice would
		// drop the <layer3/> element and lose the type entirely.
		if e.Network.Layer3 == nil || len(e.Network.Layer3) != 0 {
			t.Fatalf("layer3 with no interfaces must be a non-nil empty slice, got %#v", e.Network.Layer3)
		}
	})
	t.Run("tunnel takes no interfaces", func(t *testing.T) {
		e, err := buildZoneEntry(&ZoneWriteInput{Name: "z", NetworkType: "tunnel"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Network.Tunnel == nil {
			t.Fatalf("tunnel branch not set: %+v", e.Network)
		}
	})
}

func TestBuildZoneEntryRejects(t *testing.T) {
	bad := []struct {
		name, wantErr string
		in            ZoneWriteInput
	}{
		{"no name", "name is required", ZoneWriteInput{NetworkType: "layer3"}},
		{"no type", "network_type is required", ZoneWriteInput{Name: "z"}},
		{"bad type", "network_type must be one of", ZoneWriteInput{Name: "z", NetworkType: "l3"}},
		{"interfaces with tunnel", "tunnel zone type takes no interfaces", ZoneWriteInput{Name: "z", NetworkType: "tunnel", Interfaces: []string{"tunnel.1"}}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			if _, err := buildZoneEntry(&in); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: error %v must mention %q", c.name, err, c.wantErr)
			}
		})
	}
}

// TestOverlayZoneTypeSwitchPreservesProtection is the headline zone oneof test:
// switching network_type clears the old interface branch but keeps the shared
// protection fields and unknown nested XML on Network.
func TestOverlayZoneTypeSwitchPreservesProtection(t *testing.T) {
	e := &zone.Entry{Name: "z", Network: &zone.Network{
		Layer3:                []string{"ethernet1/1"},
		ZoneProtectionProfile: ptr("zpp"),
		MiscAttributes:        []xml.Attr{{Name: xml.Name{Local: "uuid"}, Value: "keep-me"}},
	}}
	if err := overlayZone(e, &ZoneWriteInput{NetworkType: "layer2", Interfaces: []string{"ethernet1/2"}}); err != nil {
		t.Fatal(err)
	}
	if e.Network.Layer3 != nil {
		t.Fatalf("switching to layer2 must clear Layer3, got %v", e.Network.Layer3)
	}
	if len(e.Network.Layer2) != 1 || e.Network.Layer2[0] != "ethernet1/2" {
		t.Fatalf("layer2 not set: %v", e.Network.Layer2)
	}
	if strVal(e.Network.ZoneProtectionProfile) != "zpp" {
		t.Fatalf("protection profile must survive a type switch: %v", strVal(e.Network.ZoneProtectionProfile))
	}
	if len(e.Network.MiscAttributes) != 1 || e.Network.MiscAttributes[0].Value != "keep-me" {
		t.Fatalf("unknown Network XML must survive a type switch: %+v", e.Network.MiscAttributes)
	}
}

func TestOverlayZoneInterfacesWithinType(t *testing.T) {
	t.Run("interfaces replace within the current branch", func(t *testing.T) {
		e := &zone.Entry{Name: "z", Network: &zone.Network{Layer3: []string{"ethernet1/1"}}}
		if err := overlayZone(e, &ZoneWriteInput{Interfaces: []string{"ethernet1/2", "ethernet1/3"}}); err != nil {
			t.Fatal(err)
		}
		if len(e.Network.Layer3) != 2 {
			t.Fatalf("interfaces not replaced within layer3: %v", e.Network.Layer3)
		}
	})
	t.Run("interfaces without a branch errors", func(t *testing.T) {
		e := &zone.Entry{Name: "z", Network: &zone.Network{}}
		if err := overlayZone(e, &ZoneWriteInput{Interfaces: []string{"ethernet1/1"}}); err == nil || !strings.Contains(err.Error(), "no network_type set") {
			t.Fatalf("interfaces without a branch must error: %v", err)
		}
	})
	t.Run("interfaces on a tunnel zone errors", func(t *testing.T) {
		e := &zone.Entry{Name: "z", Network: &zone.Network{Tunnel: &zone.NetworkTunnel{}}}
		if err := overlayZone(e, &ZoneWriteInput{Interfaces: []string{"tunnel.1"}}); err == nil || !strings.Contains(err.Error(), "tunnel zone type takes no interfaces") {
			t.Fatalf("interfaces on a tunnel zone must error: %v", err)
		}
	})
}

func TestZoneSummary(t *testing.T) {
	t.Run("external branch and bools", func(t *testing.T) {
		e := &zone.Entry{Name: "z", EnableUserIdentification: ptr(true), Network: &zone.Network{
			External: []string{"ext-zone-1"}, LogSetting: ptr("lf"),
		}}
		m := asMap(t, zoneSummary(e))
		if m["network_type"] != "external" {
			t.Fatalf("network_type wrong: %v", m["network_type"])
		}
		if ifs, ok := m["interfaces"].([]string); !ok || len(ifs) != 1 || ifs[0] != "ext-zone-1" {
			t.Fatalf("interfaces wrong: %v", m["interfaces"])
		}
		if m["log_setting"] != "lf" || m["enable_user_identification"] != true {
			t.Fatalf("summary fields wrong: %v", m)
		}
	})
	t.Run("tunnel has no interfaces", func(t *testing.T) {
		e := &zone.Entry{Name: "z", Network: &zone.Network{Tunnel: &zone.NetworkTunnel{}}}
		m := asMap(t, zoneSummary(e))
		if m["network_type"] != "tunnel" {
			t.Fatalf("tunnel type wrong: %v", m["network_type"])
		}
		if ifs, ok := m["interfaces"].([]string); !ok || len(ifs) != 0 {
			t.Fatalf("tunnel must report no interfaces: %v", m["interfaces"])
		}
	})
}

const zoneCreatedBody = `<response status="success"><result>` +
	`<entry name="z1"><network><layer3><member>ethernet1/1</member></layer3></network></entry></result></response>`

//nolint:gocognit,gocyclo // two independent create-scoping subtests (firewall vsys, Panorama template).
func TestZoneCreateFirewallAndPanorama(t *testing.T) {
	t.Run("firewall targets the vsys xpath", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM",
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: zoneCreatedBody},
		)
		res, _, err := zoneCreateHandler(d)(t.Context(), nil, ZoneWriteInput{Name: "z1", NetworkType: "layer3", Interfaces: []string{"ethernet1/1"}})
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
				if !strings.Contains(el, `name="z1"`) || !strings.Contains(el, "<layer3>") || !strings.Contains(el, "<member>ethernet1/1</member>") {
					t.Fatalf("set element missing fields: %s", el)
				}
				if xp := req.Get("xpath"); !strings.Contains(xp, "vsys1") || !strings.Contains(xp, "/zone") {
					t.Fatalf("firewall create must target the vsys zone xpath: %s", xp)
				}
			}
		}
		if !sawSet {
			t.Fatal("no config set recorded")
		}
		assertReadBackGet(t, f)
	})
	t.Run("panorama targets the template xpath", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama",
			fakeRoute{Match: configAction("set"), Body: configSuccessBody},
			fakeRoute{Match: configAction("get"), Body: zoneCreatedBody},
		)
		res, _, err := zoneCreateHandler(d)(t.Context(), nil, ZoneWriteInput{Name: "z1", Template: "edge", NetworkType: "layer3", Interfaces: []string{"ethernet1/1"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", textContent(t, res))
		}
		var sawSet bool
		for _, req := range f.Requests() {
			if req.Get("action") == "set" {
				sawSet = true
				if xp := req.Get("xpath"); !strings.Contains(xp, "edge") || !strings.Contains(xp, "/zone") {
					t.Fatalf("Panorama create must target the template zone xpath: %s", xp)
				}
			}
		}
		if !sawSet {
			t.Fatal("no config set recorded")
		}
	})
}

// zoneCurrentBody is the entry before an update: one layer3 interface. An update
// input must differ from it, or pango's UpdateWithXpath short-circuits on
// SpecMatches and issues no multi-config.
const zoneCurrentBody = `<response status="success"><result>` +
	`<entry name="z1"><network><layer3><member>ethernet1/1</member></layer3></network></entry></result></response>`

func TestZoneUpdateViaRegisteredTools(t *testing.T) {
	ctx := t.Context()
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: zoneCurrentBody},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "panos-test", Version: "0"}, nil)
	RegisterDeviceTools(srv, d)
	cs := connectInMemory(t, srv)

	updRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_zone_update", Arguments: map[string]any{"name": "z1", "interfaces": []string{"ethernet1/2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if updRes.IsError {
		t.Fatalf("registered zone update failed: %s", textContent(t, updRes))
	}
	// The adapter must wrap the name into an entry xpath exactly once; a raw-name
	// wiring would be rejected client-side and record no such request.
	assertSingleWrappedGet(t, f, "entry[@name='z1']")
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "ethernet1/2") || !strings.Contains(el, "vsys1") {
		t.Fatalf("registered update did not reach the API with the new interface: %s", el)
	}
}

func TestZoneDelete(t *testing.T) {
	// pango Delete removes through a multi-config request.
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody})
	res, _, err := zoneDeleteHandler(d)(t.Context(), nil, ZoneNameInput{Name: "z1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	// The multi-config element HTML-escapes the xpath quotes, so match the parts
	// rather than a literal quoted xpath.
	el := multiConfigElement(t, f)
	if !strings.Contains(el, "vsys1") || !strings.Contains(el, "/zone/entry") || !strings.Contains(el, "z1") {
		t.Fatalf("delete must target the vsys zone entry xpath: %s", el)
	}
}

func TestRegisterZoneWriteToolsReadOnly(t *testing.T) {
	assertReadOnlyGating(t, RegisterDeviceTools,
		[]string{"panos_zone_list"},
		[]string{"panos_zone_create", "panos_zone_update", "panos_zone_delete"})
}
