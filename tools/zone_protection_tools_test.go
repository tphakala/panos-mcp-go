package tools

import (
	"encoding/json"
	"strings"
	"testing"

	zoneprotection "github.com/PaloAltoNetworks/pango/network/profiles/zoneprotection"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertOnlyToggleSet asserts that key's toggle is the only one set true on e.
func assertOnlyToggleSet(t *testing.T, e *zoneprotection.Entry, key string) {
	t.Helper()
	for _, tg := range zpToggles {
		p := tg.entry(e)
		if tg.key == key {
			if *p == nil || !**p {
				t.Fatalf("key %q did not set its own entry field true (JSON tag or accessor drift)", key)
			}
			continue
		}
		if *p != nil {
			t.Fatalf("setting %q also set %q: table rows are crossed", key, tg.key)
		}
	}
}

// assertOnlyToggleInSummary asserts the summary surfaces key true and no other
// toggle key at all.
func assertOnlyToggleInSummary(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if m[key] != true {
		t.Fatalf("summary did not surface %q as true: %v", key, m[key])
	}
	for _, tg := range zpToggles {
		if tg.key == key {
			continue
		}
		if _, ok := m[tg.key]; ok {
			t.Fatalf("summary leaked %q when only %q was set", tg.key, key)
		}
	}
}

// TestZoneProtectionToggleMapping pins the entire zpToggles table end to end.
// For each toggle it unmarshals a request that sets only that field (exercising
// the JSON tag on the input struct, exactly as the MCP layer would), builds the
// entry, and asserts the toggle's own entry field is set true, every other
// toggle field stays nil, and the summary surfaces exactly that key. This
// catches any drift among a toggle's JSON key, its input accessor, its entry
// accessor, and its summary key: swap any two rows, or mistype a key, and the
// run turns red.
func TestZoneProtectionToggleMapping(t *testing.T) {
	for _, tg := range zpToggles {
		t.Run(tg.key, func(t *testing.T) {
			var in ZoneProtectionInput
			if err := json.Unmarshal([]byte(`{"name":"zp","`+tg.key+`":true}`), &in); err != nil {
				t.Fatalf("unmarshal %s: %v", tg.key, err)
			}
			e, err := buildZoneProtection(in)
			if err != nil {
				t.Fatal(err)
			}
			assertOnlyToggleSet(t, e, tg.key)
			assertOnlyToggleInSummary(t, asMap(t, zoneProtectionSummary(e)), tg.key)
		})
	}
}

// TestBuildZoneProtectionStringFields pins the three string toggles and the
// description, which sit outside the bool table.
func TestBuildZoneProtectionStringFields(t *testing.T) {
	e, err := buildZoneProtection(ZoneProtectionInput{
		Name:             "zp",
		Description:      "edge",
		AsymmetricPath:   new("drop"),
		StripMptcpOption: new("yes"),
		TcpRejectNonSyn:  new("global"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Description == nil || *e.Description != "edge" {
		t.Fatalf("description not mapped: %v", e.Description)
	}
	m := asMap(t, zoneProtectionSummary(e))
	if m[descriptionKey] != "edge" || m["asymmetric_path"] != "drop" || m["strip_mptcp_option"] != "yes" || m["tcp_reject_non_syn"] != "global" {
		t.Fatalf("string fields not surfaced in summary: %v", m)
	}
}

func TestBuildZoneProtectionEmptyName(t *testing.T) {
	if _, err := buildZoneProtection(ZoneProtectionInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestOverlayZoneProtectionPreservesDeferred pins the read-modify-write
// contract: an update setting one toggle must leave an existing sibling toggle
// and the unmanaged typed Flood sub-block exactly as read. Sabotage: rebuilding
// the entry in overlayZoneProtection (instead of overlaying in place) drops
// Flood and the sibling toggle, turning this red.
func TestOverlayZoneProtectionPreservesDeferred(t *testing.T) {
	e := &zoneprotection.Entry{
		Name:           "zp",
		DiscardIpSpoof: new(true),
		Flood:          &zoneprotection.Flood{},
	}
	if err := overlayZoneProtection(e, ZoneProtectionInput{Name: "zp", DiscardIpFrag: new(true)}); err != nil {
		t.Fatal(err)
	}
	if e.Flood == nil {
		t.Fatal("unmanaged Flood sub-block must be preserved across an update")
	}
	if e.DiscardIpSpoof == nil || !*e.DiscardIpSpoof {
		t.Fatalf("existing sibling toggle must be preserved: %v", e.DiscardIpSpoof)
	}
	if e.DiscardIpFrag == nil || !*e.DiscardIpFrag {
		t.Fatalf("the provided toggle must be applied: %v", e.DiscardIpFrag)
	}
}

// TestZoneProtectionCreateFirewallXpath drives a firewall create and pins the
// set reaches the zone-protection-profile node.
func TestZoneProtectionCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="zp"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterZoneProtectionTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_zone_protection_create",
		Arguments: map[string]any{"name": "zp", "discard_ip_spoof": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "zone-protection-profile") {
		t.Fatalf("create must target the zone-protection-profile xpath: %s", joined)
	}
}

// TestZoneProtectionCreatePanoramaTemplateXpath drives a Panorama create under a
// template and pins the set reaches the zone-protection-profile node inside that
// template's config.
func TestZoneProtectionCreatePanoramaTemplateXpath(t *testing.T) {
	d, f := newTestDeps(t, "Panorama",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="zp"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterZoneProtectionTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "panos_zone_protection_create",
		Arguments: map[string]any{"name": "zp", "template": "tmpl-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama create failed: %s", textContent(t, res))
	}
	joined := strings.Join(setXpaths(f), " ")
	if !strings.Contains(joined, "zone-protection-profile") || !strings.Contains(joined, "tmpl-a") {
		t.Fatalf("panorama create must resolve into the template scope: %s", joined)
	}
}

// TestZoneProtectionNetScopeGating pins the two net-scope rejection paths.
func TestZoneProtectionNetScopeGating(t *testing.T) {
	t.Run("panorama without template errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterZoneProtectionTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_zone_protection_list", Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textContent(t, res), "template or template_stack is required on Panorama") {
			t.Fatalf("Panorama list without a template must error: %v", textContent(t, res))
		}
	})
	t.Run("template on firewall errors", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
		RegisterZoneProtectionTools(srv, d)
		cs := connectInMemory(t, srv)
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "panos_zone_protection_list", Arguments: map[string]any{"template": "tmpl-a"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textContent(t, res), "template requires a Panorama connection") {
			t.Fatalf("a template against a firewall must error: %v", textContent(t, res))
		}
	})
}
