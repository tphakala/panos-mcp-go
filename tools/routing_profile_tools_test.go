package tools

import (
	"fmt"
	"strings"
	"testing"

	bgpauth "github.com/PaloAltoNetworks/pango/network/routing-profile/bgp/authprofile"
	ospfauth "github.com/PaloAltoNetworks/pango/network/routing-profile/ospf/authprofile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// assertNoLeak fails if any of the forbidden strings appears anywhere in the
// (possibly nested) summary value. It is used to prove a summary never carries
// key material.
func assertNoLeak(t *testing.T, v any, forbidden ...string) {
	t.Helper()
	hay := fmt.Sprintf("%v", v)
	sawNonEmpty := false
	for _, s := range forbidden {
		if s == "" {
			continue
		}
		sawNonEmpty = true
		if strings.Contains(hay, s) {
			t.Fatalf("summary leaked secret %q in %s", s, hay)
		}
	}
	// Guard against a vacuous call: a caller passing only empty strings would
	// assert nothing. Mirrors assertRedactsSecret's non-empty-needle guard.
	if !sawNonEmpty {
		t.Fatal("assertNoLeak needs at least one non-empty forbidden string")
	}
}

// --- BGP auth profile: secret never surfaces ---------------------------------

func TestBgpAuthProfileBuild(t *testing.T) {
	e, err := buildBgpAuthProfile(BgpAuthProfileInput{Name: "a1", Secret: new("s3cr3t")})
	if err != nil {
		t.Fatal(err)
	}
	mustStrPtr(t, e.Secret, "s3cr3t", "secret -> Entry.Secret")
	if _, err := buildBgpAuthProfile(BgpAuthProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestBgpAuthProfileSummaryOmitsSecret pins that the summary reports only
// whether a key is set, never the key itself. Sabotage: change has_secret to
// return strVal(e.Secret) and the "must never contain the secret" check fails.
func TestBgpAuthProfileSummaryOmitsSecret(t *testing.T) {
	m := asMap(t, bgpAuthProfileSummary(&bgpauth.Entry{Name: "a1", Secret: new("TOPSECRET")}))
	if m["has_secret"] != true {
		t.Fatalf("has_secret should be true when a key is set, got %v", m["has_secret"])
	}
	for k, v := range m {
		if s, ok := v.(string); ok && s == "TOPSECRET" {
			t.Fatalf("summary field %q leaked the secret", k)
		}
	}
	mNone := asMap(t, bgpAuthProfileSummary(&bgpauth.Entry{Name: "a2"}))
	if mNone["has_secret"] != false {
		t.Fatalf("has_secret should be false when no key is set, got %v", mNone["has_secret"])
	}
}

// --- OSPF auth profile: md5 key mapping and secret omission -------------------

func TestOspfAuthProfileBuildMapsMd5Keys(t *testing.T) {
	e, err := buildOspfAuthProfile(OspfAuthProfileInput{
		Name:     "o1",
		Password: new("pw"),
		Md5Keys: []OspfMd5KeyInput{
			{KeyID: "1", Key: new("k1"), Preferred: new(true)},
			{KeyID: "2", Key: new("k2")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustStrPtr(t, e.Password, "pw", "password -> Entry.Password")
	if len(e.Md5) != 2 {
		t.Fatalf("want 2 md5 keys, got %d", len(e.Md5))
	}
	if e.Md5[0].Name != "1" {
		t.Fatalf("key_id -> Md5.Name wrong: %q", e.Md5[0].Name)
	}
	mustStrPtr(t, e.Md5[0].Key, "k1", "key -> Md5.Key")
	mustBoolPtr(t, e.Md5[0].Preferred, true, "preferred -> Md5.Preferred")

	// A missing key_id is rejected.
	if _, err := buildOspfAuthProfile(OspfAuthProfileInput{Name: "o2", Md5Keys: []OspfMd5KeyInput{{Key: new("x")}}}); err == nil {
		t.Fatal("md5 entry without key_id must be rejected")
	}
	// Empty name rejected.
	if _, err := buildOspfAuthProfile(OspfAuthProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

// TestOspfAuthProfileOverlayMd5Semantics pins that an omitted md5_keys list
// leaves the existing keys untouched while a provided (even empty) list replaces
// the set. Sabotage: drop the `if in.Md5Keys == nil { return }` guard and the
// "omitted leaves keys" case fails.
func TestOspfAuthProfileOverlayMd5Semantics(t *testing.T) {
	existing := &ospfauth.Entry{Name: "o1", Md5: []ospfauth.Md5{{Name: "9", Key: new("old")}}}
	if err := overlayOspfAuthProfile(existing, OspfAuthProfileInput{Name: "o1", Password: new("pw")}); err != nil {
		t.Fatal(err)
	}
	if len(existing.Md5) != 1 || existing.Md5[0].Name != "9" {
		t.Fatalf("omitted md5_keys must leave existing keys untouched, got %+v", existing.Md5)
	}
	cleared := &ospfauth.Entry{Name: "o1", Md5: []ospfauth.Md5{{Name: "9"}}}
	if err := overlayOspfAuthProfile(cleared, OspfAuthProfileInput{Name: "o1", Md5Keys: []OspfMd5KeyInput{}}); err != nil {
		t.Fatal(err)
	}
	if len(cleared.Md5) != 0 {
		t.Fatalf("a provided empty md5_keys must clear the set, got %+v", cleared.Md5)
	}
}

// TestOspfAuthProfileSummaryOmitsSecrets pins that the summary lists key IDs and
// preferred flags but never the password or key material.
func TestOspfAuthProfileSummaryOmitsSecrets(t *testing.T) {
	e := &ospfauth.Entry{
		Name:     "o1",
		Password: new("PWLEAK"),
		Md5:      []ospfauth.Md5{{Name: "1", Key: new("KEYLEAK"), Preferred: new(true)}},
	}
	m := asMap(t, ospfAuthProfileSummary(e))
	if m["has_password"] != true {
		t.Fatalf("has_password should be true, got %v", m["has_password"])
	}
	keys, ok := m["md5_keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("md5_keys wrong: %v", m["md5_keys"])
	}
	km := asMap(t, keys[0])
	if km["key_id"] != "1" || km["preferred"] != true {
		t.Fatalf("md5 key summary wrong: %v", km)
	}
	// Neither the password nor the key material may appear anywhere.
	assertNoLeak(t, m, "PWLEAK", "KEYLEAK")
}

// --- BGP timer profile: mixed string/int fields ------------------------------

func TestBgpTimerProfileBuildAndSummary(t *testing.T) {
	e, err := buildBgpTimerProfile(BgpTimerProfileInput{
		Name:                   "t1",
		HoldTime:               new("90"),
		KeepAliveInterval:      new("30"),
		MinRouteAdvInterval:    new(int64(5)),
		OpenDelayTime:          new(int64(2)),
		ReconnectRetryInterval: new(int64(15)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mustStrPtr(t, e.HoldTime, "90", "hold_time -> Entry.HoldTime")
	mustStrPtr(t, e.KeepAliveInterval, "30", "keep_alive_interval -> Entry.KeepAliveInterval")
	mustInt64(t, e.MinRouteAdvInterval, 5, "min_route_adv_interval -> Entry.MinRouteAdvInterval")

	m := asMap(t, bgpTimerProfileSummary(e))
	if m["hold_time"] != "90" || m["keep_alive_interval"] != "30" {
		t.Fatalf("summary string timers wrong: %v", m)
	}
	if m["min_route_adv_interval"] != int64(5) {
		t.Fatalf("summary min_route_adv_interval wrong: %v", m["min_route_adv_interval"])
	}
}

// TestRoutingTimerFamiliesBuildSummaryOverlay covers the build, summary and
// overlay of the non-secret routing profile families (the timer, dampening, BFD
// and PIM families). Summary field-mapping is this repo's most common
// escaped-defect class, so each subtest asserts the set fields round-trip
// through summary, then overlays a partial change and asserts only the provided
// field moved. The *Entry flows opaquely between buildX and summaryX so no pango
// type is named here.
func TestRoutingTimerFamiliesBuildSummaryOverlay(t *testing.T) {
	t.Run("bgp_dampening", testRoutingBgpDampening)
	t.Run("bgp_timer_overlay", testRoutingBgpTimerOverlay)
	t.Run("ospf_interface_timer", testRoutingOspfInterfaceTimer)
	t.Run("ospf_spf_timer", testRoutingOspfSpfTimer)
	t.Run("ospfv3_interface_timer", testRoutingOspfv3InterfaceTimer)
	t.Run("ospfv3_spf_timer", testRoutingOspfv3SpfTimer)
	t.Run("routing_bfd", testRoutingBfd)
	t.Run("pim_interface_timer", testRoutingPimInterfaceTimer)
	t.Run("name_required", testRoutingNameRequired)
}

func testRoutingBgpDampening(t *testing.T) {
	e, err := buildBgpDampeningProfile(BgpDampeningProfileInput{
		Name: "d1", Description: new("desc"), HalfLife: new(int64(15)),
		MaxSuppressLimit: new(int64(60)), ReuseLimit: new(int64(750)), SuppressLimit: new(int64(3000)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, bgpDampeningProfileSummary(e))
	if m["description"] != "desc" || m["half_life"] != int64(15) || m["suppress_limit"] != int64(3000) {
		t.Fatalf("dampening summary wrong: %v", m)
	}
	if err := overlayBgpDampeningProfile(e, BgpDampeningProfileInput{Name: "d1", ReuseLimit: new(int64(900))}); err != nil {
		t.Fatal(err)
	}
	m = asMap(t, bgpDampeningProfileSummary(e))
	if m["reuse_limit"] != int64(900) || m["half_life"] != int64(15) {
		t.Fatalf("overlay must change reuse_limit only, keeping half_life: %v", m)
	}
}

func testRoutingBgpTimerOverlay(t *testing.T) {
	e, err := buildBgpTimerProfile(BgpTimerProfileInput{Name: "t1", HoldTime: new("90"), MinRouteAdvInterval: new(int64(5))})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayBgpTimerProfile(e, BgpTimerProfileInput{Name: "t1", KeepAliveInterval: new("30")}); err != nil {
		t.Fatal(err)
	}
	m := asMap(t, bgpTimerProfileSummary(e))
	if m["keep_alive_interval"] != "30" || m["hold_time"] != "90" || m["min_route_adv_interval"] != int64(5) {
		t.Fatalf("overlay must add keep_alive_interval, preserving hold_time and min_route_adv_interval: %v", m)
	}
}

func testRoutingOspfInterfaceTimer(t *testing.T) {
	e, err := buildOspfInterfaceTimerProfile(OspfInterfaceTimerProfileInput{
		Name: "i1", HelloInterval: new(int64(10)), DeadCounts: new(int64(4)),
		RetransmitInterval: new(int64(5)), TransitDelay: new(int64(1)), GrDelay: new(int64(10)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ospfInterfaceTimerProfileSummary(e))
	if m["hello_interval"] != int64(10) || m["dead_counts"] != int64(4) || m["transit_delay"] != int64(1) {
		t.Fatalf("ospf interface timer summary wrong: %v", m)
	}
	if err := overlayOspfInterfaceTimerProfile(e, OspfInterfaceTimerProfileInput{Name: "i1", HelloInterval: new(int64(20))}); err != nil {
		t.Fatal(err)
	}
	m = asMap(t, ospfInterfaceTimerProfileSummary(e))
	if m["hello_interval"] != int64(20) || m["dead_counts"] != int64(4) {
		t.Fatalf("overlay must change hello_interval only: %v", m)
	}
}

func testRoutingOspfSpfTimer(t *testing.T) {
	e, err := buildOspfSpfTimerProfile(OspfSpfTimerProfileInput{
		Name: "s1", SpfCalculationDelay: new(int64(5)), LsaInterval: new(int64(5)),
		InitialHoldTime: new(int64(50)), MaxHoldTime: new(int64(5000)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ospfSpfTimerProfileSummary(e))
	if m["spf_calculation_delay"] != int64(5) || m["max_hold_time"] != int64(5000) {
		t.Fatalf("ospf spf timer summary wrong: %v", m)
	}
	if err := overlayOspfSpfTimerProfile(e, OspfSpfTimerProfileInput{Name: "s1", MaxHoldTime: new(int64(9000))}); err != nil {
		t.Fatal(err)
	}
	if asMap(t, ospfSpfTimerProfileSummary(e))["max_hold_time"] != int64(9000) {
		t.Fatal("overlay must change max_hold_time")
	}
}

func testRoutingOspfv3InterfaceTimer(t *testing.T) {
	e, err := buildOspfv3InterfaceTimerProfile(Ospfv3InterfaceTimerProfileInput{
		Name: "i1", HelloInterval: new(int64(10)), DeadCounts: new(int64(4)), TransitDelay: new(int64(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ospfv3InterfaceTimerProfileSummary(e))
	if m["hello_interval"] != int64(10) || m["dead_counts"] != int64(4) {
		t.Fatalf("ospfv3 interface timer summary wrong: %v", m)
	}
	if err := overlayOspfv3InterfaceTimerProfile(e, Ospfv3InterfaceTimerProfileInput{Name: "i1", DeadCounts: new(int64(8))}); err != nil {
		t.Fatal(err)
	}
	if asMap(t, ospfv3InterfaceTimerProfileSummary(e))["dead_counts"] != int64(8) {
		t.Fatal("overlay must change dead_counts")
	}
}

func testRoutingOspfv3SpfTimer(t *testing.T) {
	e, err := buildOspfv3SpfTimerProfile(Ospfv3SpfTimerProfileInput{
		Name: "s1", SpfCalculationDelay: new(int64(5)), LsaInterval: new(int64(5)), InitialHoldTime: new(int64(50)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ospfv3SpfTimerProfileSummary(e))
	if m["spf_calculation_delay"] != int64(5) || m["initial_hold_time"] != int64(50) {
		t.Fatalf("ospfv3 spf timer summary wrong: %v", m)
	}
	if err := overlayOspfv3SpfTimerProfile(e, Ospfv3SpfTimerProfileInput{Name: "s1", LsaInterval: new(int64(9))}); err != nil {
		t.Fatal(err)
	}
	if asMap(t, ospfv3SpfTimerProfileSummary(e))["lsa_interval"] != int64(9) {
		t.Fatal("overlay must change lsa_interval")
	}
}

func testRoutingBfd(t *testing.T) {
	e, err := buildRoutingBfdProfile(RoutingBfdProfileInput{
		Name: "b1", Mode: new("active"), MinTxInterval: new(int64(100)),
		MinRxInterval: new(int64(200)), DetectionMultiplier: new(int64(3)), HoldTime: new(int64(500)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, routingBfdProfileSummary(e))
	if m["mode"] != "active" || m["min_tx_interval"] != int64(100) || m["detection_multiplier"] != int64(3) {
		t.Fatalf("routing bfd summary wrong: %v", m)
	}
	if err := overlayRoutingBfdProfile(e, RoutingBfdProfileInput{Name: "b1", Mode: new("passive")}); err != nil {
		t.Fatal(err)
	}
	m = asMap(t, routingBfdProfileSummary(e))
	if m["mode"] != "passive" || m["min_tx_interval"] != int64(100) {
		t.Fatalf("overlay must change mode only: %v", m)
	}
}

func testRoutingPimInterfaceTimer(t *testing.T) {
	e, err := buildPimInterfaceTimerProfile(PimInterfaceTimerProfileInput{
		Name: "p1", HelloInterval: new(int64(30)), AssertInterval: new(int64(177)), JoinPruneInterval: new(int64(60)),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, pimInterfaceTimerProfileSummary(e))
	if m["hello_interval"] != int64(30) || m["assert_interval"] != int64(177) || m["join_prune_interval"] != int64(60) {
		t.Fatalf("pim interface timer summary wrong: %v", m)
	}
	if err := overlayPimInterfaceTimerProfile(e, PimInterfaceTimerProfileInput{Name: "p1", JoinPruneInterval: new(int64(90))}); err != nil {
		t.Fatal(err)
	}
	if asMap(t, pimInterfaceTimerProfileSummary(e))["join_prune_interval"] != int64(90) {
		t.Fatal("overlay must change join_prune_interval")
	}
}

// testRoutingNameRequired checks every non-secret family rejects an empty name.
func testRoutingNameRequired(t *testing.T) {
	if _, err := buildBgpDampeningProfile(BgpDampeningProfileInput{}); err == nil {
		t.Fatal("bgp dampening: empty name must be rejected")
	}
	if _, err := buildRoutingBfdProfile(RoutingBfdProfileInput{}); err == nil {
		t.Fatal("routing bfd: empty name must be rejected")
	}
	if _, err := buildPimInterfaceTimerProfile(PimInterfaceTimerProfileInput{}); err == nil {
		t.Fatal("pim interface timer: empty name must be rejected")
	}
}

// --- read-only gating across every routing profile family --------------------

func TestRoutingProfileReadOnlyGating(t *testing.T) {
	cases := []struct {
		base     string
		register func(*mcp.Server, *Deps)
	}{
		{"panos_bgp_auth_profile", RegisterBgpAuthProfileTools},
		{"panos_bgp_dampening_profile", RegisterBgpDampeningProfileTools},
		{"panos_bgp_timer_profile", RegisterBgpTimerProfileTools},
		{"panos_ospf_auth_profile", RegisterOspfAuthProfileTools},
		{"panos_ospf_interface_timer_profile", RegisterOspfInterfaceTimerProfileTools},
		{"panos_ospf_spf_timer_profile", RegisterOspfSpfTimerProfileTools},
		{"panos_ospfv3_interface_timer_profile", RegisterOspfv3InterfaceTimerProfileTools},
		{"panos_ospfv3_spf_timer_profile", RegisterOspfv3SpfTimerProfileTools},
		{"panos_routing_bfd_profile", RegisterRoutingBfdProfileTools},
		{"panos_pim_interface_timer_profile", RegisterPimInterfaceTimerProfileTools},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			assertReadOnlyGating(t, c.register,
				[]string{c.base + "_list", c.base + "_get"},
				[]string{c.base + "_create", c.base + "_update", c.base + "_delete"})
		})
	}
}
