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
	for _, s := range forbidden {
		if s != "" && strings.Contains(hay, s) {
			t.Fatalf("summary leaked secret %q in %s", s, hay)
		}
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
