package tools

import (
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/pango/crypto/ike/gateway"
	"github.com/PaloAltoNetworks/pango/network/tunnel/ipsec"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- IKE crypto profile -------------------------------------------------------

func TestBuildIkeCryptoProfile(t *testing.T) {
	e, err := buildIkeCryptoProfile(IkeCryptoProfileInput{
		Name: "ike-cp", DhGroup: []string{"group14", "group2"}, Encryption: []string{"aes-256-cbc"},
		Hash: []string{"sha256"}, LifetimeHours: new(int64(8)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.DhGroup) != 2 || e.DhGroup[0] != "group14" {
		t.Fatalf("dh_group order not preserved: %v", e.DhGroup)
	}
	if e.Lifetime == nil || e.Lifetime.Hours == nil || *e.Lifetime.Hours != 8 {
		t.Fatalf("lifetime hours not set: %+v", e.Lifetime)
	}
	if _, err := buildIkeCryptoProfile(IkeCryptoProfileInput{}); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestIkeCryptoProfileCreateFirewallXpath(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: configSuccessBody},
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="ike-cp"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterIkeCryptoProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ike_crypto_profile_create", Arguments: map[string]any{"name": "ike-cp", "dh_group": []string{"group14"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("create failed: %s", textContent(t, res))
	}
	var sawSet bool
	for _, req := range f.Requests() {
		if req.Get("action") == "set" {
			sawSet = true
			if xp := req.Get("xpath"); !strings.Contains(xp, "ike-crypto-profiles") {
				t.Fatalf("create must target the ike-crypto-profiles xpath: %s", xp)
			}
		}
	}
	if !sawSet {
		t.Fatal("no config set recorded")
	}
}

// --- IPSec crypto profile -----------------------------------------------------

func TestBuildIpsecCryptoProfileEspAh(t *testing.T) {
	esp, err := buildIpsecCryptoProfile(IpsecCryptoProfileInput{
		Name: "ip-cp", DhGroup: new("group14"), EspEncryption: []string{"aes-256-gcm"}, EspAuthentication: []string{"sha256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if esp.Esp == nil || len(esp.Esp.Encryption) != 1 || esp.Esp.Encryption[0] != "aes-256-gcm" {
		t.Fatalf("esp not built: %+v", esp.Esp)
	}
	if esp.Ah != nil {
		t.Fatal("ah must be nil when only esp is provided")
	}
	ah, err := buildIpsecCryptoProfile(IpsecCryptoProfileInput{Name: "ah-cp", AhAuthentication: []string{"sha1"}})
	if err != nil {
		t.Fatal(err)
	}
	if ah.Ah == nil || len(ah.Ah.Authentication) != 1 || ah.Esp != nil {
		t.Fatalf("ah-only profile wrong: esp=%+v ah=%+v", ah.Esp, ah.Ah)
	}
}

func TestIpsecCryptoProfileSummary(t *testing.T) {
	e, err := buildIpsecCryptoProfile(IpsecCryptoProfileInput{Name: "ip-cp", EspEncryption: []string{"aes-128-cbc"}, LifetimeHours: new(int64(1))})
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ipsecCryptoProfileSummary(e))
	esp, ok := m["esp"].(map[string]any)
	if !ok {
		t.Fatalf("esp missing: %v", m)
	}
	if enc, ok := esp["encryption"].([]string); !ok || len(enc) != 1 {
		t.Fatalf("esp encryption wrong: %v", esp["encryption"])
	}
	if _, ok := m["ah"]; ok {
		t.Fatalf("ah must be absent when unset: %v", m)
	}
}

// --- IKE gateway --------------------------------------------------------------

// TestIkeGatewayCryptoProfileRouting pins the correctness point that the crypto
// profile is nested under the active protocol version child (ikev1 vs ikev2),
// never at the Protocol root.
func TestIkeGatewayCryptoProfileRouting(t *testing.T) {
	t.Run("ikev2 default", func(t *testing.T) {
		e, err := buildIkeGateway(IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9"), IkeCryptoProfile: new("ike-cp"), ProtocolVersion: new("ikev2")})
		if err != nil {
			t.Fatal(err)
		}
		if e.Protocol == nil || e.Protocol.Ikev2 == nil || e.Protocol.Ikev2.IkeCryptoProfile == nil || *e.Protocol.Ikev2.IkeCryptoProfile != "ike-cp" {
			t.Fatalf("ikev2 crypto profile not routed under Ikev2: %+v", e.Protocol)
		}
		if e.Protocol.Ikev1 != nil {
			t.Fatalf("ikev1 branch must stay nil for ikev2: %+v", e.Protocol.Ikev1)
		}
	})
	t.Run("ikev1 with exchange mode", func(t *testing.T) {
		e, err := buildIkeGateway(IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9"), IkeCryptoProfile: new("ike-cp"), ProtocolVersion: new("ikev1"), ExchangeMode: new("main")})
		if err != nil {
			t.Fatal(err)
		}
		if e.Protocol.Ikev1 == nil || e.Protocol.Ikev1.IkeCryptoProfile == nil || *e.Protocol.Ikev1.IkeCryptoProfile != "ike-cp" {
			t.Fatalf("ikev1 crypto profile not routed under Ikev1: %+v", e.Protocol)
		}
		if e.Protocol.Ikev1.ExchangeMode == nil || *e.Protocol.Ikev1.ExchangeMode != "main" {
			t.Fatalf("ikev1 exchange mode not set: %+v", e.Protocol.Ikev1)
		}
	})
}

// TestIkeGatewayPSKWriteOnly proves the pre-shared key is applied to the entry
// but never surfaced by the summary; only has_pre_shared_key is exposed.
func TestIkeGatewayPSKWriteOnly(t *testing.T) {
	e, err := buildIkeGateway(IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9"), PreSharedKey: new("s3cr3t")})
	if err != nil {
		t.Fatal(err)
	}
	if e.Authentication == nil || e.Authentication.PreSharedKey == nil || *e.Authentication.PreSharedKey.Key != "s3cr3t" {
		t.Fatalf("psk not applied to entry: %+v", e.Authentication)
	}
	m := asMap(t, ikeGatewaySummary(e))
	if m["has_pre_shared_key"] != true {
		t.Fatalf("has_pre_shared_key must be true: %v", m)
	}
	for k, v := range m {
		if s, ok := v.(string); ok && strings.Contains(s, "s3cr3t") {
			t.Fatalf("summary leaked the pre-shared key in %q: %v", k, v)
		}
	}
}

// TestIkeGatewayGetSingleWrap is a sabotage target: deleting the nameFixAdapter
// wiring in newIkeGatewayService (using the raw gateway.NewService) makes the
// by-name get reach the API unwrapped and this fails.
func TestIkeGatewayGetSingleWrap(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: `<response status="success"><result><entry name="gw1"/></result></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterIkeGatewayTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_ike_gateway_get", Arguments: map[string]any{"name": "gw1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("get failed: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='gw1']")
}

// TestIkeGatewayRenameReject pins the adapter's rename guard for one net-scope
// resource.
func TestIkeGatewayRenameReject(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	svc := newIkeGatewayService(d)
	loc := ikeGatewayParts().ngfw()
	_, err := svc.Update(t.Context(), loc, &gateway.Entry{Name: "gw1"}, "gw2")
	if err == nil || !strings.Contains(err.Error(), "renaming is not supported") {
		t.Fatalf("update with a mismatched name must be rejected: %v", err)
	}
}

// --- IPSec tunnel -------------------------------------------------------------

func TestIpsecTunnelBuildGatewaysOrder(t *testing.T) {
	e, err := buildIpsecTunnel(IpsecTunnelInput{Name: "t", TunnelInterface: new("tunnel.1"),
		IkeGateways: []string{"gw-a", "gw-b", "gw-c"}, IpsecCryptoProfile: new("ip-cp")})
	if err != nil {
		t.Fatal(err)
	}
	if e.AutoKey == nil || len(e.AutoKey.IkeGateway) != 3 {
		t.Fatalf("ike gateways not built: %+v", e.AutoKey)
	}
	want := []string{"gw-a", "gw-b", "gw-c"}
	for i, g := range e.AutoKey.IkeGateway {
		if g.Name != want[i] {
			t.Fatalf("gateway order not preserved at %d: got %q want %q", i, g.Name, want[i])
		}
	}
	if e.AutoKey.IpsecCryptoProfile == nil || *e.AutoKey.IpsecCryptoProfile != "ip-cp" {
		t.Fatalf("ipsec crypto profile not set: %+v", e.AutoKey)
	}
}

// TestIpsecTunnelSummaryTriState is a sabotage target: replacing the
// putBool(m, "disabled", e.Disabled) call in ipsecTunnelSummary with
// m["disabled"] = boolVal(e.Disabled) makes the nil case report false and this
// fails.
func TestIpsecTunnelSummaryTriState(t *testing.T) {
	t.Run("nil disabled is omitted", func(t *testing.T) {
		m := asMap(t, ipsecTunnelSummary(&ipsec.Entry{Name: "t"}))
		if _, ok := m["disabled"]; ok {
			t.Fatalf("a nil disabled must be omitted, got %v", m["disabled"])
		}
	})
	t.Run("explicit false reports false", func(t *testing.T) {
		m := asMap(t, ipsecTunnelSummary(&ipsec.Entry{Name: "t", Disabled: new(false)}))
		if v, ok := m["disabled"]; !ok || v != false {
			t.Fatalf("an explicit false disabled must report false, got ok=%v v=%v", ok, v)
		}
	})
}

// --- GRE tunnel ---------------------------------------------------------------

func TestBuildGreTunnelAndSummary(t *testing.T) {
	e, err := buildGreTunnel(GreTunnelInput{Name: "g", TunnelInterface: new("tunnel.2"),
		LocalInterface: new("ethernet1/1"), PeerIp: new("198.51.100.2"), Ttl: new(int64(64)),
		KeepAliveEnable: new(true), KeepAliveInterval: new(int64(10))})
	if err != nil {
		t.Fatal(err)
	}
	if e.PeerAddress == nil || e.PeerAddress.Ip == nil || *e.PeerAddress.Ip != "198.51.100.2" {
		t.Fatalf("peer ip not set: %+v", e.PeerAddress)
	}
	m := asMap(t, greTunnelSummary(e))
	if m["ttl"] != int64(64) {
		t.Fatalf("ttl wrong: %v", m["ttl"])
	}
	ka, ok := m["keep_alive"].(map[string]any)
	if !ok || ka["enable"] != true || ka["interval"] != int64(10) {
		t.Fatalf("keep_alive wrong: %v", m["keep_alive"])
	}
}

// --- read-only gating ---------------------------------------------------------

func TestVpnReadOnlyGating(t *testing.T) {
	cases := []struct {
		register func(*mcp.Server, *Deps)
		base     string
	}{
		{RegisterIkeCryptoProfileTools, "panos_ike_crypto_profile"},
		{RegisterIpsecCryptoProfileTools, "panos_ipsec_crypto_profile"},
		{RegisterIkeGatewayTools, "panos_ike_gateway"},
		{RegisterIpsecTunnelTools, "panos_ipsec_tunnel"},
		{RegisterGreTunnelTools, "panos_gre_tunnel"},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			reads := []string{c.base + "_list", c.base + "_get"}
			writes := []string{c.base + "_create", c.base + "_update", c.base + "_delete"}
			assertReadOnlyGating(t, c.register, reads, writes)
		})
	}
}

// --- update / read-modify-write coverage --------------------------------------

// TestIkeGatewayPeerMutualExclusion pins that the peer address is a mutually
// exclusive choice: overlaying one form clears the others, so switching the peer
// type on an update never leaves two children the device rejects. Sabotage:
// replacing the sibling-clearing switch in applyIkeGatewayPeer with plain setPtr
// calls turns the "must be cleared" subtests red.
func TestIkeGatewayPeerMutualExclusion(t *testing.T) {
	t.Run("switch fqdn to ip clears fqdn", func(t *testing.T) {
		e := &gateway.Entry{Name: "gw", PeerAddress: &gateway.PeerAddress{Fqdn: new("vpn.example.com")}}
		if err := overlayIkeGateway(e, IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9")}); err != nil {
			t.Fatal(err)
		}
		if e.PeerAddress.Ip == nil || *e.PeerAddress.Ip != "203.0.113.9" {
			t.Fatalf("peer ip not set: %+v", e.PeerAddress)
		}
		if e.PeerAddress.Fqdn != nil {
			t.Fatalf("peer fqdn must be cleared when switching to ip: %+v", e.PeerAddress)
		}
	})
	t.Run("switch dynamic to ip clears dynamic", func(t *testing.T) {
		e := &gateway.Entry{Name: "gw", PeerAddress: &gateway.PeerAddress{Dynamic: &gateway.PeerAddressDynamic{}}}
		if err := overlayIkeGateway(e, IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9")}); err != nil {
			t.Fatal(err)
		}
		if e.PeerAddress.Dynamic != nil {
			t.Fatalf("peer dynamic must be cleared when switching to ip: %+v", e.PeerAddress)
		}
	})
	t.Run("omitting all peer fields preserves the existing peer address", func(t *testing.T) {
		e := &gateway.Entry{Name: "gw", PeerAddress: &gateway.PeerAddress{Ip: new("198.51.100.1")}}
		if err := overlayIkeGateway(e, IkeGatewayInput{Name: "gw", Disabled: new(true)}); err != nil {
			t.Fatal(err)
		}
		if e.PeerAddress == nil || e.PeerAddress.Ip == nil || *e.PeerAddress.Ip != "198.51.100.1" {
			t.Fatalf("existing peer ip must be preserved when no peer field is provided: %+v", e.PeerAddress)
		}
	})
	t.Run("more than one peer form is rejected", func(t *testing.T) {
		if _, err := buildIkeGateway(IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9"), PeerFqdn: new("vpn.example.com")}); err == nil || !strings.Contains(err.Error(), "at most one of peer_ip") {
			t.Fatalf("providing two peer forms must be rejected: %v", err)
		}
	})
}

// TestOverlayIpsecTunnelReplaceAndPreserve pins the read-modify-write contract:
// a provided ike_gateways list replaces fully and in order, while fields the
// update omits keep their current values. Sabotage: changing
// "e.AutoKey.IkeGateway = gws" to an append in applyIpsecTunnel breaks the
// replace-in-order check; replacing setPtr(&e.Comment, in.Comment) with an
// unconditional assignment breaks the omitted-comment-preserved check.
func TestOverlayIpsecTunnelReplaceAndPreserve(t *testing.T) {
	e := &ipsec.Entry{Name: "t1", Comment: new("orig"),
		AutoKey: &ipsec.AutoKey{IkeGateway: []ipsec.AutoKeyIkeGateway{{Name: "gw-a"}}, IpsecCryptoProfile: new("cp-1")}}
	// Provide only the gateway list: it replaces fully; comment and profile survive.
	if err := overlayIpsecTunnel(e, IpsecTunnelInput{Name: "t1", IkeGateways: []string{"gw-x", "gw-y"}}); err != nil {
		t.Fatal(err)
	}
	got := ipsecTunnelGateways(e.AutoKey)
	if len(got) != 2 || got[0] != "gw-x" || got[1] != "gw-y" {
		t.Fatalf("ike gateways not replaced in order: %v", got)
	}
	if e.Comment == nil || *e.Comment != "orig" {
		t.Fatalf("omitted comment must be preserved: %+v", e.Comment)
	}
	if e.AutoKey.IpsecCryptoProfile == nil || *e.AutoKey.IpsecCryptoProfile != "cp-1" {
		t.Fatalf("omitted ipsec_crypto_profile must be preserved: %+v", e.AutoKey)
	}
	// Omitting the gateway list on a later update leaves the current gateways in place.
	if err := overlayIpsecTunnel(e, IpsecTunnelInput{Name: "t1", Comment: new("changed")}); err != nil {
		t.Fatal(err)
	}
	if got := ipsecTunnelGateways(e.AutoKey); len(got) != 2 || got[0] != "gw-x" {
		t.Fatalf("omitted ike_gateways must be preserved: %v", got)
	}
}

// TestIpsecTunnelUpdateViaRegisteredTool drives panos_ipsec_tunnel_update over a
// registered server so the net-scope update handler and the read-modify-write
// wire path are exercised end to end: it reads the current entry (wrapped once)
// then writes the changed field through a multi-config request.
func TestIpsecTunnelUpdateViaRegisteredTool(t *testing.T) {
	ctx := t.Context()
	// The current entry must differ from the update input, or pango's
	// UpdateWithXpath short-circuits on SpecMatches and issues no multi-config.
	current := `<response status="success"><result><entry name="t1"><tunnel-interface>tunnel.1</tunnel-interface></entry></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("get"), Body: current},
		fakeRoute{Match: configAction("multi-config"), Body: configSuccessBody},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterIpsecTunnelTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "panos_ipsec_tunnel_update", Arguments: map[string]any{"name": "t1", "tunnel_interface": "tunnel.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("registered ipsec tunnel update failed: %s", textContent(t, res))
	}
	assertSingleWrappedGet(t, f, "entry[@name='t1']")
	if el := multiConfigElement(t, f); !strings.Contains(el, "tunnel.2") {
		t.Fatalf("registered update did not reach the API with the new interface: %s", el)
	}
}

// TestOverlayIkeCryptoProfileReplaceAndPreserve pins that a provided ordered
// list replaces fully while an omitted lifetime is preserved on update.
func TestOverlayIkeCryptoProfileReplaceAndPreserve(t *testing.T) {
	e, err := buildIkeCryptoProfile(IkeCryptoProfileInput{Name: "cp", DhGroup: []string{"group14"}, LifetimeHours: new(int64(8))})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayIkeCryptoProfile(e, IkeCryptoProfileInput{Name: "cp", DhGroup: []string{"group20", "group19"}}); err != nil {
		t.Fatal(err)
	}
	if len(e.DhGroup) != 2 || e.DhGroup[0] != "group20" || e.DhGroup[1] != "group19" {
		t.Fatalf("dh_group not replaced in order: %v", e.DhGroup)
	}
	if e.Lifetime == nil || e.Lifetime.Hours == nil || *e.Lifetime.Hours != 8 {
		t.Fatalf("omitted lifetime must be preserved: %+v", e.Lifetime)
	}
}

// TestIkeGatewayCryptoProfileVersionSwitch pins that the summary reports the
// crypto profile of the ACTIVE protocol version. Because applyIkeGatewayProtocol
// leaves the inactive version's child in place, a gateway switched from ikev2 to
// ikev1 still carries the old ikev2 profile; the summary must follow Version.
// Sabotage: reading p.Ikev2 before checking p.Version in ikeGatewayCryptoProfile
// makes this report the stale "cp-v2".
func TestIkeGatewayCryptoProfileVersionSwitch(t *testing.T) {
	e, err := buildIkeGateway(IkeGatewayInput{Name: "gw", PeerIp: new("203.0.113.9"), ProtocolVersion: new("ikev2"), IkeCryptoProfile: new("cp-v2")})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayIkeGateway(e, IkeGatewayInput{Name: "gw", ProtocolVersion: new("ikev1"), IkeCryptoProfile: new("cp-v1")}); err != nil {
		t.Fatal(err)
	}
	m := asMap(t, ikeGatewaySummary(e))
	if m["protocol_version"] != "ikev1" {
		t.Fatalf("protocol_version must be ikev1: %v", m["protocol_version"])
	}
	if m["ike_crypto_profile"] != "cp-v1" {
		t.Fatalf("summary must report the active ikev1 profile after a version switch, got %v", m["ike_crypto_profile"])
	}
}

// TestIkeCryptoLifetimeUnitSwitch pins that lifetime is a single-unit choice:
// switching the unit on update clears the previous unit, and providing two units
// is rejected. Sabotage: reverting applyIkeCryptoLifetime to independent setPtr
// calls leaves the old unit set and the "cleared" check fails.
func TestIkeCryptoLifetimeUnitSwitch(t *testing.T) {
	e, err := buildIkeCryptoProfile(IkeCryptoProfileInput{Name: "cp", LifetimeHours: new(int64(8))})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayIkeCryptoProfile(e, IkeCryptoProfileInput{Name: "cp", LifetimeSeconds: new(int64(28800))}); err != nil {
		t.Fatal(err)
	}
	if e.Lifetime == nil || e.Lifetime.Hours != nil {
		t.Fatalf("previous lifetime unit (hours) must be cleared on a unit switch: %+v", e.Lifetime)
	}
	if e.Lifetime.Seconds == nil || *e.Lifetime.Seconds != 28800 {
		t.Fatalf("new lifetime unit (seconds) must be set: %+v", e.Lifetime)
	}
	if _, err := buildIkeCryptoProfile(IkeCryptoProfileInput{Name: "cp", LifetimeHours: new(int64(8)), LifetimeDays: new(int64(1))}); err == nil || !strings.Contains(err.Error(), "at most one lifetime unit") {
		t.Fatalf("two lifetime units must be rejected: %v", err)
	}
}

// TestOverlayIpsecCryptoProfileUnitSwitch pins the same single-unit choice for
// the IPSec profile's lifetime AND lifesize, and that an omitted esp block is
// preserved across the update.
func TestOverlayIpsecCryptoProfileUnitSwitch(t *testing.T) {
	e, err := buildIpsecCryptoProfile(IpsecCryptoProfileInput{Name: "cp", EspEncryption: []string{"aes-256-gcm"},
		LifetimeHours: new(int64(8)), LifesizeGb: new(int64(10))})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayIpsecCryptoProfile(e, IpsecCryptoProfileInput{Name: "cp", LifetimeSeconds: new(int64(28800)), LifesizeMb: new(int64(5000))}); err != nil {
		t.Fatal(err)
	}
	if e.Lifetime == nil || e.Lifesize == nil {
		t.Fatalf("lifetime and lifesize must be present after the switch: %+v %+v", e.Lifetime, e.Lifesize)
	}
	mustNilInt64(t, e.Lifetime.Hours, "lifetime hours cleared on unit switch")
	mustInt64(t, e.Lifetime.Seconds, 28800, "new lifetime seconds")
	mustNilInt64(t, e.Lifesize.Gb, "lifesize gb cleared on unit switch")
	mustInt64(t, e.Lifesize.Mb, 5000, "new lifesize mb")
	if e.Esp == nil || len(e.Esp.Encryption) != 1 || e.Esp.Encryption[0] != "aes-256-gcm" {
		t.Fatalf("omitted esp must be preserved: %+v", e.Esp)
	}
	if _, err := buildIpsecCryptoProfile(IpsecCryptoProfileInput{Name: "cp", LifesizeGb: new(int64(1)), LifesizeTb: new(int64(1))}); err == nil || !strings.Contains(err.Error(), "at most one lifesize unit") {
		t.Fatalf("two lifesize units must be rejected: %v", err)
	}
}

// mustInt64 fails unless got points to want; mustNilInt64 fails unless got is
// nil. They keep the single-unit-choice assertions out of the test bodies so the
// tests stay under the cyclomatic-complexity limit.
func mustInt64(t *testing.T, got *int64, want int64, label string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s: want %d, got %v", label, want, got)
	}
}

func mustNilInt64(t *testing.T, got *int64, label string) {
	t.Helper()
	if got != nil {
		t.Fatalf("%s: want nil, got %d", label, *got)
	}
}

// TestOverlayGreTunnelPreservesOnOmit covers the GRE tunnel overlay path: a
// provided field replaces, an omitted one is left untouched.
func TestOverlayGreTunnelPreservesOnOmit(t *testing.T) {
	e, err := buildGreTunnel(GreTunnelInput{Name: "g", TunnelInterface: new("tunnel.2"), Ttl: new(int64(64)), PeerIp: new("198.51.100.2")})
	if err != nil {
		t.Fatal(err)
	}
	if err := overlayGreTunnel(e, GreTunnelInput{Name: "g", Ttl: new(int64(128))}); err != nil {
		t.Fatal(err)
	}
	if e.Ttl == nil || *e.Ttl != 128 {
		t.Fatalf("provided ttl must replace: %+v", e.Ttl)
	}
	if e.TunnelInterface == nil || *e.TunnelInterface != "tunnel.2" {
		t.Fatalf("omitted tunnel_interface must be preserved: %+v", e.TunnelInterface)
	}
	if e.PeerAddress == nil || e.PeerAddress.Ip == nil || *e.PeerAddress.Ip != "198.51.100.2" {
		t.Fatalf("omitted peer ip must be preserved: %+v", e.PeerAddress)
	}
}
