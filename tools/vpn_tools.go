package tools

import (
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PaloAltoNetworks/pango/crypto/ike/gateway"
	"github.com/PaloAltoNetworks/pango/network/tunnel/gre"
	"github.com/PaloAltoNetworks/pango/network/tunnel/ipsec"
	"github.com/PaloAltoNetworks/pango/objects/profiles/ikecrypto"
	"github.com/PaloAltoNetworks/pango/objects/profiles/ipseccrypto"
)

// ikeVersion1 is the PAN-OS IKE protocol version value that carries the ikev1
// crypto-profile and exchange-mode children.
const ikeVersion1 = "ikev1"

// strList maps a nil slice to a non-nil empty slice so a summary renders [] and
// not null for an absent ordered list.
func strList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// The five site-to-site VPN resources (IKE and IPSec crypto profiles, IKE
// gateway, IPSec tunnel, GRE tunnel) all live at a network scope pango models as
// {Ngfw | Template | TemplateStack}, so they share the net-scope resolver
// (resolveNetScope) rather than the object LocationInput model. They are not
// Panorama-only: on a firewall they resolve to the Ngfw scope.

// ---------------------------------------------------------------------------
// IKE crypto profile (objects/profiles/ikecrypto)
// ---------------------------------------------------------------------------

func newIkeCryptoProfileService(d *Deps) nameFixAdapter[ikecrypto.Location, ikecrypto.Entry] {
	return nameFixAdapter[ikecrypto.Location, ikecrypto.Entry]{
		svc:    ikecrypto.NewService(d.Client),
		client: d.Client,
		name:   func(e *ikecrypto.Entry) string { return e.Name },
	}
}

func ikeCryptoProfileParts() netScopeParts[ikecrypto.Location] {
	return netScopeParts[ikecrypto.Location]{
		ngfw: func() ikecrypto.Location {
			return ikecrypto.Location{Ngfw: &ikecrypto.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ikecrypto.Location {
			return ikecrypto.Location{Template: &ikecrypto.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ikecrypto.Location {
			return ikecrypto.Location{TemplateStack: &ikecrypto.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// IkeCryptoProfileInput is the input for the IKE crypto profile create and
// update tools. DhGroup, Encryption and Hash are ordered lists replaced fully on
// update. The lifetime values are a single-unit choice: at most one unit may be
// set, and on update the chosen unit replaces the others so a unit switch does
// not leave a multi-unit lifetime the device rejects.
type IkeCryptoProfileInput struct {
	NetScopeInput
	Name                   string   `json:"name" jsonschema:"IKE crypto profile name"`
	DhGroup                []string `json:"dh_group,omitempty" jsonschema:"Diffie-Hellman groups in preference order, e.g. group2, group14, group19, group20"`
	Encryption             []string `json:"encryption,omitempty" jsonschema:"Encryption algorithms in preference order, e.g. aes-256-cbc, aes-256-gcm, aes-128-cbc, 3des"`
	Hash                   []string `json:"hash,omitempty" jsonschema:"Authentication hashes in preference order, e.g. sha256, sha384, sha512, sha1"`
	AuthenticationMultiple *int64   `json:"authentication_multiple,omitempty" jsonschema:"IKEv2 re-authentication interval as a multiple of the key lifetime (0 disables); omit to keep the device default"`
	LifetimeSeconds        *int64   `json:"lifetime_seconds,omitempty" jsonschema:"Key lifetime in seconds; set at most one lifetime unit"`
	LifetimeMinutes        *int64   `json:"lifetime_minutes,omitempty" jsonschema:"Key lifetime in minutes; set at most one lifetime unit"`
	LifetimeHours          *int64   `json:"lifetime_hours,omitempty" jsonschema:"Key lifetime in hours; set at most one lifetime unit"`
	LifetimeDays           *int64   `json:"lifetime_days,omitempty" jsonschema:"Key lifetime in days; set at most one lifetime unit"`
}

// countInt64Ptrs reports how many of the given optional int64 inputs are set.
// The lifetime and lifesize choices are single-unit, so a caller may provide at
// most one.
func countInt64Ptrs(ps ...*int64) int {
	n := 0
	for _, p := range ps {
		if p != nil {
			n++
		}
	}
	return n
}

// applyIkeCryptoLifetime sets the lifetime, a single-unit choice. Providing more
// than one unit is rejected; providing exactly one sets it and clears the other
// three so a unit switch on update does not leave a multi-unit lifetime the
// device rejects. Any Misc on the Lifetime node is preserved.
func applyIkeCryptoLifetime(e *ikecrypto.Entry, in *IkeCryptoProfileInput) error {
	n := countInt64Ptrs(in.LifetimeSeconds, in.LifetimeMinutes, in.LifetimeHours, in.LifetimeDays)
	if n == 0 {
		return nil
	}
	if n > 1 {
		return errors.New("at most one lifetime unit (lifetime_seconds, lifetime_minutes, lifetime_hours, lifetime_days) may be set")
	}
	lt := e.Lifetime
	if lt == nil {
		lt = &ikecrypto.Lifetime{}
		e.Lifetime = lt
	}
	lt.Seconds, lt.Minutes, lt.Hours, lt.Days = in.LifetimeSeconds, in.LifetimeMinutes, in.LifetimeHours, in.LifetimeDays
	return nil
}

func applyIkeCryptoProfile(e *ikecrypto.Entry, in *IkeCryptoProfileInput) error {
	if in.DhGroup != nil {
		e.DhGroup = in.DhGroup
	}
	if in.Encryption != nil {
		e.Encryption = in.Encryption
	}
	if in.Hash != nil {
		e.Hash = in.Hash
	}
	setPtr(&e.AuthenticationMultiple, in.AuthenticationMultiple)
	return applyIkeCryptoLifetime(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildIkeCryptoProfile(in IkeCryptoProfileInput) (*ikecrypto.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ikecrypto.Entry{Name: in.Name}
	if err := applyIkeCryptoProfile(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayIkeCryptoProfile(e *ikecrypto.Entry, in IkeCryptoProfileInput) error {
	return applyIkeCryptoProfile(e, &in)
}

// lifetimeMap renders a lifetime node as a map, emitting only the units that are
// set. Shared by the IKE and IPSec crypto profile summaries, whose Lifetime
// structs are distinct pango types with the same four *int64 unit fields.
func lifetimeMap(seconds, minutes, hours, days *int64) map[string]any {
	lm := map[string]any{}
	putInt(lm, "seconds", seconds)
	putInt(lm, "minutes", minutes)
	putInt(lm, "hours", hours)
	putInt(lm, "days", days)
	return lm
}

func ikeCryptoProfileSummary(e *ikecrypto.Entry) any {
	m := map[string]any{
		tagNameKey:   e.Name,
		"dh_group":   strList(e.DhGroup),
		"encryption": strList(e.Encryption),
		"hash":       strList(e.Hash),
	}
	putInt(m, "authentication_multiple", e.AuthenticationMultiple)
	if lt := e.Lifetime; lt != nil {
		m["lifetime"] = lifetimeMap(lt.Seconds, lt.Minutes, lt.Hours, lt.Days)
	}
	return m
}

// RegisterIkeCryptoProfileTools registers the IKE crypto profile tools.
func RegisterIkeCryptoProfileTools(s *mcp.Server, d *Deps) {
	svc := newIkeCryptoProfileService(d)
	parts := ikeCryptoProfileParts()
	scope := func(in IkeCryptoProfileInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_crypto_profile_list",
		Description: "List IKE crypto profiles (IKE phase-1 SA parameters). Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List IKE crypto profiles"),
	}, netListHandler(d, "panos_ike_crypto_profile_list", svc, parts, svc.name, ikeCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_crypto_profile_get",
		Description: "Get one IKE crypto profile (dh_group, encryption, hash, lifetime). Read-only.",
		Annotations: readOnlyTool("Get IKE crypto profile"),
	}, netGetHandler(d, "panos_ike_crypto_profile_get", svc, parts, ikeCryptoProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_crypto_profile_create",
		Description: "Create an IKE crypto profile in the candidate config. An IKE gateway references it by name. Run panos_commit to apply.",
		Annotations: createTool("Create IKE crypto profile"),
	}, netCreateHandler(d, "panos_ike_crypto_profile_create", svc, parts, scope, buildIkeCryptoProfile, ikeCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_crypto_profile_update",
		Description: "Update an IKE crypto profile: read-modify-write, only provided fields change; a provided dh_group, encryption or hash list replaces the existing one fully. Run panos_commit to apply.",
		Annotations: updateTool("Update IKE crypto profile"),
	}, netUpdateHandler(d, "panos_ike_crypto_profile_update", svc, parts, scope,
		func(in IkeCryptoProfileInput) string { return in.Name }, overlayIkeCryptoProfile, ikeCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_crypto_profile_delete",
		Description: "Delete an IKE crypto profile from the candidate config. Fails while an IKE gateway still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IKE crypto profile"),
	}, netDeleteHandler(d, "panos_ike_crypto_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// IPSec crypto profile (objects/profiles/ipseccrypto)
// ---------------------------------------------------------------------------

func newIpsecCryptoProfileService(d *Deps) nameFixAdapter[ipseccrypto.Location, ipseccrypto.Entry] {
	return nameFixAdapter[ipseccrypto.Location, ipseccrypto.Entry]{
		svc:    ipseccrypto.NewService(d.Client),
		client: d.Client,
		name:   func(e *ipseccrypto.Entry) string { return e.Name },
	}
}

func ipsecCryptoProfileParts() netScopeParts[ipseccrypto.Location] {
	return netScopeParts[ipseccrypto.Location]{
		ngfw: func() ipseccrypto.Location {
			return ipseccrypto.Location{Ngfw: &ipseccrypto.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ipseccrypto.Location {
			return ipseccrypto.Location{Template: &ipseccrypto.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ipseccrypto.Location {
			return ipseccrypto.Location{TemplateStack: &ipseccrypto.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// IpsecCryptoProfileInput is the input for the IPSec crypto profile create and
// update tools. ESP and AH are mutually exclusive at PAN-OS (esp is the common
// choice); this server sets whichever the caller provides and lets the device
// validate. The encryption and authentication lists are ordered and replaced
// fully on update. Lifetime and lifesize are each a single-unit choice: at most
// one unit may be set per group, and on update the chosen unit replaces the
// others in that group.
type IpsecCryptoProfileInput struct {
	NetScopeInput
	Name              string   `json:"name" jsonschema:"IPSec crypto profile name"`
	DhGroup           *string  `json:"dh_group,omitempty" jsonschema:"Perfect-forward-secrecy DH group, e.g. group2, group14, group19, group20, or no-pfs; omit to keep the device default"`
	EspEncryption     []string `json:"esp_encryption,omitempty" jsonschema:"ESP encryption algorithms in preference order, e.g. aes-256-gcm, aes-256-cbc, aes-128-cbc, 3des, null"`
	EspAuthentication []string `json:"esp_authentication,omitempty" jsonschema:"ESP authentication algorithms in preference order, e.g. sha256, sha1, none"`
	AhAuthentication  []string `json:"ah_authentication,omitempty" jsonschema:"AH authentication algorithms in preference order, e.g. sha256, sha1 (mutually exclusive with esp)"`
	LifetimeSeconds   *int64   `json:"lifetime_seconds,omitempty" jsonschema:"Key lifetime in seconds; set at most one lifetime unit"`
	LifetimeMinutes   *int64   `json:"lifetime_minutes,omitempty" jsonschema:"Key lifetime in minutes; set at most one lifetime unit"`
	LifetimeHours     *int64   `json:"lifetime_hours,omitempty" jsonschema:"Key lifetime in hours; set at most one lifetime unit"`
	LifetimeDays      *int64   `json:"lifetime_days,omitempty" jsonschema:"Key lifetime in days; set at most one lifetime unit"`
	LifesizeKb        *int64   `json:"lifesize_kb,omitempty" jsonschema:"Key lifesize in kilobytes; set at most one lifesize unit"`
	LifesizeMb        *int64   `json:"lifesize_mb,omitempty" jsonschema:"Key lifesize in megabytes; set at most one lifesize unit"`
	LifesizeGb        *int64   `json:"lifesize_gb,omitempty" jsonschema:"Key lifesize in gigabytes; set at most one lifesize unit"`
	LifesizeTb        *int64   `json:"lifesize_tb,omitempty" jsonschema:"Key lifesize in terabytes; set at most one lifesize unit"`
}

// applyIpsecCryptoLifetime sets the lifetime and lifesize, two independent
// single-unit choices. Providing more than one unit within a group is rejected;
// providing exactly one sets it and clears the others in that group so a unit
// switch on update does not leave a multi-unit value the device rejects. Any
// Misc on either node is preserved.
func applyIpsecCryptoLifetime(e *ipseccrypto.Entry, in *IpsecCryptoProfileInput) error {
	switch n := countInt64Ptrs(in.LifetimeSeconds, in.LifetimeMinutes, in.LifetimeHours, in.LifetimeDays); {
	case n > 1:
		return errors.New("at most one lifetime unit (lifetime_seconds, lifetime_minutes, lifetime_hours, lifetime_days) may be set")
	case n == 1:
		lt := e.Lifetime
		if lt == nil {
			lt = &ipseccrypto.Lifetime{}
			e.Lifetime = lt
		}
		lt.Seconds, lt.Minutes, lt.Hours, lt.Days = in.LifetimeSeconds, in.LifetimeMinutes, in.LifetimeHours, in.LifetimeDays
	}
	switch n := countInt64Ptrs(in.LifesizeKb, in.LifesizeMb, in.LifesizeGb, in.LifesizeTb); {
	case n > 1:
		return errors.New("at most one lifesize unit (lifesize_kb, lifesize_mb, lifesize_gb, lifesize_tb) may be set")
	case n == 1:
		ls := e.Lifesize
		if ls == nil {
			ls = &ipseccrypto.Lifesize{}
			e.Lifesize = ls
		}
		ls.Kb, ls.Mb, ls.Gb, ls.Tb = in.LifesizeKb, in.LifesizeMb, in.LifesizeGb, in.LifesizeTb
	}
	return nil
}

func applyIpsecCryptoProfile(e *ipseccrypto.Entry, in *IpsecCryptoProfileInput) error {
	setPtr(&e.DhGroup, in.DhGroup)
	espProvided := in.EspEncryption != nil || in.EspAuthentication != nil
	ahProvided := in.AhAuthentication != nil
	// PAN-OS rejects a profile carrying both <esp> and <ah>. Update is
	// read-modify-write, so a provided block clears the opposite sibling the
	// stored entry may still hold; providing both is a caller error, and
	// providing neither leaves both untouched (preserve on a no-op update).
	if espProvided && ahProvided {
		return errors.New("esp and ah are mutually exclusive; provide esp_* or ah_*, not both")
	}
	if espProvided {
		esp := e.Esp
		if esp == nil {
			esp = &ipseccrypto.Esp{}
			e.Esp = esp
		}
		if in.EspEncryption != nil {
			esp.Encryption = in.EspEncryption
		}
		if in.EspAuthentication != nil {
			esp.Authentication = in.EspAuthentication
		}
		e.Ah = nil
	}
	if ahProvided {
		ah := e.Ah
		if ah == nil {
			ah = &ipseccrypto.Ah{}
			e.Ah = ah
		}
		ah.Authentication = in.AhAuthentication
		e.Esp = nil
	}
	return applyIpsecCryptoLifetime(e, in)
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildIpsecCryptoProfile(in IpsecCryptoProfileInput) (*ipseccrypto.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ipseccrypto.Entry{Name: in.Name}
	if err := applyIpsecCryptoProfile(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayIpsecCryptoProfile(e *ipseccrypto.Entry, in IpsecCryptoProfileInput) error {
	return applyIpsecCryptoProfile(e, &in)
}

func ipsecCryptoProfileSummary(e *ipseccrypto.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["dh_group"] = strVal(e.DhGroup)
	if esp := e.Esp; esp != nil {
		m["esp"] = map[string]any{
			"encryption":     strList(esp.Encryption),
			"authentication": strList(esp.Authentication),
		}
	}
	if ah := e.Ah; ah != nil {
		m["ah"] = map[string]any{"authentication": strList(ah.Authentication)}
	}
	if lt := e.Lifetime; lt != nil {
		m["lifetime"] = lifetimeMap(lt.Seconds, lt.Minutes, lt.Hours, lt.Days)
	}
	if ls := e.Lifesize; ls != nil {
		lm := map[string]any{}
		putInt(lm, "kb", ls.Kb)
		putInt(lm, "mb", ls.Mb)
		putInt(lm, "gb", ls.Gb)
		putInt(lm, "tb", ls.Tb)
		m["lifesize"] = lm
	}
	return m
}

// RegisterIpsecCryptoProfileTools registers the IPSec crypto profile tools.
func RegisterIpsecCryptoProfileTools(s *mcp.Server, d *Deps) {
	svc := newIpsecCryptoProfileService(d)
	parts := ipsecCryptoProfileParts()
	scope := func(in IpsecCryptoProfileInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_crypto_profile_list",
		Description: "List IPSec crypto profiles (IPSec phase-2 SA parameters). Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List IPSec crypto profiles"),
	}, netListHandler(d, "panos_ipsec_crypto_profile_list", svc, parts, svc.name, ipsecCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_crypto_profile_get",
		Description: "Get one IPSec crypto profile (dh_group, esp/ah algorithms, lifetime, lifesize). Read-only.",
		Annotations: readOnlyTool("Get IPSec crypto profile"),
	}, netGetHandler(d, "panos_ipsec_crypto_profile_get", svc, parts, ipsecCryptoProfileSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_crypto_profile_create",
		Description: "Create an IPSec crypto profile in the candidate config. An IPSec tunnel references it by name. Run panos_commit to apply.",
		Annotations: createTool("Create IPSec crypto profile"),
	}, netCreateHandler(d, "panos_ipsec_crypto_profile_create", svc, parts, scope, buildIpsecCryptoProfile, ipsecCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_crypto_profile_update",
		Description: "Update an IPSec crypto profile: read-modify-write, only provided fields change; a provided algorithm list replaces the existing one fully. Run panos_commit to apply.",
		Annotations: updateTool("Update IPSec crypto profile"),
	}, netUpdateHandler(d, "panos_ipsec_crypto_profile_update", svc, parts, scope,
		func(in IpsecCryptoProfileInput) string { return in.Name }, overlayIpsecCryptoProfile, ipsecCryptoProfileSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_crypto_profile_delete",
		Description: "Delete an IPSec crypto profile from the candidate config. Fails while an IPSec tunnel still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IPSec crypto profile"),
	}, netDeleteHandler(d, "panos_ipsec_crypto_profile_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// IKE gateway (crypto/ike/gateway)
// ---------------------------------------------------------------------------

func newIkeGatewayService(d *Deps) nameFixAdapter[gateway.Location, gateway.Entry] {
	return nameFixAdapter[gateway.Location, gateway.Entry]{
		svc:    gateway.NewService(d.Client),
		client: d.Client,
		name:   func(e *gateway.Entry) string { return e.Name },
	}
}

func ikeGatewayParts() netScopeParts[gateway.Location] {
	return netScopeParts[gateway.Location]{
		ngfw: func() gateway.Location {
			return gateway.Location{Ngfw: &gateway.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) gateway.Location {
			return gateway.Location{Template: &gateway.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) gateway.Location {
			return gateway.Location{TemplateStack: &gateway.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// IkeGatewayInput is the input for the IKE gateway create and update tools. It
// models the practical peer/local address, protocol version, crypto-profile
// reference and pre-shared-key subset; the deeper certificate-auth, DPD,
// fragmentation and NAT-traversal subtrees are preserved verbatim across an
// update through pango's Misc round-trip and are not managed here. The
// pre-shared key is write-only: it is never returned by any tool.
type IkeGatewayInput struct {
	NetScopeInput
	Name             string  `json:"name" jsonschema:"IKE gateway name"`
	Disabled         *bool   `json:"disabled,omitempty" jsonschema:"Disable the gateway; omit to keep the device default"`
	Ipv6             *bool   `json:"ipv6,omitempty" jsonschema:"Use IPv6 for the gateway; omit to keep the device default"`
	PeerIp           *string `json:"peer_ip,omitempty" jsonschema:"Static peer IP address (mutually exclusive with peer_fqdn and peer_dynamic)"`
	PeerFqdn         *string `json:"peer_fqdn,omitempty" jsonschema:"Peer FQDN (mutually exclusive with peer_ip and peer_dynamic)"`
	PeerDynamic      *bool   `json:"peer_dynamic,omitempty" jsonschema:"Set true for a dynamic peer address (mutually exclusive with peer_ip and peer_fqdn)"`
	LocalInterface   *string `json:"local_interface,omitempty" jsonschema:"Local interface the gateway binds to, e.g. ethernet1/1"`
	LocalIp          *string `json:"local_ip,omitempty" jsonschema:"Local IP address on the interface, e.g. 203.0.113.1 or 203.0.113.1/24"`
	ProtocolVersion  *string `json:"protocol_version,omitempty" jsonschema:"IKE protocol version: ikev1, ikev2, or ikev2-preferred; selects which child the crypto profile is set under"`
	ExchangeMode     *string `json:"exchange_mode,omitempty" jsonschema:"IKEv1 exchange mode: auto, main, or aggressive (IKEv1 only)"`
	IkeCryptoProfile *string `json:"ike_crypto_profile,omitempty" jsonschema:"Name of an IKE crypto profile in the same scope (see panos_ike_crypto_profile_list)"`
	PreSharedKey     *string `json:"pre_shared_key,omitempty" jsonschema:"Pre-shared key for authentication; write-only, never returned"`
}

// applyIkeGatewayPeer sets the peer address. Static IP, FQDN, and dynamic are a
// mutually exclusive choice in PAN-OS, so providing one clears the other two:
// an update that switches the peer type would otherwise leave two children
// under the choice node, which the device rejects. Providing none leaves the
// existing peer address untouched. Any Misc on PeerAddress is preserved.
func applyIkeGatewayPeer(e *gateway.Entry, in *IkeGatewayInput) error {
	dynamic := in.PeerDynamic != nil && *in.PeerDynamic
	n := 0
	for _, set := range []bool{in.PeerIp != nil, in.PeerFqdn != nil, dynamic} {
		if set {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if n > 1 {
		return errors.New("at most one of peer_ip, peer_fqdn, peer_dynamic may be set")
	}
	if e.PeerAddress == nil {
		e.PeerAddress = &gateway.PeerAddress{}
	}
	switch {
	case in.PeerIp != nil:
		e.PeerAddress.Ip, e.PeerAddress.Fqdn, e.PeerAddress.Dynamic = in.PeerIp, nil, nil
	case in.PeerFqdn != nil:
		e.PeerAddress.Ip, e.PeerAddress.Fqdn, e.PeerAddress.Dynamic = nil, in.PeerFqdn, nil
	default: // dynamic
		e.PeerAddress.Ip, e.PeerAddress.Fqdn, e.PeerAddress.Dynamic = nil, nil, &gateway.PeerAddressDynamic{}
	}
	return nil
}

func applyIkeGatewayLocal(e *gateway.Entry, in *IkeGatewayInput) {
	if in.LocalInterface == nil && in.LocalIp == nil {
		return
	}
	if e.LocalAddress == nil {
		e.LocalAddress = &gateway.LocalAddress{}
	}
	setPtr(&e.LocalAddress.Interface, in.LocalInterface)
	setPtr(&e.LocalAddress.Ip, in.LocalIp)
}

// applyIkeGatewayProtocol routes the crypto profile under the active protocol
// version child (ikev1 or ikev2); pango has no crypto-profile field at the
// Protocol root. The inactive version's child is left in place on a version
// switch: ikev2-preferred negotiates ikev2 with an ikev1 fallback, so both
// children can be legitimate, and read-modify-write preserves whichever the
// caller does not touch.
func applyIkeGatewayProtocol(e *gateway.Entry, in *IkeGatewayInput) error {
	if in.ProtocolVersion == nil && in.IkeCryptoProfile == nil && in.ExchangeMode == nil {
		return nil
	}
	if e.Protocol == nil {
		e.Protocol = &gateway.Protocol{}
	}
	setPtr(&e.Protocol.Version, in.ProtocolVersion)
	if strVal(e.Protocol.Version) == ikeVersion1 {
		if e.Protocol.Ikev1 == nil {
			e.Protocol.Ikev1 = &gateway.ProtocolIkev1{}
		}
		setPtr(&e.Protocol.Ikev1.IkeCryptoProfile, in.IkeCryptoProfile)
		setPtr(&e.Protocol.Ikev1.ExchangeMode, in.ExchangeMode)
		return nil
	}
	// exchange_mode is an IKEv1-only setting. The active version is not ikev1
	// here (ikev2, ikev2-preferred, or unset defaulting to ikev2), so reject a
	// provided exchange_mode rather than silently dropping it.
	if in.ExchangeMode != nil {
		return errors.New("exchange_mode applies to ikev1 only; set protocol_version to ikev1")
	}
	// ikev2 and ikev2-preferred both carry the crypto profile under ikev2.
	if e.Protocol.Ikev2 == nil {
		e.Protocol.Ikev2 = &gateway.ProtocolIkev2{}
	}
	setPtr(&e.Protocol.Ikev2.IkeCryptoProfile, in.IkeCryptoProfile)
	return nil
}

func applyIkeGatewayAuth(e *gateway.Entry, in *IkeGatewayInput) {
	if in.PreSharedKey == nil {
		return
	}
	if e.Authentication == nil {
		e.Authentication = &gateway.Authentication{}
	}
	if e.Authentication.PreSharedKey == nil {
		e.Authentication.PreSharedKey = &gateway.AuthenticationPreSharedKey{}
	}
	e.Authentication.PreSharedKey.Key = in.PreSharedKey
}

func applyIkeGateway(e *gateway.Entry, in *IkeGatewayInput) error {
	setPtr(&e.Disabled, in.Disabled)
	setPtr(&e.Ipv6, in.Ipv6)
	if err := applyIkeGatewayPeer(e, in); err != nil {
		return err
	}
	applyIkeGatewayLocal(e, in)
	if err := applyIkeGatewayProtocol(e, in); err != nil {
		return err
	}
	applyIkeGatewayAuth(e, in)
	return nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildIkeGateway(in IkeGatewayInput) (*gateway.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &gateway.Entry{Name: in.Name}
	if err := applyIkeGateway(e, &in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayIkeGateway(e *gateway.Entry, in IkeGatewayInput) error {
	return applyIkeGateway(e, &in)
}

// ikeGatewayCryptoProfile projects the crypto profile of the active protocol
// version. Because applyIkeGatewayProtocol leaves the inactive version's child
// in place on a version switch, the summary must consult Version first: reading
// Ikev2 unconditionally would report a stale profile after switching to ikev1.
func ikeGatewayCryptoProfile(p *gateway.Protocol) string {
	if p == nil {
		return ""
	}
	if strVal(p.Version) == ikeVersion1 {
		if p.Ikev1 != nil && p.Ikev1.IkeCryptoProfile != nil {
			return *p.Ikev1.IkeCryptoProfile
		}
		if p.Ikev2 != nil && p.Ikev2.IkeCryptoProfile != nil {
			return *p.Ikev2.IkeCryptoProfile
		}
		return ""
	}
	if p.Ikev2 != nil && p.Ikev2.IkeCryptoProfile != nil {
		return *p.Ikev2.IkeCryptoProfile
	}
	if p.Ikev1 != nil && p.Ikev1.IkeCryptoProfile != nil {
		return *p.Ikev1.IkeCryptoProfile
	}
	return ""
}

func ikeGatewaySummary(e *gateway.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putBool(m, "disabled", e.Disabled)
	putBool(m, "ipv6", e.Ipv6)
	if pa := e.PeerAddress; pa != nil {
		pm := map[string]any{"dynamic": pa.Dynamic != nil}
		if pa.Ip != nil {
			pm["ip"] = *pa.Ip
		}
		if pa.Fqdn != nil {
			pm["fqdn"] = *pa.Fqdn
		}
		m["peer_address"] = pm
	}
	if la := e.LocalAddress; la != nil {
		m["local_address"] = map[string]any{
			interfaceKey: strVal(la.Interface),
			"ip":         strVal(la.Ip),
		}
	}
	if p := e.Protocol; p != nil {
		m["protocol_version"] = strVal(p.Version)
		// exchange_mode is an IKEv1-only setting; echo it only when ikev1 is the
		// active version, mirroring where applyIkeGatewayProtocol routes it.
		if strVal(p.Version) == ikeVersion1 && p.Ikev1 != nil {
			m["exchange_mode"] = strVal(p.Ikev1.ExchangeMode)
		}
	}
	m["ike_crypto_profile"] = ikeGatewayCryptoProfile(e.Protocol)
	m["has_pre_shared_key"] = e.Authentication != nil && e.Authentication.PreSharedKey != nil && e.Authentication.PreSharedKey.Key != nil
	return m
}

// RegisterIkeGatewayTools registers the IKE gateway tools.
func RegisterIkeGatewayTools(s *mcp.Server, d *Deps) {
	svc := newIkeGatewayService(d)
	parts := ikeGatewayParts()
	scope := func(in IkeGatewayInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_gateway_list",
		Description: "List IKE gateways (VPN peers). Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List IKE gateways"),
	}, netListHandler(d, "panos_ike_gateway_list", svc, parts, svc.name, ikeGatewaySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_gateway_get",
		Description: "Get one IKE gateway (peer/local address, protocol version, ike_crypto_profile). The pre-shared key is never returned; has_pre_shared_key reports whether one is set. Read-only.",
		Annotations: readOnlyTool("Get IKE gateway"),
	}, netGetHandler(d, "panos_ike_gateway_get", svc, parts, ikeGatewaySummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_gateway_create",
		Description: "Create an IKE gateway in the candidate config. Set ike_crypto_profile to a profile in the same scope, and one of peer_ip, peer_fqdn or peer_dynamic. The pre-shared key is write-only. Deeper certificate-auth, DPD and NAT-traversal settings are left at device defaults. Run panos_commit to apply.",
		Annotations: createTool("Create IKE gateway"),
	}, netCreateHandler(d, "panos_ike_gateway_create", svc, parts, scope, buildIkeGateway, ikeGatewaySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_gateway_update",
		Description: "Update an IKE gateway: read-modify-write, only provided fields change; the SDK-only certificate-auth, DPD, fragmentation and NAT-traversal subtrees are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update IKE gateway"),
	}, netUpdateHandler(d, "panos_ike_gateway_update", svc, parts, scope,
		func(in IkeGatewayInput) string { return in.Name }, overlayIkeGateway, ikeGatewaySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ike_gateway_delete",
		Description: "Delete an IKE gateway from the candidate config. Fails while an IPSec tunnel still references it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IKE gateway"),
	}, netDeleteHandler(d, "panos_ike_gateway_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// IPSec tunnel (network/tunnel/ipsec)
// ---------------------------------------------------------------------------

func newIpsecTunnelService(d *Deps) nameFixAdapter[ipsec.Location, ipsec.Entry] {
	return nameFixAdapter[ipsec.Location, ipsec.Entry]{
		svc:    ipsec.NewService(d.Client),
		client: d.Client,
		name:   func(e *ipsec.Entry) string { return e.Name },
	}
}

func ipsecTunnelParts() netScopeParts[ipsec.Location] {
	return netScopeParts[ipsec.Location]{
		ngfw: func() ipsec.Location {
			return ipsec.Location{Ngfw: &ipsec.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) ipsec.Location {
			return ipsec.Location{Template: &ipsec.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ipsec.Location {
			return ipsec.Location{TemplateStack: &ipsec.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// IpsecTunnelInput is the input for the IPSec tunnel create and update tools. It
// models the auto-key subset (bound IKE gateways and the IPSec crypto profile)
// plus the tunnel interface and the option toggles. proxy-ids, manual-key and
// GlobalProtect-satellite subtrees are preserved verbatim through Misc and are
// not managed here.
type IpsecTunnelInput struct {
	NetScopeInput
	Name                   string   `json:"name" jsonschema:"IPSec tunnel name"`
	TunnelInterface        *string  `json:"tunnel_interface,omitempty" jsonschema:"Tunnel interface the tunnel binds to, e.g. tunnel.1"`
	Disabled               *bool    `json:"disabled,omitempty" jsonschema:"Disable the tunnel; omit to keep the device default"`
	AntiReplay             *bool    `json:"anti_replay,omitempty" jsonschema:"Enable anti-replay protection; omit to keep the device default"`
	CopyTos                *bool    `json:"copy_tos,omitempty" jsonschema:"Copy the ToS/DSCP field from inner to outer header; omit to keep the device default"`
	CopyFlowLabel          *bool    `json:"copy_flow_label,omitempty" jsonschema:"Copy the IPv6 flow label from inner to outer header; omit to keep the device default"`
	EnableGreEncapsulation *bool    `json:"enable_gre_encapsulation,omitempty" jsonschema:"Add GRE encapsulation over the IPSec tunnel; omit to keep the device default"`
	Ipv6                   *bool    `json:"ipv6,omitempty" jsonschema:"Use IPv6 for the tunnel; omit to keep the device default"`
	IkeGateways            []string `json:"ike_gateways,omitempty" jsonschema:"Auto-key IKE gateway names in order (see panos_ike_gateway_list); replaces the bound gateways fully on update"`
	IpsecCryptoProfile     *string  `json:"ipsec_crypto_profile,omitempty" jsonschema:"Name of an IPSec crypto profile in the same scope (see panos_ipsec_crypto_profile_list)"`
	Comment                *string  `json:"comment,omitempty" jsonschema:"Free-text comment"`
}

func applyIpsecTunnel(e *ipsec.Entry, in *IpsecTunnelInput) {
	setPtr(&e.TunnelInterface, in.TunnelInterface)
	setPtr(&e.Disabled, in.Disabled)
	setPtr(&e.AntiReplay, in.AntiReplay)
	setPtr(&e.CopyTos, in.CopyTos)
	setPtr(&e.CopyFlowLabel, in.CopyFlowLabel)
	setPtr(&e.EnableGreEncapsulation, in.EnableGreEncapsulation)
	setPtr(&e.Ipv6, in.Ipv6)
	setPtr(&e.Comment, in.Comment)

	if in.IkeGateways != nil || in.IpsecCryptoProfile != nil {
		if e.AutoKey == nil {
			e.AutoKey = &ipsec.AutoKey{}
		}
		if in.IkeGateways != nil {
			gws := make([]ipsec.AutoKeyIkeGateway, 0, len(in.IkeGateways))
			for _, g := range in.IkeGateways {
				gws = append(gws, ipsec.AutoKeyIkeGateway{Name: g})
			}
			e.AutoKey.IkeGateway = gws
		}
		setPtr(&e.AutoKey.IpsecCryptoProfile, in.IpsecCryptoProfile)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildIpsecTunnel(in IpsecTunnelInput) (*ipsec.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &ipsec.Entry{Name: in.Name}
	applyIpsecTunnel(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayIpsecTunnel(e *ipsec.Entry, in IpsecTunnelInput) error {
	applyIpsecTunnel(e, &in)
	return nil
}

func ipsecTunnelGateways(a *ipsec.AutoKey) []string {
	if a == nil {
		return []string{}
	}
	return names(a.IkeGateway, func(g ipsec.AutoKeyIkeGateway) string { return g.Name })
}

func ipsecTunnelSummary(e *ipsec.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["tunnel_interface"] = strVal(e.TunnelInterface)
	putBool(m, "disabled", e.Disabled)
	putBool(m, "anti_replay", e.AntiReplay)
	putBool(m, "copy_tos", e.CopyTos)
	putBool(m, "copy_flow_label", e.CopyFlowLabel)
	putBool(m, "enable_gre_encapsulation", e.EnableGreEncapsulation)
	putBool(m, "ipv6", e.Ipv6)
	m["ike_gateways"] = ipsecTunnelGateways(e.AutoKey)
	if e.AutoKey != nil {
		m["ipsec_crypto_profile"] = strVal(e.AutoKey.IpsecCryptoProfile)
	} else {
		m["ipsec_crypto_profile"] = ""
	}
	m["comment"] = strVal(e.Comment)
	return m
}

// RegisterIpsecTunnelTools registers the IPSec tunnel tools.
func RegisterIpsecTunnelTools(s *mcp.Server, d *Deps) {
	svc := newIpsecTunnelService(d)
	parts := ipsecTunnelParts()
	scope := func(in IpsecTunnelInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_tunnel_list",
		Description: "List IPSec tunnels. Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List IPSec tunnels"),
	}, netListHandler(d, "panos_ipsec_tunnel_list", svc, parts, svc.name, ipsecTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_tunnel_get",
		Description: "Get one IPSec tunnel (tunnel_interface, bound ike_gateways, ipsec_crypto_profile, option toggles). Read-only.",
		Annotations: readOnlyTool("Get IPSec tunnel"),
	}, netGetHandler(d, "panos_ipsec_tunnel_get", svc, parts, ipsecTunnelSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_tunnel_create",
		Description: "Create an IPSec tunnel in the candidate config. Bind it to a tunnel_interface, one or more ike_gateways and an ipsec_crypto_profile in the same scope. proxy-ids and manual-key are left at device defaults. Run panos_commit to apply.",
		Annotations: createTool("Create IPSec tunnel"),
	}, netCreateHandler(d, "panos_ipsec_tunnel_create", svc, parts, scope, buildIpsecTunnel, ipsecTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_tunnel_update",
		Description: "Update an IPSec tunnel: read-modify-write, only provided fields change; a provided ike_gateways list replaces the bound gateways fully, and the SDK-only proxy-id and manual-key subtrees are preserved. Run panos_commit to apply.",
		Annotations: updateTool("Update IPSec tunnel"),
	}, netUpdateHandler(d, "panos_ipsec_tunnel_update", svc, parts, scope,
		func(in IpsecTunnelInput) string { return in.Name }, overlayIpsecTunnel, ipsecTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ipsec_tunnel_delete",
		Description: "Delete an IPSec tunnel from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete IPSec tunnel"),
	}, netDeleteHandler(d, "panos_ipsec_tunnel_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// GRE tunnel (network/tunnel/gre)
// ---------------------------------------------------------------------------

func newGreTunnelService(d *Deps) nameFixAdapter[gre.Location, gre.Entry] {
	return nameFixAdapter[gre.Location, gre.Entry]{
		svc:    gre.NewService(d.Client),
		client: d.Client,
		name:   func(e *gre.Entry) string { return e.Name },
	}
}

func greTunnelParts() netScopeParts[gre.Location] {
	return netScopeParts[gre.Location]{
		ngfw: func() gre.Location {
			return gre.Location{Ngfw: &gre.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) gre.Location {
			return gre.Location{Template: &gre.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) gre.Location {
			return gre.Location{TemplateStack: &gre.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// GreTunnelInput is the input for the GRE tunnel create and update tools.
type GreTunnelInput struct {
	NetScopeInput
	Name               string  `json:"name" jsonschema:"GRE tunnel name"`
	TunnelInterface    *string `json:"tunnel_interface,omitempty" jsonschema:"Tunnel interface the GRE tunnel binds to, e.g. tunnel.2"`
	Disabled           *bool   `json:"disabled,omitempty" jsonschema:"Disable the tunnel; omit to keep the device default"`
	CopyTos            *bool   `json:"copy_tos,omitempty" jsonschema:"Copy the ToS/DSCP field from inner to outer header; omit to keep the device default"`
	Erspan             *bool   `json:"erspan,omitempty" jsonschema:"Enable ERSPAN over the GRE tunnel; omit to keep the device default"`
	Ttl                *int64  `json:"ttl,omitempty" jsonschema:"Outer IP TTL for GRE packets"`
	LocalInterface     *string `json:"local_interface,omitempty" jsonschema:"Local interface the tunnel source binds to, e.g. ethernet1/1"`
	LocalIp            *string `json:"local_ip,omitempty" jsonschema:"Local (source) IP address on the interface"`
	PeerIp             *string `json:"peer_ip,omitempty" jsonschema:"Remote GRE peer IP address"`
	KeepAliveEnable    *bool   `json:"keep_alive_enable,omitempty" jsonschema:"Enable GRE keep-alive; omit to keep the device default"`
	KeepAliveHoldTimer *int64  `json:"keep_alive_hold_timer,omitempty" jsonschema:"Keep-alive hold timer in seconds"`
	KeepAliveInterval  *int64  `json:"keep_alive_interval,omitempty" jsonschema:"Keep-alive interval in seconds"`
	KeepAliveRetry     *int64  `json:"keep_alive_retry,omitempty" jsonschema:"Keep-alive retry count"`
}

func applyGreTunnel(e *gre.Entry, in *GreTunnelInput) {
	setPtr(&e.TunnelInterface, in.TunnelInterface)
	setPtr(&e.Disabled, in.Disabled)
	setPtr(&e.CopyTos, in.CopyTos)
	setPtr(&e.Erspan, in.Erspan)
	setPtr(&e.Ttl, in.Ttl)

	if in.LocalInterface != nil || in.LocalIp != nil {
		if e.LocalAddress == nil {
			e.LocalAddress = &gre.LocalAddress{}
		}
		setPtr(&e.LocalAddress.Interface, in.LocalInterface)
		setPtr(&e.LocalAddress.Ip, in.LocalIp)
	}
	if in.PeerIp != nil {
		if e.PeerAddress == nil {
			e.PeerAddress = &gre.PeerAddress{}
		}
		setPtr(&e.PeerAddress.Ip, in.PeerIp)
	}
	if in.KeepAliveEnable != nil || in.KeepAliveHoldTimer != nil || in.KeepAliveInterval != nil || in.KeepAliveRetry != nil {
		if e.KeepAlive == nil {
			e.KeepAlive = &gre.KeepAlive{}
		}
		setPtr(&e.KeepAlive.Enable, in.KeepAliveEnable)
		setPtr(&e.KeepAlive.HoldTimer, in.KeepAliveHoldTimer)
		setPtr(&e.KeepAlive.Interval, in.KeepAliveInterval)
		setPtr(&e.KeepAlive.Retry, in.KeepAliveRetry)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildGreTunnel(in GreTunnelInput) (*gre.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &gre.Entry{Name: in.Name}
	applyGreTunnel(e, &in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayGreTunnel(e *gre.Entry, in GreTunnelInput) error {
	applyGreTunnel(e, &in)
	return nil
}

func greTunnelSummary(e *gre.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	m["tunnel_interface"] = strVal(e.TunnelInterface)
	putBool(m, "disabled", e.Disabled)
	putBool(m, "copy_tos", e.CopyTos)
	putBool(m, "erspan", e.Erspan)
	putInt(m, "ttl", e.Ttl)
	if la := e.LocalAddress; la != nil {
		m["local_address"] = map[string]any{
			interfaceKey: strVal(la.Interface),
			"ip":         strVal(la.Ip),
		}
	}
	if pa := e.PeerAddress; pa != nil {
		m["peer_address"] = map[string]any{"ip": strVal(pa.Ip)}
	}
	if ka := e.KeepAlive; ka != nil {
		km := map[string]any{}
		putBool(km, "enable", ka.Enable)
		putInt(km, "hold_timer", ka.HoldTimer)
		putInt(km, "interval", ka.Interval)
		putInt(km, "retry", ka.Retry)
		m["keep_alive"] = km
	}
	return m
}

// RegisterGreTunnelTools registers the GRE tunnel tools.
func RegisterGreTunnelTools(s *mcp.Server, d *Deps) {
	svc := newGreTunnelService(d)
	parts := greTunnelParts()
	scope := func(in GreTunnelInput) NetScopeInput { return in.NetScopeInput }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_gre_tunnel_list",
		Description: "List GRE tunnels. Firewall: device scope; Panorama: template or template_stack required. Read-only.",
		Annotations: readOnlyTool("List GRE tunnels"),
	}, netListHandler(d, "panos_gre_tunnel_list", svc, parts, svc.name, greTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_gre_tunnel_get",
		Description: "Get one GRE tunnel (tunnel_interface, local/peer address, ttl, keep-alive). Read-only.",
		Annotations: readOnlyTool("Get GRE tunnel"),
	}, netGetHandler(d, "panos_gre_tunnel_get", svc, parts, greTunnelSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_gre_tunnel_create",
		Description: "Create a GRE tunnel in the candidate config. Bind it to a tunnel_interface, set local_interface/local_ip and peer_ip. Run panos_commit to apply.",
		Annotations: createTool("Create GRE tunnel"),
	}, netCreateHandler(d, "panos_gre_tunnel_create", svc, parts, scope, buildGreTunnel, greTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_gre_tunnel_update",
		Description: "Update a GRE tunnel: read-modify-write, only provided fields change. Run panos_commit to apply.",
		Annotations: updateTool("Update GRE tunnel"),
	}, netUpdateHandler(d, "panos_gre_tunnel_update", svc, parts, scope,
		func(in GreTunnelInput) string { return in.Name }, overlayGreTunnel, greTunnelSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_gre_tunnel_delete",
		Description: "Delete a GRE tunnel from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete GRE tunnel"),
	}, netDeleteHandler(d, "panos_gre_tunnel_delete", svc, parts))
}
