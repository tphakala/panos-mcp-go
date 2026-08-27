package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/network/dhcp"
	"github.com/PaloAltoNetworks/pango/network/dnsproxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// DHCP interface config (network/dhcp)
// ---------------------------------------------------------------------------
//
// A DHCP config attaches to a single interface, keyed by the interface name
// (for example "ethernet1/2"), and is either a DHCP relay (forwarding client
// requests to upstream servers) or a DHCP server (handing out leases). PAN-OS
// treats the two as mutually exclusive per interface, so the build and overlay
// paths reject a request that supplies both a relay_* and a server_* field, and
// an update that supplies the opposite block from what exists switches modes by
// clearing the sibling. Only the relay upstream-server list and a curated slice
// of the server block are modeled; everything else (relay IPv6, server options,
// reserved addresses, and any unmodeled XML) is preserved across updates.
// Net-scoped: {Ngfw | Template | TemplateStack}.

func newDhcpService(d *Deps) nameFixAdapter[dhcp.Location, dhcp.Entry] {
	return nameFixAdapter[dhcp.Location, dhcp.Entry]{
		svc:    dhcp.NewService(d.Client),
		client: d.Client,
		name:   func(e *dhcp.Entry) string { return e.Name },
	}
}

func dhcpParts() netScopeParts[dhcp.Location] {
	return netScopeParts[dhcp.Location]{
		ngfw: func() dhcp.Location {
			return dhcp.Location{Ngfw: &dhcp.NgfwLocation{NgfwDevice: defaultNgfwDevice}}
		},
		template: func(tmpl string) dhcp.Location {
			return dhcp.Location{Template: &dhcp.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) dhcp.Location {
			return dhcp.Location{TemplateStack: &dhcp.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// DhcpInput is the input for the DHCP create and update tools. The name is the
// interface the DHCP config applies to. relay_* and server_* fields are mutually
// exclusive: an interface is either a relay or a server, never both.
type DhcpInput struct {
	NetScopeInput
	Name          string   `json:"name" jsonschema:"Interface this DHCP config applies to (for example ethernet1/2); it is the entry name"`
	RelayEnabled  *bool    `json:"relay_enabled,omitzero" jsonschema:"Enable DHCP relay on the interface (relay mode; mutually exclusive with the server_* fields)"`
	RelayServers  []string `json:"relay_servers,omitzero" jsonschema:"Upstream IPv4 DHCP server addresses to relay client requests to; replaces the whole list when provided (relay mode)"`
	ServerMode    *string  `json:"server_mode,omitzero" jsonschema:"DHCP server mode (server mode; mutually exclusive with the relay_* fields). Common values: enabled, disabled, auto"`
	ServerIpPools []string `json:"server_ip_pools,omitzero" jsonschema:"IP pools the server leases from, each a range or subnet; replaces the whole list when provided (server mode)"`
	ServerProbeIp *bool    `json:"server_probe_ip,omitzero" jsonschema:"Probe each address for conflicts before leasing it (server mode)"`
}

// dhcpHasRelay reports whether the input touches the relay block.
func dhcpHasRelay(in *DhcpInput) bool {
	return in.RelayEnabled != nil || in.RelayServers != nil
}

// dhcpHasServer reports whether the input touches the server block.
func dhcpHasServer(in *DhcpInput) bool {
	return in.ServerMode != nil || in.ServerIpPools != nil || in.ServerProbeIp != nil
}

// applyDhcpRelay mutates the relay block in place, allocating Relay and Relay.Ip
// only when nil so an existing Relay.Ipv6 subtree and any unmodeled XML survive.
// It is a no-op unless the input touches a relay field.
//
//nolint:gocritic // hugeParam: in is by value to mirror the builder/overlay contract.
func applyDhcpRelay(e *dhcp.Entry, in DhcpInput) {
	if !dhcpHasRelay(&in) {
		return
	}
	if e.Relay == nil {
		e.Relay = &dhcp.Relay{}
	}
	if e.Relay.Ip == nil {
		e.Relay.Ip = &dhcp.RelayIp{}
	}
	setPtr(&e.Relay.Ip.Enabled, in.RelayEnabled)
	if in.RelayServers != nil {
		e.Relay.Ip.Server = in.RelayServers
	}
}

// applyDhcpServer mutates the server block in place, allocating Server only when
// nil so an existing Server.Option and Server.Reserved subtree and any unmodeled
// XML survive. It is a no-op unless the input touches a server field.
//
//nolint:gocritic // hugeParam: in is by value to mirror the builder/overlay contract.
func applyDhcpServer(e *dhcp.Entry, in DhcpInput) {
	if !dhcpHasServer(&in) {
		return
	}
	if e.Server == nil {
		e.Server = &dhcp.Server{}
	}
	setPtr(&e.Server.Mode, in.ServerMode)
	setPtr(&e.Server.ProbeIp, in.ServerProbeIp)
	if in.ServerIpPools != nil {
		e.Server.IpPool = in.ServerIpPools
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildDhcp(in DhcpInput) (*dhcp.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if dhcpHasRelay(&in) && dhcpHasServer(&in) {
		return nil, errors.New("an interface's DHCP config is either relay or server, not both: set only the relay_* fields or only the server_* fields")
	}
	e := &dhcp.Entry{Name: in.Name}
	applyDhcpRelay(e, in)
	applyDhcpServer(e, in)
	return e, nil
}

// overlayDhcp applies the provided fields onto the read entry. Supplying both a
// relay_* and a server_* field is rejected. Supplying only relay_* mutates the
// relay block and clears any server block (a mode switch), and only server_*
// does the reverse; supplying neither leaves both blocks untouched so unmodeled
// XML is preserved.
//
//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayDhcp(e *dhcp.Entry, in DhcpInput) error {
	relay, server := dhcpHasRelay(&in), dhcpHasServer(&in)
	if relay && server {
		return errors.New("an interface's DHCP config is either relay or server, not both: set only the relay_* fields or only the server_* fields")
	}
	if relay {
		applyDhcpRelay(e, in)
		e.Server = nil
	}
	if server {
		applyDhcpServer(e, in)
		e.Relay = nil
	}
	return nil
}

func dhcpSummary(e *dhcp.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	if e.Relay != nil && e.Relay.Ip != nil {
		putBool(m, "relay_enabled", e.Relay.Ip.Enabled)
		m["relay_servers"] = strList(e.Relay.Ip.Server)
	}
	if e.Server != nil {
		m["server_mode"] = strVal(e.Server.Mode)
		m["server_ip_pools"] = strList(e.Server.IpPool)
		putBool(m, "server_probe_ip", e.Server.ProbeIp)
	}
	return m
}

// RegisterDhcpTools registers the DHCP interface config tools on both firewall
// and Panorama.
func RegisterDhcpTools(s *mcp.Server, d *Deps) {
	svc := newDhcpService(d)
	parts := dhcpParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dhcp_list",
		Description: "List per-interface DHCP configs (relay or server). Firewall: local scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List DHCP configs"),
	}, netListHandler(d, "panos_dhcp_list", svc, parts, svc.name, dhcpSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dhcp_get",
		Description: "Get one interface's DHCP config (relay or server). Server options and reserved addresses are not modeled and are preserved on update. On Panorama a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get DHCP config"),
	}, netGetHandler(d, "panos_dhcp_get", svc, parts, dhcpSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dhcp_create",
		Description: "Create a per-interface DHCP config in the candidate config. name is the interface (for example ethernet1/2). An interface is either a relay or a server, not both: set only the relay_* fields or only the server_* fields. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: createTool("Create DHCP config"),
	}, netCreateHandler(d, "panos_dhcp_create", svc, parts, buildDhcp, dhcpSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dhcp_update",
		Description: "Update an interface's DHCP config: read-modify-write, only provided fields change. Supplying relay_* fields switches the interface to relay mode (clearing any server block) and server_* fields switch it to server mode; supplying both is rejected. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update DHCP config"),
	}, netUpdateHandler(d, "panos_dhcp_update", svc, parts,
		func(in DhcpInput) string { return in.Name }, overlayDhcp, dhcpSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dhcp_delete",
		Description: "Delete an interface's DHCP config from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete DHCP config"),
	}, netDeleteHandler(d, "panos_dhcp_delete", svc, parts))
}

// ---------------------------------------------------------------------------
// DNS proxy (network/dnsproxy)
// ---------------------------------------------------------------------------
//
// A DNS proxy object answers DNS queries on the listed interfaces, forwarding to
// default upstream servers, to per-domain servers, or resolving static FQDN ->
// address mappings. pango models it only under a template or template-stack (its
// Location has no Ngfw scope), so these tools require a template or
// template_stack on Panorama and are unavailable on a standalone firewall
// connection. The cache and per-transport (TCP/UDP) query settings are not
// modeled and are preserved across updates. The static-entry and domain-server
// lists carry no secrets and are replaced wholesale when provided.

func newDnsProxyService(d *Deps) nameFixAdapter[dnsproxy.Location, dnsproxy.Entry] {
	return nameFixAdapter[dnsproxy.Location, dnsproxy.Entry]{
		svc:    dnsproxy.NewService(d.Client),
		client: d.Client,
		name:   func(e *dnsproxy.Entry) string { return e.Name },
	}
}

func dnsProxyParts() netScopeParts[dnsproxy.Location] {
	// ngfw is intentionally nil: pango models dns-proxy only under a template or
	// template-stack, so resolveNetScope rejects a bare firewall request rather
	// than building an invalid location.
	return netScopeParts[dnsproxy.Location]{
		template: func(tmpl string) dnsproxy.Location {
			return dnsproxy.Location{Template: &dnsproxy.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) dnsproxy.Location {
			return dnsproxy.Location{TemplateStack: &dnsproxy.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// DnsProxyStaticEntry is one static FQDN -> address mapping in a DNS proxy.
type DnsProxyStaticEntry struct {
	Name      string   `json:"name" jsonschema:"Static entry name"`
	Domain    *string  `json:"domain,omitzero" jsonschema:"FQDN resolved by this static entry"`
	Addresses []string `json:"addresses,omitzero" jsonschema:"IP addresses the domain resolves to"`
}

// DnsProxyDomainServer routes queries for specific domains to their own upstream
// DNS servers.
type DnsProxyDomainServer struct {
	Name      string   `json:"name" jsonschema:"Domain-server rule name"`
	Cacheable *bool    `json:"cacheable,omitzero" jsonschema:"Cache responses from these servers"`
	Primary   *string  `json:"primary,omitzero" jsonschema:"Primary upstream DNS server for these domains"`
	Secondary *string  `json:"secondary,omitzero" jsonschema:"Secondary upstream DNS server for these domains"`
	Domains   []string `json:"domains,omitzero" jsonschema:"Domain names routed to these servers"`
}

// DnsProxyInput is the input for the DNS proxy create and update tools.
type DnsProxyInput struct {
	NetScopeInput
	Name             string                 `json:"name" jsonschema:"DNS proxy object name"`
	Enabled          *bool                  `json:"enabled,omitzero" jsonschema:"Enable the DNS proxy"`
	Interfaces       []string               `json:"interfaces,omitzero" jsonschema:"Interfaces the DNS proxy answers on; replaces the whole list when provided"`
	DefaultPrimary   *string                `json:"default_primary,omitzero" jsonschema:"Primary default upstream DNS server"`
	DefaultSecondary *string                `json:"default_secondary,omitzero" jsonschema:"Secondary default upstream DNS server"`
	StaticEntries    []DnsProxyStaticEntry  `json:"static_entries,omitzero" jsonschema:"Static FQDN to address mappings; replaces the whole list when provided"`
	DomainServers    []DnsProxyDomainServer `json:"domain_servers,omitzero" jsonschema:"Per-domain upstream server rules; replaces the whole list when provided"`
}

// dnsProxyStaticEntries builds a fresh pango static-entry slice from the input.
func dnsProxyStaticEntries(in []DnsProxyStaticEntry) []dnsproxy.StaticEntries {
	out := make([]dnsproxy.StaticEntries, 0, len(in))
	for _, s := range in {
		out = append(out, dnsproxy.StaticEntries{Name: s.Name, Domain: s.Domain, Address: s.Addresses})
	}
	return out
}

// dnsProxyDomainServers builds a fresh pango domain-server slice from the input.
func dnsProxyDomainServers(in []DnsProxyDomainServer) []dnsproxy.DomainServers {
	out := make([]dnsproxy.DomainServers, 0, len(in))
	for _, ds := range in {
		out = append(out, dnsproxy.DomainServers{
			Name: ds.Name, Cacheable: ds.Cacheable, Primary: ds.Primary, Secondary: ds.Secondary, DomainName: ds.Domains,
		})
	}
	return out
}

// applyDnsProxy writes the provided input fields onto e. Scalar and list fields
// apply only when the caller provides them (read-modify-write). The default
// block is mutated in place so its inheritance subtree and any unmodeled XML
// survive; the static-entry and domain-server lists are rebuilt only when their
// input field is non-nil.
//
//nolint:gocritic // hugeParam: in is by value to mirror the builder/overlay contract.
func applyDnsProxy(e *dnsproxy.Entry, in DnsProxyInput) {
	setPtr(&e.Enabled, in.Enabled)
	if in.Interfaces != nil {
		e.Interface = in.Interfaces
	}
	if in.DefaultPrimary != nil || in.DefaultSecondary != nil {
		if e.Default == nil {
			e.Default = &dnsproxy.Default{}
		}
		setPtr(&e.Default.Primary, in.DefaultPrimary)
		setPtr(&e.Default.Secondary, in.DefaultSecondary)
	}
	if in.StaticEntries != nil {
		e.StaticEntries = dnsProxyStaticEntries(in.StaticEntries)
	}
	if in.DomainServers != nil {
		e.DomainServers = dnsProxyDomainServers(in.DomainServers)
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildDnsProxy(in DnsProxyInput) (*dnsproxy.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &dnsproxy.Entry{Name: in.Name}
	applyDnsProxy(e, in)
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayDnsProxy(e *dnsproxy.Entry, in DnsProxyInput) error {
	applyDnsProxy(e, in)
	return nil
}

func dnsProxyStaticEntrySummaries(entries []dnsproxy.StaticEntries) []any {
	out := make([]any, 0, len(entries))
	for i := range entries {
		s := &entries[i]
		out = append(out, map[string]any{tagNameKey: s.Name, "domain": strVal(s.Domain), "addresses": strList(s.Address)})
	}
	return out
}

func dnsProxyDomainServerSummaries(servers []dnsproxy.DomainServers) []any {
	out := make([]any, 0, len(servers))
	for i := range servers {
		ds := &servers[i]
		sm := map[string]any{tagNameKey: ds.Name, "primary": strVal(ds.Primary), "secondary": strVal(ds.Secondary), "domains": strList(ds.DomainName)}
		putBool(sm, "cacheable", ds.Cacheable)
		out = append(out, sm)
	}
	return out
}

func dnsProxySummary(e *dnsproxy.Entry) any {
	m := map[string]any{tagNameKey: e.Name}
	putBool(m, "enabled", e.Enabled)
	m["interfaces"] = strList(e.Interface)
	if e.Default != nil {
		m["default_primary"] = strVal(e.Default.Primary)
		m["default_secondary"] = strVal(e.Default.Secondary)
	}
	m["static_entries"] = dnsProxyStaticEntrySummaries(e.StaticEntries)
	m["domain_servers"] = dnsProxyDomainServerSummaries(e.DomainServers)
	return m
}

// RegisterDnsProxyTools registers the DNS proxy tools on both firewall and
// Panorama. pango models dns-proxy only under a template or template-stack, so a
// template or template_stack is always required.
func RegisterDnsProxyTools(s *mcp.Server, d *Deps) {
	svc := newDnsProxyService(d)
	parts := dnsProxyParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_proxy_list",
		Description: "List DNS proxy objects. A template or template_stack is required (dns-proxy is template-scoped; list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List DNS proxies"),
	}, netListHandler(d, "panos_dns_proxy_list", svc, parts, svc.name, dnsProxySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_proxy_get",
		Description: "Get one DNS proxy object (interfaces, default servers, static entries, and per-domain servers). Cache and per-transport query settings are not modeled and are preserved on update. A template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get DNS proxy"),
	}, netGetHandler(d, "panos_dns_proxy_get", svc, parts, dnsProxySummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_proxy_create",
		Description: "Create a DNS proxy object in the candidate config. Only name is required. A template or template_stack is required (dns-proxy is template-scoped, with no firewall-local scope). Run panos_commit to apply.",
		Annotations: createTool("Create DNS proxy"),
	}, netCreateHandler(d, "panos_dns_proxy_create", svc, parts, buildDnsProxy, dnsProxySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_proxy_update",
		Description: "Update a DNS proxy object: read-modify-write, only provided fields change. A provided interfaces, static_entries, or domain_servers list replaces the whole list. A template or template_stack is required. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update DNS proxy"),
	}, netUpdateHandler(d, "panos_dns_proxy_update", svc, parts,
		func(in DnsProxyInput) string { return in.Name }, overlayDnsProxy, dnsProxySummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_proxy_delete",
		Description: "Delete a DNS proxy object from the candidate config. A template or template_stack is required. Run panos_commit to apply.",
		Annotations: deleteTool("Delete DNS proxy"),
	}, netDeleteHandler(d, "panos_dns_proxy_delete", svc, parts))
}
