package tools

// Device system services (device/services/{dns,ntp,general,proxy})
// ---------------------------------------------------------------------------
//
// These are the device's own management-plane system settings, each a singleton
// (one per device, no name). They share the {System | Template | TemplateStack}
// scope and the get/update singleton handlers in system_scope.go. Only the
// common scalar settings are modeled; anything not modeled (a DNS proxy object
// reference, NTP authentication keys, and so on) is read first and preserved by
// the read-modify-write update.
//
// Secret handling: the proxy password and any NTP authentication key are
// write-only. The get summaries never return them, and the proxy update passes
// its password through withSecrets so a failed write cannot echo it.

import (
	dnscfg "github.com/PaloAltoNetworks/pango/device/services/dns"
	generalcfg "github.com/PaloAltoNetworks/pango/device/services/general"
	ntpcfg "github.com/PaloAltoNetworks/pango/device/services/ntp"
	proxycfg "github.com/PaloAltoNetworks/pango/device/services/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- DNS settings (device/services/dns) -------------------------------------

func dnsSettingsParts() systemScopeParts[dnscfg.Location] {
	return systemScopeParts[dnscfg.Location]{
		system: func() dnscfg.Location {
			return dnscfg.Location{System: &dnscfg.SystemLocation{Device: defaultNgfwDevice}}
		},
		template: func(tmpl string) dnscfg.Location {
			return dnscfg.Location{Template: &dnscfg.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) dnscfg.Location {
			return dnscfg.Location{TemplateStack: &dnscfg.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// DnsSettingsInput is the input for the DNS settings update tool. It models the
// explicit primary/secondary DNS servers; a device configured to source DNS
// from a DNS-proxy object instead keeps that setting (it is preserved on
// update, and setting servers here would conflict with it on commit).
type DnsSettingsInput struct {
	SystemScopeInput
	PrimaryDnsServer   *string `json:"primary_dns_server,omitzero" jsonschema:"Primary DNS server IP address"`
	SecondaryDnsServer *string `json:"secondary_dns_server,omitzero" jsonschema:"Secondary DNS server IP address"`
	FqdnRefreshTime    *int64  `json:"fqdn_refresh_time,omitzero" jsonschema:"FQDN refresh interval in seconds"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the singleton overlay contract.
func overlayDnsSettings(c *dnscfg.Config, in DnsSettingsInput) error {
	setPtr(&c.FqdnRefreshTime, in.FqdnRefreshTime)
	if in.PrimaryDnsServer != nil || in.SecondaryDnsServer != nil {
		if c.DnsSetting == nil {
			c.DnsSetting = &dnscfg.DnsSetting{}
		}
		if c.DnsSetting.Servers == nil {
			c.DnsSetting.Servers = &dnscfg.DnsSettingServers{}
		}
		setPtr(&c.DnsSetting.Servers.Primary, in.PrimaryDnsServer)
		setPtr(&c.DnsSetting.Servers.Secondary, in.SecondaryDnsServer)
	}
	return nil
}

func dnsSettingsSummary(c *dnscfg.Config) any {
	m := map[string]any{}
	if c.DnsSetting != nil && c.DnsSetting.Servers != nil {
		m["primary_dns_server"] = strVal(c.DnsSetting.Servers.Primary)
		m["secondary_dns_server"] = strVal(c.DnsSetting.Servers.Secondary)
	} else {
		m["primary_dns_server"] = ""
		m["secondary_dns_server"] = ""
	}
	putInt(m, "fqdn_refresh_time", c.FqdnRefreshTime)
	return m
}

// RegisterDnsSettingsTools registers the DNS settings get and update tools on
// both firewall and Panorama.
func RegisterDnsSettingsTools(s *mcp.Server, d *Deps) {
	svc := dnscfg.NewService(d.Client)
	parts := dnsSettingsParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_settings_get",
		Description: "Get the device DNS settings (primary and secondary DNS servers, FQDN refresh interval). Firewall: local system scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("Get DNS settings"),
	}, systemGetHandler(d, "panos_dns_settings_get", svc, parts, dnsSettingsSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_dns_settings_update",
		Description: "Update the device DNS settings: read-modify-write, only provided fields change. Sets the explicit primary/secondary DNS servers. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: updateTool("Update DNS settings"),
	}, systemUpdateHandler(d, "panos_dns_settings_update", svc, parts, overlayDnsSettings, dnsSettingsSummary))
}

// --- NTP settings (device/services/ntp) -------------------------------------

func ntpSettingsParts() systemScopeParts[ntpcfg.Location] {
	return systemScopeParts[ntpcfg.Location]{
		system: func() ntpcfg.Location {
			return ntpcfg.Location{System: &ntpcfg.SystemLocation{Device: defaultNgfwDevice}}
		},
		template: func(tmpl string) ntpcfg.Location {
			return ntpcfg.Location{Template: &ntpcfg.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) ntpcfg.Location {
			return ntpcfg.Location{TemplateStack: &ntpcfg.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// NtpSettingsInput is the input for the NTP settings update tool. It models the
// primary and secondary server addresses; per-server authentication (symmetric
// key or autokey) is not modeled and is preserved unchanged across updates.
type NtpSettingsInput struct {
	SystemScopeInput
	PrimaryNtpServer   *string `json:"primary_ntp_server,omitzero" jsonschema:"Primary NTP server address (IP or FQDN)"`
	SecondaryNtpServer *string `json:"secondary_ntp_server,omitzero" jsonschema:"Secondary NTP server address (IP or FQDN)"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the singleton overlay contract.
func overlayNtpSettings(c *ntpcfg.Config, in NtpSettingsInput) error {
	if in.PrimaryNtpServer != nil {
		if c.NtpServers == nil {
			c.NtpServers = &ntpcfg.NtpServers{}
		}
		if c.NtpServers.PrimaryNtpServer == nil {
			c.NtpServers.PrimaryNtpServer = &ntpcfg.NtpServersPrimaryNtpServer{}
		}
		setPtr(&c.NtpServers.PrimaryNtpServer.NtpServerAddress, in.PrimaryNtpServer)
	}
	if in.SecondaryNtpServer != nil {
		if c.NtpServers == nil {
			c.NtpServers = &ntpcfg.NtpServers{}
		}
		if c.NtpServers.SecondaryNtpServer == nil {
			c.NtpServers.SecondaryNtpServer = &ntpcfg.NtpServersSecondaryNtpServer{}
		}
		setPtr(&c.NtpServers.SecondaryNtpServer.NtpServerAddress, in.SecondaryNtpServer)
	}
	return nil
}

// ntpSettingsSummary reports the server addresses and whether each server has
// authentication configured, but never the authentication key material.
func ntpSettingsSummary(c *ntpcfg.Config) any {
	m := map[string]any{
		"primary_ntp_server":        "",
		"secondary_ntp_server":      "",
		"primary_auth_configured":   false,
		"secondary_auth_configured": false,
	}
	if c.NtpServers == nil {
		return m
	}
	if p := c.NtpServers.PrimaryNtpServer; p != nil {
		m["primary_ntp_server"] = strVal(p.NtpServerAddress)
		m["primary_auth_configured"] = p.AuthenticationType != nil
	}
	if sec := c.NtpServers.SecondaryNtpServer; sec != nil {
		m["secondary_ntp_server"] = strVal(sec.NtpServerAddress)
		m["secondary_auth_configured"] = sec.AuthenticationType != nil
	}
	return m
}

// RegisterNtpSettingsTools registers the NTP settings get and update tools on
// both firewall and Panorama.
func RegisterNtpSettingsTools(s *mcp.Server, d *Deps) {
	svc := ntpcfg.NewService(d.Client)
	parts := ntpSettingsParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ntp_settings_get",
		Description: "Get the device NTP settings (primary and secondary server addresses, and whether each has authentication configured). Authentication keys are never returned. Firewall: local system scope; Panorama: a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get NTP settings"),
	}, systemGetHandler(d, "panos_ntp_settings_get", svc, parts, ntpSettingsSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ntp_settings_update",
		Description: "Update the device NTP settings: read-modify-write, only provided fields change. Sets the primary/secondary server addresses; existing per-server authentication is preserved. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: updateTool("Update NTP settings"),
	}, systemUpdateHandler(d, "panos_ntp_settings_update", svc, parts, overlayNtpSettings, ntpSettingsSummary))
}

// --- General/host settings (device/services/general) ------------------------

func generalSettingsParts() systemScopeParts[generalcfg.Location] {
	return systemScopeParts[generalcfg.Location]{
		system: func() generalcfg.Location {
			return generalcfg.Location{System: &generalcfg.SystemLocation{Device: defaultNgfwDevice}}
		},
		template: func(tmpl string) generalcfg.Location {
			return generalcfg.Location{Template: &generalcfg.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) generalcfg.Location {
			return generalcfg.Location{TemplateStack: &generalcfg.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// GeneralSettingsInput is the input for the general/host settings update tool.
type GeneralSettingsInput struct {
	SystemScopeInput
	Hostname             *string `json:"hostname,omitzero" jsonschema:"Device hostname"`
	Domain               *string `json:"domain,omitzero" jsonschema:"DNS domain the device belongs to"`
	LoginBanner          *string `json:"login_banner,omitzero" jsonschema:"Login banner text"`
	Timezone             *string `json:"timezone,omitzero" jsonschema:"Timezone (e.g. US/Pacific, Europe/Helsinki)"`
	SslTlsServiceProfile *string `json:"ssl_tls_service_profile,omitzero" jsonschema:"SSL/TLS service profile for the management interface"`
	GeoLatitude          *string `json:"geo_latitude,omitzero" jsonschema:"Device latitude in decimal degrees"`
	GeoLongitude         *string `json:"geo_longitude,omitzero" jsonschema:"Device longitude in decimal degrees"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the singleton overlay contract.
func overlayGeneralSettings(c *generalcfg.Config, in GeneralSettingsInput) error {
	setPtr(&c.Hostname, in.Hostname)
	setPtr(&c.Domain, in.Domain)
	setPtr(&c.LoginBanner, in.LoginBanner)
	setPtr(&c.Timezone, in.Timezone)
	setPtr(&c.SslTlsServiceProfile, in.SslTlsServiceProfile)
	if in.GeoLatitude != nil || in.GeoLongitude != nil {
		if c.GeoLocation == nil {
			c.GeoLocation = &generalcfg.GeoLocation{}
		}
		setPtr(&c.GeoLocation.Latitude, in.GeoLatitude)
		setPtr(&c.GeoLocation.Longitude, in.GeoLongitude)
	}
	return nil
}

func generalSettingsSummary(c *generalcfg.Config) any {
	m := map[string]any{
		"hostname":                strVal(c.Hostname),
		"domain":                  strVal(c.Domain),
		"login_banner":            strVal(c.LoginBanner),
		"timezone":                strVal(c.Timezone),
		"ssl_tls_service_profile": strVal(c.SslTlsServiceProfile),
	}
	if c.GeoLocation != nil {
		m["geo_latitude"] = strVal(c.GeoLocation.Latitude)
		m["geo_longitude"] = strVal(c.GeoLocation.Longitude)
	} else {
		m["geo_latitude"] = ""
		m["geo_longitude"] = ""
	}
	return m
}

// RegisterGeneralSettingsTools registers the general/host settings get and
// update tools on both firewall and Panorama.
func RegisterGeneralSettingsTools(s *mcp.Server, d *Deps) {
	svc := generalcfg.NewService(d.Client)
	parts := generalSettingsParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_general_settings_get",
		Description: "Get the device general settings (hostname, domain, login banner, timezone, management SSL/TLS service profile, geo-location). Firewall: local system scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("Get general settings"),
	}, systemGetHandler(d, "panos_general_settings_get", svc, parts, generalSettingsSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_general_settings_update",
		Description: "Update the device general settings: read-modify-write, only provided fields change. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: updateTool("Update general settings"),
	}, systemUpdateHandler(d, "panos_general_settings_update", svc, parts, overlayGeneralSettings, generalSettingsSummary))
}

// --- Update proxy settings (device/services/proxy) --------------------------

func proxySettingsParts() systemScopeParts[proxycfg.Location] {
	return systemScopeParts[proxycfg.Location]{
		system: func() proxycfg.Location {
			return proxycfg.Location{System: &proxycfg.SystemLocation{Device: defaultNgfwDevice}}
		},
		template: func(tmpl string) proxycfg.Location {
			return proxycfg.Location{Template: &proxycfg.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) proxycfg.Location {
			return proxycfg.Location{TemplateStack: &proxycfg.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// ProxySettingsInput is the input for the update-proxy settings update tool. The
// proxy password is write-only.
type ProxySettingsInput struct {
	SystemScopeInput
	SecureProxyServer   *string `json:"secure_proxy_server,omitzero" jsonschema:"Proxy server address for the device to reach update servers"`
	SecureProxyPort     *int64  `json:"secure_proxy_port,omitzero" jsonschema:"Proxy server port"`
	SecureProxyUser     *string `json:"secure_proxy_user,omitzero" jsonschema:"Proxy username"`
	SecureProxyPassword *string `json:"secure_proxy_password,omitzero" jsonschema:"Proxy password (write-only; never returned on read)"`
	LcaasUseProxy       *bool   `json:"lcaas_use_proxy,omitzero" jsonschema:"Use the proxy for the logging service (LCaaS) connection"`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the singleton overlay contract.
func overlayProxySettings(c *proxycfg.Config, in ProxySettingsInput) error {
	setPtr(&c.SecureProxyServer, in.SecureProxyServer)
	setPtr(&c.SecureProxyPort, in.SecureProxyPort)
	setPtr(&c.SecureProxyUser, in.SecureProxyUser)
	setPtr(&c.SecureProxyPassword, in.SecureProxyPassword)
	setPtr(&c.LcaasUseProxy, in.LcaasUseProxy)
	return nil
}

// proxySettingsSummary never returns the password: it is write-only and the
// summary reports only whether one is configured.
func proxySettingsSummary(c *proxycfg.Config) any {
	m := map[string]any{
		"secure_proxy_server": strVal(c.SecureProxyServer),
		"secure_proxy_user":   strVal(c.SecureProxyUser),
		hasPasswordKey:        c.SecureProxyPassword != nil,
	}
	putInt(m, "secure_proxy_port", c.SecureProxyPort)
	putBool(m, "lcaas_use_proxy", c.LcaasUseProxy)
	return m
}

// RegisterProxySettingsTools registers the update-proxy settings get and update
// tools on both firewall and Panorama.
func RegisterProxySettingsTools(s *mcp.Server, d *Deps) {
	svc := proxycfg.NewService(d.Client)
	parts := proxySettingsParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_proxy_settings_get",
		Description: "Get the device update-proxy settings (server, port, username, whether a password is set, and the LCaaS proxy flag). The password is never returned. Firewall: local system scope; Panorama: a template or template_stack is required. Read-only.",
		Annotations: readOnlyTool("Get proxy settings"),
	}, systemGetHandler(d, "panos_proxy_settings_get", svc, parts, proxySettingsSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_proxy_settings_update",
		Description: "Update the device update-proxy settings: read-modify-write, only provided fields change. Provide secure_proxy_password to set the proxy password. Panorama: a template or template_stack is required. Run panos_commit to apply.",
		Annotations: updateTool("Update proxy settings"),
	}, systemUpdateHandler(d, "panos_proxy_settings_update", svc, parts, overlayProxySettings, proxySettingsSummary,
		withSecrets(proxySettingsSecrets)))
}
