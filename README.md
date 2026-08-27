<p align="center">
  <img src="assets/panos-mcp-go.svg" alt="panos-mcp-go Banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/tphakala/panos-mcp-go/actions/workflows/ci.yml"><img src="https://github.com/tphakala/panos-mcp-go/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/tphakala/panos-mcp-go/actions/workflows/codeql.yml"><img src="https://github.com/tphakala/panos-mcp-go/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/tphakala/panos-mcp-go/releases/latest"><img src="https://img.shields.io/github/v/release/tphakala/panos-mcp-go?sort=semver" alt="Release"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/tphakala/panos-mcp-go" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/tphakala/panos-mcp-go"><img src="https://pkg.go.dev/badge/github.com/tphakala/panos-mcp-go.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/tphakala/panos-mcp-go?color=FA582D" alt="License"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Protocol-00ADD8" alt="MCP Spec"></a>
</p>

An MCP server for Palo Alto Networks PAN-OS firewalls and Panorama, written in Go on top of the [pango](https://github.com/PaloAltoNetworks/pango) SDK. It gives an MCP client (an AI assistant, for example) configuration management of a single device: address and service objects, groups and tags, security, NAT, decryption, authentication and policy-based forwarding policy, and the candidate commit lifecycle. One server instance talks to one device.

## Safety model

Writes only ever touch the candidate configuration. Nothing reaches the running configuration until an explicit `panos_commit` (or, on Panorama, `panos_push` after a commit) is called, so an assistant can stage changes for review without applying them.

The server is read-only by default. Write tools are registered only when `PANOS_ALLOW_WRITES=true` is set, so a stale deployment cannot silently come up writable. `PANOS_ALLOW_WRITES` replaces the earlier `PANOS_READ_ONLY`; a non-empty `PANOS_READ_ONLY` is now rejected at startup, forcing a conscious migration rather than silently ignoring a prior write intent.

Each tool carries an annotation describing its effect (read-only, create, update, delete) so a client can warn before a destructive call. `panos_revert` in particular discards every pending candidate change on the device, including other admins' work; check `panos_config_diff` first.

## API user permissions

The API user's Admin Role profile needs specific XML API permissions. Grant these on the profile's XML API tab, matched to the tools you intend to use:

- **Operational Requests** (`type=op`): required at startup and for device operations. The server runs a warm-up at startup (it retrieves system info and detects whether the device is a firewall or Panorama) before it serves anything, and that warm-up is an operational request. `panos_system_info`, `panos_job_status`, `panos_config_diff` (a `show config list changes` operational command), and the job polling behind commit, validate, and push also need it. The operational-visibility and policy-test tools (`panos_system_resources`, `panos_ha_status`, `panos_session_list`, `panos_interface_status`, `panos_route_list`, `panos_test_security_policy_match`, `panos_test_nat_policy_match`) are operational requests too.
- **Configuration** (`type=config`): required for every object and policy tool (address, service, group, tag, and security, NAT, decryption, authentication and PBF rule create/update/delete/move).
- **Commit**: required for `panos_commit`, and for `panos_push` to a Panorama device group.

A Configuration-only role cannot start the server: the warm-up is an operational request, so startup fails with

```text
retrieving system info: API Error: Type [op] not authorized for user role.
```

Grant Operational Requests to fix it. This is intentional fail-loud behavior, not a bug.

## Configuration

Configuration comes from environment variables. `PANOS_HOST` is required, along with either `PANOS_API_KEY` or both `PANOS_USERNAME` and `PANOS_PASSWORD`. Nothing loads a `.env` file automatically: export the variables yourself or set them in your MCP client's server configuration. See [.env.example](.env.example) for the same set with inline notes.

| Variable | Default | Meaning |
|----------|---------|---------|
| `PANOS_HOST` | (required) | Firewall or Panorama hostname or IP. `PANOS_HOSTNAME` (pango's own name) is accepted as a fallback; `PANOS_HOST` wins when both are set. |
| `PANOS_PORT` | (https default) | Management port. Leave unset for the default HTTPS port. |
| `PANOS_API_KEY` | (empty) | API key auth. Used in preference to username/password when both are supplied. |
| `PANOS_USERNAME` | (empty) | Username auth, with `PANOS_PASSWORD`. |
| `PANOS_PASSWORD` | (empty) | Password for `PANOS_USERNAME`. |
| `PANOS_SKIP_VERIFY` | `false` | Disable TLS certificate verification. This exposes the management session to interception; prefer `PANOS_CA_CERT`. `PANOS_SKIP_VERIFY_CERTIFICATE` (pango's own name) is accepted as a fallback; `PANOS_SKIP_VERIFY` wins when both are set. |
| `PANOS_CA_CERT` | (empty) | Path to a PEM-encoded CA certificate for the firewall. Validated at startup: an unreadable file, or one with no PEM certificate, is a startup error. Mutually exclusive with `PANOS_SKIP_VERIFY=true`. |
| `PANOS_ALLOW_WRITES` | `false` | Set to a true value (`true`, `1`, `t`) to register write tools. Unset, empty, or false keeps the server read-only. A non-boolean value is a startup error. Replaces `PANOS_READ_ONLY`, which is now rejected at startup. |
| `PANOS_JOB_WAIT` | `120` | Maximum seconds a commit or push waits for its job. Integer, 1 to 86400. |
| `MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `http`. |
| `MCP_HTTP_HOST` | `127.0.0.1` | Bind address for the `http` transport. Loopback by default. A non-loopback bind requires `MCP_HTTP_TOKEN`. |
| `MCP_HTTP_PORT` | `8080` | Port for the `http` transport. |
| `MCP_HTTP_TOKEN` | (empty) | Bearer token for the `http` transport. When set, every request to `/mcp` must send `Authorization: Bearer <token>`; requests without it get 401. Required when `MCP_HTTP_HOST` is not a loopback address. |
| `PANOS_LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, `error` (case-insensitive). An unrecognized value is a startup error. Renamed from `LOG_LEVEL`, which is no longer read, so an unrelated `LOG_LEVEL` inherited from the MCP client cannot change this server's verbosity. |

The `http` transport serves the MCP endpoint at `/mcp` (point clients at `http://host:port/mcp`) and answers unauthenticated liveness probes at `/health`. Cross-site browser requests are refused regardless of the token.

## Tools

The server registers 313 tools on Panorama and 297 on a firewall (the 21 Panorama-only tools below are absent on a firewall, and the five firewall-only tools below are absent on Panorama). In read-only mode (the default) only the read-only tools are registered: 125 on Panorama, 122 on a firewall. These counts and the tables below are pinned by a test. Write tools require `PANOS_ALLOW_WRITES=true`. The object and policy write tools stage the candidate configuration, so run `panos_commit` to apply; the commit-lifecycle tools (`panos_commit`, `panos_validate`, `panos_revert`, `panos_push`) act on the candidate or running config directly. The descriptions in the tables below are one-line summaries; each tool's full description, including parameter constraints, is what the MCP client receives in the tool listing.

`panos_validate` is listed as a write-mode tool: it does not modify configuration, but it holds the write lock to avoid contending with a concurrent commit or push for the device-side config lock, so it is registered only when writes are enabled.

### Address, service, and tag objects

| Tool | Mode | Description |
|------|------|-------------|
| `panos_address_list` | read-only | List address objects (IP netmask, IP range, FQDN) at a location. |
| `panos_address_get` | read-only | Get one address object by name with all fields. |
| `panos_address_create` | write | Create an address object in the candidate config. |
| `panos_address_update` | write | Update an address object: read-modify-write, only provided fields change; provided arrays replace fully. |
| `panos_address_delete` | write | Delete an address object from the candidate config. |
| `panos_address_group_list` | read-only | List address groups (static member list or dynamic tag filter) at a location. |
| `panos_address_group_get` | read-only | Get one address group by name with all fields. |
| `panos_address_group_create` | write | Create an address group in the candidate config. |
| `panos_address_group_update` | write | Update an address group: read-modify-write, only provided fields change. |
| `panos_address_group_delete` | write | Delete an address group from the candidate config. |
| `panos_dynamic_user_group_list` | read-only | List dynamic user groups (tag-based member selection) at a location. |
| `panos_dynamic_user_group_get` | read-only | Get one dynamic user group by name with all fields. |
| `panos_dynamic_user_group_create` | write | Create a dynamic user group; filter is the tag-match expression selecting members. |
| `panos_dynamic_user_group_update` | write | Update a dynamic user group: read-modify-write, only provided fields change. |
| `panos_dynamic_user_group_delete` | write | Delete a dynamic user group from the candidate config. |
| `panos_service_list` | read-only | List service objects (TCP/UDP port definitions) at a location. |
| `panos_service_get` | read-only | Get one service object by name with all fields. |
| `panos_service_create` | write | Create a service object in the candidate config. |
| `panos_service_update` | write | Update a service object: read-modify-write, only provided fields change; changing ports requires protocol and port together and replaces the whole protocol block. |
| `panos_service_delete` | write | Delete a service object from the candidate config. |
| `panos_service_group_list` | read-only | List service groups (named sets of services and service groups) at a location. |
| `panos_service_group_get` | read-only | Get one service group by name with all fields. |
| `panos_service_group_create` | write | Create a service group in the candidate config. |
| `panos_service_group_update` | write | Update a service group: read-modify-write, only provided fields change. |
| `panos_service_group_delete` | write | Delete a service group from the candidate config. |
| `panos_tag_list` | read-only | List tags (labels attachable to objects and rules, each with an optional color) at a location. |
| `panos_tag_get` | read-only | Get one tag by name with all fields. |
| `panos_tag_create` | write | Create a tag in the candidate config. |
| `panos_tag_update` | write | Update a tag: read-modify-write, only provided fields change; an omitted color or comments keeps the current value, so neither can be cleared in place. |
| `panos_tag_delete` | write | Delete a tag from the candidate config. |

### Applications, application groups, external dynamic lists, URL categories, and schedules

These are the config objects rules and profiles commonly reference. They reuse the same generic CRUD and location model as the address, service, and tag objects.

| Tool | Mode | Description |
|------|------|-------------|
| `panos_application_list` | read-only | List custom application objects at a location. |
| `panos_application_get` | read-only | Get one custom application by name with its classification, default ports, timeouts and characteristics. |
| `panos_application_create` | write | Create a custom application object in the candidate config; PAN-OS requires category, subcategory, technology and risk before commit. |
| `panos_application_update` | write | Update a custom application: read-modify-write, only provided fields change; a provided default_ports list replaces the whole list. |
| `panos_application_delete` | write | Delete a custom application object from the candidate config. |
| `panos_application_group_list` | read-only | List application groups (named sets of applications, filters, and nested groups) at a location. |
| `panos_application_group_get` | read-only | Get one application group by name with its members. |
| `panos_application_group_create` | write | Create an application group in the candidate config; at least one member is required. |
| `panos_application_group_update` | write | Update an application group: read-modify-write; a non-empty members list replaces the full membership. |
| `panos_application_group_delete` | write | Delete an application group from the candidate config. |
| `panos_edl_list` | read-only | List external dynamic lists (EDLs) with their type and source URL at a location. |
| `panos_edl_get` | read-only | Get one external dynamic list by name with its type, source, exceptions, and refresh schedule. |
| `panos_edl_create` | write | Create an external dynamic list; type and url are required, and recurring is required for the ip, domain, and url types (predefined types use the built-in list name and refresh with content updates). |
| `panos_edl_update` | write | Update an external dynamic list: read-modify-write; a provided type replaces the whole source definition (recurring required for the ip, domain, and url types). |
| `panos_edl_delete` | write | Delete an external dynamic list from the candidate config. |
| `panos_custom_url_category_list` | read-only | List custom URL categories (URL lists or category-match sets) at a location. |
| `panos_custom_url_category_get` | read-only | Get one custom URL category by name with its type and members. |
| `panos_custom_url_category_create` | write | Create a custom URL category; type ('URL List' or 'Category Match') and at least one member are required. |
| `panos_custom_url_category_update` | write | Update a custom URL category: read-modify-write; a non-empty members list replaces the full list. |
| `panos_custom_url_category_delete` | write | Delete a custom URL category from the candidate config. |
| `panos_schedule_list` | read-only | List schedules (time windows a rule can be bound to) at a location. |
| `panos_schedule_get` | read-only | Get one schedule by name with its type and time ranges. |
| `panos_schedule_create` | write | Create a schedule; schedule_type (non-recurring, daily, or weekly) is required (non-recurring and daily take time ranges, weekly takes per-day lists). |
| `panos_schedule_update` | write | Update a schedule: read-modify-write; a provided schedule_type replaces the whole definition. |
| `panos_schedule_delete` | write | Delete a schedule from the candidate config. |

### Security profiles and profile groups

A security rule references a profile group via its `profile_group` field. create/update model the practical flat field subset per profile. The deeply nested per-signature rule subtrees (vulnerability/anti-spyware threat rules, anti-spyware DNS security, URL credential-enforcement and HTTP-header-insertion) are neither reported by get nor settable here; an update preserves them unchanged. The three profile types and the profile group that have no vsys location in the pango SDK (vulnerability, URL filtering, WildFire analysis, and profile groups) are managed at the shared location on a firewall. Because a shared profile group cannot reference a vsys-scoped profile, on a firewall the antivirus, anti-spyware, and file-blocking profiles a group references must also be created at the shared location (`location.shared: true`), not the default vsys. The `inline_exception_ip_addresses` field on vulnerability and anti-spyware profiles takes the names of ip-type external dynamic lists (created with `panos_edl_create`), not IP literals or address objects; PAN-OS rejects any other value as an invalid reference. On a firewall a vulnerability profile is created at the shared location while an external dynamic list defaults to the vsys, and a shared object cannot reference a vsys-scoped one, so an ip-type EDL referenced from a vulnerability profile must also be created at shared (`location.shared: true`). An anti-spyware profile is vsys-scoped and can reference an EDL created at the same vsys (or at shared).

| Tool | Mode | Description |
|------|------|-------------|
| `panos_antivirus_profile_list` | read-only | List antivirus profiles at a location. |
| `panos_antivirus_profile_get` | read-only | Get one antivirus profile by name with its managed fields (description, packet_capture, decoders). |
| `panos_antivirus_profile_create` | write | Create an antivirus profile in the candidate config. |
| `panos_antivirus_profile_update` | write | Update an antivirus profile: read-modify-write; a provided decoders list replaces the whole set, and an explicit empty list clears it. |
| `panos_antivirus_profile_delete` | write | Delete an antivirus profile from the candidate config. |
| `panos_vulnerability_profile_list` | read-only | List vulnerability protection profiles at a location. |
| `panos_vulnerability_profile_get` | read-only | Get one vulnerability protection profile by name with its managed fields; per-signature rules are not exposed. |
| `panos_vulnerability_profile_create` | write | Create a vulnerability protection profile in the candidate config. |
| `panos_vulnerability_profile_update` | write | Update a vulnerability protection profile: read-modify-write, only provided fields change. |
| `panos_vulnerability_profile_delete` | write | Delete a vulnerability protection profile from the candidate config. |
| `panos_anti_spyware_profile_list` | read-only | List anti-spyware profiles at a location. |
| `panos_anti_spyware_profile_get` | read-only | Get one anti-spyware profile by name; per-threat rules and DNS-security settings are not exposed. |
| `panos_anti_spyware_profile_create` | write | Create an anti-spyware profile in the candidate config. |
| `panos_anti_spyware_profile_update` | write | Update an anti-spyware profile: read-modify-write, only provided fields change. |
| `panos_anti_spyware_profile_delete` | write | Delete an anti-spyware profile from the candidate config. |
| `panos_url_filtering_profile_list` | read-only | List URL filtering profiles at a location. |
| `panos_url_filtering_profile_get` | read-only | Get one URL filtering profile by name with its category actions. |
| `panos_url_filtering_profile_create` | write | Create a URL filtering profile in the candidate config. |
| `panos_url_filtering_profile_update` | write | Update a URL filtering profile: read-modify-write; a provided category list replaces that action's whole set, and an explicit empty list clears it. |
| `panos_url_filtering_profile_delete` | write | Delete a URL filtering profile from the candidate config. |
| `panos_file_blocking_profile_list` | read-only | List file-blocking profiles at a location. |
| `panos_file_blocking_profile_get` | read-only | Get one file-blocking profile by name with its rules. |
| `panos_file_blocking_profile_create` | write | Create a file-blocking profile in the candidate config. |
| `panos_file_blocking_profile_update` | write | Update a file-blocking profile: read-modify-write; a provided rules list replaces the whole set, and an explicit empty list clears it. |
| `panos_file_blocking_profile_delete` | write | Delete a file-blocking profile from the candidate config. |
| `panos_wildfire_analysis_profile_list` | read-only | List WildFire analysis profiles at a location. |
| `panos_wildfire_analysis_profile_get` | read-only | Get one WildFire analysis profile by name with its rules. |
| `panos_wildfire_analysis_profile_create` | write | Create a WildFire analysis profile in the candidate config. |
| `panos_wildfire_analysis_profile_update` | write | Update a WildFire analysis profile: read-modify-write; a provided rules list replaces the whole set, and an explicit empty list clears it. |
| `panos_wildfire_analysis_profile_delete` | write | Delete a WildFire analysis profile from the candidate config. |
| `panos_profile_group_list` | read-only | List security profile groups at a location. |
| `panos_profile_group_get` | read-only | Get one security profile group by name with the profile referenced for each type. |
| `panos_profile_group_create` | write | Create a security profile group in the candidate config, referencing one profile per type. |
| `panos_profile_group_update` | write | Update a security profile group: read-modify-write, only provided profile references change. |
| `panos_profile_group_delete` | write | Delete a security profile group from the candidate config. |
| `panos_log_forwarding_profile_list` | read-only | List log-forwarding profiles at a location (managed at shared on a firewall). |
| `panos_log_forwarding_profile_get` | read-only | Get one log-forwarding profile by name with its match lists. |
| `panos_log_forwarding_profile_create` | write | Create a log-forwarding profile in the candidate config; match lists select which logs are forwarded to server profiles or Panorama. |
| `panos_log_forwarding_profile_update` | write | Update a log-forwarding profile: read-modify-write; a provided match_lists list replaces the whole set. |
| `panos_log_forwarding_profile_delete` | write | Delete a log-forwarding profile from the candidate config. |
| `panos_decryption_profile_list` | read-only | List decryption profiles at a location. |
| `panos_decryption_profile_get` | read-only | Get one decryption profile by name with its managed fields and presence flags for the SDK-only proxy subtrees. |
| `panos_decryption_profile_create` | write | Create a decryption profile in the candidate config. |
| `panos_decryption_profile_update` | write | Update a decryption profile: read-modify-write; the SDK-only proxy subtrees and per-algorithm toggles are preserved. |
| `panos_decryption_profile_delete` | write | Delete a decryption profile from the candidate config. |

### Security and NAT policy

| Tool | Mode | Description |
|------|------|-------------|
| `panos_security_rule_list` | read-only | List security rules in evaluation order at a location. |
| `panos_security_rule_get` | read-only | Get one security rule by name with its managed fields plus the read-only advanced detail (schedule, rule type, logging, negate flags, source users, HIP profiles, category, group tag, uuid, and any individually assigned profiles). |
| `panos_security_rule_create` | write | Create a security rule in the candidate config; an optional schedule limits when it is active. |
| `panos_security_rule_update` | write | Update a security rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field); a provided schedule sets the rule's schedule. |
| `panos_security_rule_delete` | write | Delete a security rule from the candidate config. |
| `panos_security_rule_move` | write | Move a security rule within its rulebase: top, bottom, or directly before/after another rule. |
| `panos_nat_rule_list` | read-only | List NAT rules in evaluation order at a location. |
| `panos_nat_rule_get` | read-only | Get one NAT rule by name with all fields including the full translation subtrees. |
| `panos_nat_rule_create` | write | Create a NAT rule in the candidate config. |
| `panos_nat_rule_update` | write | Update a NAT rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field). |
| `panos_nat_rule_delete` | write | Delete a NAT rule from the candidate config. |
| `panos_nat_rule_move` | write | Move a NAT rule within its rulebase: top, bottom, or directly before/after another rule. |

### Decryption, authentication, and policy-based forwarding policy

| Tool | Mode | Description |
|------|------|-------------|
| `panos_decryption_rule_list` | read-only | List decryption rules in evaluation order at a location. |
| `panos_decryption_rule_get` | read-only | Get one decryption rule by name with the managed fields, including the decryption type and its certificates. |
| `panos_decryption_rule_create` | write | Create a decryption rule in the candidate config. action (decrypt or no-decrypt) is required; decryption_type selects ssh-proxy, ssl-forward-proxy or ssl-inbound-inspection. |
| `panos_decryption_rule_update` | write | Update a decryption rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field). A provided decryption_type replaces the whole type choice. |
| `panos_decryption_rule_delete` | write | Delete a decryption rule from the candidate config. |
| `panos_decryption_rule_move` | write | Move a decryption rule within its rulebase: top, bottom, or directly before/after another rule. |
| `panos_authentication_rule_list` | read-only | List authentication rules in evaluation order at a location. |
| `panos_authentication_rule_get` | read-only | Get one authentication rule by name with the managed fields, including the authentication enforcement object and timeout. |
| `panos_authentication_rule_create` | write | Create an authentication rule in the candidate config. Nothing beyond name is required; authentication_enforcement names the enforcement object applied to matching traffic. |
| `panos_authentication_rule_update` | write | Update an authentication rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field). |
| `panos_authentication_rule_delete` | write | Delete an authentication rule from the candidate config. |
| `panos_authentication_rule_move` | write | Move an authentication rule within its rulebase: top, bottom, or directly before/after another rule. |
| `panos_pbf_rule_list` | read-only | List policy-based forwarding rules in evaluation order at a location. |
| `panos_pbf_rule_get` | read-only | Get one policy-based forwarding rule by name with the managed fields, including the action and its forward parameters. |
| `panos_pbf_rule_create` | write | Create a policy-based forwarding rule in the candidate config. action (forward, forward-to-vsys, discard or no-pbf) and from (source zones) are required; action forward requires egress_interface with optional nexthop_ip or nexthop_fqdn. |
| `panos_pbf_rule_update` | write | Update a policy-based forwarding rule: read-modify-write, only provided fields change; a provided action or from replaces the whole choice; non-empty lists replace fully. |
| `panos_pbf_rule_delete` | write | Delete a policy-based forwarding rule from the candidate config. |
| `panos_pbf_rule_move` | write | Move a policy-based forwarding rule within its rulebase: top, bottom, or directly before/after another rule. |

### Device operations

| Tool | Mode | Description |
|------|------|-------------|
| `panos_system_info` | read-only | Show device system info (model, serial, versions). Doubles as the connection test. |
| `panos_job_status` | read-only | Poll a device job (commit, push, validate) by ID. |
| `panos_config_diff` | read-only | List pending candidate changes (changed path, action, owner) versus the running config. |
| `panos_zone_list` | read-only | List security zone names for use in rules. Firewall: optional vsys (a template is rejected); Panorama: template required (a vsys is rejected). |
| `panos_zone_get` | read-only | Get one security zone's full detail (network type, interfaces, protection settings, and user/device-id flags). Firewall: optional vsys; Panorama: template required. |
| `panos_zone_create` | write | Create a security zone; network_type is required. Firewall: vsys scope; Panorama: template required. |
| `panos_zone_update` | write | Update a security zone: read-modify-write; a provided network_type replaces the type and its interface list. |
| `panos_zone_delete` | write | Delete a security zone from the candidate config. |
| `panos_device_group_list` *(Panorama only)* | read-only | List Panorama device groups. |
| `panos_template_list` *(Panorama only)* | read-only | List Panorama templates (zone and network config scopes). |
| `panos_commit` | write | Commit the candidate config to the running config. On Panorama this commits to Panorama itself; push to firewalls with `panos_push`. |
| `panos_validate` | write | Validate the candidate config without committing. |
| `panos_revert` | write | Revert the candidate config to the running config. Discards all pending changes device-wide; check `panos_config_diff` first. |
| `panos_push` *(Panorama only)* | write | Push committed config to a device group's firewalls (commit-all). Does not commit first; run `panos_commit` before it. |

### Operational visibility and policy tests

These are read-only operational commands (`type=op`), not configuration changes. The policy-match tests evaluate a hypothetical flow against the running (committed) config, so they are a safe way to reason about a rule before or after a change. The firewall-only tools (sessions, interfaces, routes, and the two policy-match tests) need a dataplane or a running firewall policy that Panorama does not have, so they are absent there.

| Tool | Mode | Description |
|------|------|-------------|
| `panos_system_resources` | read-only | Show management-plane resource usage (CPU, memory, load) as reported by the device. |
| `panos_ha_status` | read-only | Show high-availability state: enabled, mode, and local and peer state. |
| `panos_session_list` *(Firewall only)* | read-only | List active sessions from the flow table, with optional source, destination, port, application, and zone filters. |
| `panos_interface_status` *(Firewall only)* | read-only | Show interface status (hardware and logical), optionally filtered to one interface. |
| `panos_route_list` *(Firewall only)* | read-only | List routes from the legacy virtual-router routing table, optionally scoped to one virtual router. |
| `panos_test_security_policy_match` *(Firewall only)* | read-only | Test which security rule a hypothetical flow would match against the running config. |
| `panos_test_nat_policy_match` *(Firewall only)* | read-only | Test which NAT rule a hypothetical flow would match, and the resulting translation, against the running config. |

### Site-to-site VPN

These configure IPSec and GRE VPN. On a firewall they apply at the device scope; on Panorama they require a `template` or `template_stack`. The crypto profiles, gateway, and tunnels reference each other by name within the same scope.

| Tool | Mode | Description |
|------|------|-------------|
| `panos_ike_crypto_profile_list` | read-only | List IKE crypto profiles (IKE phase-1 SA parameters). |
| `panos_ike_crypto_profile_get` | read-only | Get one IKE crypto profile (dh_group, encryption, hash, lifetime). |
| `panos_ike_crypto_profile_create` | write | Create an IKE crypto profile; an IKE gateway references it by name. |
| `panos_ike_crypto_profile_update` | write | Update an IKE crypto profile: read-modify-write; a provided algorithm list replaces the existing one fully. |
| `panos_ike_crypto_profile_delete` | write | Delete an IKE crypto profile from the candidate config. |
| `panos_ipsec_crypto_profile_list` | read-only | List IPSec crypto profiles (IPSec phase-2 SA parameters). |
| `panos_ipsec_crypto_profile_get` | read-only | Get one IPSec crypto profile (dh_group, esp/ah algorithms, lifetime, lifesize). |
| `panos_ipsec_crypto_profile_create` | write | Create an IPSec crypto profile; an IPSec tunnel references it by name. |
| `panos_ipsec_crypto_profile_update` | write | Update an IPSec crypto profile: read-modify-write; a provided algorithm list replaces the existing one fully. |
| `panos_ipsec_crypto_profile_delete` | write | Delete an IPSec crypto profile from the candidate config. |
| `panos_ike_gateway_list` | read-only | List IKE gateways (VPN peers). |
| `panos_ike_gateway_get` | read-only | Get one IKE gateway (peer/local address, protocol version, ike_crypto_profile). The pre-shared key is never returned. |
| `panos_ike_gateway_create` | write | Create an IKE gateway; set ike_crypto_profile and one of peer_ip, peer_fqdn or peer_dynamic. The pre-shared key is write-only. |
| `panos_ike_gateway_update` | write | Update an IKE gateway: read-modify-write; the SDK-only certificate-auth, DPD and NAT-traversal subtrees are preserved. |
| `panos_ike_gateway_delete` | write | Delete an IKE gateway from the candidate config. |
| `panos_ipsec_tunnel_list` | read-only | List IPSec tunnels. |
| `panos_ipsec_tunnel_get` | read-only | Get one IPSec tunnel (tunnel_interface, bound ike_gateways, ipsec_crypto_profile, option toggles). |
| `panos_ipsec_tunnel_create` | write | Create an IPSec tunnel; bind it to a tunnel_interface, ike_gateways and an ipsec_crypto_profile. |
| `panos_ipsec_tunnel_update` | write | Update an IPSec tunnel: read-modify-write; a provided ike_gateways list replaces the bound gateways fully. |
| `panos_ipsec_tunnel_delete` | write | Delete an IPSec tunnel from the candidate config. |
| `panos_gre_tunnel_list` | read-only | List GRE tunnels. |
| `panos_gre_tunnel_get` | read-only | Get one GRE tunnel (tunnel_interface, local/peer address, ttl, keep-alive). |
| `panos_gre_tunnel_create` | write | Create a GRE tunnel; bind it to a tunnel_interface and set local/peer addresses. |
| `panos_gre_tunnel_update` | write | Update a GRE tunnel: read-modify-write, only provided fields change. |
| `panos_gre_tunnel_delete` | write | Delete a GRE tunnel from the candidate config. |

### Panorama device groups and templates

These manage the Panorama containers themselves. They are Panorama-only. The device-group and template list tools are under Device operations above. Parent device-group hierarchy is not managed.

| Tool | Mode | Description |
|------|------|-------------|
| `panos_device_group_get` *(Panorama only)* | read-only | Get one Panorama device group (description, bound templates, member devices). |
| `panos_device_group_create` *(Panorama only)* | write | Create a Panorama device group. Parent hierarchy is not managed. |
| `panos_device_group_update` *(Panorama only)* | write | Update a Panorama device group: read-modify-write; a provided templates list replaces the bound templates fully. |
| `panos_device_group_delete` *(Panorama only)* | write | Delete a Panorama device group from the candidate config. |
| `panos_template_get` *(Panorama only)* | read-only | Get one Panorama template (description, default_vsys). |
| `panos_template_create` *(Panorama only)* | write | Create a Panorama template. |
| `panos_template_update` *(Panorama only)* | write | Update a Panorama template: read-modify-write; the device/vsys config subtree is preserved. |
| `panos_template_delete` *(Panorama only)* | write | Delete a Panorama template from the candidate config. |
| `panos_template_stack_list` *(Panorama only)* | read-only | List Panorama template stacks (member templates, assigned devices). |
| `panos_template_stack_get` *(Panorama only)* | read-only | Get one Panorama template stack (ordered member templates, default_vsys, assigned devices, master_device). |
| `panos_template_stack_create` *(Panorama only)* | write | Create a Panorama template stack; list member templates in priority order, highest first (the first member is the top of the stack and wins any duplicated setting), and assign firewalls by serial. |
| `panos_template_stack_update` *(Panorama only)* | write | Update a Panorama template stack: read-modify-write; a provided templates or devices list replaces that member list fully. |
| `panos_template_stack_delete` *(Panorama only)* | write | Delete a Panorama template stack from the candidate config. |
| `panos_template_variable_list` *(Panorama only)* | read-only | List Panorama template variables in a template or template_stack. |
| `panos_template_variable_get` *(Panorama only)* | read-only | Get one Panorama template variable (type and value). |
| `panos_template_variable_create` *(Panorama only)* | write | Create a Panorama template variable; var_type and value are required. |
| `panos_template_variable_update` *(Panorama only)* | write | Update a Panorama template variable; provide var_type and value together to change the value. |
| `panos_template_variable_delete` *(Panorama only)* | write | Delete a Panorama template variable from a template or template_stack. |

### Layer 3 interfaces, virtual routers, and interface management

These network-configuration tools are net-scoped: on a firewall they act on the local device; on Panorama a `template` or `template_stack` is required. The interface tools model the Layer 3 configuration (addresses, MTU, management profile, IPv6 enable); other interface modes (Layer 2, virtual wire, tap) and deep subtrees are preserved untouched across updates but are not settable here, so converting an existing non-L3 port is out of scope.

| Tool | Mode | Description |
| --- | --- | --- |
| `panos_ethernet_interface_list` | read-only | List Layer 3 ethernet interfaces at a location. |
| `panos_ethernet_interface_get` | read-only | Get one ethernet interface (comment, mtu, ips, management profile, ipv6, link settings, aggregate group). |
| `panos_ethernet_interface_create` | write | Create a Layer 3 ethernet interface in the candidate config. |
| `panos_ethernet_interface_update` | write | Update an ethernet interface: read-modify-write; a provided ips list replaces the addresses fully. |
| `panos_ethernet_interface_delete` | write | Delete an ethernet interface from the candidate config. |
| `panos_aggregate_interface_list` | read-only | List Layer 3 aggregate (ae) interfaces at a location. |
| `panos_aggregate_interface_get` | read-only | Get one aggregate interface (comment, mtu, ips, management profile, ipv6). |
| `panos_aggregate_interface_create` | write | Create a Layer 3 aggregate interface in the candidate config. |
| `panos_aggregate_interface_update` | write | Update an aggregate interface: read-modify-write; a provided ips list replaces the addresses fully. |
| `panos_aggregate_interface_delete` | write | Delete an aggregate interface from the candidate config. |
| `panos_loopback_interface_list` | read-only | List loopback interfaces at a location. |
| `panos_loopback_interface_get` | read-only | Get one loopback interface (comment, mtu, ips, management profile, ipv6). |
| `panos_loopback_interface_create` | write | Create a loopback interface in the candidate config. |
| `panos_loopback_interface_update` | write | Update a loopback interface: read-modify-write; a provided ips list replaces the addresses fully. |
| `panos_loopback_interface_delete` | write | Delete a loopback interface from the candidate config. |
| `panos_vlan_interface_list` | read-only | List VLAN interfaces at a location. |
| `panos_vlan_interface_get` | read-only | Get one VLAN interface (comment, mtu, ips, management profile, ipv6). |
| `panos_vlan_interface_create` | write | Create a VLAN interface in the candidate config. |
| `panos_vlan_interface_update` | write | Update a VLAN interface: read-modify-write; a provided ips list replaces the addresses fully. |
| `panos_vlan_interface_delete` | write | Delete a VLAN interface from the candidate config. |
| `panos_tunnel_interface_list` | read-only | List tunnel interfaces at a location. |
| `panos_tunnel_interface_get` | read-only | Get one tunnel interface (comment, mtu, ips, management profile, ipv6, link_tag). |
| `panos_tunnel_interface_create` | write | Create a tunnel interface in the candidate config. |
| `panos_tunnel_interface_update` | write | Update a tunnel interface: read-modify-write; a provided ips list replaces the addresses fully. |
| `panos_tunnel_interface_delete` | write | Delete a tunnel interface from the candidate config. |
| `panos_virtual_router_list` | read-only | List virtual routers at a location. |
| `panos_virtual_router_get` | read-only | Get one virtual router (bound interfaces, administrative distances). |
| `panos_virtual_router_create` | write | Create a virtual router; bind member interfaces and set administrative distances. |
| `panos_virtual_router_update` | write | Update a virtual router: read-modify-write; a provided interfaces list replaces the members fully. Routing protocols (BGP, OSPF, OSPFv3, RIP), ECMP and multicast are preserved untouched. |
| `panos_virtual_router_delete` | write | Delete a virtual router from the candidate config. |
| `panos_logical_router_list` | read-only | List logical routers at a location. |
| `panos_logical_router_get` | read-only | Get one logical router (name and VRF count). |
| `panos_logical_router_create` | write | Create an empty logical router; per-VRF routing is configured elsewhere and preserved. |
| `panos_logical_router_delete` | write | Delete a logical router (and its VRF configuration) from the candidate config. |
| `panos_interface_mgmt_profile_list` | read-only | List interface management profiles at a location. |
| `panos_interface_mgmt_profile_get` | read-only | Get one interface management profile (permitted services and permitted IPs). |
| `panos_interface_mgmt_profile_create` | write | Create an interface management profile in the candidate config. |
| `panos_interface_mgmt_profile_update` | write | Update an interface management profile: read-modify-write; a provided permitted_ip list replaces the entries fully. |
| `panos_interface_mgmt_profile_delete` | write | Delete an interface management profile from the candidate config. |

### LLDP, BFD, monitor profiles, and Layer 2 switching

These network profiles and the two Layer 2 switching objects are net-scoped: on a firewall they act on the local device; on Panorama a `template` or `template_stack` is required. Optional subtrees (LLDP TLVs, BFD multihop, virtual-wire link-state and multicast, the VLAN virtual-interface) are preserved untouched across updates but are not settable here. The `panos_vlan_*` tools manage the Layer 2 VLAN object, distinct from the Layer 3 VLAN interface (`panos_vlan_interface_*`).

| Tool | Mode | Description |
| --- | --- | --- |
| `panos_lldp_profile_list` | read-only | List LLDP profiles at a location. |
| `panos_lldp_profile_get` | read-only | Get one LLDP profile (mode and the notification toggle). |
| `panos_lldp_profile_create` | write | Create an LLDP profile in the candidate config. |
| `panos_lldp_profile_update` | write | Update an LLDP profile: read-modify-write; the TLV set is preserved. |
| `panos_lldp_profile_delete` | write | Delete an LLDP profile from the candidate config. |
| `panos_bfd_profile_list` | read-only | List BFD profiles at a location. |
| `panos_bfd_profile_get` | read-only | Get one BFD profile (mode and detection timers). |
| `panos_bfd_profile_create` | write | Create a BFD profile in the candidate config. |
| `panos_bfd_profile_update` | write | Update a BFD profile: read-modify-write; the multihop settings are preserved. |
| `panos_bfd_profile_delete` | write | Delete a BFD profile from the candidate config. |
| `panos_monitor_profile_list` | read-only | List monitor profiles at a location. |
| `panos_monitor_profile_get` | read-only | Get one monitor profile (action, interval, threshold). |
| `panos_monitor_profile_create` | write | Create a monitor profile in the candidate config. |
| `panos_monitor_profile_update` | write | Update a monitor profile: read-modify-write. |
| `panos_monitor_profile_delete` | write | Delete a monitor profile from the candidate config. |
| `panos_zone_protection_list` | read-only | List zone protection profiles at a location. |
| `panos_zone_protection_get` | read-only | Get one zone protection profile (packet-based-attack toggles). |
| `panos_zone_protection_create` | write | Create a zone protection profile in the candidate config. |
| `panos_zone_protection_update` | write | Update a zone protection profile: read-modify-write; flood, IPv6, reconnaissance, non-IP-protocol and scan sub-blocks are preserved. |
| `panos_zone_protection_delete` | write | Delete a zone protection profile from the candidate config. |
| `panos_virtual_wire_list` | read-only | List virtual wires at a location. |
| `panos_virtual_wire_get` | read-only | Get one virtual wire (bound interfaces and allowed tags). |
| `panos_virtual_wire_create` | write | Create a virtual wire binding two Layer 2 interfaces. |
| `panos_virtual_wire_update` | write | Update a virtual wire: read-modify-write; link-state and multicast settings are preserved. |
| `panos_virtual_wire_delete` | write | Delete a virtual wire from the candidate config. |
| `panos_vlan_list` | read-only | List VLAN objects (Layer 2 broadcast domains) at a location. |
| `panos_vlan_get` | read-only | Get one VLAN object (its Layer 2 member interfaces). |
| `panos_vlan_create` | write | Create a VLAN object in the candidate config. |
| `panos_vlan_update` | write | Update a VLAN object: read-modify-write; a provided interfaces list replaces the members fully. |
| `panos_vlan_delete` | write | Delete a VLAN object from the candidate config. |

### DHCP and DNS proxy

These net-scoped network services follow the same scoping as the interface tools: on a firewall they act on the local device; on Panorama a `template` or `template_stack` is required. DNS proxy is template-only, so it needs a `template` or `template_stack` even on a firewall. A DHCP entry is named by its interface and is either a relay or a server, never both. Subtrees not modeled here (DHCP server options and reservations, IPv6 relay, DNS proxy cache and TCP/UDP query tuning) are preserved untouched across updates.

| Tool | Mode | Description |
| --- | --- | --- |
| `panos_dhcp_list` | read-only | List DHCP interface configurations at a location. |
| `panos_dhcp_get` | read-only | Get one interface's DHCP configuration (relay or server). |
| `panos_dhcp_create` | write | Create an interface DHCP relay or server in the candidate config. |
| `panos_dhcp_update` | write | Update an interface's DHCP configuration: read-modify-write; switching between relay and server clears the other. |
| `panos_dhcp_delete` | write | Delete an interface's DHCP configuration from the candidate config. |
| `panos_dns_proxy_list` | read-only | List DNS proxy objects at a location (template or template_stack). |
| `panos_dns_proxy_get` | read-only | Get one DNS proxy object (default servers, static entries, domain servers). |
| `panos_dns_proxy_create` | write | Create a DNS proxy object in the candidate config. |
| `panos_dns_proxy_update` | write | Update a DNS proxy object: read-modify-write; a provided static-entry or domain-server list replaces that list. |
| `panos_dns_proxy_delete` | write | Delete a DNS proxy object from the candidate config. |

### Device server profiles

These authentication and log-forwarding server profiles are device-scoped: on a firewall they resolve to a `vsys` (or `shared`, for the authentication profiles); on Panorama a `template`, `template_stack`, or `shared` selection is required. The log-forwarding profiles (syslog, SNMP-trap, email) have no shared scope. Secrets (bind and shared-secret passwords, SNMP communities and v3 passwords, SMTP passwords) are write-only: they are accepted on create and update but never returned, and a get reports only a `has_<secret>` boolean.

| Tool | Mode | Description |
| --- | --- | --- |
| `panos_ldap_profile_list` | read-only | List LDAP server profiles at a location. |
| `panos_ldap_profile_get` | read-only | Get one LDAP server profile (the bind password is never returned). |
| `panos_ldap_profile_create` | write | Create an LDAP server profile; bind_password is write-only. |
| `panos_ldap_profile_update` | write | Update an LDAP server profile: read-modify-write; an omitted bind_password is kept; a provided servers list is merged by name, so a server absent from the list is removed. |
| `panos_ldap_profile_delete` | write | Delete an LDAP server profile from the candidate config. |
| `panos_tacacs_profile_list` | read-only | List TACACS+ server profiles at a location. |
| `panos_tacacs_profile_get` | read-only | Get one TACACS+ server profile (per-server secrets are never returned). |
| `panos_tacacs_profile_create` | write | Create a TACACS+ server profile; server secrets are write-only. |
| `panos_tacacs_profile_update` | write | Update a TACACS+ server profile: read-modify-write; a provided servers list is merged by name, so an omitted per-server secret is kept and a server absent from the list is removed. |
| `panos_tacacs_profile_delete` | write | Delete a TACACS+ server profile from the candidate config. |
| `panos_radius_profile_list` | read-only | List RADIUS server profiles at a location. |
| `panos_radius_profile_get` | read-only | Get one RADIUS server profile (per-server secrets are never returned). |
| `panos_radius_profile_create` | write | Create a RADIUS server profile; server secrets are write-only. |
| `panos_radius_profile_update` | write | Update a RADIUS server profile: read-modify-write; a provided servers list is merged by name, so an omitted per-server secret is kept and a server absent from the list is removed. |
| `panos_radius_profile_delete` | write | Delete a RADIUS server profile from the candidate config. |
| `panos_syslog_profile_list` | read-only | List syslog server profiles at a location. |
| `panos_syslog_profile_get` | read-only | Get one syslog server profile (its servers). |
| `panos_syslog_profile_create` | write | Create a syslog server profile in the candidate config. |
| `panos_syslog_profile_update` | write | Update a syslog server profile: read-modify-write; a provided servers list is merged by name, so a server absent from the list is removed. |
| `panos_syslog_profile_delete` | write | Delete a syslog server profile from the candidate config. |
| `panos_snmptrap_profile_list` | read-only | List SNMP-trap server profiles at a location. |
| `panos_snmptrap_profile_get` | read-only | Get one SNMP-trap server profile (communities and v3 passwords are never returned). |
| `panos_snmptrap_profile_create` | write | Create an SNMP-trap server profile; version (v2c or v3) is required, secrets are write-only. |
| `panos_snmptrap_profile_update` | write | Update an SNMP-trap server profile: read-modify-write; switching version clears the other receivers; within a version a provided receiver list is merged by name, so an omitted community or password is kept and a receiver absent from the list is removed. |
| `panos_snmptrap_profile_delete` | write | Delete an SNMP-trap server profile from the candidate config. |
| `panos_email_profile_list` | read-only | List email server profiles at a location. |
| `panos_email_profile_get` | read-only | Get one email server profile (SMTP passwords are never returned). |
| `panos_email_profile_create` | write | Create an email server profile; SMTP passwords are write-only. |
| `panos_email_profile_update` | write | Update an email server profile: read-modify-write; a provided servers list is merged by name, so an omitted password is kept and a server absent from the list is removed. |
| `panos_email_profile_delete` | write | Delete an email server profile from the candidate config. |

### Local users and authentication profiles

These device-scoped identity objects resolve the same way as the server profiles: a firewall `vsys` or `shared`, or a Panorama `template`, `template_stack`, or `shared` selection. A local user's `password_hash` is a write-only pre-hashed password (PHASH): it is accepted on create and update but never returned, and a get reports only `has_password_hash`. The SAML IdP and MFA profiles reference a device certificate and a certificate profile by name.

| Tool | Mode | Description |
| --- | --- | --- |
| `panos_local_user_list` | read-only | List local database users at a location. |
| `panos_local_user_get` | read-only | Get one local user (disabled state; the password hash is never returned). |
| `panos_local_user_create` | write | Create a local database user; password_hash is required and is a write-only PHASH. |
| `panos_local_user_update` | write | Update a local user: read-modify-write; an omitted password_hash is kept. |
| `panos_local_user_delete` | write | Delete a local database user from the candidate config. |
| `panos_saml_idp_profile_list` | read-only | List SAML identity provider profiles at a location. |
| `panos_saml_idp_profile_get` | read-only | Get one SAML IdP profile (entity ID, SSO/SLO URLs, certificate). |
| `panos_saml_idp_profile_create` | write | Create a SAML IdP profile in the candidate config. |
| `panos_saml_idp_profile_update` | write | Update a SAML IdP profile: read-modify-write. |
| `panos_saml_idp_profile_delete` | write | Delete a SAML IdP profile from the candidate config. |
| `panos_mfa_profile_list` | read-only | List multi-factor authentication server profiles at a location. |
| `panos_mfa_profile_get` | read-only | Get one MFA profile (certificate profile, vendor type, config item names; vendor config values are write-only and never returned). |
| `panos_mfa_profile_create` | write | Create an MFA server profile in the candidate config. |
| `panos_mfa_profile_update` | write | Update an MFA profile: read-modify-write; a provided config list replaces it. |
| `panos_mfa_profile_delete` | write | Delete an MFA server profile from the candidate config. |

## Example MCP client configuration

A stdio server entry, read-only:

```json
{
  "mcpServers": {
    "panos": {
      "command": "/usr/local/bin/panos-mcp-go",
      "env": {
        "PANOS_HOST": "firewall.example.com",
        "PANOS_API_KEY": "<api key>"
      }
    }
  }
}
```

Add `"PANOS_ALLOW_WRITES": "true"` to the `env` block to register the write tools.

## Building

Requires Go 1.27, [Task](https://taskfile.dev) and [golangci-lint](https://golangci-lint.run) 2.x.

```bash
task check     # format check, tidy check, vet, lint and test, without modifying files
task build     # build the binary
task go:test   # run tests with the race detector
```

`task check` does not modify files. Use `task go:fmt` and `task go:tidy` to apply formatting and tidying. Formatting goes through `golangci-lint fmt` rather than a standalone goimports, because the two disagree on gofmt's doc comment rules and using both produces a tree that passes locally and fails in CI.

### Docker

```bash
task image:build   # builds panos-mcp-go:<version> via docker
```

Or build and run directly. `task image:build` tags the image `panos-mcp-go:<version>` from `git describe`, while the manual commands below build and run `panos-mcp-go:latest`. The image sets `MCP_HTTP_HOST=0.0.0.0` so a published port is reachable, which means the `http` transport requires `MCP_HTTP_TOKEN`:

```bash
docker build --build-arg VERSION="$(git describe --tags --always --dirty)" -t panos-mcp-go .

docker run --rm \
  -e PANOS_HOST=firewall.example.com \
  -e PANOS_API_KEY=<api key> \
  -e MCP_TRANSPORT=http \
  -e MCP_HTTP_TOKEN=<token> \
  -p 8080:8080 \
  panos-mcp-go
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
