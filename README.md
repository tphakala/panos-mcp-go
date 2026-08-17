# panos-mcp-go

An MCP server for Palo Alto Networks PAN-OS firewalls and Panorama, written in Go on top of the [pango](https://github.com/PaloAltoNetworks/pango) SDK. It gives an MCP client (an AI assistant, for example) configuration management of a single device: address and service objects, groups and tags, security and NAT policy, and the candidate commit lifecycle. One server instance talks to one device.

## Safety model

Writes only ever touch the candidate configuration. Nothing reaches the running configuration until an explicit `panos_commit` (or, on Panorama, `panos_push` after a commit) is called, so an assistant can stage changes for review without applying them.

The server is read-only by default. Write tools are registered only when `PANOS_ALLOW_WRITES=true` is set, so a stale deployment cannot silently come up writable. `PANOS_ALLOW_WRITES` replaces the earlier `PANOS_READ_ONLY`; a non-empty `PANOS_READ_ONLY` is now rejected at startup, forcing a conscious migration rather than silently ignoring a prior write intent.

Each tool carries an annotation describing its effect (read-only, create, update, delete) so a client can warn before a destructive call. `panos_revert` in particular discards every pending candidate change on the device, including other admins' work; check `panos_config_diff` first.

## API user permissions

The API user's Admin Role profile needs specific XML API permissions. Grant these on the profile's XML API tab, matched to the tools you intend to use:

- **Operational Requests** (`type=op`): required at startup and for device operations. The server runs a warm-up at startup (it retrieves system info and detects whether the device is a firewall or Panorama) before it serves anything, and that warm-up is an operational request. `panos_system_info`, `panos_job_status`, `panos_config_diff` (a `show config diff` operational command), and the job polling behind commit, validate, and push also need it.
- **Configuration** (`type=config`): required for every object and policy tool (address, service, group, tag, security and NAT rule create/update/delete/move).
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

The server registers 47 tools on Panorama and 44 on a firewall (the three Panorama-only tools below are absent on a firewall). In read-only mode (the default) only the read-only tools are registered: 20 on Panorama, 18 on a firewall. These counts are pinned by a test. Write tools require `PANOS_ALLOW_WRITES=true`. The object and policy write tools stage the candidate configuration, so run `panos_commit` to apply; the commit-lifecycle tools (`panos_commit`, `panos_validate`, `panos_revert`, `panos_push`) act on the candidate or running config directly. The descriptions in the tables below are one-line summaries; each tool's full description, including parameter constraints, is what the MCP client receives in the tool listing.

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

### Security and NAT policy

| Tool | Mode | Description |
|------|------|-------------|
| `panos_security_rule_list` | read-only | List security rules in evaluation order at a location. |
| `panos_security_rule_get` | read-only | Get one security rule by name with all fields. |
| `panos_security_rule_create` | write | Create a security rule in the candidate config. |
| `panos_security_rule_update` | write | Update a security rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field). |
| `panos_security_rule_delete` | write | Delete a security rule from the candidate config. |
| `panos_security_rule_move` | write | Move a security rule within its rulebase: top, bottom, or directly before/after another rule. |
| `panos_nat_rule_list` | read-only | List NAT rules in evaluation order at a location. |
| `panos_nat_rule_get` | read-only | Get one NAT rule by name with all fields including the full translation subtrees. |
| `panos_nat_rule_create` | write | Create a NAT rule in the candidate config. |
| `panos_nat_rule_update` | write | Update a NAT rule: read-modify-write, only provided fields change; non-empty lists replace fully (send `["any"]` to reset a match field). |
| `panos_nat_rule_delete` | write | Delete a NAT rule from the candidate config. |
| `panos_nat_rule_move` | write | Move a NAT rule within its rulebase: top, bottom, or directly before/after another rule. |

### Device operations

| Tool | Mode | Description |
|------|------|-------------|
| `panos_system_info` | read-only | Show device system info (model, serial, versions). Doubles as the connection test. |
| `panos_job_status` | read-only | Poll a device job (commit, push, validate) by ID. |
| `panos_config_diff` | read-only | Show pending candidate changes versus the running config. |
| `panos_zone_list` | read-only | List security zone names for use in rules. On Panorama, requires a template. |
| `panos_device_group_list` *(Panorama only)* | read-only | List Panorama device groups. |
| `panos_template_list` *(Panorama only)* | read-only | List Panorama templates (zone and network config scopes). |
| `panos_commit` | write | Commit the candidate config to the running config. On Panorama this commits to Panorama itself; push to firewalls with `panos_push`. |
| `panos_validate` | write | Validate the candidate config without committing. |
| `panos_revert` | write | Revert the candidate config to the running config. Discards all pending changes device-wide; check `panos_config_diff` first. |
| `panos_push` *(Panorama only)* | write | Push committed config to a device group's firewalls (commit-all). Does not commit first; run `panos_commit` before it. |

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

Requires Go 1.26, [Task](https://taskfile.dev) and [golangci-lint](https://golangci-lint.run) 2.x.

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

Or build and run directly. The image sets `MCP_HTTP_HOST=0.0.0.0` so a published port is reachable, which means the `http` transport requires `MCP_HTTP_TOKEN`:

```bash
docker build --build-arg VERSION="$(git describe --tags --always)" -t panos-mcp-go .

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
