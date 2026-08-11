# panos-mcp-go

An MCP server for Palo Alto Networks PAN-OS firewalls and Panorama, written in Go on top of the [pango](https://github.com/PaloAltoNetworks/pango) SDK.

## Status

Early development, and **not yet usable**. The server does not start: `run` returns "server not implemented yet". What exists today is the module scaffold, environment configuration parsing with tests, and the build and lint toolchain.

## Planned

The goal is to give an AI assistant configuration management of a single device:

- Address and service objects, address and service groups, tags
- Security and NAT policy, including rule movement
- The candidate commit lifecycle: commit, push, validate, revert, config diff, job status

Two safety properties are planned alongside it. Writes will touch the candidate configuration only, so nothing reaches the running configuration until an explicit commit tool is called, and the server is read-only by default: write tools will be registered only when `PANOS_ALLOW_WRITES=true` is set explicitly.

None of the above is implemented yet.

## Configuration

Configuration comes from environment variables. `PANOS_HOST` is required, along with either `PANOS_API_KEY` or both `PANOS_USERNAME` and `PANOS_PASSWORD`.

The server is read-only unless `PANOS_ALLOW_WRITES=true` is set, so a stale deployment cannot silently come up writable: enabling writes now requires the new variable. `PANOS_ALLOW_WRITES` replaces the earlier `PANOS_READ_ONLY`, and the server refuses to start while a non-empty `PANOS_READ_ONLY` is still set, forcing a conscious migration rather than silently ignoring a prior write-intent.

Several variable names align with the pango SDK's own environment contract. `PANOS_HOSTNAME` is accepted as a fallback for `PANOS_HOST`, and `PANOS_SKIP_VERIFY_CERTIFICATE` for `PANOS_SKIP_VERIFY`; the project's own names stay primary and win when both are set. The log level is read from `PANOS_LOG_LEVEL` only, and a bare `LOG_LEVEL` is intentionally ignored so an unrelated value inherited from the MCP client's environment cannot change this server's verbosity.

See [.env.example](.env.example) for the full set with defaults and notes. Nothing loads a `.env` file automatically; export the variables yourself or set them in your MCP client's server configuration.

## Building

Requires Go 1.26, [Task](https://taskfile.dev) and [golangci-lint](https://golangci-lint.run) 2.x.

```bash
task check   # format, tidy, vet, lint and test, without modifying files
task build   # build the binary
```

`task check` does not modify files. Use `task go:fmt` and `task go:tidy` to apply formatting and tidying. Formatting goes through `golangci-lint fmt` rather than a standalone goimports, because the two disagree on gofmt's doc comment rules and using both produces a tree that passes locally and fails in CI.

## License

Apache License 2.0. See [LICENSE](LICENSE).
