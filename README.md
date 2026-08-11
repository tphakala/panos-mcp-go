# panos-mcp-go

An MCP server for Palo Alto Networks PAN-OS firewalls and Panorama, written in Go on top of the [pango](https://github.com/PaloAltoNetworks/pango) SDK.

## Status

Early development, and **not yet usable**. The server does not start: `run` returns "server not implemented yet". What exists today is the module scaffold, environment configuration parsing with tests, and the build and lint toolchain.

## Planned

The goal is to give an AI assistant configuration management of a single device:

- Address and service objects, address and service groups, tags
- Security and NAT policy, including rule movement
- The candidate commit lifecycle: commit, push, validate, revert, config diff, job status

Two safety properties are planned alongside it. Writes will touch the candidate configuration only, so nothing reaches the running configuration until an explicit commit tool is called, and a read-only mode will be available that registers no write tools at all.

None of the above is implemented yet.

## Configuration

Configuration comes from environment variables. `PANOS_HOST` is required, along with either `PANOS_API_KEY` or both `PANOS_USERNAME` and `PANOS_PASSWORD`.

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
