# panos-mcp-go

An MCP server for Palo Alto Networks PAN-OS firewalls and Panorama, written in Go on top of the [pango](https://github.com/PaloAltoNetworks/pango) SDK.

## Status

Empty. This commit is the build and lint toolchain only; there is no Go code yet. The implementation lands in reviewed pull requests on top of it.

## Planned

The goal is to give an AI assistant configuration management of a single device:

- Address and service objects, address and service groups, tags
- Security and NAT policy, including rule movement
- The candidate commit lifecycle: commit, push, validate, revert, config diff, job status

Two safety properties are planned alongside it. Writes will touch the candidate configuration only, so nothing reaches the running configuration until an explicit commit tool is called, and a read-only mode will be available that registers no write tools at all.

## Toolchain

Requires Go 1.26, [Task](https://taskfile.dev), [golangci-lint](https://golangci-lint.run) 2.x.

```bash
task check   # format, tidy, vet, lint and test, without modifying files
```

`task check` does not modify files. Use `task go:fmt` and `task go:tidy` to apply formatting and tidying.

Linting runs 45 linters including gosec, plus a set of [ruleguard](https://github.com/quasilyte/go-ruleguard) rules in `rules/` that gocritic loads. `task go:lint:selftest` proves those rules are actually loaded, by planting a violation and requiring a hit: a silently empty rule set otherwise looks identical to a clean run.

## License

Apache License 2.0. See [LICENSE](LICENSE).
