# Security Policy

## Supported versions

panos-mcp-go is pre-1.0 and moving quickly. Security fixes are made against the
latest tagged release and the `main` branch. Older releases do not receive
backported fixes, so the remedy for a vulnerability is to upgrade to the latest
release.

| Version        | Supported          |
| -------------- | ------------------ |
| Latest release | :white_check_mark: |
| Older releases | :x:                |

## Reporting a vulnerability

Please report security issues privately, not through a public issue or pull
request. This repository has GitHub private vulnerability reporting enabled: open
the [Security tab](https://github.com/tphakala/panos-mcp-go/security) and use
**Report a vulnerability**, which starts a private advisory visible only to you
and the maintainers.

A useful report includes:

- The affected version or commit.
- A description of the issue and its impact (for example credential exposure,
  an unintended write to a firewall, or a bypass of the read-only default).
- Steps to reproduce, and a proof of concept if you have one.
- Any suggested fix or mitigation.

What to expect: reports are triaged on a best-effort basis. You will get an
acknowledgement, a maintainer will confirm the issue and work on a fix, and a
release plus a published advisory follows once a fix is ready. Please give a
reasonable window to address the issue before any public disclosure, and avoid
testing against systems you do not own or have permission to test.

## Security model

This server talks to a live firewall or Panorama with an API key, so a few
properties are worth keeping in mind when assessing risk. They are described in
full in the [README](README.md#safety-model):

- **Read-only by default.** Write tools are registered only when
  `PANOS_ALLOW_WRITES=true` is set, so a stale deployment cannot silently come up
  writable.
- **Candidate-only writes.** Nothing reaches the running configuration until an
  explicit commit (and, on Panorama, a push), so staged changes can be reviewed
  before they apply.
- **TLS verification is on by default.** `PANOS_SKIP_VERIFY` disables it and the
  server logs a loud warning naming the variable that set it, because a disabled
  check exposes the session to interception.

## Handling credentials

The PAN-OS API key and any private CA material are supplied through environment
variables (`PANOS_API_KEY`, `PANOS_CA_CERT`, and related), never through
committed files. The repository's `.gitignore` excludes `.env` files and common
key and certificate extensions so credentials are not committed by accident, but
that is a backstop, not a guarantee: keep secrets out of the repository and out
of shell history, and scope the API user's Admin Role profile to only the XML API
permissions the tools you use actually require (see the README).
