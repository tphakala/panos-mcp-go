//go:build tools

// pango and the MCP go-sdk are required by go.mod but not yet imported by any
// built file. These blank imports keep "go mod tidy" from removing those two
// requirements, which would discard the exact pango version go.mod names.
//
// That matters in the downgrade direction, not the upgrade one: the pinned
// pango version is an untagged commit ahead of every published tag, so a later
// bare "go get github.com/PaloAltoNetworks/pango" resolves to the newest TAG
// and moves the dependency backwards. Recovery is:
//
//	go get github.com/PaloAltoNetworks/pango@v0.10.3-0.20260731153743-efa43570c367
//
// "task go:tidy:check" (and the CI tidy step) fail if this stops working.
// Delete this file once both modules are imported by real code.
package main

import (
	_ "github.com/PaloAltoNetworks/pango"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
)
