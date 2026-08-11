package main

import (
	"context"
	"errors"
	"log/slog"
)

// errNotImplemented reports that the server has no implementation yet, so a
// caller can tell a deliberate placeholder apart from a runtime failure.
var errNotImplemented = errors.New("server not implemented yet")

// run will start the MCP server. It is not implemented yet: it returns
// errNotImplemented so the binary exits non-zero instead of appearing to serve.
func run(_ context.Context, _ *Config, _ *slog.Logger) error {
	return errNotImplemented
}
